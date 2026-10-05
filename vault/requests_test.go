package vault

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// Two vaults in process (VAULT-MESSAGING 0.10.2, 0.10.3, §6.4): the
// inviter A and the accepter B, each with its app, sharing claims.

func newVaultPair(t *testing.T) (a, b *devFixture) {
	a, b = newDevFixture(t), newDevFixture(t)
	claims := map[string][]byte{}
	a.relay.claims, b.relay.claims = &claims, &claims
	return a, b
}

var pumped int

// pump moves from's deposits for to's vault mailbox into to, in one
// batch, as the relay would: the collect sender is from's relay key and
// the jti that of the token used (issued by to).
func pump(t *testing.T, from, to *devFixture) int {
	t.Helper()
	toPK := to.m.keys.relay.Public().(ed25519.PublicKey)
	fromPK := from.m.keys.relay.Public().(ed25519.PublicKey)
	var msgs []Message
	from.m.mu.Lock()
	from.m.drainOutbox(context.Background())
	from.m.mu.Unlock()
	from.relay.mu.Lock()
	kept := from.relay.deposits[:0]
	for _, dep := range from.relay.deposits {
		if dep.mailbox != to.m.st.Relay.Mailbox {
			kept = append(kept, dep)
			continue
		}
		jti := ""
		if c, err := relayauth.ParseToken(dep.token, toPK); err == nil {
			jti = c.Jti
		}
		pumped++
		msgs = append(msgs, Message{MsgID: fmt.Sprintf("pump%d", pumped), Sender: relayauth.EncodeKey(fromPK), JTI: jti, Payload: dep.payload})
	}
	from.relay.deposits = kept
	from.relay.mu.Unlock()
	if len(msgs) > 0 {
		if err := to.m.ProcessBatch(context.Background(), &fakeCollector{}, msgs); err != nil {
			t.Fatal(err)
		}
	}
	return len(msgs)
}

func (d *devFixture) linkFor(t *testing.T, ttl time.Duration) (*Invite, string) {
	t.Helper()
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	inv, link, err := d.m.createInvite(context.Background(), KindConnection, ttl, "dev1", d.m.now())
	if err != nil {
		t.Fatal(err)
	}
	return inv, link
}

// request sends a request from the fixture's app and returns its response
// and the events that arrived with it.
func (d *devFixture) request(t *testing.T, typ, body string) (*envelope.Inner, []*envelope.Inner) {
	t.Helper()
	id := d.sendAs(d.self(), typ, body)
	in := d.appInbox()
	var evs []*envelope.Inner
	var r *envelope.Inner
	for _, x := range in {
		if x.Re == id {
			r = x
		} else if x.Re == "" {
			evs = append(evs, x)
		}
	}
	if r == nil {
		t.Fatalf("%s: no response", typ)
	}
	return r, evs
}

// appInbox decrypts and removes the deposits to the fixture's app only,
// keeping those for other mailboxes (the peer vault's).
func (d *devFixture) appInbox() []*envelope.Inner {
	var out []*envelope.Inner
	d.relay.mu.Lock()
	defer d.relay.mu.Unlock()
	kept := d.relay.deposits[:0]
	for _, dep := range d.relay.deposits {
		if dep.mailbox != d.devPeer.Relay.Mailbox {
			kept = append(kept, dep)
			continue
		}
		if env, err := envelope.Parse(dep.payload); err == nil {
			var kr handshake.Keyring
			kr.Activate(d.ep, time.Now())
			if in, _, err := kr.Open(env, time.Now()); err == nil {
				out = append(out, in)
			}
		}
	}
	d.relay.deposits = kept
	return out
}

func event(evs []*envelope.Inner, typ string) *envelope.Inner {
	return find(evs, ofType(typ))
}

// §6.4 (0.10.2, 0.10.3): the handshake runs before approval; both members
// see the same SAS; each approval is a connection.approved carrying the
// standing and reconnect tokens; the connection is active with both, in
// either order.
func TestConnectionRequestBothApprove(t *testing.T) {
	a, b := newVaultPair(t)
	_, link := a.linkFor(t, time.Hour)
	r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
	if r.Status != envelope.StatusOK || bodyStr(t, r, "state") != "waiting" || bodyStr(t, r, "exp") == "" {
		t.Fatalf("accept: %+v %s", r, r.Body)
	}
	cid := bodyStr(t, r, "connection_id")
	// No SAS yet: approving the outgoing request is refused.
	if r, _ := b.request(t, "connection.approve", `{"connection_id":"`+cid+`"}`); errCode(r) != "bad_request" {
		t.Fatalf("approve while waiting: %+v", r)
	}
	if r, _ := b.request(t, "connection.request.list", `{}`); !strings.Contains(string(r.Body), `"state":"waiting"`) {
		t.Fatalf("list while waiting: %s", r.Body)
	}
	pump(t, b, a) // hs.init: answered at once
	if len(a.m.st.Awaiting) != 1 || len(a.appInbox()) != 0 {
		t.Fatal("the inviter showed the request before hs.fin")
	}
	pump(t, a, b) // hs.resp: hs.fin at once, the SAS to B's devices
	bOut := event(b.appInbox(), "connection.request.outgoing")
	if bOut == nil || bodyStr(t, bOut, "connection_id") != cid || len(bodyStr(t, bOut, "sas")) != 6 {
		t.Fatalf("outgoing: %+v", bOut)
	}
	pump(t, b, a) // hs.fin
	aPend := event(a.appInbox(), "connection.request.pending")
	if aPend == nil || bodyStr(t, aPend, "sas") != bodyStr(t, bOut, "sas") || bodyStr(t, aPend, "state") != "pending" {
		t.Fatalf("pending: %+v", aPend)
	}
	pid := bodyStr(t, aPend, "pending_id")
	if r, _ := a.request(t, "connection.request.list", `{}`); !strings.Contains(string(r.Body), pid) || !strings.Contains(string(r.Body), `"peer_approved":false`) {
		t.Fatalf("inviter list: %s", r.Body)
	}
	// A approves first: B learns peer_approved, nothing is active yet.
	if r, _ := a.request(t, "connection.approve", `{"pending_id":"`+pid+`"}`); r.Status != envelope.StatusOK {
		t.Fatalf("A approve: %+v", r)
	}
	pump(t, a, b)
	var peerApproved bool
	for _, ev := range b.appInbox() {
		peerApproved = peerApproved || ev.Type == "sync.event" && bodyStr(t, ev, "state") == "peer_approved"
	}
	if !peerApproved || len(a.m.st.Connections) != 0 || len(b.m.st.Connections) != 0 {
		t.Fatal("active before both approvals")
	}
	// B approves: B is active; then A at B's connection.approved.
	r, evs := b.request(t, "connection.approve", `{"connection_id":"`+cid+`"}`)
	added := event(evs, "connection.event")
	if r.Status != envelope.StatusOK || added == nil || bodyStr(t, added, "event") != "added" || bodyStr(t, added, "connection_id") != cid {
		t.Fatalf("B approve: %+v %+v", r, evs)
	}
	pump(t, b, a)
	added = event(a.appInbox(), "connection.event")
	if added == nil || bodyStr(t, added, "event") != "added" || bodyStr(t, added, "pending_id") != pid {
		t.Fatalf("A added: %+v", added)
	}
	pa, pb := a.m.st.Connections[bodyStr(t, added, "connection_id")], b.m.st.Connections[cid]
	if pa == nil || pb == nil || pa.State != PeerActive || pb.State != PeerActive || len(a.m.st.Requests)+len(b.m.st.Requests) != 0 {
		t.Fatal("not active on both sides")
	}
	// The tokens each holds are standing and reconnect tokens.
	for _, c := range []struct {
		p      *Peer
		issuer ed25519.PublicKey
	}{{pa, b.m.keys.relay.Public().(ed25519.PublicKey)}, {pb, a.m.keys.relay.Public().(ed25519.PublicKey)}} {
		st, err1 := relayauth.ParseToken(c.p.Standing.Token, c.issuer)
		rt, err2 := relayauth.ParseToken(c.p.Reconnect.Token, c.issuer)
		if err1 != nil || err2 != nil || *st.Quota.Msgs != PeerQuotaMsgs || *rt.Quota.Msgs != handshake.ReconnectTokenQuotaMsgs {
			t.Fatal("standing or reconnect token missing after activation")
		}
	}
	// Messages flow under the session (identity.rotate is a V↔V event).
	a.m.mu.Lock()
	a.m.sendTo(pa, "connection.removed", []byte(`{}`), a.m.now())
	a.m.mu.Unlock()
	pump(t, a, b)
	if b.m.st.Connections[cid] != nil {
		t.Fatal("the session does not carry messages")
	}
}

// §6.4 "Already connected" (0.10.2): the accepter answers exists with its
// connection id, before any hs.init; and an outgoing request counts too.
func TestAcceptExists(t *testing.T) {
	a, b := newVaultPair(t)
	_, link := a.linkFor(t, time.Hour)
	r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
	cid := bodyStr(t, r, "connection_id")
	_, link2 := a.linkFor(t, time.Hour)
	r, _ = b.request(t, "connection.invite.accept", `{"link":"`+link2+`"}`)
	if errCode(r) != "exists" || bodyStr(t, r, "connection_id") != cid {
		t.Fatalf("exists: %+v %s", r, r.Body)
	}
	if pump(t, b, a) != 1 {
		t.Fatal("an hs.init went out for an existing request")
	}
}

// §6.4 "The inviter's drop" (0.10.2): an hs.init whose from.ik is that of
// an active connection is dropped, from any relay key.
func TestInviterDropsKnownIdentity(t *testing.T) {
	d := newDevFixture(t)
	n := newNewcomer(t, 0x80)
	d.addConnection("c1", 0x80) // same ik as the newcomer, another relay key
	n.relay = ed25519.NewKeyFromSeed(make([]byte, 32))
	pk := n.relay.Public().(ed25519.PublicKey)
	n.addr.PK, n.addr.Mailbox = pk, relayauth.MailboxID(pk)
	inv := d.invite(t, KindConnection, time.Hour)
	n.hsInit(t, d.m, handshake.PurposeConnection, inv.ID, "k1")
	if d.firstContact() != 0 || !d.audited("hs_init_from_known_peer") || d.depositsTo(n.addr.Mailbox) != 0 {
		t.Fatal("hs.init from a known identity answered")
	}
}

// §6.4 (0.10.3) "Before activation" and §7.1: before the member's
// approval anything but connection.approved is dropped and audited; after
// it, left unacked; a request token carries nothing else, and
// relay.token.refresh on it is forbidden.
func TestPreActivationAndRequestToken(t *testing.T) {
	d := newDevFixture(t)
	inv := d.invite(t, KindConnection, time.Hour)
	n := newNewcomer(t, 0x50)
	n.hsInit(t, d.m, handshake.PurposeConnection, inv.ID, "c1")
	n.finish(t, d)
	if _, err := relayauth.ParseToken(n.tok, d.m.keys.relay.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	n.send(t, d, "message.deliver", []byte(`{}`))
	if !d.audited("unapproved_peer") {
		t.Fatal("message before approval not dropped")
	}
	var pid string
	for id := range d.m.st.Requests {
		pid = id
	}
	_ = d.send("connection.approve", []byte(`{"pending_id":"`+pid+`"}`))
	got := n.received(d)
	if len(got) != 1 || got[0].Type != "connection.approved" {
		t.Fatalf("connection.approved: %+v", got)
	}
	// After the approval: left unacked (processed at activation).
	n.n++
	id, _ := envelope.NewULID(time.Now())
	raw, _ := n.ep.Seal(&envelope.Inner{ID: id, Type: "message.deliver", TS: time.Now(), Body: []byte(`{}`)})
	msgID := fmt.Sprintf("late%d", n.n)
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{{MsgID: msgID, Sender: relayauth.EncodeKey(n.addr.PK), Payload: raw}})
	if _, seen := d.m.st.SeenMsgIDs[msgID]; seen {
		t.Fatal("message after our approval was acked before activation")
	}
	// The peer's approval activates the connection.
	vaultPK := d.m.keys.relay.Public().(ed25519.PublicKey)
	mint := func(q int64) string {
		tok, err := relayclient.New(n.addr.URL, n.relay).MintToken(relayauth.EncodeKey(vaultPK), n.addr.URL,
			relayclient.TokenOptions{TTL: 24 * time.Hour, Quota: &relayauth.Quota{Msgs: &q}})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	n.send(t, d, "connection.approved", []byte(`{"token":"`+mint(PeerQuotaMsgs)+`","reconnect_token":"`+mint(4)+`"}`))
	if len(d.m.st.Connections) != 1 || len(d.m.st.Requests) != 0 {
		t.Fatal("not active after both approvals")
	}
	// relay.token.refresh on the request token: forbidden.
	n.send(t, d, "relay.token.refresh", []byte(`{}`))
	var forbidden bool
	for _, in := range n.received(d) {
		forbidden = forbidden || in.Type == "relay.token.refresh" && errCode(in) == "forbidden"
	}
	if !forbidden {
		t.Fatal("relay.token.refresh on a request token not forbidden")
	}
}

// §6.4 (0.10.5): declining sends connection.declined (until 0.10.4 the
// peer was not told); the request token is denylisted; an unknown request
// is not_found.
func TestDeclineRequest(t *testing.T) {
	d := newDevFixture(t)
	inv := d.invite(t, KindConnection, time.Hour)
	n := newNewcomer(t, 0x50)
	n.hsInit(t, d.m, handshake.PurposeConnection, inv.ID, "c1")
	n.finish(t, d)
	var pid string
	for id := range d.m.st.Requests {
		pid = id
	}
	_ = d.send("connection.decline", []byte(`{"pending_id":"`+pid+`"}`))
	d.m.mu.Lock()
	d.m.drainOutbox(context.Background())
	d.m.mu.Unlock()
	c, _ := relayauth.ParseToken(n.tok, d.m.keys.relay.Public().(ed25519.PublicKey))
	got := n.received(d)
	if len(d.m.st.Requests) != 0 || !containsStr(d.relay.revoked, "jti:"+c.Jti) || len(got) != 1 ||
		got[0].Type != "connection.declined" || string(got[0].Body) != `{}` {
		t.Fatalf("decline did not drop the request and its token, or did not tell the peer: %+v", got)
	}
	_ = d.send("connection.decline", []byte(`{"pending_id":"`+pid+`"}`))
	_ = d.send("connection.approve", []byte(`{"pending_id":"`+pid+`","connection_id":"x"}`))
	rs := d.responses(t)
	if len(rs) < 2 || errCode(rs[len(rs)-2]) != "not_found" || errCode(rs[len(rs)-1]) != "bad_request" {
		t.Fatalf("after decline: %+v", rs)
	}
}

// §6.4 (0.10.2): an outgoing request not active 8 days after the accept
// is dropped, its request token denylisted, connection.event{failed}.
func TestOutgoingRequestExpires(t *testing.T) {
	a, b := newVaultPair(t)
	_, link := a.linkFor(t, time.Hour)
	r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
	cid := bodyStr(t, r, "connection_id")
	in9 := time.Now().Add(9 * 24 * time.Hour)
	b.m.now = func() time.Time { return in9 }
	_ = b.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	var failed bool
	for _, ev := range b.appInbox() {
		failed = failed || ev.Type == "connection.event" && bodyStr(t, ev, "event") == "failed" && bodyStr(t, ev, "connection_id") == cid
	}
	if !failed || b.m.countRequests(ReqOut) != 0 {
		t.Fatal("outgoing request not failed after 8 days")
	}
}

// FuzzRequestRef: connection.approve / .decline bodies name exactly one
// of pending_id and connection_id (§10.4).
func FuzzRequestRef(f *testing.F) {
	f.Add([]byte(`{"pending_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V"}`))
	f.Add([]byte(`{"connection_id":"x"}`))
	f.Add([]byte(`{"pending_id":"a","connection_id":"b"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		id, dir, err := requestRef(&envelope.Inner{Body: b})
		if err != nil {
			return
		}
		if id == "" || len(id) > 128 || (dir != ReqIn && dir != ReqOut) {
			t.Fatalf("accepted %q %q", id, dir)
		}
	})
}
