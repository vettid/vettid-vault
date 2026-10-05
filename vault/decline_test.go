package vault

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// VAULT-MESSAGING 0.10.5: a declined connection request is sent to the
// other party (connection.declined, §6.4, §7.1, §7.4, §10.4), and the
// owner's rejection of a pairing or transfer after hs.fin to the new
// device (device.pair.rejected, §6.7, §6.7.1, §10.3).

// requested runs a connection request between two vaults up to the point
// where both members see the SAS: A (the inviter) holds the incoming
// request pid, B (the accepter) the outgoing request cid.
func requested(t *testing.T) (a, b *devFixture, pid, cid string) {
	t.Helper()
	a, b = newVaultPair(t)
	sinkOf(a)
	sinkOf(b)
	_, link := a.linkFor(t, time.Hour)
	r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
	cid = bodyStr(t, r, "connection_id")
	pump(t, b, a) // hs.init
	pump(t, a, b) // hs.resp; hs.fin goes out
	if event(b.appInbox(), "connection.request.outgoing") == nil {
		t.Fatal("no outgoing request")
	}
	pump(t, b, a) // hs.fin
	pend := event(a.appInbox(), "connection.request.pending")
	if pend == nil {
		t.Fatal("no pending request")
	}
	return a, b, bodyStr(t, pend, "pending_id"), cid
}

// outTo drains from's outbox and returns, without removing them, its
// deposits to to's vault mailbox, with the jti of the token each used
// (issued by to).
func outTo(t *testing.T, from, to *devFixture) (deps []stubDeposit, jtis []string) {
	t.Helper()
	from.m.mu.Lock()
	from.m.drainOutbox(context.Background())
	from.m.mu.Unlock()
	toPK := to.m.keys.relay.Public().(ed25519.PublicKey)
	from.relay.mu.Lock()
	defer from.relay.mu.Unlock()
	for _, dep := range from.relay.deposits {
		if dep.mailbox != to.m.st.Relay.Mailbox {
			continue
		}
		c, err := relayauth.ParseToken(dep.token, toPK)
		if err != nil {
			t.Fatalf("deposit on a token %s did not issue: %v", "the receiver", err)
		}
		deps, jtis = append(deps, dep), append(jtis, c.Jti)
	}
	return deps, jtis
}

func syncState(t *testing.T, evs []*envelope.Inner, idKey, id, state string) bool {
	t.Helper()
	for _, ev := range evs {
		if ev.Type == "sync.event" && bodyStr(t, ev, "kind") == "connection.request" && bodyStr(t, ev, "state") == state &&
			strings.Contains(string(ev.Body), `"`+idKey+`":"`+id+`"`) {
			return true
		}
	}
	return false
}

func failedDeclined(t *testing.T, evs []*envelope.Inner, cid string) (failed, declined bool) {
	t.Helper()
	for _, ev := range evs {
		if ev.Type == "connection.event" && bodyStr(t, ev, "event") == "failed" && bodyStr(t, ev, "connection_id") == cid {
			failed = true
			declined = declined || strings.Contains(string(ev.Body), `"reason":"declined"`)
		}
	}
	return failed, declined
}

// The issued tokens of every request of to's that came from (the jti of
// each) are denylisted at to's relay.
func allDenied(t *testing.T, d *devFixture) {
	t.Helper()
	for _, it := range d.m.st.Issued {
		if it.Kind == TokRequest || it.Kind == TokStanding && it.PeerID != d.devPeer.ID || it.Kind == TokReconnect {
			if !it.Denied || !d.relayRevoked("jti", it.JTI) {
				t.Fatalf("%s token %s not denylisted", it.Kind, it.JTI)
			}
		}
	}
}

// §6.4 (0.10.5): the inviter's decline sends connection.declined on the
// accepter's request token, under the handshake's epoch, before the drop;
// the accepter ends its request: peer_declined, connection.event{failed,
// reason: declined}, its tokens denylisted, the slot freed, exists cleared,
// audit and feed. A redelivered copy is dropped and audited.
func TestDeclineSentInviterToAccepter(t *testing.T) {
	a, b, pid, cid := requested(t)
	if r, _ := a.request(t, "connection.decline", `{"pending_id":"`+pid+`"}`); r.Status != envelope.StatusOK {
		t.Fatalf("decline: %+v", r)
	}
	if len(a.m.st.Requests) != 0 {
		t.Fatal("the decliner kept the request")
	}
	deps, jtis := outTo(t, a, b)
	if len(deps) != 1 || b.m.issuedKind(jtis[0]) != TokRequest {
		t.Fatalf("connection.declined not on the accepter's request token: %d deposits", len(deps))
	}
	// The decliner's own tokens are denylisted, not the one it used.
	if a.relayRevoked("jti", jtis[0]) {
		t.Fatal("the decliner revoked the peer's token")
	}
	allDenied(t, a)
	dup := deps[0].payload
	pump(t, a, b)
	evs := b.appInbox()
	if !syncState(t, evs, "connection_id", cid, "peer_declined") {
		t.Fatalf("no peer_declined: %+v", evs)
	}
	if f, d := failedDeclined(t, evs, cid); !f || !d {
		t.Fatalf("no connection.event{failed, reason: declined}: %+v", evs)
	}
	if len(b.m.st.Requests) != 0 || b.m.countRequests(ReqOut) != 0 {
		t.Fatal("the accepter kept the request")
	}
	allDenied(t, b)
	if !b.hasActivity("connection.request.peer_declined") {
		t.Fatal("not audited")
	}
	var feed bool
	for _, act := range sinkOf(b).got {
		feed = feed || act.Kind == "connection.request.peer_declined" && act.Feed && act.Audit && act.Ref == cid
	}
	if !feed {
		t.Fatal("no feed item")
	}
	// A late duplicate finds no request: dropped and audited.
	_ = b.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{{MsgID: "dup1",
		Sender: relayauth.EncodeKey(a.m.keys.relay.Public().(ed25519.PublicKey)), JTI: jtis[0], Payload: dup}})
	if len(b.appInbox()) != 0 || !b.audited("request_token_misuse") {
		t.Fatal("a late connection.declined was not dropped")
	}
	// exists no longer refers to it: a new invitation from A is accepted.
	_, link := a.linkFor(t, time.Hour)
	if r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`); r.Status != envelope.StatusOK {
		t.Fatalf("accept after peer_declined: %+v %s", r, r.Body)
	}
}

// §6.4 (0.10.5): the accepter's decline in pending; the inviter gets
// peer_declined for its pending_id and no connection.event{failed}.
func TestDeclineSentAccepterToInviter(t *testing.T) {
	a, b, pid, cid := requested(t)
	if r, _ := b.request(t, "connection.decline", `{"connection_id":"`+cid+`"}`); r.Status != envelope.StatusOK {
		t.Fatalf("decline: %+v", r)
	}
	deps, jtis := outTo(t, b, a)
	if len(deps) != 1 || a.m.issuedKind(jtis[0]) != TokRequest {
		t.Fatal("connection.declined not on the inviter's request token")
	}
	pump(t, b, a)
	evs := a.appInbox()
	if !syncState(t, evs, "pending_id", pid, "peer_declined") {
		t.Fatalf("no peer_declined: %+v", evs)
	}
	for _, ev := range evs {
		if ev.Type == "connection.event" {
			t.Fatalf("connection.event on the inviter's side: %s", ev.Body)
		}
	}
	if len(a.m.st.Requests) != 0 || a.m.countRequests(ReqIn) != 0 || !a.hasActivity("connection.request.peer_declined") {
		t.Fatal("the inviter kept the request")
	}
	allDenied(t, a)
	allDenied(t, b)
}

// §6.4 (0.10.5): a decline after the peer's approval still goes on the
// peer's request token, not the standing token its connection.approved
// carried; the receiver, which approved, ends its request and denylists
// the standing and reconnect tokens it sent.
func TestDeclineAfterPeerApproval(t *testing.T) {
	a, b, pid, cid := requested(t)
	if r, _ := b.request(t, "connection.approve", `{"connection_id":"`+cid+`"}`); r.Status != envelope.StatusOK {
		t.Fatalf("B approve: %+v", r)
	}
	pump(t, b, a) // A: peer_approved
	a.appInbox()
	if r := a.m.st.Requests[pid]; r == nil || !r.PeerApproved {
		t.Fatal("A has not the peer's approval")
	}
	if r, _ := a.request(t, "connection.decline", `{"pending_id":"`+pid+`"}`); r.Status != envelope.StatusOK {
		t.Fatalf("decline: %+v", r)
	}
	deps, jtis := outTo(t, a, b)
	if len(deps) != 1 || b.m.issuedKind(jtis[0]) != TokRequest {
		t.Fatal("connection.declined not on the request token")
	}
	pump(t, a, b)
	if evs := b.appInbox(); !syncState(t, evs, "connection_id", cid, "peer_declined") {
		t.Fatalf("approved receiver: %+v", evs)
	}
	if len(b.m.st.Requests) != 0 || len(b.m.st.Connections) != 0 {
		t.Fatal("receiver kept the request")
	}
	allDenied(t, b) // the request token and the standing and reconnect tokens
}

// §10.4 (0.10.5): block.add{pending_id} is a decline: connection.declined
// is sent, and the peer cannot tell it from a decline.
func TestBlockPendingSendsDecline(t *testing.T) {
	a, b, pid, cid := requested(t)
	if r, _ := a.request(t, "block.add", `{"pending_id":"`+pid+`"}`); r.Status != envelope.StatusOK {
		t.Fatalf("block: %+v", r)
	}
	pump(t, a, b)
	evs := b.appInbox()
	if !syncState(t, evs, "connection_id", cid, "peer_declined") {
		t.Fatalf("block not sent as a decline: %+v", evs)
	}
	for _, ev := range evs {
		if strings.Contains(string(ev.Body), "block") {
			t.Fatalf("the block is visible: %s", ev.Body)
		}
	}
	if len(a.m.st.Blocks) != 1 || len(b.m.st.Requests) != 0 {
		t.Fatal("block or decline incomplete")
	}
}

// §6.4 "After activation" (0.10.5): A approves; B, holding A's approval,
// approves and is active; A declines before B's connection.approved
// arrives. The decline reaches B's active connection and is handled as
// connection.removed (devices: connection.event{removed}), audited
// connection.request.peer_declined; B's connection.approved then finds
// nothing at A.
func TestDeclineCrossingActivation(t *testing.T) {
	a, b, pid, cid := requested(t)
	if r, _ := a.request(t, "connection.approve", `{"pending_id":"`+pid+`"}`); r.Status != envelope.StatusOK {
		t.Fatalf("A approve: %+v", r)
	}
	pump(t, a, b) // B: peer_approved
	b.appInbox()
	r, evs := b.request(t, "connection.approve", `{"connection_id":"`+cid+`"}`)
	if r.Status != envelope.StatusOK || event(evs, "connection.event") == nil || b.m.st.Connections[cid] == nil {
		t.Fatalf("B not active: %+v", evs)
	}
	// A declines before B's connection.approved arrives (it is held back).
	b.m.mu.Lock()
	b.m.drainOutbox(context.Background())
	b.m.mu.Unlock()
	b.relay.mu.Lock()
	held := b.relay.deposits
	b.relay.deposits = nil
	b.relay.mu.Unlock()
	if r, _ := a.request(t, "connection.decline", `{"pending_id":"`+pid+`"}`); r.Status != envelope.StatusOK {
		t.Fatalf("A decline: %+v", r)
	}
	pump(t, a, b)
	evs = b.appInbox()
	var removed bool
	for _, ev := range evs {
		removed = removed || ev.Type == "connection.event" && bodyStr(t, ev, "event") == "removed" && bodyStr(t, ev, "connection_id") == cid
	}
	if !removed || b.m.st.Connections[cid] != nil || b.m.sessions[cid] != nil {
		t.Fatalf("active connection not removed: %+v", evs)
	}
	if !b.hasActivity("connection.request.peer_declined") || !b.hasActivity("connection.removed") {
		t.Fatal("not audited")
	}
	allDenied(t, b)
	// No notice back to the decliner.
	if deps, _ := outTo(t, b, a); len(deps) != 0 {
		t.Fatalf("B answered the decline: %d deposits", len(deps))
	}
	// B's held connection.approved now reaches A: no request, dropped.
	b.relay.mu.Lock()
	b.relay.deposits = append(b.relay.deposits, held...)
	b.relay.mu.Unlock()
	pump(t, b, a)
	if len(a.m.st.Connections) != 0 || len(a.m.st.Requests) != 0 {
		t.Fatal("A activated after its decline")
	}
}

// §6.4 (0.10.5) "When it can be sent": the accepter in waiting holds no
// token to the inviter and no epoch, and the inviter's decline of an
// hs.init without hs.fin concerns a request its devices never saw:
// neither sends anything.
func TestDeclineWaitingSendsNothing(t *testing.T) {
	a, b := newVaultPair(t)
	_, link := a.linkFor(t, time.Hour)
	r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
	cid := bodyStr(t, r, "connection_id")
	if r, _ := b.request(t, "connection.decline", `{"connection_id":"`+cid+`"}`); r.Status != envelope.StatusOK {
		t.Fatalf("decline in waiting: %+v", r)
	}
	if deps, _ := outTo(t, b, a); len(deps) != 1 { // the hs.init only
		t.Fatalf("waiting decline sent %d deposits", len(deps))
	}

	// The inviter, an hs.init without hs.fin.
	a, b = newVaultPair(t)
	_, link = a.linkFor(t, time.Hour)
	b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
	pump(t, b, a) // hs.init; hs.resp queued
	var awID string
	for id := range a.m.st.Awaiting {
		awID = id
	}
	if r, _ := a.request(t, "connection.decline", `{"pending_id":"`+awID+`"}`); r.Status != envelope.StatusOK {
		t.Fatalf("inviter decline before hs.fin: %+v", r)
	}
	deps, _ := outTo(t, a, b)
	if len(deps) != 1 { // hs.resp only
		t.Fatalf("decline before hs.fin sent %d deposits", len(deps))
	}
	if env, err := envelope.Parse(deps[0].payload); err != nil || env.Mode() != envelope.ModeSealed {
		t.Fatal("not hs.resp")
	}
}

// §6.4, §7.4 (0.10.5): expiry sends nothing.
func TestExpirySendsNoDecline(t *testing.T) {
	a, b, _, _ := requested(t)
	in8 := time.Now().Add(8 * 24 * time.Hour)
	a.m.now = func() time.Time { return in8 }
	_ = a.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	if len(a.m.st.Requests) != 0 {
		t.Fatal("not expired")
	}
	if deps, _ := outTo(t, a, b); len(deps) != 0 {
		t.Fatalf("expiry sent %d deposits", len(deps))
	}
}

// §6.7 (0.10.5): the owner's rejection after hs.fin is sent to the new
// device as device.pair.rejected, under the handshake's epoch, on the
// token the device issued in hs.init, before the drop; a rejection before
// hs.fin, and an expiry, send nothing.
func TestPairRejectedSent(t *testing.T) {
	d := newDevFixture(t)
	inv := d.invite(t, KindDesktop, PairingApprovalTTL)
	n := newNewcomer(t, 0x50)
	n.hsInit(t, d.m, handshake.PurposeDesktop, inv.ID, "p1")
	n.finish(t, d)
	d.responses(t)
	reqJTI := ""
	if c, err := relayauth.ParseToken(n.tok, d.m.keys.relay.Public().(ed25519.PublicKey)); err == nil {
		reqJTI = c.Jti
	}
	if err := d.send("device.pair.reject", []byte(`{"pairing_id":"`+inv.ID+`"}`)); err != nil {
		t.Fatal(err)
	}
	// On the device's own token (issued by the device to the vault).
	nPK := n.addr.PK
	var onDeviceToken bool
	d.relay.mu.Lock()
	for _, dep := range d.relay.deposits {
		if dep.mailbox == n.addr.Mailbox {
			_, err := relayauth.ParseToken(dep.token, d.m.keys.relay.Public().(ed25519.PublicKey))
			c, err2 := relayauth.ParseToken(dep.token, nPK)
			onDeviceToken = err != nil && err2 == nil && c.Sub == relayauth.EncodeKey(d.m.keys.relay.Public().(ed25519.PublicKey))
		}
	}
	d.relay.mu.Unlock()
	if !onDeviceToken {
		t.Fatal("device.pair.rejected not on the device's token")
	}
	got := n.received(d)
	if len(got) != 1 || got[0].Type != "device.pair.rejected" || string(got[0].Body) != `{}` {
		t.Fatalf("device.pair.rejected: %+v", got)
	}
	if d.firstContact() != 0 || !d.relayRevoked("jti", reqJTI) || !d.relayRevoked("jti", inv.OpenJTI) {
		t.Fatal("pairing not dropped and denylisted")
	}

	// Before hs.fin: nothing.
	inv = d.invite(t, KindDesktop, PairingApprovalTTL)
	n = newNewcomer(t, 0x60)
	n.hsInit(t, d.m, handshake.PurposeDesktop, inv.ID, "p2")
	d.relay.mu.Lock()
	d.relay.deposits = nil // the hs.resp: the device never answers
	d.relay.mu.Unlock()
	if err := d.send("device.pair.reject", []byte(`{"pairing_id":"`+inv.ID+`"}`)); err != nil {
		t.Fatal(err)
	}
	if d.depositsTo(n.addr.Mailbox) != 0 {
		t.Fatal("rejection before hs.fin sent")
	}

	// An expiry after hs.fin: nothing.
	inv = d.invite(t, KindDesktop, PairingApprovalTTL)
	n = newNewcomer(t, 0x70)
	n.hsInit(t, d.m, handshake.PurposeDesktop, inv.ID, "p3")
	n.finish(t, d)
	d.responses(t)
	later := time.Now().Add(11 * time.Minute)
	d.m.now = func() time.Time { return later }
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	if d.firstContact() != 0 || d.depositsTo(n.addr.Mailbox) != 0 {
		t.Fatal("expiry sent device.pair.rejected")
	}
}

// §6.7, §6.7.1 (0.10.5): the holder's rejection of a transfer after the
// new app's hs.fin is device.pair.rejected; an abort by a clone alarm,
// a recovery or an expiry sends nothing.
func TestTransferRejectedSent(t *testing.T) {
	for _, reason := range []string{"rejected", "alarm", "replaced", "expired"} {
		t.Run(reason, func(t *testing.T) {
			d := newDevFixture(t)
			attestOK(d)
			inv := d.transferInvite(t)
			n := newNewcomer(t, 0x50)
			n.hsInitAttest(t, d.m, handshake.PurposeApp, inv.ID, "t1", testAttest)
			n.finish(t, d)
			d.responses(t)
			d.m.mu.Lock()
			err := managerHost{d.m}.EndTransfer(inv.ID, reason, d.m.now())
			d.m.drainOutbox(context.Background())
			d.m.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			got := n.received(d)
			want := 0
			if reason == "rejected" {
				want = 1
			}
			if len(got) != want || want == 1 && got[0].Type != "device.pair.rejected" {
				t.Fatalf("%s: %+v", reason, got)
			}
			if d.m.st.Transfer != nil || d.firstContact() != 0 {
				t.Fatal("transfer not aborted")
			}
		})
	}
}

// 0.10.5: the best-effort deposits of connection.declined and
// device.pair.rejected stop at their NotAfter.
func TestOutboxNotAfter(t *testing.T) {
	d := newDevFixture(t)
	now := time.Now()
	d.m.mu.Lock()
	d.m.queueDeposit(&OutboxEntry{RelayURL: "https://relay.example.org", Mailbox: "mb", Token: "t", Payload: []byte("x"),
		NotAfter: now.Add(-time.Second)}, now)
	d.m.drainOutbox(context.Background())
	d.m.mu.Unlock()
	if d.depositsTo("mb") != 0 {
		t.Fatal("deposited after NotAfter")
	}
}
