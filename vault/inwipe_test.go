package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// wipedInners records each inner wipeInner wipes, for the test's life.
type wipedInners struct {
	t    *testing.T
	seen []*envelope.Inner
}

func recordWipedInners(t *testing.T) *wipedInners {
	w := &wipedInners{t: t}
	testWipeInnerHook = func(in *envelope.Inner) { w.seen = append(w.seen, in) }
	t.Cleanup(func() { testWipeInnerHook = nil })
	return w
}

// wiped fails the test unless the inner with this id was wiped: recorded
// at least once, its body all zeros each time. (Matched by id: the vault's
// own messages of the same type, read back from its outbox, would hide a
// path that wipes nothing.)
func (w *wipedInners) wiped(id string) {
	w.t.Helper()
	n := 0
	for _, in := range w.seen {
		if in.ID != id {
			continue
		}
		n++
		if len(in.Body) == 0 || bytes.Count(in.Body, []byte{0}) != len(in.Body) {
			w.t.Fatalf("inner %s (%s): its body was not wiped: %q", id, in.Type, in.Body)
		}
	}
	if n == 0 {
		w.t.Fatalf("inner %s was not wiped", id)
	}
}

// Every inbound session message the vault opens is wiped once handled: a
// device's request (dispatch), a connection's messages under its request
// epoch before activation (handleRequestMessage), and one on its request
// token after activation (handleOnRequestToken). What outlives them is a
// copy: connection.approved's tokens still activate the connection.
func TestInboundSessionPlaintextWiped(t *testing.T) {
	d := newDevFixture(t)
	inv := d.invite(t, KindConnection, time.Hour)
	n := newNewcomer(t, 0x50)
	n.hsInit(t, d.m, handshake.PurposeConnection, inv.ID, "c1")
	n.finish(t, d)
	w := recordWipedInners(t)

	early := n.send(t, d, "message.deliver", []byte(`{"under":"the request epoch"}`)) // before our approval: dropped
	if !d.audited("unapproved_peer") {
		t.Fatal("message before approval not dropped")
	}
	w.wiped(early)

	var pid string
	for id := range d.m.st.Requests {
		pid = id
	}
	approve := d.sendAs(d.self(), "connection.approve", `{"pending_id":"`+pid+`"}`) // a device's request: dispatch
	if got := n.received(d); len(got) != 1 || got[0].Type != "connection.approved" {
		t.Fatalf("connection.approved: %+v", got)
	}
	w.wiped(approve)

	vaultPK := d.m.keys.relay.Public().(ed25519.PublicKey)
	mint := func(q int64) string {
		tok, err := relayclient.New(n.addr.URL, n.relay).MintToken(relayauth.EncodeKey(vaultPK), n.addr.URL,
			relayclient.TokenOptions{TTL: 24 * time.Hour, Quota: &relayauth.Quota{Msgs: &q}})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	tok, rtok := mint(PeerQuotaMsgs), mint(4)
	approved := n.send(t, d, "connection.approved", []byte(`{"token":"`+tok+`","reconnect_token":"`+rtok+`"}`))
	if len(d.m.st.Connections) != 1 || len(d.m.st.Requests) != 0 {
		t.Fatal("not active after both approvals: the body was wiped before it was read")
	}
	var c *Peer
	for _, p := range d.m.st.Connections {
		c = p
	}
	if c.Standing.Token != tok {
		t.Fatal("the stored token is not the one sent: it aliases the wiped body")
	}
	w.wiped(approved)

	refresh := n.send(t, d, "relay.token.refresh", []byte(`{"on":"the request token"}`)) // answered forbidden
	var forbidden bool
	for _, in := range n.received(d) {
		forbidden = forbidden || in.Type == "relay.token.refresh" && errCode(in) == "forbidden"
	}
	if !forbidden {
		t.Fatal("relay.token.refresh on a request token not forbidden")
	}
	w.wiped(refresh)
}

// A message after our approval, before the peer's, is left unacked under
// the request epoch, and still wiped: it is opened again at activation.
func TestRequestEpochUnackedPlaintextWiped(t *testing.T) {
	d := newDevFixture(t)
	inv := d.invite(t, KindConnection, time.Hour)
	n := newNewcomer(t, 0x50)
	n.hsInit(t, d.m, handshake.PurposeConnection, inv.ID, "c1")
	n.finish(t, d)
	var pid string
	for id := range d.m.st.Requests {
		pid = id
	}
	_ = d.send("connection.approve", []byte(`{"pending_id":"`+pid+`"}`))
	_ = n.received(d)
	w := recordWipedInners(t)
	n.n++
	id, _ := envelope.NewULID(time.Now())
	raw, _ := n.ep.Seal(&envelope.Inner{ID: id, Type: "message.deliver", TS: time.Now(), Body: []byte(`{"left":"unacked"}`)})
	msgID := fmt.Sprintf("late%d", n.n)
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{{MsgID: msgID, Sender: relayauth.EncodeKey(n.addr.PK), Payload: raw}})
	if _, seen := d.m.st.SeenMsgIDs[msgID]; seen {
		t.Fatal("message after our approval was acked before activation")
	}
	w.wiped(id)
}

// A blob call outlives the handling of its request, whose body (the blob's
// key among it) is wiped then: the call keeps the request without it.
func TestBlobCallKeepsNoRequestBody(t *testing.T) {
	d := newDevFixture(t)
	st := &blobStub{}
	d.m.addFeature(st)
	max, ttl := int64(1<<24), int64(3600)
	d.m.limits.MaxBlobBytes, d.m.limits.BlobTTLSeconds = &max, &ttl
	data, k, sum, err := envelope.SealBlob([]byte("hello blob"))
	if err != nil {
		t.Fatal(err)
	}
	id := "01JB2Z6V9K3M4N5P6Q7R8S0009"
	d.relay.blobs = &stubBlobs{byID: map[string]stubBlob{id: {mailbox: mailboxOf(d.relay.key), data: data}}}
	w := recordWipedInners(t)
	req := d.sendAs(d.self(), "test.blobcall", `{"id":"`+id+`","key":"`+base64.StdEncoding.EncodeToString(k)+
		`","sha256":"`+base64.StdEncoding.EncodeToString(sum[:])+`","size":10}`)
	w.wiped(req)
	deadline := time.Now().Add(5 * time.Second)
	var r *envelope.Inner
	for r == nil && time.Now().Before(deadline) {
		for _, x := range d.appInbox() {
			if x.Re == req {
				r = x
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if r == nil || r.Status != envelope.StatusOK || !strings.Contains(string(r.Body), `"len":10`) {
		t.Fatalf("the blob call's answer: %+v", r)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.bodies) != 1 || st.bodies[0] != nil {
		t.Fatalf("the blob call kept the request's body: %q", st.bodies)
	}
}

// The vault's own messages read back from the outbox are wiped too: past
// RestampAfter (ageCheck, re-sealed with a fresh ts), at a key change
// (reholdAt, held as a copy), and when only the type is read (entryType,
// for an entry that does not record it).
// The copy that goes on arrives intact.
func TestOutboxReadBackWiped(t *testing.T) {
	t.Run("restamped", func(t *testing.T) {
		f := newR29Fx(t)
		f.longTokens()
		e, in := f.waitingNote(0, "restamped")
		f.advance(17 * 24 * time.Hour)
		w := recordWipedInners(t)
		f.do(0, func(m *Manager, p *Peer) {
			if !m.ageCheck(e, f.clk) {
				t.Fatal("not re-sealed")
			}
		})
		w.wiped(in.ID)
		testWipeInnerHook = nil
		f.release(0)
		f.settle()
		if n := f.arrived(1, `{"n":"restamped"}`); n != 1 { // its body, as sent: not wiped before it was sealed again
			t.Fatalf("arrived %d times, want 1", n)
		}
	})
	t.Run("reheld", func(t *testing.T) {
		f := newR29Fx(t)
		f.longTokens()
		e, in := f.waitingNote(0, "reheld")
		w := recordWipedInners(t)
		f.do(0, func(m *Manager, p *Peer) { m.reholdAt(p, m.sessions[p.ID].Current(), true, f.clk) })
		w.wiped(in.ID)
		if e.Held == nil || !bytes.Contains(e.Held, []byte(`"n":"reheld"`)) {
			t.Fatalf("the held copy is not intact: %q", e.Held)
		}
	})
	t.Run("type read", func(t *testing.T) {
		f := newR29Fx(t)
		f.longTokens()
		e, in := f.waitingNote(0, "typed")
		w := recordWipedInners(t)
		f.do(0, func(m *Manager, p *Peer) {
			e.Type = "" // as an entry queued before its type was recorded: read from the payload
			if typ := m.entryType(e); typ != "test.note" {
				t.Fatalf("entryType %q", typ)
			}
		})
		w.wiped(in.ID)
	})
}
