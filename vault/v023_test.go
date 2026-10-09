package vault

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// §6.3 (0.23.0, a MUST for every responder): a message of the new epoch
// that reaches the vault, as responder, before hs.fin is left unacked —
// not processed, dropped or deduplicated — and processed when the relay
// redelivers it after hs.fin established the epoch.
func TestNewEpochBeforeFinUnacked(t *testing.T) {
	d := newDevFixture(t)
	inv := d.invite(t, KindConnection, 10*time.Minute)
	n := newNewcomer(t, 0x64)
	n.hsInit(t, d.m, handshake.PurposeConnection, inv.ID, "e1")
	var resp []byte
	d.relay.mu.Lock()
	for i, dep := range d.relay.deposits {
		env, err := envelope.Parse(dep.payload)
		if err == nil && dep.mailbox == n.addr.Mailbox && env.Mode() == envelope.ModeSealed && env.RecipientKid().Equal(n.ini.EphKid()) {
			resp = dep.payload
			d.relay.deposits = append(d.relay.deposits[:i:i], d.relay.deposits[i+1:]...)
			break
		}
	}
	d.relay.mu.Unlock()
	if resp == nil {
		t.Fatal("no hs.resp")
	}
	res, err := n.ini.HandleResp(resp, d.m.keys.relay.Public().(ed25519.PublicKey), d.m.now())
	if err != nil {
		t.Fatal(err)
	}
	n.ep, n.tok = res.Epoch, res.Resp.Token
	jti := ""
	if c, err := relayauth.ParseToken(n.tok, d.m.keys.relay.Public().(ed25519.PublicKey)); err == nil {
		jti = c.Jti
	}
	id, _ := envelope.NewULID(time.Now())
	early, err := n.ep.Seal(&envelope.Inner{ID: id, Type: "message.send", TS: time.Now(), Body: []byte(`{"text":"hi"}`)})
	if err != nil {
		t.Fatal(err)
	}
	msg := Message{MsgID: "early-1", Sender: relayauth.EncodeKey(n.addr.PK), JTI: jti, Payload: early}
	c := &fakeCollector{}
	if err := d.m.ProcessBatch(context.Background(), c, []Message{msg}); err != nil {
		t.Fatal(err)
	}
	d.m.mu.Lock()
	_, seen := d.m.st.SeenMsgIDs[msg.MsgID]
	d.m.mu.Unlock()
	if len(c.acked) != 0 || seen {
		t.Fatalf("a new epoch's message before hs.fin was acked (%v) or deduplicated (%v)", c.acked, seen)
	}
	// hs.fin establishes the epoch; the redelivered message is then taken
	// (acked).
	n.deliver(t, d, res.Fin)
	c = &fakeCollector{}
	if err := d.m.ProcessBatch(context.Background(), c, []Message{msg}); err != nil {
		t.Fatal(err)
	}
	if len(c.acked) != 1 || c.acked[0] != msg.MsgID {
		t.Fatalf("redelivery after hs.fin not taken: %v", c.acked)
	}
}
