package vault

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Release 29 rules that had no vault test (§6.3.2 gaps; the step 6
// review's M3). Each fails without its rule.

// R29-G2 (§10.8; §10.2 device.features): hs_confirm, once seen, stays,
// also against a later list without it.
func TestR29G2ConfirmSticky(t *testing.T) {
	f := newR29Fx(t)
	f.do(0, func(m *Manager, p *Peer) {
		m.noteFeatures(p, []string{handshake.CapConfirm})
		m.noteFeatures(p, []string{"other"})
		m.noteFeatures(p, []string{})
		if !p.hasConfirm() {
			t.Fatal("a later list without hs_confirm removed it (connection)")
		}
	})
	d := newDevFixture(t)
	td := d.addDevice(t, "g2", KindDesktop, 0x5b)
	d.sendAs(td, "device.features", `{"features":["hs_confirm"]}`)
	d.sendAs(td, "device.features", `{"features":[]}`)
	if !td.peer.hasConfirm() {
		t.Fatal("a later device.features without hs_confirm removed it (device)")
	}
}

// R29-I3 (§6.3.1 "Initiator"): while the vault's own reconnect epoch is
// pending, it sends the peer nothing but the handshake, hs.confirm
// included: its outbox waits, and goes once the epoch is confirmed.
func TestR29I3PendingReconnectHoldsOutbox(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	if f.p(0).Pending == nil {
		t.Fatal("setup: no pending reconnect")
	}
	f.note(0, "while-pending")
	f.do(0, func(m *Manager, p *Peer) { m.queueConfirm(p, f.clk) })
	if n := f.deliver(0, 1, kHSFin); n != 1 {
		t.Fatalf("the handshake did not pass: %d", n)
	}
	waiting := 0
	for _, e := range f.m(0).st.Outbox {
		if !e.Done && e.PeerID == f.id[0] && !e.Handshake {
			waiting++
		}
	}
	if waiting < 2 || f.lose(0, 1, kAny) != 0 {
		t.Fatalf("the outbox did not wait while pending (%d waiting)", waiting)
	}
	f.deliver(1, 0, kConfirm) // confirmed: the outbox goes
	f.deliver(0, 1, kAny)
	if f.arrived(1, "while-pending") != 1 {
		t.Fatal("the held message did not go once confirmed")
	}
}

// R29-R1 (§6.3.1 "Responder"): the responder queues hs.confirm in the
// write that activates at a verified hs.fin.
func TestR29R1ConfirmAtActivation(t *testing.T) {
	f := newR29Fx(t)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	f.deliver(0, 1, kHSFin)
	if n := len(f.takeKind(1, 0, kConfirm)); n != 1 {
		t.Fatalf("hs.confirm at activation: %d", n)
	}
}

// R29-X4 (§6.6; §3.4.1 "After a demotion"): one reconnect at a time per
// peer, whatever its trigger: none starts beside an open one or a pending
// one.
func TestR29X4OneReconnectAtATime(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.do(0, func(m *Manager, p *Peer) {
		m.startReconnect(p, f.clk)
		m.startReconnect(p, f.clk)
	})
	if n := f.countOutgoingReconnects(0); n != 1 {
		t.Fatalf("%d reconnects open", n)
	}
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	if f.p(0).Pending == nil {
		t.Fatal("setup: not pending")
	}
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	if n := f.countOutgoingReconnects(0); n != 0 || f.p(0).Pending == nil {
		t.Fatal("a reconnect started beside a pending one")
	}
}

// R29-X6 (§6.2): a rekey hs.init in sealed mode is refused as malformed
// (hs_init_rejected), not answered.
func TestR29X6SealedRekeyRefused(t *testing.T) {
	f := newR29Fx(t)
	f.rekey(0)
	msgs := f.takeKind(0, 1, kHSInit)
	if len(msgs) != 1 {
		t.Fatal("setup: no rekey hs.init")
	}
	env, err := envelope.Parse(msgs[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	in, _, err := f.m(1).sessions[f.id[1]].Open(env, f.clk)
	if err != nil {
		t.Fatal(err)
	}
	in.Seq = 0
	padded, err := envelope.EncodeInner(in, envelope.ModeSealed)
	if err != nil {
		t.Fatal(err)
	}
	sealed, _, err := envelope.SealSealed(f.m(1).keys.kem.Public(), suite.Anonymous, padded)
	if err != nil {
		t.Fatal(err)
	}
	before := len(f.m(1).st.Audit)
	f.process(1, Message{MsgID: "x6", Sender: relayauth.EncodeKey(f.pk(0)), Payload: sealed})
	rejected := false
	for _, a := range f.m(1).st.Audit[before:] {
		rejected = rejected || a.Event == "hs_init_rejected"
	}
	if !rejected || f.answerCount(1) != 0 {
		t.Fatal("a sealed rekey hs.init was not refused as malformed")
	}
}

// R29-K3 (§3.4.1 S5 "Resend"): a session message from P under an epoch
// signed by an ancestor of the vault's ik, more than an hour after the
// vault's rotation, brings identity.rotate again; at most once an hour
// and 3 times per rotation.
func TestR29K3IdentityRotateResend(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rotate(0)
	f.lose(0, 1, kAny) // P misses the identity.rotate (and the rekey)
	resends := 0
	for i := 0; i < 5; i++ {
		f.advance(90 * time.Minute)
		f.note(1, "under-E0")
		f.deliver(1, 0, kNote)
		resends += len(f.takeKind(0, 1, kRotate))
		f.lose(0, 1, kAny)
		if i == 0 && resends != 1 {
			t.Fatal("no identity.rotate resent")
		}
	}
	if resends != 3 {
		t.Fatalf("%d resends (at most 3 per rotation)", resends)
	}
}

// R29-D1 (§6.3.1 "Devices and agents"; §6.7): toward its device the vault
// is the initiator; at B it rekeys from its current epoch and never
// reconnects, and the device is not made stale.
func TestR29D1DeviceRekeyAtB(t *testing.T) {
	g := newGapF(t)
	p := g.td.peer
	p.Standing.Exp = g.clk.Add(365 * 24 * time.Hour)
	g.d.withLock(func(m *Manager) { m.startRekey(p, g.clk) })
	g.drain()
	g.answerRekey(g.take(), g.e0)
	if p.Pending == nil {
		t.Fatal("setup: not pending")
	}
	g.clk = g.clk.Add(PendingLife + time.Hour)
	for i := 0; i < 2; i++ {
		if err := g.d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if !g.d.audited("pending_abandoned_b_passed") {
		t.Fatal("setup: B did not pass")
	}
	rekey, reconnect := false, false
	for _, og := range g.d.m.st.Outgoing {
		rekey = rekey || og.PeerID == p.ID && og.Purpose == handshake.PurposeRekey
		reconnect = reconnect || og.PeerID == p.ID && og.Purpose == handshake.PurposeReconnect
	}
	if !rekey || reconnect || p.State != PeerActive {
		t.Fatalf("at B toward a device: rekey %v, reconnect %v, state %v", rekey, reconnect, p.State)
	}
}
