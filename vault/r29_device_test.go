package vault

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// R29-D3 (§6.3.1 "Devices and agents"): a rekey hs.init from a device or
// agent is acked, dropped and audited drop.peer_key (ref unexpected); the
// vault answers none.
func TestR29D3DeviceRekeyRefused(t *testing.T) {
	d := newDevFixture(t)
	sink := sinkOf(d)
	for _, kind := range []string{KindApp, KindDesktop, KindAgent} {
		td := d.addDevice(t, "d3-"+kind, kind, map[string]byte{KindApp: 0x3d, KindDesktop: 0x41, KindAgent: 0x45}[kind])
		d.inbox(td)
		d.sendAs(td, handshake.TypeInit, `{"purpose":"rekey"}`)
		refused := false
		for _, a := range sink.got {
			refused = refused || a.Kind == "drop.peer_key" && a.Ref == "unexpected" && a.DeviceID == td.peer.ID
		}
		if !refused {
			t.Fatalf("%s: a rekey hs.init was not refused drop.peer_key (unexpected)", kind)
		}
		for _, aw := range d.m.st.Awaiting {
			if aw.PeerID == td.peer.ID {
				t.Fatalf("%s: the vault answered a device's rekey", kind)
			}
		}
		d.relay.mu.Lock()
		for _, dep := range d.relay.deposits {
			if env, err := envelope.Parse(dep.payload); err == nil && dep.mailbox == td.peer.Relay.Mailbox && env.Mode() == envelope.ModeSealed {
				d.relay.mu.Unlock()
				t.Fatalf("%s: the vault answered (a sealed hs.resp)", kind)
			}
		}
		d.relay.mu.Unlock()
		for _, in := range d.inbox(td)[td.peer.ID] {
			if in.Type == handshake.TypeInit || in.Type == handshake.TypeConfirm {
				t.Fatalf("%s: the vault answered with %s", kind, in.Type)
			}
		}
	}
}

// R29-D4 (§6.3.1 "An app from before release 29"): device.update_needed,
// a feed item (priority high, device_id set) to the member's app and
// desktops, once per device until that device advertises hs_confirm.

func updateNotices(s *recSink, dev string) int {
	n := 0
	for _, a := range s.got {
		if a.Kind == "device.update_needed" && a.DeviceID == dev && a.Feed && a.Priority == "high" {
			n++
		}
	}
	return n
}

// sendBare sends a message from td without inner features (an app from
// before release 29).
func (d *devFixture) sendBare(t *testing.T, td *tdev, typ string) {
	t.Helper()
	d.seq++
	id, _ := envelope.NewULID(time.Now())
	raw, err := td.ep.Seal(&envelope.Inner{ID: id, Type: typ, TS: time.Now(), Body: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	msg := Message{MsgID: fmt.Sprintf("bare%d", d.seq), Sender: relayauth.EncodeKey(td.peer.Relay.PK), Payload: raw}
	if err := d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg}); err != nil {
		t.Fatal(err)
	}
}

// A message without hs_confirm raises it once; after the device
// advertises hs_confirm it is never raised again.
func TestR29D4MessageWithoutConfirm(t *testing.T) {
	d := newDevFixture(t)
	sink := sinkOf(d)
	td := d.addDevice(t, "old-desk", KindDesktop, 0x49)
	if updateNotices(sink, td.peer.ID) != 0 {
		t.Fatal("raised for a device that has sent nothing")
	}
	d.sendBare(t, td, "vault.status")
	if updateNotices(sink, td.peer.ID) != 1 {
		t.Fatal("a message without hs_confirm did not raise device.update_needed")
	}
	d.sendBare(t, td, "vault.status")
	if updateNotices(sink, td.peer.ID) != 1 {
		t.Fatal("raised twice")
	}
	d.sendAs(td, "vault.status", `{}`) // advertises hs_confirm
	td.peer.UpdateNoticed = false      // even were it not recorded: hs_confirm stays
	d.sendBare(t, td, "vault.status")
	if updateNotices(sink, td.peer.ID) != 1 {
		t.Fatal("raised after the device advertised hs_confirm")
	}
	// A release-29 device never sees it.
	td2 := d.addDevice(t, "new-desk", KindDesktop, 0x4d)
	d.sendAs(td2, "vault.status", `{}`)
	if updateNotices(sink, td2.peer.ID) != 0 {
		t.Fatal("raised for a device with hs_confirm")
	}
}

// B passing for a pending epoch toward a device without hs_confirm raises
// it, but not for a device that has sent nothing yet.
func TestR29D4AtB(t *testing.T) {
	for _, heard := range []bool{false, true} {
		g := newGapF(t)
		p := g.td.peer
		p.Standing.Exp = g.clk.Add(365 * 24 * time.Hour)
		g.d.withLock(func(m *Manager) { m.startRekey(p, g.clk) })
		g.drain()
		g.answerRekey(g.take(), g.e0)
		if p.Pending == nil {
			t.Fatal("setup: not pending")
		}
		// The device's own record: heard from without hs_confirm, not yet
		// noticed; or never heard from.
		g.d.withLock(func(*Manager) { p.PeerFeatures, p.Heard, p.UpdateNoticed = nil, heard, false })
		g.clk = g.clk.Add(PendingLife + time.Hour)
		for i := 0; i < 2; i++ {
			if err := g.d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
				t.Fatal(err)
			}
		}
		if !g.d.audited("pending_abandoned_b_passed") {
			t.Fatal("setup: B did not pass")
		}
		if n := updateNotices(g.sink, p.ID); heard && n != 1 || !heard && n != 0 {
			t.Fatalf("heard %v: %d notices at B", heard, n)
		}
	}
}

// L5: device.update_needed is judged only for a stored, paired device,
// not for a pairing's hs.init from one not yet paired.
func TestR29D4NotForUnpairedDevice(t *testing.T) {
	d := newDevFixture(t)
	sink := sinkOf(d)
	np := &Peer{ID: "pairing", Kind: KindApp}
	d.withLock(func(m *Manager) { m.noteFeatures(np, nil) })
	if updateNotices(sink, np.ID) != 0 || np.Heard {
		t.Fatal("judged a device that is not paired")
	}
}
