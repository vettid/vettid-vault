package vault

import (
	"testing"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// R29-D3 (§6.3.1 "Devices and agents"): a rekey hs.init from a device or
// agent is acked, dropped and audited drop.peer_key (ref unexpected); the
// vault answers none.
func TestR29D3DeviceRekeyRefused(t *testing.T) {
	d := newDevFixture(t)
	sink := sinkOf(d)
	for _, kind := range []string{KindDesktop, KindAgent} {
		td := d.addDevice(t, "d3-"+kind, kind, map[string]byte{KindDesktop: 0x41, KindAgent: 0x45}[kind])
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
