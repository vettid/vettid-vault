package vault

import (
	"context"
	"testing"
	"time"
)

// §10.9 (0.20.0): the audit search reads a device's name as device.list
// lists it, whatever its state (no access session, recovering), and a
// connection's alias; removed peers resolve to nothing.
func TestSearchNamesFromManager(t *testing.T) {
	d := newDevFixture(t)
	d.m.st.Devices["desk9"] = &Peer{ID: "desk9", Kind: KindDesktop, State: PeerActive, Name: "Office Desk"}
	d.m.st.Devices["rec9"] = &Peer{ID: "rec9", Kind: KindApp, State: PeerActive, Recovering: true, Name: "New Phone"}
	d.m.st.Connections["c9"] = &Peer{ID: "c9", Kind: KindConnection, State: PeerActive, Name: "Bob", Meta: &PeerMeta{Alias: "Gardener"}}
	s := NewSession(context.Background(), managerHost{d.m}, PeerInfo{}, time.Now(), nil)
	for id, want := range map[string]string{"desk9": "Office Desk", "rec9": "New Phone"} {
		if p, ok := s.ListedDevice(id); !ok || p.Name != want {
			t.Errorf("%s: %+v %v", id, p, ok)
		}
	}
	if _, ok := s.PairedDevice("rec9"); ok {
		t.Error("PairedDevice lists a recovering app")
	}
	if _, ok := s.ListedDevice("gone"); ok {
		t.Error("an unlinked device resolved")
	}
	if p, ok := s.Connection("c9"); !ok || p.Alias != "Gardener" || p.Name != "Bob" {
		t.Errorf("connection: %+v", p)
	}
}
