package vault

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/vettid/vettid-vault/vms/envelope"
)

type appFeaturesStub struct{ told int }

func (o *appFeaturesStub) Name() string                   { return "appfeatstub" }
func (o *appFeaturesStub) Types() []TypeSpec              { return nil }
func (o *appFeaturesStub) Load(json.RawMessage) error     { return nil }
func (o *appFeaturesStub) Save() (json.RawMessage, error) { return nil, nil }
func (o *appFeaturesStub) AppFeaturesChanged(*Session)    { o.told++ }
func (o *appFeaturesStub) Handle(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) {
	return nil, nil
}

// §10.2, §10.4 "Approval documents" (0.89.0): the vault keeps a device's last features list as sent, not merged,
// so approval_document counts only while the app's last list carries it; features are told at a batch's end
// whenever that differs from what they were last told, whether the list changed or the devices did.
func TestAppFeaturesLastList(t *testing.T) {
	d := newDevFixture(t)
	o := &appFeaturesStub{}
	d.m.addFeature(o)
	app := d.self()
	p := d.m.st.Devices[d.devPeer.ID]
	note := func(names ...string) {
		d.m.mu.Lock()
		d.m.noteFeatures(p, names)
		d.m.syncAppFeatures(d.m.now()) // a batch's end
		d.m.mu.Unlock()
	}
	note("approval_document", "hs_confirm")
	if !d.m.appFeature(FeatureApprovalDocument) || o.told != 1 || !slices.Equal(p.LastFeatures, []string{"approval_document", "hs_confirm"}) {
		t.Fatalf("listed: %v, told %d", p.LastFeatures, o.told)
	}
	note("approval_document", "hs_confirm") // the same list: nothing to tell
	note("approval_document", "hs_confirm", "relay_follow")
	if o.told != 1 {
		t.Fatalf("told %d for lists that keep the name", o.told)
	}
	note("hs_confirm")
	if d.m.appFeature(FeatureApprovalDocument) || o.told != 2 || !slices.Contains(p.PeerFeatures, "approval_document") {
		t.Fatalf("not sticky: %v (merged %v), told %d", p.LastFeatures, p.PeerFeatures, o.told)
	}
	// A device.features message from the app: told at its batch's end.
	d.sendAs(app, TypeDeviceFeatures, `{"features":["approval_document","hs_confirm"]}`)
	if !slices.Contains(d.m.st.Devices[d.devPeer.ID].LastFeatures, "approval_document") || o.told != 3 {
		t.Fatalf("device.features: %v, told %d", d.m.st.Devices[d.devPeer.ID].LastFeatures, o.told)
	}
	// The devices change, the lists do not: the app that listed it goes (removed, or replaced by a transfer).
	d.m.mu.Lock()
	delete(d.m.st.Devices, p.ID)
	d.m.syncAppFeatures(d.m.now())
	told := o.told
	// A desktop's list, or an app that is not active, counts for nothing.
	desk := &Peer{ID: "desk-x", Kind: KindDesktop, State: PeerActive, LastFeatures: []string{"approval_document"}}
	idle := &Peer{ID: "app-x", Kind: KindApp, State: PeerPending, LastFeatures: []string{"approval_document"}}
	d.m.st.Devices[desk.ID], d.m.st.Devices[idle.ID] = desk, idle
	d.m.syncAppFeatures(d.m.now())
	got := d.m.appFeature(FeatureApprovalDocument)
	// A new app, paired, transferred or recovered, with the name: told.
	idle.State = PeerActive
	d.m.syncAppFeatures(d.m.now())
	d.m.mu.Unlock()
	if told != 4 || got || o.told != 5 {
		t.Fatalf("removed: told %d; desktop or inactive app counted: %v; activated: told %d", told, got, o.told)
	}
}
