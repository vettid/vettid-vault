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
// so approval_document counts only while the app's last list carries it; features are told when it comes or goes,
// not at every list.
func TestAppFeaturesLastList(t *testing.T) {
	d := newDevFixture(t)
	o := &appFeaturesStub{}
	d.m.addFeature(o)
	app := d.self()
	p := d.m.st.Devices[d.devPeer.ID]
	d.m.mu.Lock()
	d.m.noteFeatures(p, []string{"approval_document", "hs_confirm"})
	d.m.mu.Unlock()
	if !d.m.appFeature(FeatureApprovalDocument) || o.told != 1 || !slices.Equal(p.LastFeatures, []string{"approval_document", "hs_confirm"}) {
		t.Fatalf("listed: %v, told %d", p.LastFeatures, o.told)
	}
	d.m.mu.Lock()
	d.m.noteFeatures(p, []string{"approval_document", "hs_confirm"}) // the same list: nothing to tell
	d.m.noteFeatures(p, []string{"approval_document", "hs_confirm", "relay_follow"})
	d.m.mu.Unlock()
	if o.told != 1 {
		t.Fatalf("told %d for lists that keep the name", o.told)
	}
	d.m.mu.Lock()
	d.m.noteFeatures(p, []string{"hs_confirm"})
	d.m.mu.Unlock()
	if d.m.appFeature(FeatureApprovalDocument) || o.told != 2 || !slices.Contains(p.PeerFeatures, "approval_document") {
		t.Fatalf("not sticky: %v (merged %v), told %d", p.LastFeatures, p.PeerFeatures, o.told)
	}
	// A device.features message from the app counts as its last list.
	d.sendAs(app, TypeDeviceFeatures, `{"features":["approval_document","hs_confirm"]}`)
	if !slices.Contains(d.m.st.Devices[d.devPeer.ID].LastFeatures, "approval_document") {
		t.Fatalf("device.features: %v", d.m.st.Devices[d.devPeer.ID].LastFeatures)
	}
}
