package vault

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// spendFeature stands in for the credential feature's 0.52.0 hooks in the
// runtime's tests: it records every SpendPresentedUTK and EndPresentedUTK
// call, reports a holder, and offers types that reach each refusal made
// before a handler.
type spendFeature struct {
	recSink
	holder  string
	spends  []string // deviceID + " " + body
	ends    int
	handled int
}

func (f *spendFeature) Name() string { return "spend" }
func (f *spendFeature) Types() []TypeSpec {
	return []TypeSpec{
		{Type: "spend.ok", Request: true, From: []string{KindApp, KindDesktop, KindAgent}},
		{Type: "spend.desk", Request: true, From: []string{KindDesktop}},
		{Type: "spend.shape", Request: true, From: []string{KindApp}, Shape: func([]byte) bool { return false }},
		{Type: "spend.apponly", Request: true, From: []string{KindApp, KindDesktop, KindAgent}},
		{Type: "spend.conn", Request: true, From: []string{KindConnection}},
		{Type: "spend.event", From: []string{KindApp}},
	}
}
func (f *spendFeature) AppOnly(typ string, _ json.RawMessage) bool { return typ == "spend.apponly" }
func (f *spendFeature) CredentialHolder() string                   { return f.holder }
func (f *spendFeature) SpendPresentedUTK(device, _ string, body json.RawMessage, _ time.Time) bool {
	f.spends = append(f.spends, device+" "+string(body))
	return true
}
func (f *spendFeature) EndPresentedUTK() { f.ends++ }
func (f *spendFeature) Handle(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) {
	f.handled++
	return nil, nil
}

const spendBody = `{"utk_id":"0123456789abcdef","sealed":"AAAA"}`

func newSpendFixture(t *testing.T) (*ocFixture, *spendFeature) {
	t.Helper()
	f := newOCFixture(t)
	sp := &spendFeature{holder: f.app.peer.ID}
	f.m.addFeature(sp)
	return f, sp
}

// §3.5.4 "Using a UTK" (0.52.0): the runtime spends the UTK a request
// presents before every refusal it makes before the type's handler:
// the shape's bad_request, credential_required (with and without a
// holder), owner_check_required, forbidden (a type the role may not send,
// an app-only form, an agent's LEASH refusal) and session_required. A
// handled request spends it too, once; the key is wiped when the request
// ends.
func TestSpendBeforeEveryRuntimeRefusal(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*ocFixture, *spendFeature) *tdev
		typ   string
		code  string
		body  string // the error body expected ("" for none)
	}{
		{"handled", func(f *ocFixture, _ *spendFeature) *tdev { return f.app }, "spend.ok", "", ""},
		{"shape", func(f *ocFixture, _ *spendFeature) *tdev { return f.app }, "spend.shape", "bad_request", ""},
		{"no credential", func(f *ocFixture, _ *spendFeature) *tdev { f.oc.noCred = true; return f.app }, "spend.ok", "credential_required", ""},
		{"no holder", func(f *ocFixture, sp *spendFeature) *tdev { sp.holder = ""; return f.app }, "spend.ok", "credential_required", string(NoHolderBody)},
		{"dead holder", func(f *ocFixture, sp *spendFeature) *tdev { sp.holder = "removed-app"; return f.app }, "spend.ok", "credential_required", string(NoHolderBody)},
		{"owner check", func(f *ocFixture, _ *spendFeature) *tdev { f.pastDeadline(); return f.app }, "spend.ok", "owner_check_required", ""},
		{"role", func(f *ocFixture, _ *spendFeature) *tdev { return f.app }, "spend.desk", "forbidden", ""},
		{"app-only form", func(f *ocFixture, _ *spendFeature) *tdev { return f.desk }, "spend.apponly", "forbidden", ""},
		{"LEASH", func(f *ocFixture, _ *spendFeature) *tdev { return f.agent }, "spend.desk", "forbidden", ""},
		{"session", func(f *ocFixture, _ *spendFeature) *tdev { f.desk.peer.Access = nil; return f.desk }, "spend.ok", "session_required", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, sp := newSpendFixture(t)
			td := tc.setup(f, sp)
			r := f.req(t, td, tc.typ, spendBody)
			switch {
			case tc.code == "" && r.Status != envelope.StatusOK:
				t.Fatalf("refused: %+v", r.Error)
			case tc.code != "" && (r.Error == nil || r.Error.Code != tc.code):
				t.Fatalf("answer %+v, want %s", r.Error, tc.code)
			case tc.code != "" && string(r.Body) != tc.body && !(tc.body == "" && (len(r.Body) == 0 || string(r.Body) == "{}")):
				t.Fatalf("error body %s, want %q", r.Body, tc.body)
			}
			if len(sp.spends) != 1 || sp.spends[0] != td.peer.ID+" "+spendBody {
				t.Fatalf("spends %q", sp.spends)
			}
			if sp.ends != 1 {
				t.Fatalf("the spent key was not wiped at the end: %d", sp.ends)
			}
			if wantHandled := tc.code == ""; (sp.handled == 1) != wantHandled {
				t.Fatalf("handled %d", sp.handled)
			}
		})
	}
}

// §3.5.4 (0.52.0): a request that is never handled spends nothing: an
// unsupported type, a retransmission answered from the cache, a message
// the rate limit drops; nor does an event. During enrollment (no
// credential) credential_required carries no body.
func TestNoSpendWhenNeverHandled(t *testing.T) {
	f, sp := newSpendFixture(t)
	if r := f.req(t, f.app, "no.such.type", spendBody); r.Error == nil || r.Error.Code != "unsupported_type" {
		t.Fatalf("unknown type: %+v", r)
	}
	if len(sp.spends) != 0 {
		t.Fatalf("an unsupported type spent: %q", sp.spends)
	}
	// A retransmission (§8.2): the cached answer, no second spend.
	id, _ := envelope.NewULID(time.Now())
	f.sendID(f.app, id, "spend.ok", spendBody)
	f.sendID(f.app, id, "spend.ok", spendBody)
	if len(sp.spends) != 1 || sp.handled != 1 {
		t.Fatalf("retransmission: spends %d, handled %d", len(sp.spends), sp.handled)
	}
	// An event is not a request.
	sp.spends = nil
	f.sendFrom(t, f.app, &envelope.Inner{Type: "spend.event", Body: []byte(spendBody)})
	if len(sp.spends) != 0 {
		t.Fatalf("an event spent: %q", sp.spends)
	}
	// The rate limit (§7.3): the dropped message spends nothing.
	c := f.asConnection(t, "c1", 0x52)
	for i := 0; i < PeerRateLimit+1; i++ {
		f.sendFrom(t, c, &envelope.Inner{Type: "spend.conn", Body: []byte(spendBody)})
	}
	if len(sp.spends) != PeerRateLimit {
		t.Fatalf("%d spends for %d messages within the limit", len(sp.spends), PeerRateLimit)
	}
	// Enrollment: no credential, no no_holder body.
	f.oc.noCred, sp.holder = true, ""
	r := f.req(t, f.app, "spend.ok", spendBody)
	if r.Error == nil || r.Error.Code != "credential_required" || len(r.Body) != 0 && string(r.Body) != "{}" {
		t.Fatalf("enrollment: %+v %s", r.Error, r.Body)
	}
}

// pruneFeature records the holder ClearDeadHolder sees.
type pruneFeature struct {
	recSink
	holder string
}

func (f *pruneFeature) Name() string { return "prune" }
func (f *pruneFeature) ClearDeadHolder(live func(string) bool) bool {
	if f.holder == "" || live(f.holder) {
		return false
	}
	f.holder = ""
	return true
}

// §3.5.9 (0.52.0): when the state is loaded, a holder that names no live
// app is cleared: a removed device, a desktop, a pairing not completed. A
// paired app keeps it, also one whose mailbox went stale.
func TestLoadClearsDeadHolder(t *testing.T) {
	d := newDevFixture(t)
	desk := d.addDevice(t, "desk1", KindDesktop, 0x60)
	app2 := d.addDevice(t, "app2", KindApp, 0x64)
	app3 := d.addDevice(t, "app3", KindApp, 0x68)
	app2.peer.State = PeerPending
	app3.peer.State = PeerStale
	for _, tc := range []struct {
		holder string
		kept   bool
	}{
		{d.devPeer.ID, true}, {app3.peer.ID, true}, {"removed-app", false}, {desk.peer.ID, false}, {app2.peer.ID, false}, {"", true},
	} {
		pf := &pruneFeature{holder: tc.holder}
		m := newManager(d.m.opt, d.m.st, d.m.hdr, nil)
		m.features = nil
		m.addFeature(pf)
		m.clearDeadHolder()
		if (pf.holder == tc.holder) != tc.kept {
			t.Errorf("holder %q: now %q", tc.holder, pf.holder)
		}
		if m.dirty != !tc.kept {
			t.Errorf("holder %q: dirty %v", tc.holder, m.dirty)
		}
	}
	// newManager runs the pass itself.
	pf := &pruneFeature{holder: "removed-app"}
	o := d.m.opt
	o.Features = []Feature{pf}
	_ = newManager(o, d.m.st, d.m.hdr, nil)
	if pf.holder != "" {
		t.Fatal("newManager kept a dead holder")
	}
}

// holderFeature follows the holder as the credential does: cleared when
// its device is removed, moved by TransferCompleted.
type holderFeature struct {
	recSink
	holder  string
	removed []string
}

func (f *holderFeature) Name() string { return "holder" }
func (f *holderFeature) DeviceRemoved(_ *Session, id string) {
	f.removed = append(f.removed, id)
	if f.holder == id {
		f.holder = ""
	}
}
func (f *holderFeature) TransferCompleted(_ *Session, _, newDevice string) { f.holder = newDevice }

// §3.5.9, §11.14.6 (0.52.0): a recovered phone's first handshake makes it
// the holder and, in the same flush, removes every other app
// (device.unlinked{reason: "replaced"}); desktops stay.
func TestRecoveredPhonePairingRemovesOtherApps(t *testing.T) {
	d := newDevFixture(t)
	desk := d.addDevice(t, "desk1", KindDesktop, 0x60)
	other := d.addDevice(t, "app2", KindApp, 0x64)
	phone := d.addDevice(t, "phone", KindApp, 0x68)
	phone.peer.Recovering = true
	hf := &holderFeature{holder: other.peer.ID}
	d.m.addFeature(hf)
	d.m.mu.Lock()
	d.m.recoveredPhonePaired(phone.peer, time.Now())
	d.m.mu.Unlock()
	if hf.holder != phone.peer.ID {
		t.Fatalf("holder %q", hf.holder)
	}
	for _, id := range []string{d.devPeer.ID, other.peer.ID} {
		if _, ok := d.m.st.Devices[id]; ok {
			t.Errorf("app %s not removed", id)
		}
	}
	if len(hf.removed) != 2 {
		t.Errorf("removed %v", hf.removed)
	}
	for _, id := range []string{desk.peer.ID, phone.peer.ID} {
		if _, ok := d.m.st.Devices[id]; !ok {
			t.Errorf("%s removed", id)
		}
	}
	if !hf.has("device.replaced") {
		t.Error("device.replaced not recorded")
	}
}
