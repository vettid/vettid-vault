package credential

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/audit"
	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// exportWith sends audit.export to the audit feature (backed by this
// credential) with payload sealed to u, bound to audit.export and the
// request's id; members are the body's other members.
func (e *env) exportWith(a *audit.Feature, kind string, u utk, payload map[string]any, members string) featuretest.Result {
	e.t.Helper()
	pt, _ := json.Marshal(payload)
	e.clk.Advance(time.Second)
	id, _ := envelope.NewULID(e.clk.T)
	sealed, err := credwire.SealPayload(u.ek, e.h.VaultID(), u.id, "audit.export", id, pt)
	if err != nil {
		e.t.Fatal(err)
	}
	body := `{"utk_id":"` + u.id + `","sealed":"` + base64.StdEncoding.EncodeToString(sealed) + `"` + members + `}`
	return featuretest.CallID(a, e.h, e.clk.T, kind, "audit.export", id, body)
}

// VAULT-MESSAGING 0.22.0 (§3.5.4, §3.5.9, §10.9): audit.export carries
// the PIN alone, sealed to a UTK of the holder's app and bound to the
// request: no blob, no password, no CEK rotation, no UTKs answered. A
// clone alarm refuses it, the preview included, with the freeze code
// before the UTK is spent; only the holder may send it.
func TestSpendPINForExport(t *testing.T) {
	e := newEnv(t)
	e.h.PIN = "246810"
	a := audit.New()
	a.SetCredential(e.f)
	e.h.Sinks = append(e.h.Sinks, a)
	blob := e.create()
	e.h.Record(vault.Activity{Kind: "credential.created", Audit: true}, e.clk.T)
	seq := len(a.Entries())
	members := `,"format":"json","upto_seq":` + itoa(uint64(seq))
	version := e.f.CredentialVersion()

	r := e.exportWith(a, "app", e.take("app"), map[string]any{"pin": "246810"}, members)
	o := e.ok(r).Obj(t)
	if o.Has("utks") || o.Has("credential") || e.f.CredentialVersion() != version {
		t.Fatalf("a PIN-only request answered UTKs or rotated the CEK: %s", r.Body)
	}
	if es := a.Entries(); es[len(es)-1].Kind != audit.KindExported || es[len(es)-1].DeviceID != "dev-app" {
		t.Fatalf("no audit.exported: %+v", es[len(es)-1])
	}
	// The UTK is single-use and bound to audit.export.
	u := e.take("app")
	e.ok(e.exportWith(a, "app", u, map[string]any{"pin": "246810"}, members))
	if r := e.exportWith(a, "app", u, map[string]any{"pin": "246810"}, members); r.Code != "utk_invalid" {
		t.Fatalf("spent UTK: %q", r.Code)
	}
	u = e.take("app")
	if r := e.callWith("app", "credential.unlock", blob, map[string]any{"password": pw}, u); !r.OK() {
		t.Fatal(r.Code)
	}
	// A payload without a valid PIN: bad_request, the UTK spent.
	before := e.f.PoolSizeOf("dev-app")
	if r := e.exportWith(a, "app", e.take("app"), map[string]any{"pin": "12"}, members); r.Code != "bad_request" {
		t.Fatalf("short PIN: %q", r.Code)
	}
	if r := e.exportWith(a, "app", e.take("app"), map[string]any{"password": pw}, members); r.Code != "bad_request" {
		t.Fatalf("no PIN: %q", r.Code)
	}
	if e.f.PoolSizeOf("dev-app") != before-2 {
		t.Fatal("a malformed payload left its UTK unspent")
	}
	// A wrong PIN: bad_pin from the runtime's check, no failed owner check.
	if r := e.exportWith(a, "app", e.take("app"), map[string]any{"pin": "135791"}, members); r.Code != "bad_pin" || len(e.h.CheckFailed) != 0 {
		t.Fatalf("wrong PIN: %q %v", r.Code, e.h.CheckFailed)
	}
	// Holder only: another app, a recovering app.
	for _, k := range []string{"app2", "recovering-app"} {
		if r := featuretest.Call(a, e.h, e.clk.T, k, "audit.export", `{"dry_run":true}`); r.Code != "forbidden" {
			t.Fatalf("%s: %q", k, r.Code)
		}
	}
	// A clone alarm: the preview and the export get the freeze code, the
	// UTK unspent.
	if r := e.call("app2", "credential.unlock", blob, map[string]any{"password": pw}); r.Code != "credential_frozen" {
		t.Fatalf("clone: %q", r.Code)
	}
	if r := featuretest.Call(a, e.h, e.clk.T, "app", "audit.export", `{"dry_run":true}`); r.Code != "credential_frozen" {
		t.Fatalf("preview during the alarm: %q", r.Code)
	}
	u = e.take("app")
	pool := e.f.PoolSizeOf("dev-app")
	if r := e.exportWith(a, "app", u, map[string]any{"pin": "246810"}, members); r.Code != "credential_frozen" {
		t.Fatalf("export during the alarm: %q", r.Code)
	}
	if e.f.PoolSizeOf("dev-app") != pool {
		t.Fatal("the UTK was spent during the alarm")
	}
	// rotation_required once the holder confirms the alarm as not theirs.
	alarm := e.f.st.Alarm.ID
	e.ok(e.raw("app", "credential.alarm.confirm", `{"alarm_id":"`+alarm+`","mine":false}`))
	if e.f.AlarmState() != AlarmRotationRequired {
		t.Fatalf("alarm state %q", e.f.AlarmState())
	}
	if r := e.exportWith(a, "app", u, map[string]any{"pin": "246810"}, members); r.Code != "rotation_required" {
		t.Fatalf("export in rotation_required: %q", r.Code)
	}
	if e.f.PoolSizeOf("dev-app") != pool {
		t.Fatal("the UTK was spent in rotation_required")
	}
}
