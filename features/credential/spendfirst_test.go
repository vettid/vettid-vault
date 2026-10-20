package credential

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// inPool reports whether the vault still holds UTK id for device.
func (e *env) inPool(device, id string) bool {
	for _, l := range e.f.st.Pools[device] {
		if l.ID == id {
			return true
		}
	}
	return false
}

// openAlarm opens a clone alarm: another app presents the blob to a
// credential operation.
func (e *env) openAlarm(blob string) {
	e.t.Helper()
	if r := e.call("app2", "credential.rotate", blob, map[string]any{"password": pw}); r.Code != "credential_frozen" {
		e.t.Fatalf("clone: %q", r.Code)
	}
}

// §3.5.4 "Using a UTK" (0.52.0): a request spends the UTK it presents as
// soon as its body parses and its utk_id reads, before any other check;
// every refusal leaves it spent: a recovering app's limits, the removed
// credential.recover, the holder rule, the clone alarm (credential
// operations and Operate), Operate's app-only rule, no holder, and a
// bad_request whose utk_id still reads. The spent UTK opens nothing
// afterwards.
func TestRefusalsSpendTheUTK(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kind  string
		setup func(e *env, blob string)
		send  func(e *env, blob string, u utk) featuretest.Result
		code  string
	}{
		{name: "recovering app's limits", kind: "recovering-app",
			send: func(e *env, blob string, u utk) featuretest.Result {
				return e.callWith("recovering-app", "credential.unlock", blob, map[string]any{"password": pw}, u)
			}, code: "forbidden"},
		{name: "credential.recover", kind: "recovering-app",
			send: func(e *env, _ string, u utk) featuretest.Result {
				return e.callWith("recovering-app", "credential.recover", "", map[string]any{"password": pw}, u)
			}, code: "forbidden"},
		{name: "holder-only unlock", kind: "app2",
			send: func(e *env, blob string, u utk) featuretest.Result {
				return e.callWith("app2", "credential.unlock", blob, map[string]any{"password": pw}, u)
			}, code: "forbidden"},
		{name: "holder-only type without a payload", kind: "app2",
			send: func(e *env, _ string, u utk) featuretest.Result {
				return e.raw("app2", "credential.get", `{"utk_id":"`+u.id+`"}`)
			}, code: "forbidden"},
		{name: "alarm: unlock", kind: "app", setup: (*env).openAlarm,
			send: func(e *env, blob string, u utk) featuretest.Result {
				return e.callWith("app", "credential.unlock", blob, map[string]any{"password": pw}, u)
			}, code: "credential_frozen"},
		{name: "alarm: owner check", kind: "app", setup: (*env).openAlarm,
			send: func(e *env, blob string, u utk) featuretest.Result {
				return e.callWith("app", vault.TypeOwnerCheck, blob, map[string]any{"password": pw, "pin": testPIN}, u)
			}, code: "credential_frozen"},
		{name: "alarm: Operate", kind: "app", setup: (*env).openAlarm,
			send: func(e *env, blob string, u utk) featuretest.Result {
				return e.callWith("app", "test.op", blob, map[string]any{"password": pw}, u)
			}, code: "credential_frozen"},
		{name: "Operate: app only", kind: "recovering-app",
			send: func(e *env, blob string, u utk) featuretest.Result {
				return e.callWith("recovering-app", "test.op", blob, map[string]any{"password": pw}, u)
			}, code: "forbidden"},
		{name: "no holder", kind: "app", setup: func(e *env, _ string) { e.f.st.Holder = "" },
			send: func(e *env, blob string, u utk) featuretest.Result {
				return e.callWith("app", "credential.unlock", blob, map[string]any{"password": pw}, u)
			}, code: "credential_required"},
		{name: "malformed sealed, readable utk_id", kind: "app",
			send: func(e *env, blob string, u utk) featuretest.Result {
				return e.raw("app", "credential.unlock", `{"credential":"`+blob+`","utk_id":"`+u.id+`","sealed":7}`)
			}, code: "bad_request"},
		{name: "malformed blob, readable utk_id", kind: "app",
			send: func(e *env, _ string, u utk) featuretest.Result {
				return e.raw("app", "credential.unlock", `{"credential":"!!","utk_id":"`+u.id+`","sealed":"AAAA"}`)
			}, code: "bad_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.op = &opFeature{cred: e.f, op: func(*Inner, *Payload) error { return nil }}
			blob := e.create()
			if tc.setup != nil {
				tc.setup(e, blob)
			}
			u := e.take(tc.kind)
			dev := "dev-" + tc.kind
			if tc.kind == "recovering-app" {
				dev = "dev-recovering"
			}
			if !e.inPool(dev, u.id) {
				t.Fatal("the UTK is not in the pool")
			}
			if r := tc.send(e, blob, u); r.Code != tc.code {
				t.Fatalf("answer %q, want %q", r.Code, tc.code)
			}
			if e.inPool(dev, u.id) {
				t.Fatal("the refusal left the UTK in the pool")
			}
			if e.f.pres != nil {
				t.Fatal("the spent key outlived the request")
			}
		})
	}
}

// §3.5.4 (0.52.0): a body that does not parse, or whose utk_id is absent
// or not a UTK id, spends nothing; a utk_id of another device's pool
// removes nothing from it.
func TestUnreadableUTKSpendsNothing(t *testing.T) {
	e := newEnv(t)
	blob := e.create()
	u := e.take("app")
	pool := e.f.PoolSizeOf("dev-app")
	for _, b := range []string{
		`{"credential":"` + blob + `","utk_id":"` + u.id + `"`,
		`["` + u.id + `"]`,
		`{"credential":"` + blob + `","sealed":"AAAA"}`,
		`{"credential":"` + blob + `","utk_id":"` + strings.ToUpper(u.id) + `","sealed":"AAAA"}`,
		`{"credential":"` + blob + `","utk_id":"` + u.id + `0","sealed":"AAAA"}`,
		`{"credential":"` + blob + `","utk_id":7,"sealed":"AAAA"}`,
		`{"credential":"` + blob + `","utk_id":"` + u.id + `","utk_id":"` + u.id + `","sealed":"AAAA"}`,
	} {
		if r := e.raw("app", "credential.unlock", b); r.Code != "bad_request" {
			t.Errorf("%s: %q", b, r.Code)
		}
	}
	if e.f.PoolSizeOf("dev-app") != pool || !e.inPool("dev-app", u.id) {
		t.Fatal("an unreadable utk_id spent a UTK")
	}
	// Another app presents the holder's UTK: nothing leaves the holder's pool.
	if r := e.raw("app2", "credential.unlock", `{"credential":"`+blob+`","utk_id":"`+u.id+`","sealed":"AAAA"}`); r.Code != "forbidden" {
		t.Fatalf("another app: %q", r.Code)
	}
	if !e.inPool("dev-app", u.id) {
		t.Fatal("another device spent the holder's UTK")
	}
	// The UTK still works for its own device.
	e.ok(e.callWith("app", "credential.unlock", blob, map[string]any{"password": pw}, u))
}

// §3.5.4 Pool, §10.6, §11.10.8 (0.52.0): credential.utk.get{resync: true}
// drops the device's pool, wiping its keys, and issues 20, at most once
// per 10 minutes per device divided by the time scale; sooner is too_soon
// {allowed_after} and changes nothing; each resync is audited
// credential.utk_resync (device_id, ref = the count dropped). Without
// resync, or with false, the pool is topped up.
func TestUTKResync(t *testing.T) {
	e := newEnv(t)
	e.create()
	old := append([]LTK(nil), e.f.st.Pools["dev-app"]...)
	if len(old) == 0 {
		t.Fatal("no pool")
	}
	r := e.ok(e.raw("app", "credential.utk.get", `{"resync":true}`))
	if n := strings.Count(string(r.Body), `"utk_id"`); n != PoolSize || e.f.PoolSizeOf("dev-app") != PoolSize {
		t.Fatalf("resync issued %d, pool %d", n, e.f.PoolSizeOf("dev-app"))
	}
	for _, l := range old {
		if e.inPool("dev-app", l.ID) {
			t.Fatalf("UTK %s kept by the resync", l.ID)
		}
		if !bytes.Equal(l.Seed, make([]byte, len(l.Seed))) {
			t.Fatalf("UTK %s's key not wiped", l.ID)
		}
	}
	last := e.h.Activities[len(e.h.Activities)-1]
	if last.Kind != "credential.utk_resync" || !last.Audit || last.DeviceID != "dev-app" || last.Ref != itoa(uint64(len(old))) {
		t.Fatalf("audit %+v", last)
	}
	resyncAt := e.clk.T.UTC().Truncate(time.Millisecond)
	// Sooner: too_soon{allowed_after}, nothing changed, nothing audited.
	ids := append([]LTK(nil), e.f.st.Pools["dev-app"]...)
	acts := len(e.h.Activities)
	e.clk.Advance(ResyncEvery - 2*time.Second)
	r = e.raw("app", "credential.utk.get", `{"resync":true}`)
	want := `{"allowed_after":"` + envelope.FormatTS(resyncAt.Add(ResyncEvery)) + `"}`
	if r.Code != "too_soon" || string(r.Body) != want {
		t.Fatalf("too soon: %q %s, want %s", r.Code, r.Body, want)
	}
	if len(e.h.Activities) != acts || len(e.f.st.Pools["dev-app"]) != len(ids) || e.f.st.Pools["dev-app"][0].ID != ids[0].ID {
		t.Fatal("a refused resync changed something")
	}
	// Another device has its own limit.
	e.ok(e.raw("app2", "credential.utk.get", `{"resync":true}`))
	e.clk.Advance(2 * time.Second)
	e.ok(e.raw("app", "credential.utk.get", `{"resync":true}`))
	// Without resync, or false: a top-up, no audit.
	e.take("app")
	acts = len(e.h.Activities)
	for _, b := range []string{`{}`, `{"resync":false}`} {
		e.ok(e.raw("app", "credential.utk.get", b))
		if e.f.PoolSizeOf("dev-app") != PoolSize || len(e.h.Activities) != acts {
			t.Fatalf("%s: pool %d", b, e.f.PoolSizeOf("dev-app"))
		}
	}
	for _, b := range []string{`{"resync":"yes"}`, `{"resync":1}`, `{"resync":null}`, `[]`} {
		if r := e.raw("app", "credential.utk.get", b); r.Code != "bad_request" {
			t.Fatalf("%s: %q", b, r.Code)
		}
	}
	// At time scale 24 the limit is 25 s.
	e.clk.Advance(ResyncEvery)
	e.h.Scale = 24
	e.ok(e.raw("app", "credential.utk.get", `{"resync":true}`)) // e.raw advances 1 s first
	e.clk.Advance(23 * time.Second)
	if r := e.raw("app", "credential.utk.get", `{"resync":true}`); r.Code != "too_soon" {
		t.Fatalf("24 s at scale 24: %q", r.Code)
	}
	e.ok(e.raw("app", "credential.utk.get", `{"resync":true}`))
	// The limit survives a flush and an unlock.
	g := New(Options{KDF: MinKDF})
	featuretest.RoundTrip(t, e.f, g)
	e.f = g
	if r := e.raw("app", "credential.utk.get", `{"resync":true}`); r.Code != "too_soon" {
		t.Fatalf("after a round trip: %q", r.Code)
	}
}

// §3.5.7, §3.5.9, §10.1 (0.52.0): forbidden to a holder-only type means
// only that another live app holds the credential; a vault with a
// credential and no live holder (none, or one naming a removed device)
// answers credential_required{reason: "no_holder"}, also through the blob
// check and HolderGate, and opens no clone alarm; never during
// enrollment.
func TestNoHolderVersusForbidden(t *testing.T) {
	// Enrollment: no credential, no no_holder.
	e := newEnv(t)
	if r := e.raw("app2", "credential.get", `{}`); r.Code != "forbidden" || r.Body != nil {
		t.Fatalf("enrollment: %q %s", r.Code, r.Body)
	}
	blob := e.create()
	for _, typ := range []string{"credential.get", "credential.ack", "device.transfer.create"} {
		if r := e.raw("app2", typ, `{"version":1}`); r.Code != "forbidden" || r.Body != nil {
			t.Fatalf("%s with a live holder: %q %s", typ, r.Code, r.Body)
		}
	}
	noHolder := func(r featuretest.Result) bool {
		return r.Code == "credential_required" && string(r.Body) == string(vault.NoHolderBody)
	}
	// A holder whose device record is gone (left by an earlier release).
	delete(e.h.Devices, "dev-app")
	if r := e.raw("app2", "credential.get", `{}`); !noHolder(r) {
		t.Fatalf("dangling holder: %q %s", r.Code, r.Body)
	}
	if !e.f.CredentialReady() || e.f.CredentialHolder() != "dev-app" {
		t.Fatal("the feature alone cannot see the peers")
	}
	// Cleared (the device removed): no holder at all.
	e.h.AddDevice("dev-app", vault.KindApp)
	e.f.DeviceRemoved(nil, "dev-app")
	if e.f.Holder() != "" || e.f.CredentialReady() || !e.f.CredentialExists() {
		t.Fatal("DeviceRemoved left the holder")
	}
	e.pools["app"] = nil // its pool went with the record
	for _, kind := range []string{"app", "app2"} {
		if r := e.raw(kind, "credential.get", `{}`); !noHolder(r) {
			t.Fatalf("%s: %q %s", kind, r.Code, r.Body)
		}
		if r := e.call(kind, "credential.unlock", blob, map[string]any{"password": pw}); !noHolder(r) {
			t.Fatalf("%s unlock: %q %s", kind, r.Code, r.Body)
		}
		// A credential operation that is not holder-only: the blob check.
		if r := e.call(kind, "credential.rotate", blob, map[string]any{"password": pw}); !noHolder(r) {
			t.Fatalf("%s rotate: %q %s", kind, r.Code, r.Body)
		}
	}
	if e.f.st.Alarm != nil || len(e.h.Alarms) != 0 {
		t.Fatal("a vault without a holder opened a clone alarm")
	}
	if e.f.Holder() != "" {
		t.Fatal("an app was adopted as holder")
	}
	in := &envelope.Inner{ID: testID, Type: "audit.export", Body: []byte(`{}`)}
	s := vault.NewSession(context.Background(), e.h, vault.PeerInfo{ID: "dev-app", Kind: vault.KindApp, State: vault.PeerActive}, e.clk.T, in)
	if err := e.f.HolderGate(s, in); !vault.IsCode(err, "credential_required") {
		t.Fatalf("HolderGate: %v", err)
	}
}

// §3.5.9 (0.52.0): the holder is none or exactly one live app. Removing
// its device clears it (another device's removal does not); when the
// state is loaded a holder that names no live app is cleared; a transfer
// moves it in the flush that removes the old app.
func TestHolderHardening(t *testing.T) {
	e := newEnv(t)
	e.create()
	e.f.DeviceRemoved(nil, "dev-other")
	if e.f.Holder() != "dev-app" {
		t.Fatal("another device's removal cleared the holder")
	}
	if e.f.ClearDeadHolder(func(id string) bool { return id == "dev-app" }) || e.f.Holder() != "dev-app" {
		t.Fatal("a live holder cleared")
	}
	if !e.f.ClearDeadHolder(func(string) bool { return false }) || e.f.Holder() != "" {
		t.Fatal("a dead holder kept")
	}
	if e.f.ClearDeadHolder(func(string) bool { return false }) {
		t.Fatal("no holder reported cleared")
	}
	// A transfer: the old app removed, then the holder moved.
	e = newEnv(t)
	e.create()
	e.f.DeviceRemoved(nil, "dev-app")
	e.f.TransferCompleted(nil, "dev-app", "dev-app2")
	if e.f.Holder() != "dev-app2" || e.f.PoolSizeOf("dev-app") != 0 {
		t.Fatalf("holder %q", e.f.Holder())
	}
}

// §3.5.9 (0.52.0): credential.unlock is holder-only: another live app's
// is forbidden before its blob is opened (no clone alarm, nothing
// counted); the holder's works.
func TestUnlockHolderOnly(t *testing.T) {
	e := newEnv(t)
	blob := e.create()
	e.h.AddDevice("dev-app2", vault.KindApp)
	if r := e.call("app2", "credential.unlock", blob, map[string]any{"password": "wrong password here"}); r.Code != "forbidden" {
		t.Fatalf("another app: %q", r.Code)
	}
	if e.f.st.Alarm != nil || e.f.st.Failures != 0 {
		t.Fatal("a forbidden unlock opened an alarm or counted a password")
	}
	e.ok(e.unlock(blob, pw))
}

func TestPresentedUTKID(t *testing.T) {
	for b, want := range map[string]string{
		`{"utk_id":"0123456789abcdef"}`:       "0123456789abcdef",
		`{"utk_id":"0123456789ABCDEF"}`:       "",
		`{"utk_id":"0123456789abcde"}`:        "",
		`{"utk_id":7}`:                        "",
		`{"utk":"0123456789abcdef"}`:          "",
		`"0123456789abcdef"`:                  "",
		`{"utk_id":"0123456789abcdef"`:        "",
		``:                                    "",
		`{"a":1,"utk_id":"ffffffffffffffff"}`: "ffffffffffffffff",
	} {
		if got := PresentedUTKID([]byte(b)); got != want {
			t.Errorf("%s: %q", b, got)
		}
	}
}
