package credential

import (
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// §10.8 (0.18.0): account.name.set is the holder's; it answers too_soon
// with {allowed_after} while the snapshot's allowed_after lies ahead
// (nothing counted), refuses names outside the registration rule or
// equal to the current ones with bad_request, checks the blob, the PIN
// and the password as the owner check (the same failed checks), and on
// success rotates the CEK, records the request and answers {credential,
// version, utks, request}; it does not count as an owner check.
func TestAccountNameSet(t *testing.T) {
	e := newEnv(t)
	e.h.PIN = "246810"
	blob := e.create()
	good := map[string]any{"pin": "246810", "password": pw, "first_name": " Ada ", "last_name": "King-Noël"}
	if r := e.raw("desktop", vault.TypeAccountNameSet, `{}`); r.Code != "forbidden" {
		t.Fatalf("desktop: %q", r.Code)
	}
	if r := e.call("app2", vault.TypeAccountNameSet, blob, good); r.Code != "forbidden" {
		t.Fatalf("another app: %q", r.Code)
	}
	// The 30 days, before the PIN: nothing counted.
	e.h.AllowedAfter = e.clk.T.Add(48 * time.Hour)
	r := e.call("app", vault.TypeAccountNameSet, blob, map[string]any{"pin": "000000", "password": "wrong password", "first_name": "Ada", "last_name": "King"})
	if r.Code != "too_soon" || string(r.Body) != `{"allowed_after":"`+envelope.FormatTS(e.h.AllowedAfter)+`"}` || len(e.h.CheckFailed) != 0 {
		t.Fatalf("too_soon: %q %s %v", r.Code, r.Body, e.h.CheckFailed)
	}
	e.h.AllowedAfter = e.clk.T.Add(-time.Hour) // past: allowed
	// The names, before the PIN: bad_request, not a failed check.
	for _, n := range [][2]string{{"", "King"}, {"Ada", "   "}, {"1Ada", "King"}, {"Ada", "King!"}, {"Ada", "-King"},
		{strings.Repeat("a", 41), "King"}, {"Ada", "Lovelace"}, {" Ada", "Lovelace "}} {
		p := map[string]any{"pin": "000000", "password": pw, "first_name": n[0], "last_name": n[1]}
		if r := e.call("app", vault.TypeAccountNameSet, blob, p); r.Code != "bad_request" {
			t.Fatalf("names %q: %q", n, r.Code)
		}
	}
	if r := e.call("app", vault.TypeAccountNameSet, blob, map[string]any{"pin": "246810", "password": pw, "first_name": "Ada"}); r.Code != "bad_request" {
		t.Fatalf("no last_name: %q", r.Code)
	}
	if len(e.h.CheckFailed) != 0 || len(e.h.NameRequests) != 0 {
		t.Fatal("a bad_request counted or requested")
	}
	// A wrong PIN, a wrong password: failed checks as in the owner check.
	if r := e.call("app", vault.TypeAccountNameSet, blob, map[string]any{"pin": "135791", "password": pw, "first_name": "Ada", "last_name": "King"}); r.Code != "bad_pin" {
		t.Fatalf("wrong PIN: %q", r.Code)
	}
	if r := e.call("app", vault.TypeAccountNameSet, blob, map[string]any{"pin": "246810", "password": "wrong password", "first_name": "Ada", "last_name": "King"}); r.Code != "bad_password" {
		t.Fatalf("wrong password: %q", r.Code)
	}
	if strings.Join(e.h.CheckFailed, ",") != "pin,password" || len(e.h.NameRequests) != 0 {
		t.Fatalf("failed checks %v", e.h.CheckFailed)
	}
	// Success: trimmed names (40 UTF-16 units allowed), the CEK rotates, not an owner check.
	r = e.ok(e.call("app", vault.TypeAccountNameSet, blob, good))
	o := r.Obj(t)
	for _, k := range []string{"credential", "version", "utks", "request"} {
		if !o.Has(k) {
			t.Fatalf("response lacks %s: %s", k, r.Body)
		}
	}
	if blobOf(t, r) == blob || len(e.h.Passed) != 0 {
		t.Fatal("CEK not rotated, or counted as an owner check")
	}
	if len(e.h.NameRequests) != 1 || e.h.NameRequests[0] != (vault.NameChange{Seq: 1, FirstName: "Ada", LastName: "King-Noël"}) {
		t.Fatalf("requests %+v", e.h.NameRequests)
	}
	if !strings.Contains(string(o["request"]), `"seq":1,"first_name":"Ada","last_name":"King-Noël"`) ||
		!strings.Contains(string(o["request"]), `"state":"pending"`) {
		t.Fatalf("request %s", o["request"])
	}
	blob = blobOf(t, r)
	e.ok(e.raw("app", "credential.ack", `{"version":`+itoa(e.f.CredentialVersion())+`}`))
	e.ok(e.call("app", vault.TypeAccountNameSet, blob, map[string]any{"pin": "246810", "password": pw,
		"first_name": strings.Repeat("é", 40), "last_name": "O’Brien"}))
}

// §10.8, §3.5.9: during a clone alarm account.name.set is refused.
func TestAccountNameSetDuringAlarm(t *testing.T) {
	e := newEnv(t)
	e.h.PIN = "246810"
	blob := e.create()
	e.f.st.Alarm = &Alarm{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", State: AlarmFrozen, At: e.clk.T}
	if r := e.call("app", vault.TypeAccountNameSet, blob, map[string]any{"pin": "246810", "password": pw, "first_name": "Ada", "last_name": "King"}); r.Code != "credential_frozen" {
		t.Fatalf("frozen: %q", r.Code)
	}
}
