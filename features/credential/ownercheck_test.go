package credential

import (
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

func (e *env) check(blob string, payload map[string]any) featuretest.Result {
	e.t.Helper()
	return e.call("app", vault.TypeOwnerCheck, blob, payload)
}

// §3.6.1: vault.owner_check checks, in order, the alarm (before the UTK),
// the UTK, the hold change (bad_request before the PIN), the blob, the PIN
// (bad_pin, a failed check), the password backoff and the password
// (bad_password, a failed check); on success it rotates the CEK and
// answers {credential, version, utks, deadline, interval_seconds, hold,
// hold_off_until?}.
func TestOwnerCheck(t *testing.T) {
	e := newEnv(t)
	e.h.PIN = "246810"
	blob := e.create()
	if e.h.Enrolled != 1 {
		t.Fatalf("enrollment's credential.create did not start the clock: %d", e.h.Enrolled)
	}
	good := map[string]any{"pin": "246810", "password": pw}
	// Holder only; a malformed PIN is bad_request.
	if r := e.raw("desktop", vault.TypeOwnerCheck, `{}`); r.Code != "forbidden" {
		t.Fatalf("desktop: %q", r.Code)
	}
	if r := e.check(blob, map[string]any{"pin": "12", "password": pw}); r.Code != "bad_request" {
		t.Fatalf("malformed PIN: %q", r.Code)
	}
	// A spent or unknown UTK.
	u := e.take("app")
	blob = blobOf(t, e.ok(e.callWith("app", vault.TypeOwnerCheck, blob, good, u)))
	if len(e.h.Passed) != 1 {
		t.Fatal("check not recorded")
	}
	if r := e.callWith("app", vault.TypeOwnerCheck, blob, good, u); r.Code != "utk_invalid" {
		t.Fatalf("spent UTK: %q", r.Code)
	}
	// hold_off_until: only with hold false, in the future, at most 30 days
	// ahead; otherwise bad_request before the PIN is tried (not a failure).
	for _, p := range []map[string]any{
		{"pin": "000000", "password": pw, "hold": false, "hold_off_until": e.clk.T.Add(31 * 24 * time.Hour).Format(time.RFC3339)},
		{"pin": "000000", "password": pw, "hold": false, "hold_off_until": e.clk.T.Add(-time.Hour).Format(time.RFC3339)},
		{"pin": "000000", "password": pw, "hold": true, "hold_off_until": e.clk.T.Add(time.Hour).Format(time.RFC3339)},
		{"pin": "000000", "password": pw, "hold_off_until": e.clk.T.Add(time.Hour).Format(time.RFC3339)},
		{"pin": "000000", "password": pw, "hold": false, "hold_off_until": "tomorrow"},
		{"pin": "000000", "password": pw, "hold": "no"},
	} {
		if r := e.check(blob, p); r.Code != "bad_request" {
			t.Fatalf("hold change %v: %q", p, r.Code)
		}
	}
	if len(e.h.CheckFailed) != 0 {
		t.Fatal("a bad_request counted as a failed check")
	}
	// The blob is checked before the PIN: the holder's own retry of the
	// previous version is stale_credential, not a failed check.
	old := blob
	r := e.ok(e.check(blob, good))
	blob = blobOf(t, r)
	if r := e.check(old, map[string]any{"pin": "000000", "password": pw}); r.Code != "stale_credential" || len(e.h.CheckFailed) != 0 {
		t.Fatalf("stale blob: %q %v", r.Code, e.h.CheckFailed)
	}
	e.ok(e.raw("app", "credential.ack", `{"version":`+itoa(e.f.CredentialVersion())+`}`))
	// A wrong PIN: bad_pin, a failed check; the password is not tried.
	if r := e.check(blob, map[string]any{"pin": "135791", "password": "wrong password"}); r.Code != "bad_pin" {
		t.Fatalf("wrong PIN: %q", r.Code)
	}
	if e.f.st.Failures != 0 {
		t.Fatal("password tried after a wrong PIN")
	}
	// A wrong password: bad_password, a failed check, in the password
	// backoff.
	if r := e.check(blob, map[string]any{"pin": "246810", "password": "wrong password"}); r.Code != "bad_password" {
		t.Fatalf("wrong password: %q", r.Code)
	}
	if strings.Join(e.h.CheckFailed, ",") != "pin,password" || e.f.st.Failures != 1 {
		t.Fatalf("failed checks %v, password failures %d", e.h.CheckFailed, e.f.st.Failures)
	}
	// Success: the CEK rotates (the old blob is a clone afterwards) and
	// the answer carries the record.
	r = e.ok(e.check(blob, map[string]any{"pin": "246810", "password": pw, "hold": false,
		"hold_off_until": e.clk.T.Add(48 * time.Hour).Format(time.RFC3339)}))
	o := r.Obj(t)
	for _, k := range []string{"credential", "version", "utks", "deadline", "interval_seconds", "hold", "hold_off_until"} {
		if !o.Has(k) {
			t.Fatalf("response lacks %s: %s", k, r.Body)
		}
	}
	if h, _ := o.Bool("hold"); h {
		t.Fatal("hold not off")
	}
	c := e.h.Passed[len(e.h.Passed)-1]
	if c == nil || c.On || c.Until.IsZero() || !e.h.PassedAudit[len(e.h.PassedAudit)-1] {
		t.Fatalf("hold change %+v", c)
	}
	if blobOf(t, r) == blob || e.f.st.Failures != 0 {
		t.Fatal("CEK not rotated or password backoff not reset")
	}
	e.ok(e.check(blobOf(t, r), map[string]any{"pin": "246810", "password": pw, "hold": true}))
	if c := e.h.Passed[len(e.h.Passed)-1]; c == nil || !c.On {
		t.Fatalf("hold on: %+v", c)
	}
}

// §3.6.1 step 1, §3.5.9: during a clone alarm the check is refused before
// the UTK is spent.
func TestOwnerCheckDuringAlarm(t *testing.T) {
	e := newEnv(t)
	e.h.PIN = "246810"
	blob := e.create()
	if r := e.call("app2", "credential.unlock", blob, map[string]any{"password": pw}); r.Code != "credential_frozen" {
		t.Fatalf("clone: %q", r.Code)
	}
	if e.f.AlarmState() != AlarmFrozen {
		t.Fatal("no alarm")
	}
	u := e.take("app")
	if r := e.callWith("app", vault.TypeOwnerCheck, blob, map[string]any{"pin": "246810", "password": pw}, u); r.Code != "credential_frozen" {
		t.Fatalf("check during the alarm: %q", r.Code)
	}
	// The UTK was not spent: it still opens another operation.
	if r := e.callWith("app", "credential.unlock", blob, map[string]any{"password": pw}, u); r.Code == "utk_invalid" {
		t.Fatal("UTK spent by a refused check")
	}
}

// §6.7.1, §3.6.1: a transfer's approval is a check: its wrong entries are
// failed checks and its success starts the clock (no owner_check.passed).
func TestTransferApprovalIsCheck(t *testing.T) {
	e := newEnv(t)
	e.h.PIN = "246810"
	blob := e.create()
	o := e.ok(e.raw("app", "device.transfer.create", `{}`)).Obj(t)
	id, _ := o.String("transfer_id")
	e.h.Xfer.Scanned = true
	appr := func(pin, password string) featuretest.Result {
		return e.callBody("app", "device.transfer.approve", blob, map[string]any{"password": password, "pin": pin}, `"transfer_id":"`+id+`"`)
	}
	if r := appr("135791", pw); r.Code != "bad_pin" {
		t.Fatal(r.Code)
	}
	if r := appr("246810", "wrong password"); r.Code != "bad_password" {
		t.Fatal(r.Code)
	}
	if strings.Join(e.h.CheckFailed, ",") != "pin,password" || len(e.h.Passed) != 0 {
		t.Fatalf("failed %v passed %v", e.h.CheckFailed, e.h.Passed)
	}
	e.ok(appr("246810", pw))
	if len(e.h.Passed) != 1 || e.h.Passed[0] != nil || e.h.PassedAudit[0] {
		t.Fatalf("approval not recorded as a clock start: %v %v", e.h.Passed, e.h.PassedAudit)
	}
}

// §3.6.1 (owner decision of 2026-10-06): every new credential starts the
// clock fresh: credential.create (also after credential.delete), a
// completed recovery (credential.recover, and credential.reset after a
// backup-off recovery).
func TestOwnerCheckClockStarters(t *testing.T) {
	e := newEnv(t)
	blob := e.create()
	e.ok(e.call("app", "credential.delete", blob, map[string]any{"password": pw}))
	e.pools["app"] = nil // the pools went with the credential
	e.create()
	if e.h.Enrolled != 2 {
		t.Fatalf("credential.create after credential.delete did not start the clock: %d", e.h.Enrolled)
	}
	e2 := newEnv(t)
	e2.create()
	e2.ok(e2.call("recovering-app", "credential.recover", "", map[string]any{"password": pw}))
	if len(e2.h.Passed) != 1 || e2.h.Passed[0] != nil {
		t.Fatalf("recovery did not start the clock: %v", e2.h.Passed)
	}
	// Backup off: the recovering app's credential.reset makes a new
	// credential and starts the clock.
	e3 := newEnv(t)
	e3.h.Set = vault.Settings{NoBackup: true}
	b3 := e3.create()
	e3.ok(e3.raw("app", "credential.ack", `{"version":1}`))
	_ = b3
	e3.ok(e3.call("recovering-app", "credential.reset", "", map[string]any{"password": pw}))
	if len(e3.h.Passed) != 1 || e3.h.Passed[0] != nil || e3.h.PassedAudit[0] {
		t.Fatalf("reset did not start the clock: %v", e3.h.Passed)
	}
}

// §3.6.3: the hold ends the unlock window.
func TestHoldEndsUnlockWindow(t *testing.T) {
	e := newEnv(t)
	blob := e.create()
	e.ok(e.unlock(blob, pw))
	if _, ok := e.f.UseKey(e.clk.T, time.Minute); !ok {
		t.Fatal("window not open")
	}
	e.f.OwnerHoldStarted(nil)
	if _, ok := e.f.UseKey(e.clk.T, time.Minute); ok {
		t.Fatal("window open in the hold")
	}
}

func TestHoldChangeParse(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	ok := []*Payload{
		{},
		{HasHold: true, Hold: true},
		{HasHold: true},
		{HasHold: true, HoldOffUntil: envelope.FormatTS(now.Add(30 * 24 * time.Hour))},
		{HasHold: true, HoldOffUntil: "2026-10-07T12:00:00+02:00"},
	}
	for i, p := range ok {
		if _, err := holdChange(p, now); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
	}
	bad := []*Payload{
		{HoldOffUntil: "2026-10-07T12:00:00Z"},
		{HasHold: true, Hold: true, HoldOffUntil: "2026-10-07T12:00:00Z"},
		{HasHold: true, HoldOffUntil: envelope.FormatTS(now)},
		{HasHold: true, HoldOffUntil: envelope.FormatTS(now.Add(30*24*time.Hour + time.Millisecond))},
		{HasHold: true, HoldOffUntil: "2026-10-07"},
	}
	for i, p := range bad {
		if _, err := holdChange(p, now); err == nil {
			t.Fatalf("bad %d accepted", i)
		}
	}
	c, _ := holdChange(&Payload{HasHold: true, HoldOffUntil: "2026-10-07T12:00:00+02:00"}, now)
	if c.On || !c.Until.Equal(time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("%+v", c)
	}
	_ = vault.HoldChange{}
}
