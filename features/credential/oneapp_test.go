package credential

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
)

// alarmSent returns the credential.alarm events sent to the holder.
func (e *env) alarmSent(to string) []featuretest.Sent {
	var out []featuretest.Sent
	for _, s := range e.h.SentOfType("credential.alarm") {
		if s.To == to {
			out = append(out, s)
		}
	}
	return out
}

func (e *env) alarmID() string {
	e.t.Helper()
	o := e.ok(e.raw("app", "credential.version", `{}`)).Obj(e.t)
	a, err := o.Object("alarm")
	if err != nil {
		e.t.Fatalf("no alarm: %s", e.ok(e.raw("app", "credential.version", `{}`)).Body)
	}
	id, _ := a.String("alarm_id")
	return id
}

// §3.5.9: the app that creates the credential holds it; only the holder
// fetches or confirms it; a blob presented by another app is a clone.
func TestOneHolder(t *testing.T) {
	e := newEnv(t)
	blob := e.create()
	if e.f.Holder() != "dev-app" {
		t.Fatalf("holder %q", e.f.Holder())
	}
	for _, typ := range []string{"credential.get", "credential.ack", "device.transfer.create"} {
		if r := e.raw("app2", typ, `{"version":1}`); r.Code != "forbidden" {
			t.Fatalf("%s by another app: %q", typ, r.Code)
		}
	}
	if r := e.raw("desktop", "credential.version", `{}`); !r.OK() {
		t.Fatal("desktops still read the version")
	}
	if r := e.unlock(blob, pw); !r.OK() {
		t.Fatal(r.Code)
	}
	if r := e.call("app2", "credential.unlock", blob, map[string]any{"password": pw}); r.Code != "credential_frozen" {
		t.Fatalf("another app's blob: %q", r.Code)
	}
	if len(e.h.Alarms) != 1 || e.h.Alarms[0] != vault.AlarmCredentialClone {
		t.Fatalf("host alarm %v", e.h.Alarms)
	}
	s := e.alarmSent("dev-app")
	if len(s) != 1 || !strings.Contains(string(s[0].Body), `"presenter":"other"`) || !strings.Contains(string(s[0].Body), `"state":"frozen"`) {
		t.Fatalf("alert to the holder: %+v", s)
	}
}

// §3.5.3, §3.5.9: the holder's own retry of the previous version, before it
// confirmed the current one, is explained (stale_credential, fetch with
// credential.get); everything else is a clone: refused, the holder
// alerted urgently, the host told once, audited; credential operations
// freeze (messaging is not this feature's) until the holder confirms, and
// then only the forced rotation runs; the rotation kills every older copy.
func TestCloneAlarmFreezeConfirmRotate(t *testing.T) {
	e := newEnv(t)
	b1 := e.create()
	b2 := blobOf(t, e.ok(e.unlock(b1, pw))) // the response is "lost"
	if r := e.unlock(b1, pw); r.Code != "stale_credential" || len(e.h.Alarms) != 0 {
		t.Fatalf("own retry: %q %v", r.Code, e.h.Alarms)
	}
	if got := blobOf(t, e.ok(e.raw("app", "credential.get", `{}`))); got != b2 {
		t.Fatal("credential.get")
	}
	e.ok(e.raw("app", "credential.ack", `{"version":2}`))
	e.h.Set.CredentialUnlockTTL = 600
	b3 := blobOf(t, e.ok(e.unlock(b2, pw)))
	if _, ok := e.f.UseKey(e.clk.T, time.Minute); !ok {
		t.Fatal("window")
	}
	e.ok(e.raw("app", "credential.ack", `{"version":3}`))
	// b2 after the holder confirmed b3: a clone.
	if r := e.unlock(b2, pw); r.Code != "credential_frozen" {
		t.Fatalf("clone: %q", r.Code)
	}
	if len(e.h.Alarms) != 1 || !e.h.HasActivity("credential.clone_detected") {
		t.Fatal("alarm not reported or audited")
	}
	urgent := false
	for _, a := range e.h.Activities {
		urgent = urgent || a.Kind == "credential.alarm" && a.Feed && a.Priority == "urgent"
	}
	if !urgent || len(e.alarmSent("dev-app")) != 1 {
		t.Fatal("no urgent alert")
	}
	if _, ok := e.f.UseKey(e.clk.T, time.Minute); ok {
		t.Fatal("unlock window open under an alarm")
	}
	id := e.alarmID()
	// Frozen: credential operations refused, the current blob included;
	// UTKs, the version and the lock still answer.
	if r := e.unlock(b3, pw); r.Code != "credential_frozen" {
		t.Fatalf("frozen unlock: %q", r.Code)
	}
	for _, typ := range []string{"credential.get", "device.transfer.create"} {
		if r := e.raw("app", typ, `{}`); r.Code != "credential_frozen" {
			t.Fatalf("frozen %s: %q", typ, r.Code)
		}
	}
	e.op = &opFeature{cred: e.f, op: func(*Inner, *Payload) error { return nil }}
	if r := e.call("app", "test.op", b3, map[string]any{"password": pw}); r.Code != "credential_frozen" {
		t.Fatalf("frozen operation: %q", r.Code)
	}
	e.ok(e.raw("app", "credential.utk.get", `{}`))
	e.ok(e.raw("app", "credential.lock", `{}`))
	// A second clone while frozen: refused and audited, no new alarm.
	if r := e.unlock(b1, pw); r.Code != "credential_frozen" || len(e.h.Alarms) != 1 {
		t.Fatalf("second clone: %q %v", r.Code, e.h.Alarms)
	}
	// Confirmation: only the holder, only this alarm.
	if r := e.raw("app2", "credential.alarm.confirm", `{"alarm_id":"`+id+`","mine":false}`); r.Code != "forbidden" {
		t.Fatalf("confirm by another app: %q", r.Code)
	}
	if r := e.raw("app", "credential.alarm.confirm", `{"alarm_id":"`+testID+`","mine":false}`); r.Code != "not_found" {
		t.Fatalf("other alarm id: %q", r.Code)
	}
	if r := e.raw("app", "credential.alarm.confirm", `{"alarm_id":"`+id+`"}`); r.Code != "bad_request" {
		t.Fatal("mine missing")
	}
	if st, _ := e.ok(e.raw("app", "credential.alarm.confirm", `{"alarm_id":"`+id+`","mine":false}`)).Obj(t).String("state"); st != AlarmRotationRequired {
		t.Fatalf("state %q", st)
	}
	if !e.h.HasActivity("credential.alarm.confirmed") {
		t.Fatal("confirmation not audited")
	}
	// Rotation required: only the rotation (and fetching the latest blob).
	if r := e.unlock(b3, pw); r.Code != "rotation_required" {
		t.Fatalf("unlock before the rotation: %q", r.Code)
	}
	if got := blobOf(t, e.ok(e.raw("app", "credential.get", `{}`))); got != b3 {
		t.Fatal("latest blob")
	}
	k1, _ := e.ok(e.raw("app", "credential.version", `{}`)).Obj(t).String("key")
	r := e.ok(e.call("app", "credential.rotate", b3, map[string]any{"password": pw}))
	if k2, _ := r.Obj(t).String("key"); k2 == k1 {
		t.Fatal("credential key not rotated")
	}
	if !e.h.HasActivity("credential.alarm.resolved") {
		t.Fatal("not resolved")
	}
	if strings.Contains(string(e.ok(e.raw("app", "credential.version", `{}`)).Body), `"alarm"`) {
		t.Fatal("alarm still open")
	}
	resolved := false
	for _, s := range e.h.SentOfType("sync.event") {
		resolved = resolved || strings.Contains(string(s.Body), `"credential.alarm"`) && strings.Contains(string(s.Body), `"resolved"`)
	}
	if !resolved {
		t.Fatal("no resolved sync event")
	}
	b4 := blobOf(t, r)
	e.ok(e.unlock(b4, pw))
	// Every older copy is dead: presented again, a new alarm.
	if r := e.unlock(b3, pw); r.Code != "credential_frozen" || len(e.h.Alarms) != 2 {
		t.Fatalf("old copy after the rotation: %q %v", r.Code, e.h.Alarms)
	}
}

// §3.5.9: the kinds of presentation that are clones.
func TestCloneVariants(t *testing.T) {
	forge := func(t *testing.T, blob string, f func([]byte)) string {
		raw, _ := base64.StdEncoding.DecodeString(blob)
		f(raw)
		return base64.StdEncoding.EncodeToString(raw)
	}
	for name, mk := range map[string]func(t *testing.T, e *env, cur string) string{
		"same version, other bytes": func(t *testing.T, _ *env, cur string) string {
			return forge(t, cur, func(b []byte) { b[len(b)-1] ^= 1 })
		},
		"version above the current": func(t *testing.T, _ *env, cur string) string {
			return forge(t, cur, func(b []byte) { binary.BigEndian.PutUint64(b[1:9], 99) })
		},
		"previous version after the ack": func(t *testing.T, e *env, cur string) string {
			prev := cur
			next := blobOf(t, e.ok(e.unlock(cur, pw)))
			e.ok(e.raw("app", "credential.ack", `{"version":3}`))
			_ = next
			return prev
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			b1 := e.create()
			b2 := blobOf(t, e.ok(e.unlock(b1, pw)))
			e.ok(e.raw("app", "credential.ack", `{"version":2}`))
			if r := e.unlock(mk(t, e, b2), pw); r.Code != "credential_frozen" || len(e.h.Alarms) != 1 {
				t.Fatalf("%q %v", r.Code, e.h.Alarms)
			}
		})
	}
}

// §6.7.1: the holder transfers to a new phone: approval with the PIN and
// the password (backoffs apply), the CEK rotated (the old copy dead), the
// old app's credential operations held; on completion the new app holds
// the credential; on an abort the old app keeps it and fetches the
// rotated blob.
func TestTransfer(t *testing.T) {
	e := newEnv(t)
	e.h.PIN = "246810"
	blob := e.create()
	if r := e.raw("app2", "device.transfer.create", `{}`); r.Code != "forbidden" {
		t.Fatal("transfer by another app")
	}
	o := e.ok(e.raw("app", "device.transfer.create", `{}`)).Obj(t)
	id, _ := o.String("transfer_id")
	if l, _ := o.String("link"); l == "" {
		t.Fatal("link")
	}
	if r := e.raw("app", "device.transfer.create", `{}`); r.Code != "exists" {
		t.Fatalf("second transfer: %q", r.Code)
	}
	appr := func(pin, password string) featuretest.Result {
		return e.callBody("app", "device.transfer.approve", blob, map[string]any{"password": password, "pin": pin}, `"transfer_id":"`+id+`"`)
	}
	if r := appr("246810", pw); r.Code != "not_found" {
		t.Fatalf("approve before the scan: %q", r.Code)
	}
	e.h.Xfer.Scanned = true
	if r := appr("13579", pw); r.Code != "bad_pin" {
		t.Fatalf("wrong PIN: %q", r.Code)
	}
	if r := appr("abc", pw); r.Code != "bad_request" {
		t.Fatalf("malformed PIN: %q", r.Code)
	}
	if r := appr("246810", "wrong password"); r.Code != "bad_password" {
		t.Fatalf("wrong password: %q", r.Code)
	}
	r := e.ok(appr("246810", pw))
	if ex, _ := r.Obj(t).String("exp"); ex == "" || strings.Contains(string(r.Body), `"credential"`) {
		t.Fatalf("approve response %s", r.Body)
	}
	if e.h.Xfer.State != vault.TransferApproved {
		t.Fatal("not approved")
	}
	// The old app is about to go: no credential operations.
	if r := e.unlock(blob, pw); r.Code != "transfer_pending" {
		t.Fatalf("old app after approval: %q", r.Code)
	}
	if r := e.raw("app", "credential.get", `{}`); r.Code != "transfer_pending" {
		t.Fatalf("old app get: %q", r.Code)
	}
	// Completion: the new app holds the credential.
	e.f.TransferCompleted(nil, "dev-app", "dev-app2")
	if e.f.Holder() != "dev-app2" || e.f.PoolSizeOf("dev-app") != 0 {
		t.Fatal("holder not moved")
	}
	e.h.Xfer = nil
	latest := blobOf(t, e.ok(e.raw("app2", "credential.get", `{}`)))
	if latest == blob {
		t.Fatal("CEK not rotated at the approval")
	}
	e.ok(e.raw("app2", "credential.ack", `{"version":2}`))
	e.ok(e.call("app2", "credential.unlock", latest, map[string]any{"password": pw}))
}

func TestTransferAbortKeepsHolder(t *testing.T) {
	e := newEnv(t)
	e.h.PIN = "246810"
	blob := e.create()
	o := e.ok(e.raw("app", "device.transfer.create", `{}`)).Obj(t)
	id, _ := o.String("transfer_id")
	e.h.Xfer.Scanned = true
	e.ok(e.callBody("app", "device.transfer.approve", blob, map[string]any{"password": pw, "pin": "246810"}, `"transfer_id":"`+id+`"`))
	// The new app never finished: the runtime aborted the transfer.
	e.h.Xfer = nil
	if r := e.unlock(blob, pw); r.Code != "stale_credential" || len(e.h.Alarms) != 0 {
		t.Fatalf("old app after an abort: %q %v", r.Code, e.h.Alarms)
	}
	latest := blobOf(t, e.ok(e.raw("app", "credential.get", `{}`)))
	e.ok(e.unlock(latest, pw))
	// Reject: the holder ends an open transfer.
	o = e.ok(e.raw("app", "device.transfer.create", `{}`)).Obj(t)
	id, _ = o.String("transfer_id")
	e.ok(e.raw("app", "device.transfer.reject", `{"transfer_id":"`+id+`"}`))
	if len(e.h.XferEnded) != 1 || !strings.HasSuffix(e.h.XferEnded[0], ":rejected") {
		t.Fatalf("ended %v", e.h.XferEnded)
	}
	// An alarm cancels an open transfer.
	e.ok(e.raw("app", "device.transfer.create", `{}`))
	if r := e.unlock(blob, pw); r.Code != "credential_frozen" || len(e.h.XferEnded) != 2 || !strings.HasSuffix(e.h.XferEnded[1], ":alarm") {
		t.Fatalf("alarm during a transfer: %q %v", r.Code, e.h.XferEnded)
	}
}

// §3.5.9: a recovery during an alarm hands the credential to the new app,
// which must still rotate.
func TestRecoverDuringAlarm(t *testing.T) {
	e := newEnv(t)
	b1 := e.create()
	e.ok(e.unlock(b1, pw))
	e.ok(e.raw("app", "credential.ack", `{"version":2}`))
	if r := e.unlock(b1, pw); r.Code != "credential_frozen" {
		t.Fatal(r.Code)
	}
	e.ok(e.call("recovering-app", "credential.recover", "", map[string]any{"password": pw}))
	if e.f.Holder() != "dev-recovering" || !strings.Contains(string(e.ok(e.raw("desktop", "credential.version", `{}`)).Body), `"rotation_required"`) {
		t.Fatal("alarm not moved to rotation_required")
	}
}

// callBody is call with extra top-level members in the body.
func (e *env) callBody(kind, typ, blob string, payload map[string]any, extra string) featuretest.Result {
	e.t.Helper()
	e.extra = extra
	defer func() { e.extra = "" }()
	return e.call(kind, typ, blob, payload)
}

// The one-app bodies (§3.5.9, §6.7.1) are parsed strictly; nothing panics.
func FuzzOneAppBodies(f *testing.F) {
	f.Add(0, []byte(`{"alarm_id":"`+testID+`","mine":true}`))
	f.Add(1, []byte(`{"transfer_id":"`+testID+`"}`))
	f.Add(2, []byte(`{}`))
	f.Add(5, []byte(`{"confirm":"delete my vault","utk_id":"0011223344556677","sealed":"AAAA"}`))
	types := []string{"credential.alarm.confirm", "device.transfer.reject", "device.transfer.create", "device.transfer.approve", "credential.reset", "vault.delete"}
	h := featuretest.NewHost()
	h.AddDevice("dev-app", vault.KindApp)
	cr := New(Options{KDF: MinKDF})
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, i int, b []byte) {
		if i < 0 {
			i = -i
		}
		_ = featuretest.Call(cr, h, now, "app", types[i%len(types)], string(b))
		h.Xfer = nil
	})
}

// §12.5: vault.delete authorizes a deletion: the confirmation phrase and
// the PIN always; the holder's current blob and password; refused during
// an alarm; nothing of the credential is returned.
func TestVaultDelete(t *testing.T) {
	e := newEnv(t)
	e.h.PIN = "246810"
	blob := e.create()
	del := func(kind, blob string, payload map[string]any, confirm string) featuretest.Result {
		return e.callBody(kind, "vault.delete", blob, payload, `"confirm":"`+confirm+`"`)
	}
	if r := del("app", blob, map[string]any{"pin": "246810", "password": pw}, "yes"); r.Code != "bad_request" {
		t.Fatalf("confirmation: %q", r.Code)
	}
	if r := del("app", blob, map[string]any{"pin": "135791", "password": pw}, vault.DeleteConfirmation); r.Code != "bad_pin" {
		t.Fatalf("wrong PIN: %q", r.Code)
	}
	if r := del("app", blob, map[string]any{"pin": "246810", "password": "wrong password"}, vault.DeleteConfirmation); r.Code != "bad_password" {
		t.Fatalf("wrong password: %q", r.Code)
	}
	if r := del("app", blob, map[string]any{"pin": "246810"}, vault.DeleteConfirmation); r.Code != "bad_request" {
		t.Fatalf("no password: %q", r.Code)
	}
	if r := del("app2", blob, map[string]any{"pin": "246810", "password": pw}, vault.DeleteConfirmation); r.Code != "forbidden" {
		t.Fatalf("another app: %q", r.Code)
	}
	if len(e.h.Deletions) != 0 {
		t.Fatal("deleted early")
	}
	r := e.ok(del("app", blob, map[string]any{"pin": "246810", "password": pw}, vault.DeleteConfirmation))
	if strings.Contains(string(r.Body), "credential") || len(e.h.Deletions) != 1 || e.h.Deletions[0] != "app" {
		t.Fatalf("delete: %s %v", r.Body, e.h.Deletions)
	}
	e.f.VaultDeleting(nil)
	if e.f.CredentialExists() {
		t.Fatal("credential kept")
	}
}

func TestVaultDeleteDuringAlarmAndRecovery(t *testing.T) {
	e := newEnv(t)
	e.h.PIN = "246810"
	b1 := e.create()
	b2 := blobOf(t, e.ok(e.unlock(b1, pw)))
	e.ok(e.raw("app", "credential.ack", `{"version":2}`))
	e.unlock(b1, pw) // a clone: frozen
	if r := e.callBody("app", "vault.delete", b2, map[string]any{"pin": "246810", "password": pw}, `"confirm":"`+vault.DeleteConfirmation+`"`); r.Code != "credential_frozen" {
		t.Fatalf("delete during an alarm: %q", r.Code)
	}
	// The recovery path: backup on → the password against the vault's copy.
	if r := e.callBody("recovering-app", "vault.delete", "", map[string]any{"pin": "246810"}, `"confirm":"`+vault.DeleteConfirmation+`"`); r.Code != "bad_request" {
		t.Fatalf("recovery delete without the password (backup on): %q", r.Code)
	}
	e.ok(e.callBody("recovering-app", "vault.delete", "", map[string]any{"pin": "246810", "password": pw}, `"confirm":"`+vault.DeleteConfirmation+`"`))
	if len(e.h.Deletions) != 1 || e.h.Deletions[0] != "recovery" {
		t.Fatalf("%v", e.h.Deletions)
	}
}

// §11.11.5 (0.9.0): with backup off a recovery restores access only: no
// credential content is ever returned; the app may reset or delete (PIN
// only, the credential being lost).
func TestBackupOffRecoveryAccessOnly(t *testing.T) {
	e := newEnv(t)
	e.h.PIN = "246810"
	e.h.Set.NoBackup = true
	e.create()
	e.ok(e.raw("app", "credential.ack", `{"version":1}`))
	for _, typ := range []string{"credential.get", "credential.version"} {
		if r := e.raw("recovering-app", typ, `{}`); r.Code != "forbidden" {
			t.Fatalf("%s from a recovering app: %q", typ, r.Code)
		}
	}
	if r := e.call("recovering-app", "credential.recover", "", map[string]any{"password": pw}); r.Code != "credential_lost" || r.Body != nil {
		t.Fatalf("recover: %q %s", r.Code, r.Body)
	}
	e.ok(e.callBody("recovering-app", "vault.delete", "", map[string]any{"pin": "246810"}, `"confirm":"`+vault.DeleteConfirmation+`"`))
	if len(e.h.Deletions) != 1 {
		t.Fatal("not deleted")
	}
}

// §3.5.9 (0.9.0): a credential without a holder never adopts an app: the
// vault is restricted to the recovery path and deletion.
func TestNoHolderNoAdoption(t *testing.T) {
	e := newEnv(t)
	blob := e.create()
	e.f.mu.Lock()
	e.f.st.Holder = ""
	e.f.mu.Unlock()
	if e.f.CredentialReady() || !e.f.CredentialExists() {
		t.Fatal("holderless credential ready")
	}
	if r := e.unlock(blob, pw); r.Code != "forbidden" && r.Code != "credential_required" {
		t.Fatalf("holderless unlock: %q", r.Code)
	}
	if e.f.Holder() != "" {
		t.Fatal("adopted")
	}
	e.ok(e.call("recovering-app", "credential.recover", "", map[string]any{"password": pw}))
	if e.f.Holder() != "dev-recovering" {
		t.Fatal("recovery did not set the holder")
	}
}
