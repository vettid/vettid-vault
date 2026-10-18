//go:build devenclave && e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// A lost answer to pin.change or credential.password.change
// (VAULT-MESSAGING 0.44.0 §11.14.9 "A lost answer", §11.14.14), through
// the real relay: the same request resent (same inner id, same body) is
// answered from the response cache and tests no secret again;
// credential.version shows the change applied (one higher); a new request
// with the old blob is answered stale_credential before any PIN or
// password is tested, for both types (credential.password.change checks
// the blob before the PIN since this rule); a copy that reaches the vault
// after its exp is dropped unanswered and never applies; and a handled
// request resent after its exp gets no cached answer.

const lostNewPW = "violet-Kestrel-91-moss"

// changeRequest builds a credential change as the app sends it: the
// payload sealed to a fresh UTK under the inner id, and the blob.
func changeRequest(t *testing.T, d *client.Device, typ string, blob []byte, payload map[string]any) (string, json.RawMessage) {
	t.Helper()
	u := takeUTK(t, d)
	id, err := envelope.NewULID(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pt, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := suite.ParsePublicKey(u.EK)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := credwire.SealPayload(ek, d.VaultID(), u.ID, typ, id, pt)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"utk_id": u.ID, "sealed": base64.StdEncoding.EncodeToString(sealed),
		"credential": base64.StdEncoding.EncodeToString(blob)})
	return id, b
}

// send sends the request with its exp and waits for the answer to its id.
func send(t *testing.T, d *client.Device, id, typ string, body json.RawMessage, exp time.Time) *client.Response {
	t.Helper()
	ctx := ctxT(t, 60*time.Second)
	if _, err := d.SendWithIDExp(ctx, id, typ, body, exp); err != nil {
		t.Fatal(err)
	}
	r, err := d.AwaitResponse(ctx, id)
	if err != nil {
		t.Fatalf("%s: %v", typ, err)
	}
	return r
}

func credVersion(t *testing.T, d *client.Device) uint64 {
	t.Helper()
	o, err := d.CredentialVersion(ctxT(t, 30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	v, err := o.Uint("version", 1, strictjson.MaxSafeInteger)
	if err != nil {
		t.Fatalf("credential.version: %v", err)
	}
	return v
}

// audits counts the vault's audit entries of an event: the runtime's
// (dropped messages) and the audit feature's (activities).
func audits(tv *testVault, event string) int {
	n := 0
	for _, a := range tv.manager().Audit() {
		if a.Event == event {
			n++
		}
	}
	tv.mu.Lock()
	fs := tv.fs
	tv.mu.Unlock()
	for _, e := range fs.Audit.Entries() {
		if e.Kind == event {
			n++
		}
	}
	return n
}

func ownerCheckFailures(t *testing.T, tv *testVault) uint64 {
	t.Helper()
	o := mustOK(t, tv.request(tv.app, "vault.status", `{}`))
	oc, err := o.Object("owner_check")
	if err != nil {
		t.Fatal(err)
	}
	n, err := oc.Uint("failures", 0, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// nextSecret is the phone's next unlock secret; the harness's app
// enrolled without a phone key (devenclave.Create), so a fixed test value
// of the right size stands in for it.
func nextSecret(d *client.Device) []byte {
	if s := d.NextUnlockSecret(); len(s) == 32 {
		return s
	}
	return bytes.Repeat([]byte{0x5a}, 32)
}

// nothingTested reports that no secret was tested and failed: no failed
// owner check or password, no PIN failure (vault.pin_failed, the §11.8
// backoff), and vault.status shows no owner-check failures.
func nothingTested(t *testing.T, tv *testVault) bool {
	t.Helper()
	return audits(tv, "owner_check.failed") == 0 && audits(tv, "credential.password_failed") == 0 &&
		audits(tv, "vault.pin_failed") == 0 && ownerCheckFailures(t, tv) == 0
}

type lostCase struct {
	typ     string
	applied string // the audit event of an applied change
	// payload is the change with the given current PIN and password.
	payload func(d *client.Device, curPIN, curPW string) map[string]any
}

var lostCases = []lostCase{
	{typ: "pin.change", applied: "vault.pin_changed", payload: func(d *client.Device, curPIN, curPW string) map[string]any {
		return map[string]any{"pin": curPIN, "new_pin": "135790", "password": curPW,
			"new_unlock_secret": base64.StdEncoding.EncodeToString(nextSecret(d))}
	}},
	{typ: "credential.password.change", applied: "credential.password_changed", payload: func(_ *client.Device, curPIN, curPW string) map[string]any {
		return map[string]any{"pin": curPIN, "password": curPW, "new_password": lostNewPW}
	}},
}

// The answer is lost; the app resends the same request while its exp has
// not passed and asks credential.version; a new request with the old blob
// (the generic retry the rule forbids) is stale_credential before any
// secret is tested.
func TestLostAnswerResendAndVersion(t *testing.T) {
	for _, c := range lostCases {
		t.Run(c.typ, func(t *testing.T) {
			r := relaytest.Start(t, nil)
			tv := newTestVault(t, r.URL, "a", nil)
			d := tv.app
			v0 := credVersion(t, d)
			blob0 := append([]byte(nil), d.CredentialBlob()...)
			exp := time.Now().Add(10 * time.Minute)
			id, body := changeRequest(t, d, c.typ, blob0, c.payload(d, pin, credPW))

			// The first answer arrives at the transport and is lost: the
			// app never acts on it.
			first := send(t, d, id, c.typ, body, exp)
			if !first.OK() {
				t.Fatalf("first: %s", first.ErrorCode())
			}
			// The same request again: the cached answer, nothing re-run.
			again := send(t, d, id, c.typ, body, exp)
			if !again.OK() || !bytes.Equal(again.Body(), first.Body()) {
				t.Fatalf("resend: %s %s", again.ErrorCode(), again.Body())
			}
			if n := audits(tv, c.applied); n != 1 {
				t.Fatalf("%s audited %d times", c.applied, n)
			}
			if !nothingTested(t, tv) {
				t.Fatal("an attempt was counted")
			}
			// credential.version: one above the version sent, so applied.
			if v := credVersion(t, d); v != v0+1 {
				t.Fatalf("credential.version %d after the change from %d", v, v0)
			}
			// A new request with the old blob, as a generic retry would
			// send it with the typed secrets: stale_credential, nothing
			// counted. Both types check the blob before any secret, so a
			// wrong password or a wrong PIN with it is not tested either.
			retries := []map[string]any{c.payload(d, pin, credPW), c.payload(d, pin, "wrong password entirely"),
				c.payload(d, "000000", credPW), c.payload(d, "000000", "wrong password entirely")}
			for _, p := range retries {
				nid, nbody := changeRequest(t, d, c.typ, blob0, p)
				if rr := send(t, d, nid, c.typ, nbody, time.Now().Add(10*time.Minute)); rr.ErrorCode() != "stale_credential" {
					t.Fatalf("retry with the old blob: %q", rr.ErrorCode())
				}
			}
			if !nothingTested(t, tv) {
				t.Fatal("the old-blob retry tested a secret")
			}
			if n := audits(tv, c.applied); n != 1 {
				t.Fatalf("%s audited %d times after the retries", c.applied, n)
			}
			// Decided: the app fetches the latest blob, which carries the
			// new version (and, after a password change, opens with the
			// new password).
			if err := d.CredentialFetch(ctxT(t, 30*time.Second)); err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(d.CredentialBlob(), blob0) {
				t.Fatal("the blob did not change")
			}
			if c.typ == "credential.password.change" {
				if _, err := d.CredentialUnlock(ctxT(t, 30*time.Second), lostNewPW); err != nil {
					t.Fatalf("the new password: %v", err)
				}
			}
		})
	}
}

// A copy that reaches the vault after its exp is dropped before the dedupe
// and before any handler: unanswered, never applied, nothing tested; the
// same request resent after its exp is dropped too.
func TestLostAnswerPastExpNeverApplies(t *testing.T) {
	for _, c := range lostCases {
		t.Run(c.typ, func(t *testing.T) {
			r := relaytest.Start(t, nil)
			tv := newTestVault(t, r.URL, "a", nil)
			d := tv.app
			v0 := credVersion(t, d)
			blob0 := append([]byte(nil), d.CredentialBlob()...)
			id, body := changeRequest(t, d, c.typ, blob0, c.payload(d, pin, credPW))
			stale0 := audits(tv, "stale_or_future")

			// The vault is not collecting while the request waits at the
			// relay past its exp.
			tv.stop()
			exp := time.Now().Add(2 * time.Second)
			ctx := ctxT(t, 60*time.Second)
			if _, err := d.SendWithIDExp(ctx, id, c.typ, body, exp); err != nil {
				t.Fatal(err)
			}
			time.Sleep(time.Until(exp) + time.Second)
			tv.restart()
			deadline := time.Now().Add(30 * time.Second)
			for audits(tv, "stale_or_future") == stale0 {
				if time.Now().After(deadline) {
					t.Fatal("the expired request was not seen")
				}
				time.Sleep(200 * time.Millisecond)
			}
			// Resent after its exp: dropped as well.
			if _, err := d.SendWithIDExp(ctx, id, c.typ, body, exp); err != nil {
				t.Fatal(err)
			}
			wctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if rr, err := d.AwaitResponse(wctx, id); err == nil {
				t.Fatalf("an expired request was answered: %s %s", rr.ErrorCode(), rr.Body())
			}
			if v := credVersion(t, d); v != v0 {
				t.Fatalf("credential.version %d, was %d: the expired change applied", v, v0)
			}
			if audits(tv, c.applied) != 0 || !nothingTested(t, tv) {
				t.Fatal("the expired request reached its handler")
			}
			// Not applied and never will be: the current secrets still
			// work, with the blob the app holds.
			if _, err := d.CredentialUnlock(ctxT(t, 30*time.Second), credPW); err != nil {
				t.Fatalf("the current password after the expired change: %v", err)
			}
		})
	}
}

// A request the vault handled, resent after its exp, gets no answer: the
// exp check comes before the dedupe and its response cache, so the
// cached answer is never resent then, and nothing applies twice.
func TestLostAnswerHandledResentAfterExp(t *testing.T) {
	for _, c := range lostCases {
		t.Run(c.typ, func(t *testing.T) {
			r := relaytest.Start(t, nil)
			tv := newTestVault(t, r.URL, "a", nil)
			d := tv.app
			v0 := credVersion(t, d)
			id, body := changeRequest(t, d, c.typ, d.CredentialBlob(), c.payload(d, pin, credPW))
			exp := time.Now().Add(3 * time.Second)
			if first := send(t, d, id, c.typ, body, exp); !first.OK() {
				t.Fatalf("first: %s", first.ErrorCode())
			}
			stale0 := audits(tv, "stale_or_future")
			time.Sleep(time.Until(exp) + time.Second)
			if _, err := d.SendWithIDExp(ctxT(t, 30*time.Second), id, c.typ, body, exp); err != nil {
				t.Fatal(err)
			}
			wctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if rr, err := d.AwaitResponse(wctx, id); err == nil {
				t.Fatalf("a cached answer after exp: %s %s", rr.ErrorCode(), rr.Body())
			}
			if audits(tv, "stale_or_future") == stale0 {
				t.Fatal("the resend after exp was not dropped as expired")
			}
			if v := credVersion(t, d); v != v0+1 {
				t.Fatalf("credential.version %d from %d", v, v0)
			}
			if n := audits(tv, c.applied); n != 1 || !nothingTested(t, tv) {
				t.Fatalf("%s audited %d times", c.applied, n)
			}
		})
	}
}

// Owner decisions 2026-10-18: a wrong PIN or password on
// credential.password.change, tested after the blob passed, is a failed
// owner check (as for pin.change and the owner check); with an old blob
// nothing is tested and nothing is counted.
func TestPasswordChangeWrongSecretIsAFailedCheck(t *testing.T) {
	r := relaytest.Start(t, nil)
	tv := newTestVault(t, r.URL, "a", nil)
	d := tv.app
	const typ = "credential.password.change"
	blob0 := append([]byte(nil), d.CredentialBlob()...)
	wrong := map[string]any{"pin": "000000", "password": credPW, "new_password": lostNewPW}
	id, body := changeRequest(t, d, typ, blob0, wrong)
	if rr := send(t, d, id, typ, body, time.Now().Add(10*time.Minute)); rr.ErrorCode() != "bad_pin" {
		t.Fatalf("wrong PIN with the current blob: %q", rr.ErrorCode())
	}
	if n := ownerCheckFailures(t, tv); n != 1 {
		t.Fatalf("owner_check.failures %d after a wrong PIN, want 1", n)
	}
	if audits(tv, "owner_check.failed") != 1 || audits(tv, "vault.pin_failed") != 1 {
		t.Fatalf("audits: owner_check.failed %d, vault.pin_failed %d", audits(tv, "owner_check.failed"), audits(tv, "vault.pin_failed"))
	}
	// A wrong password with the right PIN (once the PIN backoff of §11.8
	// has run out) is a failed check too (owner decision 2026-10-18).
	deadline := time.Now().Add(2 * time.Minute)
	for {
		id, body = changeRequest(t, d, typ, d.CredentialBlob(), map[string]any{"pin": pin, "password": "wrong password entirely", "new_password": lostNewPW})
		rr := send(t, d, id, typ, body, time.Now().Add(10*time.Minute))
		if rr.ErrorCode() == "bad_password" {
			break
		}
		if rr.ErrorCode() != "backoff" || time.Now().After(deadline) {
			t.Fatalf("wrong password: %q", rr.ErrorCode())
		}
		time.Sleep(time.Second)
	}
	if n := ownerCheckFailures(t, tv); n != 2 {
		t.Fatalf("owner_check.failures %d after a wrong password, want 2", n)
	}
	if audits(tv, "owner_check.failed") != 2 || audits(tv, "credential.password_failed") != 1 {
		t.Fatalf("audits: owner_check.failed %d, credential.password_failed %d", audits(tv, "owner_check.failed"), audits(tv, "credential.password_failed"))
	}
	// The change applies with the right PIN and password (after the
	// backoffs); then an old blob with a wrong PIN counts nothing more.
	for {
		id, body = changeRequest(t, d, typ, d.CredentialBlob(), map[string]any{"pin": pin, "password": credPW, "new_password": lostNewPW})
		rr := send(t, d, id, typ, body, time.Now().Add(10*time.Minute))
		if rr.OK() {
			break
		}
		if rr.ErrorCode() != "backoff" || time.Now().After(deadline) {
			t.Fatalf("the change with the right PIN: %q", rr.ErrorCode())
		}
		time.Sleep(time.Second)
	}
	failed, pinFailed := audits(tv, "owner_check.failed"), audits(tv, "vault.pin_failed")
	id, body = changeRequest(t, d, typ, blob0, wrong)
	if rr := send(t, d, id, typ, body, time.Now().Add(10*time.Minute)); rr.ErrorCode() != "stale_credential" {
		t.Fatalf("old blob, wrong PIN: %q", rr.ErrorCode())
	}
	if audits(tv, "owner_check.failed") != failed || audits(tv, "vault.pin_failed") != pinFailed {
		t.Fatal("an old blob's wrong PIN was counted")
	}
	// The successful change was not an owner check (§3.6.1 lists what
	// is), so failures stay where the wrong entries left them.
	if n := ownerCheckFailures(t, tv); n != 2 {
		t.Fatalf("owner_check.failures %d after the old blob's wrong PIN, want 2", n)
	}
}
