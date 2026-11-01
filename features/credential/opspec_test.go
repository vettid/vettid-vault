package credential

import (
	"testing"

	"github.com/vettid/vettid-vault/vault"
)

// §3.5.3 steps 3-5 (VAULT-MESSAGING 0.56.0, §10.18): an operation's gate
// runs after the blob and the backoff and before the password is tried,
// so its refusal tests no guess, counts nothing and rotates nothing.
func TestOperateGateBeforePassword(t *testing.T) {
	e := newEnv(t)
	blob := e.create()
	refuse := true
	e.op = &opFeature{cred: e.f, gate: func(*Payload) error {
		if refuse {
			return vault.NewError("cap_exceeded", "per_tx")
		}
		return nil
	}, op: func(*Inner, *Payload) error { return nil }}
	// A wrong password behind a refusing gate is the gate's refusal.
	for i := 0; i < BackoffAfter+2; i++ {
		if r := e.call("app", "test.op", blob, map[string]any{"password": "not the password 91"}); r.Code != "cap_exceeded" {
			t.Fatalf("gate: %q", r.Code)
		}
	}
	if e.f.st.Failures != 0 || !e.f.st.NotBefore.IsZero() || len(e.h.CheckFailed) != 0 {
		t.Fatal("a gate refusal counted a failure")
	}
	if e.f.st.Version != 1 {
		t.Fatal("a gate refusal rotated the CEK")
	}
	// Past the gate the password is tried.
	refuse = false
	if r := e.call("app", "test.op", blob, map[string]any{"password": "not the password 91"}); r.Code != "bad_password" {
		t.Fatalf("past the gate: %q", r.Code)
	}
	if e.f.st.Failures != 1 {
		t.Fatal("the failure is counted past the gate")
	}
	// The backoff comes before the gate.
	refuse = true
	for i := 0; i < BackoffAfter; i++ {
		refuse = false
		e.call("app", "test.op", blob, map[string]any{"password": "not the password 91"})
	}
	refuse = true
	if r := e.call("app", "test.op", blob, map[string]any{"password": pw}); r.Code != "backoff" {
		t.Fatalf("backoff before the gate: %q", r.Code)
	}
}

// §3.6.1, §10.18 (0.56.0): an operation with a PIN checks it, and the
// password, as an owner check does: a wrong one is a failed check and
// counts in its backoff; a success rotates the CEK and is not itself an
// owner check. A PIN that is optional is checked when present only.
func TestOperatePINAsOwnerCheck(t *testing.T) {
	e := newEnv(t)
	blob := e.create()
	e.op = &opFeature{cred: e.f, need: NeedPIN, op: func(*Inner, *Payload) error { return nil }}
	if r := e.call("app", "test.op", blob, map[string]any{"password": pw}); r.Code != "bad_request" {
		t.Fatalf("no pin: %q", r.Code)
	}
	if r := e.call("app", "test.op", blob, map[string]any{"password": pw, "pin": "000000"}); r.Code != "bad_pin" {
		t.Fatalf("wrong pin: %q", r.Code)
	}
	if len(e.h.CheckFailed) != 1 || e.h.CheckFailed[0] != "pin" || e.f.st.Failures != 0 {
		t.Fatalf("a wrong PIN is a failed check and tests no password: %v", e.h.CheckFailed)
	}
	if r := e.call("app", "test.op", blob, map[string]any{"password": "not the password 91", "pin": testPIN}); r.Code != "bad_password" {
		t.Fatalf("wrong password: %q", r.Code)
	}
	if len(e.h.CheckFailed) != 2 || e.h.CheckFailed[1] != "password" || e.f.st.Failures != 1 {
		t.Fatalf("a wrong password is a failed check: %v", e.h.CheckFailed)
	}
	passed := len(e.h.Passed)
	r := e.ok(e.call("app", "test.op", blob, map[string]any{"password": pw, "pin": testPIN}))
	if e.f.st.Version != 2 || len(e.h.Passed) != passed {
		t.Fatal("rotated once, and not an owner check")
	}
	blob = blobOf(t, e.ok(r))

	// Optional: no PIN tried without one, checked when present.
	e.op = &opFeature{cred: e.f, need: NeedOptPIN, op: func(*Inner, *Payload) error { return nil }}
	tries := e.h.PINTries
	blob = blobOf(t, e.ok(e.call("app", "test.op", blob, map[string]any{"password": pw})))
	if e.h.PINTries != tries {
		t.Fatal("a PIN was checked that was not sent")
	}
	if r := e.call("app", "test.op", blob, map[string]any{"password": pw, "pin": "000000"}); r.Code != "bad_pin" {
		t.Fatalf("a present PIN is checked: %q", r.Code)
	}
	if r := e.call("app", "test.op", blob, map[string]any{"password": pw, "pin": "12ab"}); r.Code != "bad_request" {
		t.Fatalf("malformed pin: %q", r.Code)
	}
	e.ok(e.call("app", "test.op", blob, map[string]any{"password": pw, "pin": testPIN}))
}
