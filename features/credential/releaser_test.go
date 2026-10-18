package credential

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/vault"
)

var nextSecret = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x45}, 32))

// Release R (VAULT-MESSAGING 0.33.0 §11.14.7, §11.14.9): credential.create
// carries the PIN and arms; a weak password is refused before anything
// changes.
func TestCreateReleaseR(t *testing.T) {
	e := newEnv(t)
	for pass, reason := range map[string]string{"short-pass": "short", "QWERTY123456": "common", "abcdefghijklmn": "guessable",
		"zzzzzzzzzzzzzz": "repeated"} {
		r := e.call("app", "credential.create", "", map[string]any{"password": pass})
		if r.Code != "weak_password" || !strings.Contains(string(r.Body), `"reason":"`+reason+`"`) {
			t.Fatalf("%s: %s %s", pass, r.Code, r.Body)
		}
	}
	if e.f.CredentialExists() {
		t.Fatal("a weak password created a credential")
	}
	if r := e.call("app", "credential.create", "", map[string]any{"password": pw, "pin": "000000"}); r.Code != "bad_pin" {
		t.Fatalf("wrong PIN: %s", r.Code)
	}
	if r := e.call("app", "credential.create", "", map[string]any{"password": pw, "pin": testPIN}); !r.OK() || e.h.Arms != 1 {
		t.Fatalf("create: %s, armings %d", r.Code, e.h.Arms)
	}
}

func TestPINChangeAndRenew(t *testing.T) {
	e := newEnv(t)
	blob := e.create()
	// A refused change (busy, counter_unavailable, retry) changes nothing
	// of the credential: the same blob still works.
	for _, code := range []string{"busy", "counter_unavailable", "retry"} {
		e.h.ChangeErr = vault.NewError(code, "")
		r := e.call("app", TypePINChange, blob, map[string]any{"pin": testPIN, "new_pin": "246802", "password": pw, "new_unlock_secret": nextSecret})
		if r.Code != code {
			t.Fatalf("%s: %s", code, r.Code)
		}
	}
	e.h.ChangeErr = nil
	for name, p := range map[string]map[string]any{
		"short new pin":  {"pin": testPIN, "new_pin": "123", "password": pw, "new_unlock_secret": nextSecret},
		"short secret":   {"pin": testPIN, "new_pin": "246802", "password": pw, "new_unlock_secret": "AAAA"},
		"missing secret": {"pin": testPIN, "new_pin": "246802", "password": pw},
	} {
		if r := e.call("app", TypePINChange, blob, p); r.Code != "bad_request" {
			t.Fatalf("%s: %s", name, r.Code)
		}
	}
	if r := e.call("app", TypePINChange, blob, map[string]any{"pin": "000000", "new_pin": "246802", "password": pw, "new_unlock_secret": nextSecret}); r.Code != "bad_pin" || len(e.h.CheckFailed) != 1 {
		t.Fatalf("wrong PIN: %s, failed checks %v", r.Code, e.h.CheckFailed)
	}
	r := e.ok(e.call("app", TypePINChange, blob, map[string]any{"pin": testPIN, "new_pin": "246802", "password": pw, "new_unlock_secret": nextSecret}))
	if !strings.Contains(string(r.Body), `"epoch_advanced":true`) || len(e.h.Changes) != 1 {
		t.Fatalf("%s %+v", r.Body, e.h.Changes)
	}
	c := e.h.Changes[0]
	if c.Reason != vault.ReplacePIN || c.NewPIN != "246802" || len(c.NewUnlockSecret) != 32 || string(c.Password) != pw {
		t.Fatalf("%+v", c)
	}
	blob = blobOf(t, r)
	r = e.ok(e.call("app", TypeSecretRenew, blob, map[string]any{"pin": testPIN, "password": pw, "new_unlock_secret": nextSecret}))
	if len(e.h.Changes) != 2 || e.h.Changes[1].Reason != vault.ReplaceRenew || strings.Contains(string(r.Body), "epoch_advanced") {
		t.Fatalf("renew %+v %s", e.h.Changes, r.Body)
	}
}

func TestPasswordChangeReleaseR(t *testing.T) {
	e := newEnv(t)
	blob := e.create()
	if r := e.call("app", "credential.password.change", blob, map[string]any{"pin": testPIN, "password": pw, "new_password": "password1234"}); r.Code != "weak_password" {
		t.Fatalf("weak: %s", r.Code)
	}
	if r := e.call("app", "credential.password.change", blob, map[string]any{"pin": "000000", "password": pw, "new_password": "glacier mango tuesday piano"}); r.Code != "bad_pin" {
		t.Fatalf("pin: %s", r.Code)
	}
	e.h.ChangeErr = vault.NewError("counter_unavailable", "")
	if r := e.call("app", "credential.password.change", blob, map[string]any{"pin": testPIN, "password": pw, "new_password": "glacier mango tuesday piano"}); r.Code != "counter_unavailable" {
		t.Fatalf("counter: %s", r.Code)
	}
	e.h.ChangeErr = nil
	r := e.ok(e.call("app", "credential.password.change", blob, map[string]any{"pin": testPIN, "password": pw, "new_password": "glacier mango tuesday piano"}))
	if len(e.h.Changes) != 1 || e.h.Changes[0].Reason != vault.ReplacePassword {
		t.Fatalf("%+v", e.h.Changes)
	}
	blob = blobOf(t, r)
	if r := e.call("app", "credential.unlock", blob, map[string]any{"password": "glacier mango tuesday piano"}); !r.OK() {
		t.Fatal(r.Code)
	}
}

// NFC (§11.14.7): a password typed in another Unicode form is the same.
func TestPasswordNFC(t *testing.T) {
	e := newEnv(t)
	composed := "caf\u00e9-Kestrel-91-moss"
	decomposed := "cafe\u0301-Kestrel-91-moss"
	r := e.ok(e.call("app", "credential.create", "", map[string]any{"password": composed}))
	if r := e.call("app", "credential.unlock", blobOf(t, r), map[string]any{"password": decomposed}); !r.OK() {
		t.Fatalf("decomposed form refused: %s", r.Code)
	}
}

// VAULT-MESSAGING 0.44.0 §11.14.9 "A lost answer": credential.password.change
// checks the blob before any secret, in verifyPair's order (blob, PIN,
// password). After an applied change whose answer was lost, a new request
// with the old blob is stale_credential however wrong its PIN and
// password: neither is tested and nothing is counted. With the current
// blob the PIN comes before the password.
func TestPasswordChangeChecksBlobFirst(t *testing.T) {
	e := newEnv(t)
	blob0 := e.create()
	const newPW = "glacier mango tuesday piano"
	e.ok(e.call("app", "credential.password.change", blob0, map[string]any{"pin": testPIN, "password": pw, "new_password": newPW}))
	tries, failed := e.h.PINTries, len(e.h.CheckFailed)
	for name, p := range map[string]map[string]any{
		"typed secrets":             {"pin": testPIN, "password": pw, "new_password": newPW},
		"wrong PIN":                 {"pin": "000000", "password": pw, "new_password": newPW},
		"wrong PIN, wrong password": {"pin": "000000", "password": "wrong password entirely", "new_password": newPW},
	} {
		if r := e.call("app", "credential.password.change", blob0, p); r.Code != "stale_credential" {
			t.Fatalf("old blob, %s: %s", name, r.Code)
		}
	}
	if e.h.PINTries != tries || len(e.h.CheckFailed) != failed {
		t.Fatalf("the old blob's requests tested the PIN: %d tries (was %d), failed checks %v", e.h.PINTries, tries, e.h.CheckFailed)
	}
	for _, a := range e.h.Activities {
		if a.Kind == "credential.password_failed" {
			t.Fatal("the old blob's requests tested the password")
		}
	}
}

// With the current blob: the PIN before the password, so a wrong PIN with
// a wrong password is bad_pin and the password is not tried.
func TestPasswordChangePINBeforePassword(t *testing.T) {
	e := newEnv(t)
	blob := e.create()
	e.h.Reset()
	if r := e.call("app", "credential.password.change", blob, map[string]any{"pin": "000000", "password": "wrong password entirely", "new_password": "glacier mango tuesday piano"}); r.Code != "bad_pin" {
		t.Fatalf("wrong PIN and password: %s", r.Code)
	}
	for _, a := range e.h.Activities {
		if a.Kind == "credential.password_failed" {
			t.Fatal("the password was tried after a wrong PIN")
		}
	}
	if r := e.call("app", "credential.password.change", blob, map[string]any{"pin": testPIN, "password": "wrong password entirely", "new_password": "glacier mango tuesday piano"}); r.Code != "bad_password" {
		t.Fatalf("wrong password: %s", r.Code)
	}
}
