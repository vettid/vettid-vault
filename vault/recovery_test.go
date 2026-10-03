package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vault/store"
)

const recID = "01JB2Z6V9K3M4N5P6Q7R8S9T0V"

type recFixture struct {
	*fixture
	now time.Time
}

func newRecFixture(t *testing.T) *recFixture {
	f := newFixture(t)
	if err := f.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &recFixture{fixture: f, now: time.Now()}
}

func (r *recFixture) params() HeaderParams {
	o := r.opts
	o.Now = func() time.Time { return r.now }
	return HeaderParams{Options: o, VaultID: r.vid, UserGUID: "u1"}
}

func (r *recFixture) header(t *testing.T) (*Header, []byte) {
	t.Helper()
	blob, _, err := r.store.Get(context.Background(), store.HeaderKey(r.vid, testRelease.PCR0))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := r.opts.Sealer.Unseal(context.Background(), blob, headerAAD(r.vid))
	if err != nil {
		t.Fatal(err)
	}
	var h Header
	if err := json.Unmarshal(pt, &h); err != nil {
		t.Fatal(err)
	}
	return &h, pt
}

var testApp = RecoveryApp{IK: bytes.Repeat([]byte{9}, 32), KEM: bytes.Repeat([]byte{8}, 1216), RelayPK: bytes.Repeat([]byte{7}, 32)}

func ok() (json.RawMessage, error) { return json.RawMessage(`{"platform":"android"}`), nil }

func TestRecoveryHeaderOps(t *testing.T) {
	r := newRecFixture(t)
	ctx := context.Background()
	if _, _, err := RecoveryRequest(ctx, HeaderParams{Options: r.opts, VaultID: r.vid, UserGUID: "someone else"}, recID, RecoveryDelay); !errors.Is(err, ErrHeader) {
		t.Fatalf("another member's request: %v", err)
	}
	code, rec, err := RecoveryRequest(ctx, r.params(), recID, RecoveryDelay)
	if err != nil || !ValidRecoveryCode(code) || !rec.NotBefore.Equal(r.now.Add(RecoveryDelay)) {
		t.Fatalf("request: %v %q", err, code)
	}
	h, raw := r.header(t)
	if h.Recovery == nil || bytes.Contains(raw, []byte(code)) {
		t.Fatal("record missing, or the code itself is in the header")
	}
	if err := RecoveryRegister(ctx, r.params(), recID, code, testApp, ok); !errors.Is(err, ErrRecoveryEarly) {
		t.Fatalf("early: %v", err)
	}
	r.now = r.now.Add(RecoveryDelay + time.Minute)
	if err := RecoveryRegister(ctx, r.params(), "01JB2Z6V9K3M4N5P6Q7R8S9T0W", code, testApp, ok); !errors.Is(err, ErrRecoveryNone) {
		t.Fatalf("other recovery id: %v", err)
	}
	// Attestation is checked only after the code matched; a failure keeps
	// the code usable.
	if err := RecoveryRegister(ctx, r.params(), recID, code, testApp, func() (json.RawMessage, error) { return nil, ErrDeviceAttestation }); !errors.Is(err, ErrDeviceAttestation) {
		t.Fatalf("attestation: %v", err)
	}
	if err := RecoveryRegister(ctx, r.params(), recID, code, testApp, ok); err != nil {
		t.Fatal(err)
	}
	h, _ = r.header(t)
	if findUnlockKey(h, testApp.IK) == nil || h.Recovery.State != RecoveryRegistered || h.Recovery.CodeHash != nil {
		t.Fatal("not registered")
	}
	if err := RecoveryRegister(ctx, r.params(), recID, code, testApp, ok); !errors.Is(err, ErrRecoveryUsed) {
		t.Fatalf("reuse: %v", err)
	}
	// An unlock (owner device or the recovered app) keeps the registered key.
	m, _, err := r.unlock(testPIN, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	if h, _ = r.header(t); findUnlockKey(h, testApp.IK) == nil {
		t.Fatal("registered key dropped by a flush")
	}
	if err := RecoveryCancel(ctx, r.params(), ""); err != nil {
		t.Fatal(err)
	}
	h, _ = r.header(t)
	if h.Recovery != nil || findUnlockKey(h, testApp.IK) != nil {
		t.Fatal("cancel left the record or the key")
	}
	kinds := ""
	for _, e := range h.RecoveryLog {
		kinds += e.Kind + " "
	}
	if !strings.Contains(kinds, "recovery.cancelled") { // earlier steps moved to the audit log at the unlock
		t.Fatalf("log: %s", kinds)
	}
}

func TestRecoveryCodeAttempts(t *testing.T) {
	r := newRecFixture(t)
	ctx := context.Background()
	code, _, _ := RecoveryRequest(ctx, r.params(), recID, RecoveryDelay)
	r.now = r.now.Add(RecoveryDelay)
	wrong := strings.Repeat("0", 32)
	for i := 0; i < RecoveryMaxAttempts; i++ {
		if err := RecoveryRegister(ctx, r.params(), recID, wrong, testApp, ok); !errors.Is(err, ErrRecoveryCode) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if err := RecoveryRegister(ctx, r.params(), recID, code, testApp, ok); !errors.Is(err, ErrRecoveryNone) {
		t.Fatalf("voided recovery accepted the code: %v", err)
	}
}

func TestRecoveryExpiryAndReplace(t *testing.T) {
	r := newRecFixture(t)
	ctx := context.Background()
	old, _, _ := RecoveryRequest(ctx, r.params(), recID, RecoveryDelay)
	code, _, _ := RecoveryRequest(ctx, r.params(), "01JB2Z6V9K3M4N5P6Q7R8S9T0W", RecoveryDelay)
	r.now = r.now.Add(RecoveryDelay)
	if err := RecoveryRegister(ctx, r.params(), recID, old, testApp, ok); !errors.Is(err, ErrRecoveryNone) {
		t.Fatalf("replaced request: %v", err)
	}
	r.now = r.now.Add(RecoveryValidity)
	if err := RecoveryRegister(ctx, r.params(), "01JB2Z6V9K3M4N5P6Q7R8S9T0W", code, testApp, ok); !errors.Is(err, ErrRecoveryExpired) {
		t.Fatalf("expired: %v", err)
	}
	if h, _ := r.header(t); h.Recovery != nil {
		t.Fatal("expired record kept")
	}
}

func TestRecoveryCode(t *testing.T) {
	if ValidRecoveryCode(strings.Repeat("I", 32)) || ValidRecoveryCode(strings.Repeat("0", 31)) || !ValidRecoveryCode(strings.Repeat("0", 32)) {
		t.Fatal("code form")
	}
	a := RecoveryCodeHash("v", recID, "X")
	if bytes.Equal(a, RecoveryCodeHash("w", recID, "X")) || bytes.Equal(a, RecoveryCodeHash("v", recID, "Y")) {
		t.Fatal("hash not bound")
	}
}
