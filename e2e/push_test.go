//go:build devenclave && e2e

package e2e

import (
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/internal/pushtest"
	"github.com/vettid/vettid-vault/vms/pushwire"
)

// VAULT-MESSAGING 0.24.0 §14 through the host stack: a vault process
// registers with the push gateway stand-in through the supervisor (which
// attaches the dev enclave's TEST attestation), the registration survives
// a lock, and a host lock wakes the app through the enclave's egress.
func TestHostPush(t *testing.T) {
	hs := newHostStack(t)
	gw := pushtest.New(pushtest.Config{Roots: enclavetest.TestNitroCA().Roots(), PCR0s: []string{enclavetest.Spec(3, "").PCR0Hex()}})
	hs.resolve["push.vettid.test"] = tlsFront(t, gw, true, "push.vettid.test")
	hs.pushURL = "https://push.vettid.test"
	a := hs.start("i-p", 3, 0)
	m := hs.newApp("member-push", 0x71)
	m.enroll(a, "77777777777777777777777777777777")

	ps, err := m.dev.PushRegister(ctxT(t, 30*time.Second), pushwire.Registration{Platform: "fcm", Token: "e2e-token", AppID: "com.vettid.app"})
	if err != nil || ps.State != "active" || ps.Platform != "fcm" {
		t.Fatalf("push.register: %+v %v", ps, err)
	}
	if gw.Registrations() != 1 {
		t.Fatalf("stand-in registrations %d, refusals %v", gw.Registrations(), gw.Refusals())
	}
	// A host lock: vault.locking, then the wake, before the vault zeroizes.
	m.lock(a)
	if !gw.Wait(30*time.Second, func(s *pushtest.Server) bool { return len(s.Wakes()) == 1 }) {
		t.Fatalf("no wake; refusals %v", gw.Refusals())
	}
	if w := gw.Wakes()[0]; w.Platform != "fcm" || w.AppID != "com.vettid.app" {
		t.Fatalf("wake %+v", w)
	}
	// The registration is DEK state: it is back after the unlock.
	if u, _ := m.unlock(a); !u.OK {
		t.Fatalf("unlock: %+v", u)
	}
	waitUntil(t, "vault running", m.status)
	st, err := m.dev.PushStatus(ctxT(t, 30*time.Second))
	if err != nil || st == nil || st.AppID != "com.vettid.app" {
		t.Fatalf("push status: %+v %v", st, err)
	}
	if err := m.dev.PushUnregister(ctxT(t, 30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if st, err := m.dev.PushStatus(ctxT(t, 30*time.Second)); err != nil || st != nil {
		t.Fatalf("after unregister: %+v %v", st, err)
	}
}
