//go:build devenclave && integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/parent"
	"github.com/vettid/vettid-vault/vault/store"
)

// TestCompatMoveOnly is one row of the compatibility matrix
// (VAULT-RELEASES §3.4, §11.3; scripts/compat-matrix.sh): a previous
// release's parent and dev enclave (built from its tag, in
// VAULT_COMPAT_PREV_BIN) run release 3, and everything else is HEAD's:
// vaultctl and the client library, the member API stand-in and its
// queue messages, the relay, and release 4's parent and enclave. The
// move-only contract must hold:
//
//   - C2/C8: enroll, unlock and lock through HEAD's member API and queue
//     messages, answered by the old parent and enclave;
//   - C3: the old parent's rows and the storage layout are what HEAD reads
//     (vault row state, sealed release and lease; vaults/<id>/state);
//   - C1: the old release still unlocks under a manifest that lists it as
//     deprecated, then retired, signed by HEAD's publisher;
//   - the move: the member approves release 4 in an unlock of the old
//     release, which seals to HEAD's key; HEAD's release then unlocks it.
//
// Not covered here: recovery (the member API stand-in has its routes,
// cmd/devstack exercises them) and the host delete (no stand-in route
// yet), device attestation roots (C6, test CA only) and AWS itself (C5).
func TestCompatMoveOnly(t *testing.T) {
	prev := os.Getenv("VAULT_COMPAT_PREV_BIN")
	if prev == "" {
		t.Skip("VAULT_COMPAT_PREV_BIN not set (scripts/compat-matrix.sh)")
	}
	for _, f := range []string{"vault-parent", "vault-enclave"} {
		if _, err := os.Stat(filepath.Join(prev, f)); err != nil {
			t.Fatalf("previous release binaries: %v", err)
		}
	}
	s := newStack(t)
	s.prevDir, s.prevRelease = prev, 3
	t.Logf("release 3: %s (%s); release 4: HEAD", prev, os.Getenv("VAULT_COMPAT_PREV_NAME"))
	a := s.start("old", 3)

	m := filepath.Join(s.dir, "member.json")
	api := []string{"-api", s.api.URL, "-guid", "member-compat", "-pin", pin1}
	s.mustVaultctl(m, "init", "-role", "app", "-name", "phone", "-relay", relayURL)
	out := s.mustVaultctl(m, append([]string{"api-enroll"}, api...)...)
	vid := vaultIDRE.FindString(out)
	if vid == "" {
		t.Fatalf("enroll into the old release: %s", out)
	}
	pcr3 := enclavetest.Spec(3, "").PCR0Hex()
	if r := s.vaultRow(vid); r.State != "unlocked" || r.LeaseInstance != a.id || r.SealedRelease != pcr3 {
		t.Fatalf("vault row written by the old parent: %+v", r)
	}
	s.getObject(store.StateKey(vid)) // the storage layout HEAD reads
	status := func(what string) {
		t.Helper()
		if out := s.mustVaultctl(m, "request", "vault.status", "{}"); !strings.Contains(out, `"status": "ok"`) {
			t.Fatalf("vault.status %s: %s", what, out)
		}
	}
	status("in the old release")

	lock := func(in *instance) {
		t.Helper()
		if out := s.mustVaultctl(m, append([]string{"api-lock"}, api[:4]...)...); !strings.Contains(out, `"status": "done"`) {
			t.Fatalf("lock: %s", out)
		}
		in.waitHealth(func(h parent.Health) bool { return h.Vaults == 0 }, "with the vault locked")
		if r := s.vaultRow(vid); r.State != "locked" || r.LeaseInstance != "" {
			t.Fatalf("vault row after lock: %+v", r)
		}
	}
	unlock := func(extra ...string) map[string]any {
		t.Helper()
		out, err := s.vaultctl(m, append(append([]string{"api-unlock"}, api...), extra...)...)
		if err != nil {
			t.Fatalf("unlock %v: %s", extra, out)
		}
		return firstValue(t, out)
	}

	// A newer release is active; the old one is deprecated, then retired:
	// it still unlocks (move-only).
	lock(a)
	s.addRelease(4)
	b := s.start("head", 4)
	for _, st := range []string{"deprecated", "retired"} {
		s.w.SetStatus(3, st)
		if u := unlock(); u["ok"] != true || u["instance_id"] != a.id {
			t.Fatalf("unlock of the %s old release: %v", st, u)
		}
		status("in the " + st + " old release")
		lock(a)
	}

	// The move: approved in an unlock of the old release, sealed to HEAD's
	// release key; HEAD's release unlocks it.
	if u := unlock("-approve", "4"); u["ok"] != true || u["update"] != "moved" || u["instance_id"] != a.id {
		t.Fatalf("approved move out of the old release: %v", u)
	}
	pcr4 := enclavetest.Spec(4, "").PCR0Hex()
	waitFor(t, "sealed_release = release 4", func() bool { r := s.vaultRow(vid); return r.SealedRelease == pcr4 && r.LeaseInstance == "" })
	if u := unlock(); u["ok"] != true || u["release_number"] != float64(4) || u["instance_id"] != b.id {
		t.Fatalf("unlock in HEAD's release after the move: %v", u)
	}
	status("in HEAD's release")
	lock(b)
}
