//go:build devenclave && e2e

package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/vault"
)

// VAULT-MESSAGING 0.29.0 §3.6.8 (release L) through the real relay, on a
// stepped owner-check clock: with idle_lock.after_seconds at its minimum
// (1 h) the vault, held past its deadline, locks itself an hour later,
// sends vault.locking{reason: "idle"} and audits vault.locked{idle}; a
// vault unlocked past that time waits one hour from the unlock, and a
// check in that hour moves the idle lock with the deadline.
func TestIdleLock(t *testing.T) {
	r := relaytest.Start(t, nil)
	clk := &ocClock{}
	a := newTestVault(t, r.URL, "a", func(o *vault.Options) { o.OwnerCheckClock = clk.Now })
	ctx := ctxT(t, 300*time.Second)
	ver, _ := mustOK(t, a.request(a.app, "settings.get", `{}`)).Uint("version", 0, 1<<53)
	mustOK(t, a.request(a.app, "settings.set", fmt.Sprintf(`{"version":%d,"set":{"idle_lock.after_seconds":3600}}`, ver)))
	st, err := a.app.OwnerCheckState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deadline := st.Deadline

	// Held, with the time of the idle lock in vault.held.
	clk.add(time.Until(deadline) + 30*time.Minute)
	held := waitEvent(t, a.app, "vault.held", nil)
	if !strings.Contains(string(held.Body), `"idle_lock_at":"`) {
		t.Fatalf("vault.held %s", held.Body)
	}
	if a.manager().Locked() {
		t.Fatal("locked before its time")
	}
	// An hour past the deadline: locked by itself.
	clk.add(31 * time.Minute)
	waitEvent(t, a.app, "vault.locking", has("reason", "idle"))
	for end := time.Now().Add(30 * time.Second); !a.manager().Locked(); {
		if time.Now().After(end) {
			t.Fatal("the vault did not lock")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Unlocked again past the time: one hour from the unlock.
	_ = a.stop()
	m, f, err := a.unlock(ctx, func(o *vault.Options) { o.OwnerCheckClock = clk.Now })
	if err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.msg = f
	a.mu.Unlock()
	a.start(m)
	clk.add(59 * time.Minute)
	if _, err := a.app.OwnerCheckState(ctx); err != nil {
		t.Fatalf("status inside the hour: %v", err)
	}
	if a.manager().Locked() {
		t.Fatal("locked inside the hour after the unlock")
	}
	// History has the idle lock (§10.9: vault.locked with ref idle).
	if r := a.request(a.app, "audit.list", `{"kinds":["vault"]}`); r.ErrorCode() != "owner_check_required" {
		t.Fatalf("audit.list while held: %q", r.ErrorCode()) // read after the check, below
	}
	// The check in that hour moves the deadline, and the idle lock with it.
	if _, err := a.app.OwnerCheck(ctx, pin, credPW, nil, nil); err != nil {
		t.Fatal(err)
	}
	clk.add(2 * time.Minute)
	if st, err := a.app.OwnerCheckState(ctx); err != nil || st.State != vault.OwnerCheckOK {
		t.Fatalf("after the check: %+v %v", st, err)
	}
	if a.manager().Locked() {
		t.Fatal("locked after a check")
	}
	au, err := a.app.AuditList(ctx, map[string]any{"kinds": []string{"vault"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if e := string(au["entries"]); !strings.Contains(e, `"vault.locked"`) || !strings.Contains(e, `"ref":"idle"`) {
		t.Fatalf("History lacks the idle lock: %s", e)
	}
}
