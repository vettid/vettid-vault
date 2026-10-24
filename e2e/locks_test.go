//go:build devenclave && e2e

package e2e

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/altchan"
)

// VAULT-MESSAGING 0.29.0 §10.2 "Locks" (release L) with the real relay:
// the enroll and unlock results name the opening; vault.status repeats it;
// a relay lock that names an earlier unlock is refused (stale_lock) and the
// vault stays open; a bound lock locks and vault.locking names the unlock;
// a desktop locks with the value from vault.status.
func TestBoundLocks(t *testing.T) {
	aw := newACWorld(t)
	a := aw.newApp("member-locks", enclavetest.NewAndroidAttester(0x84, enclavetest.AndroidOptions{}))
	er := aw.enroll(a, acPIN)
	if !er.OK || !altchan.ValidUnlockID(er.UnlockID) || a.dev.UnlockID() != er.UnlockID {
		t.Fatalf("enroll result unlock_id %q (device %q)", er.UnlockID, a.dev.UnlockID())
	}
	ctx := ctxT(t, 120*time.Second)
	if got := statusUnlockID(t, ctx, a.dev); got != er.UnlockID {
		t.Fatalf("status unlock_id %q, want %q", got, er.UnlockID)
	}
	first := er.UnlockID

	// A new unlock has a new name.
	aw.lock(a)
	u := aw.mustUnlock(a, acPIN, client.UnlockOptions{}, "")
	if !u.OK || !altchan.ValidUnlockID(u.UnlockID) || u.UnlockID == first || a.dev.UnlockID() != u.UnlockID {
		t.Fatalf("unlock result unlock_id %q (first %q)", u.UnlockID, first)
	}
	// The lock of the first unlock arrives after the second: refused, and
	// nothing is locked.
	body, _ := json.Marshal(map[string]string{"unlock_id": first})
	if _, err := a.dev.Op(ctx, "vault.lock", json.RawMessage(body)); client.Code(err) != "stale_lock" {
		t.Fatalf("late lock: %v", err)
	}
	if got := statusUnlockID(t, ctx, a.dev); got != u.UnlockID {
		t.Fatalf("after the late lock: status unlock_id %q, want %q (still open)", got, u.UnlockID)
	}

	// A desktop locks with the value from vault.status; vault.locking
	// names the unlock it ends.
	desk := acPairDesktop(t, aw, a)
	if err := desk.LockVault(ctx); err != nil {
		t.Fatalf("desktop lock: %v", err)
	}
	waitEvent(t, a.dev, "vault.locking", has("unlock_id", u.UnlockID))

	// The app's own bound lock.
	u2 := aw.mustUnlock(a, acPIN, client.UnlockOptions{}, "")
	if !u2.OK || u2.UnlockID == u.UnlockID {
		t.Fatalf("third unlock %q", u2.UnlockID)
	}
	if err := a.dev.LockVault(ctx); err != nil {
		t.Fatalf("app lock: %v", err)
	}
	waitEvent(t, desk, "vault.locking", has("unlock_id", u2.UnlockID))
}

func statusUnlockID(t *testing.T, ctx context.Context, d *client.Device) string {
	t.Helper()
	o, err := d.Op(ctx, "vault.status", nil)
	if err != nil {
		t.Fatalf("vault.status: %v", err)
	}
	id, _, _ := o.OptString("unlock_id")
	return id
}
