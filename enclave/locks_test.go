package enclave_test

import (
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/enclave"
)

// VAULT-MESSAGING 0.29.0 §11.5 "The lock operation" (release L): an
// unconditional lock is carried out only if it was queued after the
// message that opened the vault (an equal or earlier time is stale); a
// bound one only for the current unlock_id; the answer comes after the
// lock with locked, not_running or stale.
func TestLockOperation(t *testing.T) {
	f := newFx(t)
	in := f.w.Instance(3)
	a := f.newApp("user-lock", android(0x62))
	if r := f.enroll(a, pin); !r.OK {
		t.Fatal(r.Code)
	}
	opened := f.w.LastEnqueuedAt()
	running := func() bool { return in.Manager(a.vid) != nil }
	code := func(r *enclave.Response) string {
		t.Helper()
		if r == nil || r.Status != enclave.StatusDone || r.Envelope != nil {
			t.Fatalf("lock answer %+v", r)
		}
		return r.Code
	}

	// Unconditional: queued before, or in the same millisecond as, the
	// enrollment that opened the vault: stale, nothing done.
	for _, at := range []time.Time{opened.Add(-time.Second), opened.Add(-time.Millisecond), opened} {
		if c := code(f.w.LockWith(f.ctx, in, a.vid, a.guid, "", at)); c != enclave.CodeStale || !running() {
			t.Fatalf("lock queued at %v (opened %v): %q, running %v", at.Sub(opened), opened, c, running())
		}
	}
	// Bound to another unlock: stale.
	if c := code(f.w.LockWith(f.ctx, in, a.vid, a.guid, "0123456789abcdef0123456789abcdef", f.w.EnqueuedAt())); c != enclave.CodeStale || !running() {
		t.Fatalf("bound to another unlock: %q", c)
	}
	// Queued after: locked, and the answer comes after the lock: when it
	// returns, the vault's Manager is locked (zeroized) already.
	m := in.Manager(a.vid)
	if c := code(f.w.LockWith(f.ctx, in, a.vid, a.guid, "", opened.Add(time.Millisecond))); c != enclave.CodeLocked || running() || !m.Locked() {
		t.Fatalf("lock queued after the opening: %q, running %v, manager locked %v", c, running(), m.Locked())
	}
	// Nothing runs: not_running, bound or not.
	if c := code(f.w.LockWith(f.ctx, in, a.vid, a.guid, "", f.w.EnqueuedAt())); c != enclave.CodeNotRunning {
		t.Fatalf("no vault: %q", c)
	}

	// Bound to the current unlock: locked.
	u := f.mustUnlock(a, pin, client.UnlockOptions{}, "")
	if !u.OK || u.UnlockID == "" {
		t.Fatalf("unlock %+v", u)
	}
	unlockedAt := f.w.LastEnqueuedAt()
	// A late unconditional lock, queued before this unlock (the queue is
	// not ordered): stale.
	if c := code(f.w.LockWith(f.ctx, in, a.vid, a.guid, "", unlockedAt.Add(-time.Millisecond))); c != enclave.CodeStale || !running() {
		t.Fatalf("a lock queued before the unlock: %q", c)
	}
	m = in.Manager(a.vid)
	if c := code(f.w.LockWith(f.ctx, in, a.vid, a.guid, u.UnlockID, f.w.EnqueuedAt())); c != enclave.CodeLocked || running() || !m.Locked() {
		t.Fatalf("bound to the current unlock: %q, running %v, manager locked %v", c, running(), m.Locked())
	}
	if c := code(f.w.LockWith(f.ctx, in, a.vid, a.guid, u.UnlockID, f.w.EnqueuedAt())); c != enclave.CodeNotRunning {
		t.Fatalf("bound, nothing running: %q", c)
	}
	// A bound lock is not ordered by time: one queued before a later
	// unlock still names its own unlock and is stale after it.
	u2 := f.mustUnlock(a, pin, client.UnlockOptions{}, "")
	if c := code(f.w.LockWith(f.ctx, in, a.vid, a.guid, u.UnlockID, f.w.EnqueuedAt())); c != enclave.CodeStale || !running() {
		t.Fatalf("bound to the previous unlock: %q", c)
	}
	if c := code(f.w.LockWith(f.ctx, in, a.vid, a.guid, u2.UnlockID, unlockedAt)); c != enclave.CodeLocked {
		t.Fatalf("bound to the current unlock, queued earlier: %q", c)
	}

	// An opening of unknown time (no enqueued_at): an unconditional lock
	// locks, whatever its own time (locking only reduces exposure).
	f.w.ZeroEnqueuedAt = true
	f.mustUnlock(a, pin, client.UnlockOptions{}, "")
	f.w.ZeroEnqueuedAt = false
	if c := code(f.w.LockWith(f.ctx, in, a.vid, a.guid, "", time.Time{}.Add(time.Millisecond))); c != enclave.CodeLocked || running() {
		t.Fatalf("opening of unknown time: %q, running %v", c, running())
	}
}

// The queue message's unlock_id: lock only, 32 lowercase hex; enqueued_at
// is written with milliseconds, so two times of the same second differ.
func TestQueueMessageUnlockID(t *testing.T) {
	at := time.Date(2026, 10, 23, 12, 0, 0, 123_000_000, time.UTC)
	q := &enclave.QueueMessage{Op: enclave.OpLock, VaultID: "v", UserGUID: "u", RequestID: "01JB2Z6V9K3M4N5P6Q7R8S9T21",
		EnqueuedAt: at, UnlockID: "0123456789abcdef0123456789abcdef"}
	p, err := enclave.ParseQueueMessage(q.Marshal())
	if err != nil || p.UnlockID != q.UnlockID || !p.EnqueuedAt.Equal(at) {
		t.Fatalf("%v %+v", err, p)
	}
	for _, bad := range []string{
		`{"v":1,"op":"lock","vault_id":"v","user_guid":"u","request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T21","unlock_id":"0123","enqueued_at":"2026-10-23T12:00:00.123Z"}`,
		`{"v":1,"op":"lock","vault_id":"v","user_guid":"u","request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T21","unlock_id":"0123456789ABCDEF0123456789ABCDEF","enqueued_at":"2026-10-23T12:00:00.123Z"}`,
		`{"v":1,"op":"delete","vault_id":"v","user_guid":"u","request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T21","unlock_id":"0123456789abcdef0123456789abcdef","enqueued_at":"2026-10-23T12:00:00.123Z"}`,
	} {
		if _, err := enclave.ParseQueueMessage([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	// The member API's form parses (an older enclave ignores unlock_id).
	api := `{"v":1,"op":"lock","vault_id":"v","user_guid":"u","request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T21","unlock_id":"0123456789abcdef0123456789abcdef","enqueued_at":"2026-10-23T12:00:00.123Z"}`
	if p, err := enclave.ParseQueueMessage([]byte(api)); err != nil || !p.EnqueuedAt.Equal(at) {
		t.Fatalf("API form: %v", err)
	}
}
