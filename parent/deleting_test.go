package parent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/parenttest"
	"github.com/vettid/vettid-vault/parent"
)

// VAULT-MESSAGING 0.51.0 §11.5, VAULT-HOST-PROTOCOL 0.1.14 §5.6, §6.1:
// MarkDeleting's conditional write of deleting_at, the unlocked event that
// removes it, and delete_resume routed as delete.

func (e *fakeEnclave) markDeleting(t *testing.T, fields ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := e.conn.Call(ctx, hostproto.KindMarkDeleting, hostproto.Strings(fields...)...)
	if err != nil || len(r) != 1 {
		t.Fatalf("MarkDeleting: %v %q", err, r)
	}
	return string(r[0])
}

func TestMarkDeleting(t *testing.T) {
	h := newHarness(t, nil)
	e := h.connect("boot-1", nil)
	e.descriptor()
	waitFor(t, "ready", func() bool { return h.p.Health().Release == pcr })
	other := time.Now().Add(time.Hour).Unix()
	// Whatever the lease: another instance holds this one.
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked", LeaseInstance: "i-other", LeaseExpires: other})
	before, _ := h.tables.Vault(vaultID)
	if got := e.markDeleting(t, vaultID); got != hostproto.StatusOK {
		t.Fatalf("first: %s", got)
	}
	r, _ := h.tables.Vault(vaultID)
	if r.DeletingAt == 0 || r.DeletingAt > time.Now().Unix() {
		t.Fatalf("deleting_at %d", r.DeletingAt)
	}
	// Nothing else in that update: not the state, the lease or updated_at.
	r.DeletingAt = 0
	if r.State != before.State || r.LeaseInstance != before.LeaseInstance || r.LeaseExpires != before.LeaseExpires || r.UpdatedAt != before.UpdatedAt {
		t.Fatalf("other attributes written: %+v", r)
	}
	// A mark is never moved; a refused condition is ok.
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked", DeletingAt: 1000})
	if got := e.markDeleting(t, vaultID); got != hostproto.StatusOK {
		t.Fatalf("marked already: %s", got)
	}
	if r, _ := h.tables.Vault(vaultID); r.DeletingAt != 1000 {
		t.Fatalf("mark moved to %d", r.DeletingAt)
	}
	// A deleted row and a missing one: ok, nothing written.
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "deleted"})
	if got := e.markDeleting(t, vaultID); got != hostproto.StatusOK {
		t.Fatalf("deleted row: %s", got)
	}
	if r, _ := h.tables.Vault(vaultID); r.DeletingAt != 0 {
		t.Fatal("a deleted row was marked")
	}
	const gone = "fedcba9876543210fedcba9876543210"
	if got := e.markDeleting(t, gone); got != hostproto.StatusOK {
		t.Fatalf("no row: %s", got)
	}
	if _, ok := h.tables.Vault(gone); ok {
		t.Fatal("a row was made")
	}
	// Any other failure of the write is error (the enclave retries).
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked"})
	h.tables.MarkDeletingErr = errors.New("throttled")
	if got := e.markDeleting(t, vaultID); got != hostproto.StatusError {
		t.Fatalf("failed write: %s", got)
	}
	h.tables.MarkDeletingErr = nil
	// Not one well-formed vault_id: invalid.
	for _, f := range [][]string{{}, {"NOT/AN/ID"}, {vaultID, "x"}} {
		if got := e.markDeleting(t, f...); got != hostproto.StatusInvalid {
			t.Fatalf("%q: %s", f, got)
		}
	}
	if r, _ := h.tables.Vault(vaultID); r.DeletingAt != 0 {
		t.Fatal("marked by a refused request")
	}
}

// An unlocked event removes deleting_at in its own update (a vault that
// runs is not being deleted); other events leave it.
func TestUnlockedClearsDeletingAt(t *testing.T) {
	tb := parenttest.NewTables()
	ctx, now := context.Background(), time.Unix(1_800_000_000, 0)
	for _, c := range []struct {
		event string
		keep  bool
	}{{"unlocked", false}, {"locked", true}, {"enrolled", true}, {"moved", true}} {
		tb.PutVault(parenttest.VaultRow{VaultID: "v1", UserGUID: "u1", State: "locked", DeletingAt: 1000})
		if err := tb.Lifecycle(ctx, parent.Lifecycle{Event: c.event, VaultID: "v1"}, "me", now); err != nil {
			t.Fatal(err)
		}
		if r, _ := tb.Vault("v1"); (r.DeletingAt == 1000) != c.keep {
			t.Fatalf("%s: deleting_at %d", c.event, r.DeletingAt)
		}
	}
	// Under the event's lease rule: an unlocked refused is no clearing.
	tb.PutVault(parenttest.VaultRow{VaultID: "v2", UserGUID: "u1", State: "locked", DeletingAt: 1000, LeaseInstance: "other", LeaseExpires: now.Add(time.Hour).Unix()})
	_ = tb.Lifecycle(ctx, parent.Lifecycle{Event: "unlocked", VaultID: "v2"}, "me", now)
	if r, _ := tb.Vault("v2"); r.DeletingAt != 1000 {
		t.Fatal("cleared without the lease")
	}
}

// An unlocked event still queued is written before a MarkDeleting that
// follows it on the connection, so it cannot remove the new mark.
func TestMarkDeletingAfterQueuedUnlocked(t *testing.T) {
	h := newHarness(t, nil)
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked"})
	e := h.connect("boot-1", nil)
	e.descriptor()
	waitFor(t, "ready", func() bool { return h.p.Health().Release == pcr })
	e.lifecycle("unlocked")
	if got := e.markDeleting(t, vaultID); got != hostproto.StatusOK {
		t.Fatal(got)
	}
	time.Sleep(100 * time.Millisecond)
	if r, _ := h.tables.Vault(vaultID); r.DeletingAt == 0 || r.State != "unlocked" {
		t.Fatalf("row %+v", r)
	}
}

// delete_resume is routed as delete: no lease, no code copied into a slot,
// the message deleted on the enclave's answer.
func TestDeleteResumeRouted(t *testing.T) {
	h := newHarness(t, nil)
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked", DeletingAt: 1000})
	env := bytes.Repeat([]byte{7}, 5252)
	e := h.connect("boot-1", func(msg []byte) []byte {
		var m struct {
			RequestID string `json:"request_id"`
			Op        string `json:"op"`
		}
		_ = json.Unmarshal(msg, &m)
		if m.Op != "delete_resume" {
			t.Errorf("op %s", m.Op)
		}
		// Even a code the enclave should not send is not copied.
		return cancelAnswer(m.RequestID, env, "recovery_cancelled", cancelledID)
	})
	e.descriptor()
	waitFor(t, "ready", func() bool { return h.p.Health().Release == pcr })
	const rid = "01JAAAAAAAAAAAAAAAAAAAAAAA"
	h.tables.PutSlot(rid, "i-test")
	h.queues.Send(h.queue, queueMsg("delete_resume", rid))
	waitFor(t, "forwarded", func() bool { e.mu.Lock(); defer e.mu.Unlock(); return len(e.queued) == 1 })
	waitFor(t, "message deleted", func() bool { return h.queues.Pending(h.queue) == 0 })
	if s, _ := h.tables.Slot(rid); s.Code != "" || s.CancelledRecoveryID != "" {
		t.Fatalf("slot %+v", s)
	}
	if r, _ := h.tables.Vault(vaultID); r.LeaseInstance != "" {
		t.Fatalf("a lease was taken: %+v", r)
	}
}
