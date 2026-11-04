package vault

import (
	"bytes"
	"context"
	"testing"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// Nothing leaves the vault before the write that commits it (§11.14.2
// "order of writes", §8.3): a batch whose state write failed keeps its
// in-memory state, but no drain sends its outbox entries until a later
// write stores them. A lock or crash before that loses them with it.

// failWrites makes the next n state writes of d's vault fail.
func failWrites(d *devFixture, n int) *faultStore {
	fs := &faultStore{Store: d.store, failState: n}
	d.m.mu.Lock()
	d.m.opt.Store = fs
	d.m.mu.Unlock()
	return fs
}

func typesOf(ins []*envelope.Inner) []string {
	out := []string{}
	for _, in := range ins {
		out = append(out, in.Type)
	}
	return out
}

// A batch's write fails, then the vault is locked: nothing of the batch
// (its response) is delivered, no vault.locking is sent for the devices in
// memory, and the vault opens again at the stored state.
func TestFailedWriteThenLockSendsNothing(t *testing.T) {
	d := newDevFixture(t)
	d.m.mu.Lock()
	if err := d.m.persist(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	seq := d.m.st.StateSeq
	d.m.mu.Unlock()
	_ = d.responses(t)
	failWrites(d, 1<<20)
	if err := d.send("vault.status", []byte(`{}`)); err == nil {
		t.Fatal("the batch's write did not fail")
	}
	if got := d.responses(t); len(got) != 0 {
		t.Fatalf("sent after the failed write: %v", typesOf(got))
	}
	var locked []LifecycleEvent
	d.m.mu.Lock()
	d.m.opt.Lifecycle = func(ev LifecycleEvent) { locked = append(locked, ev) }
	d.m.mu.Unlock()
	if err := d.m.Lock(context.Background()); err == nil {
		t.Fatal("the lock's write did not fail")
	}
	if got := d.responses(t); len(got) != 0 {
		t.Fatalf("sent by the lock: %v", typesOf(got))
	}
	if len(locked) != 1 || locked[0].Event != "locked" {
		t.Fatalf("lifecycle %+v", locked)
	}
	d.m.opt.Store = d.store
	m, res, err := Unlock(context.Background(), UnlockParams{Options: d.opts, VaultID: d.vid, PIN: testPIN, UnlockSecret: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Crash()
	if res.StateSeq != seq { // a PIN-only unlock writes no state
		t.Fatalf("state_seq %d, stored %d", res.StateSeq, seq)
	}
}

// The base branch's case, generalized: the relay settles the old phone's
// notice, the rotation it owes is made in memory and its write fails. No
// later drain and no lock sends identity.rotate; the stored state owes the
// rotation still, and the next start makes it and sends it.
func TestSettledRotationFailedWriteThenDrainAndLock(t *testing.T) {
	w := newTRWorld(t)
	w.reopen()
	w.fs.mu.Lock()
	w.fs.failState = 1 << 20
	w.fs.mu.Unlock()
	w.m.mu.Lock()
	w.m.drainOutbox(context.Background())
	rot := len(w.m.st.Rotations)
	w.m.drainOutbox(context.Background())
	w.m.mu.Unlock()
	if got := w.connTypes(); !eq(got, "statement", "unlinked") || rot != 1 {
		t.Fatalf("deposits %v, %d rotations in memory", got, rot)
	}
	if err := w.m.Lock(context.Background()); err == nil {
		t.Fatal("the lock's write did not fail")
	}
	if got := w.connTypes(); len(got) != 0 {
		t.Fatalf("the lock sent %v", got)
	}
	w.fs.mu.Lock()
	w.fs.failState = 0
	w.fs.mu.Unlock()
	w.reopen()
	w.m.mu.Lock()
	o, rot := w.m.st.RotationOwed, len(w.m.st.Rotations)
	w.m.mu.Unlock()
	if o == nil || rot != 0 {
		t.Fatalf("stored: owed %+v, %d rotations", o, rot)
	}
	w.start()
	if got := w.connTypes(); !eq(got, "statement", "unlinked", "identity.rotate") || w.rotations() != 1 {
		t.Fatalf("after the start: %v, %d rotations", got, w.rotations())
	}
}

// A failed write, then a later write that succeeds: the failed batch's
// in-memory state is stored by the later write and only then sent (an
// honest replay: what goes out is what is stored), once.
func TestFailedWriteThenLaterWriteSendsStored(t *testing.T) {
	d := newDevFixture(t)
	_ = d.responses(t)
	failWrites(d, 1)
	if err := d.send("vault.status", []byte(`{}`)); err == nil {
		t.Fatal("the batch's write did not fail")
	}
	d.m.mu.Lock()
	d.m.drainOutbox(context.Background()) // any drain in between (the attachment runner's)
	d.m.mu.Unlock()
	if got := d.responses(t); len(got) != 0 {
		t.Fatalf("sent before a write stored it: %v", typesOf(got))
	}
	if err := d.send("device.list", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	got := typesOf(d.responses(t))
	if len(got) != 2 || got[0] != "vault.status" || got[1] != "device.list" {
		t.Fatalf("after the later write: %v", got)
	}
	d.m.mu.Lock()
	_ = d.m.flushThenDrain(context.Background())
	d.m.mu.Unlock()
	if got := d.responses(t); len(got) != 0 {
		t.Fatalf("sent again: %v", typesOf(got))
	}
}

// A drain that does not write first (SendRaw, the attachment runner)
// sends nothing a failed write left unstored.
func TestFailedWriteSendRawSendsNothing(t *testing.T) {
	d := newDevFixture(t)
	c := d.asConnection(t, "c1", 0x71)
	_ = d.inbox(c)
	failWrites(d, 1<<20)
	if _, err := d.m.SendRaw(context.Background(), "c1", "test.raw", []byte(`{}`)); err == nil {
		t.Fatal("the write did not fail")
	}
	d.m.mu.Lock()
	d.m.attFlushThenDrain(context.Background())
	d.m.mu.Unlock()
	if got := d.inbox(c)["c1"]; len(got) != 0 {
		t.Fatalf("sent: %v", typesOf(got))
	}
}

// A lock whose write fails reports the app key the stored header names,
// not one a batch whose write failed adopted in memory (§11.5).
func TestFailedLockReportsStoredAppKey(t *testing.T) {
	d := newDevFixture(t)
	k1, k2 := testAppKeyDER(t, 1), testAppKeyDER(t, 2)
	d.m.mu.Lock()
	d.m.setAppKey(k1)
	if err := d.m.persist(context.Background(), false); err != nil {
		d.m.mu.Unlock()
		t.Fatal(err)
	}
	d.m.setAppKey(k2) // a transfer's step 2, in memory
	d.m.mu.Unlock()
	failWrites(d, 1<<20)
	var evs []LifecycleEvent
	d.m.mu.Lock()
	d.m.opt.Lifecycle = func(ev LifecycleEvent) { evs = append(evs, ev) }
	d.m.mu.Unlock()
	if err := d.m.Lock(context.Background()); err == nil {
		t.Fatal("the lock's write did not fail")
	}
	if len(evs) != 1 || evs[0].Event != "locked" || !bytes.Equal(evs[0].AppKey, k1) || evs[0].AppKeySeq != 1 {
		t.Fatalf("locked %+v", evs)
	}
}

// A host deletion whose marking state write fails (§12.5): the header's
// mark and the host's commit the deletion, and its notices go out at step
// 2; what an earlier write that failed left unstored does not.
func TestFailedWriteThenDeleteSendsOnlyTheDeletion(t *testing.T) {
	d := newDevFixture(t)
	_ = d.responses(t)
	failWrites(d, 1<<20)
	if err := d.send("vault.status", []byte(`{}`)); err == nil {
		t.Fatal("the batch's write did not fail")
	}
	if err := d.m.Delete(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := d.responses(t)
	if len(got) != 1 || got[0].Type != "device.unlinked" {
		t.Fatalf("sent at the deletion: %v", typesOf(got))
	}
}
