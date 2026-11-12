package vault

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vault/store"
)

// R29-U1 (VAULT-MESSAGING 0.87.1 §6.3.1 "No upgrade: release 29 starts
// clean"): a state without messaging_release 29 or more is not started,
// on every path that opens the state, after §12.5's deleting check and
// before anything is written.

// writeCounter counts the store writes made through it.
type writeCounter struct {
	store.Store
	mu     sync.Mutex
	writes int
}

func (w *writeCounter) Put(ctx context.Context, key string, data []byte, ifMatch store.Version) (store.Version, error) {
	w.mu.Lock()
	w.writes++
	w.mu.Unlock()
	return w.Store.Put(ctx, key, data, ifMatch)
}

func (w *writeCounter) Delete(ctx context.Context, key string, ifMatch store.Version) error {
	w.mu.Lock()
	w.writes++
	w.mu.Unlock()
	return w.Store.Delete(ctx, key, ifMatch)
}

func (w *writeCounter) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writes
}

// u1Locked makes a vault whose stored state records messaging_release
// release (0: absent), locked.
func u1Locked(t *testing.T, release int) *rFixture {
	t.Helper()
	f := newRFixture(t)
	if f.m.st.MessagingRelease != MessagingRelease {
		t.Fatalf("a new vault's marker is %d", f.m.st.MessagingRelease)
	}
	f.m.mu.Lock()
	f.m.st.MessagingRelease = release
	f.m.dirty = true
	f.m.mu.Unlock()
	f.flush()
	if err := f.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestR29U1UnlockRefused(t *testing.T) {
	for _, release := range []int{0, 28} {
		f := u1Locked(t, release)
		wc := &writeCounter{Store: f.opts.Store}
		f.opts.Store = wc
		m, out := f.unlock(testPIN, testSecret)
		if m != nil || out.OK || out.Code != CodeStateUnsupported {
			t.Fatalf("messaging_release %d: %+v", release, out)
		}
		if out.StateSeq == 0 {
			t.Fatalf("messaging_release %d: no state_seq on the refusal (state_unreadable gives it)", release)
		}
		if wc.count() != 0 {
			t.Fatalf("messaging_release %d: %d writes on refusal", release, wc.count())
		}
		for _, ev := range out.Events {
			if ev.Event == "unlocked" {
				t.Fatal("unlocked reported")
			}
		}
		if _, _, err := Unlock(context.Background(), UnlockParams{Options: f.opts, VaultID: f.vid, PIN: testPIN, UnlockSecret: testSecret}); !errors.Is(err, ErrStateUnsupported) {
			t.Fatalf("Unlock: %v", err)
		}
	}
}

func TestR29U1Opens29And30(t *testing.T) {
	for _, release := range []int{29, 30} {
		f := u1Locked(t, release)
		m, out := f.unlock(testPIN, testSecret)
		if m == nil || !out.OK {
			t.Fatalf("messaging_release %d: %+v", release, out)
		}
		if m.st.MessagingRelease != release {
			t.Fatalf("messaging_release %d rewritten as %d", release, m.st.MessagingRelease)
		}
		m.Crash()
	}
}

func TestR29U1RecoveryOpenRefused(t *testing.T) {
	f := newOpenFixtureWith(t, func(f *openFixture) {
		f.m.mu.Lock()
		f.m.st.MessagingRelease = 28
		f.m.dirty = true
		f.m.mu.Unlock()
		f.flush()
	})
	before, _, err := f.st.Get(context.Background(), store.StateKey(f.vid))
	if err != nil {
		t.Fatal(err)
	}
	wc := &writeCounter{Store: f.opts.Store}
	f.opts.Store = wc
	m, out := f.open(testPIN, rPW)
	if m != nil || out.OK || out.Code != CodeStateUnsupported || !out.AttemptUsed() {
		t.Fatalf("recovery open: %+v", out)
	}
	if wc.count() != 0 {
		t.Fatalf("%d store writes on refusal", wc.count())
	}
	after, _, err := f.st.Get(context.Background(), store.StateKey(f.vid))
	if err != nil || string(before) != string(after) {
		t.Fatal("the state was written after it opened")
	}
}

// The recovery's resume path (the stored `next`, no new attempt) opens
// the state through openState too: a state without the marker is refused
// there, with no write. The stored state is replaced, after step 1, by
// the same state (same seq and DEK) recording messaging_release 28.
func TestR29U1RecoveryResumeRefused(t *testing.T) {
	var dek []byte
	f := newOpenFixtureWith(t, func(f *openFixture) {
		f.m.mu.Lock()
		dek = append([]byte(nil), f.m.dek...)
		f.m.mu.Unlock()
	})
	f.st.failState = 1
	if m, out := f.open(testPIN, rPW); m != nil || out.Code != OpenRetry {
		t.Fatalf("setup: failed completion: %+v", out)
	}
	if h := f.storedHeader(); h.Next == nil || h.Next.Reason != ReplaceRecovery {
		t.Fatal("setup: step 1 not stored")
	}
	ctx := context.Background()
	blob, ver, err := f.st.Get(ctx, store.StateKey(f.vid))
	if err != nil {
		t.Fatal(err)
	}
	dv, _ := StateDEKVersion(blob)
	pt, seq, err := decryptState(dek, f.vid, blob)
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(pt, &st); err != nil {
		t.Fatal(err)
	}
	st["messaging_release"] = 28
	pt, _ = json.Marshal(st)
	nb, err := encryptState(dek, dv, f.vid, seq, pt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Store.Put(ctx, store.StateKey(f.vid), nb, ver); err != nil {
		t.Fatal(err)
	}
	wc := &writeCounter{Store: f.opts.Store}
	f.opts.Store = wc
	m, out := f.open(testPIN, rPW)
	if m != nil || out.OK || out.Code != CodeStateUnsupported || out.AttemptUsed() {
		t.Fatalf("resume: %+v (no attempt is spent on the resume path)", out)
	}
	if wc.count() != 0 {
		t.Fatalf("%d store writes on refusal", wc.count())
	}
}

// A state that records deleting completes its deletion (§12.5) first; the
// U1 check is not reached.
func TestR29U1DeletingStateCompletesFirst(t *testing.T) {
	f := newFixture(t)
	vid := f.m.VaultID()
	f.m.mu.Lock()
	f.m.st.MessagingRelease = 0
	f.m.mu.Unlock()
	f.m.opt.Hooks.AfterFlush = func() error { return errors.New("crash") }
	f.m.mu.Lock()
	f.m.beginDelete("app", time.Now())
	f.m.mu.Unlock()
	_ = f.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	if _, _, err := f.unlock(testPIN, 0, 0); !errors.Is(err, ErrDeleted) {
		t.Fatalf("unlock of a deleting state: %v", err)
	}
	for _, k := range []string{store.StateKey(vid), store.HeaderKey(vid, testRelease.PCR0)} {
		if exists(t, f.store, k) {
			t.Fatalf("%s left: the deletion did not complete", k)
		}
	}
}
