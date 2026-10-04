package vault

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/vault/store"
)

func exists(t *testing.T, st store.Store, key string) bool {
	t.Helper()
	_, _, err := st.Get(context.Background(), key)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	return err == nil
}

// §12.5: a deletion marks state and header, deletes the vault's relay
// mailbox (which makes the queued revocations moot), tells the devices
// (and connections), destroys the keys, erases every stored object and
// reports `deleted`. On a relay before 0.5.0 (no delete route) every token
// and peer key is revoked instead.
func TestDeleteRuntime(t *testing.T) {
	for _, relay := range []string{"0.5", "0.4"} {
		t.Run(relay, func(t *testing.T) {
			d := newDevFixture(t)
			c := d.addConnection("c1", 0x80)
			if relay == "0.4" {
				d.relay.deleteErr = &relayclient.Error{Status: 404, Code: "not_found"}
			}
			var events []string
			d.m.opt.Lifecycle = func(ev LifecycleEvent) { events = append(events, ev.Event) }
			vid := d.m.VaultID()
			d.m.mu.Lock()
			d.m.beginDelete("app", time.Now())
			if !d.m.hdr.Deleting || d.m.st.Deleting == nil {
				d.m.mu.Unlock()
				t.Fatal("not marked")
			}
			d.m.mu.Unlock()
			if err := d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
				t.Fatal(err)
			}
			if !d.m.Locked() {
				t.Fatal("still running")
			}
			if relay == "0.5" {
				if d.relay.mailboxDeleted != 1 || len(d.relay.revoked) != 0 {
					t.Fatalf("mailbox deleted %d times, revoked %v", d.relay.mailboxDeleted, d.relay.revoked)
				}
			} else {
				for _, want := range []string{"jti:j1", "sub:" + relayauth.EncodeKey(c.Relay.PK), "sub:" + relayauth.EncodeKey(d.devPeer.Relay.PK)} {
					if !containsStr(d.relay.revoked, want) {
						t.Errorf("not revoked: %s (%v)", want, d.relay.revoked)
					}
				}
			}
			if d.depositsTo(d.devPeer.Relay.Mailbox) == 0 {
				t.Fatal("device not told")
			}
			for _, k := range []string{store.StateKey(vid), store.HeaderKey(vid, testRelease.PCR0)} {
				if exists(t, d.store, k) {
					t.Fatalf("%s left", k)
				}
			}
			if len(events) == 0 || events[len(events)-1] != "deleted" {
				t.Fatalf("lifecycle %v", events)
			}
			// Unlocking a deleted vault finds nothing.
			if _, _, err := d.unlock(testPIN, 0, 0); err == nil {
				t.Fatal("deleted vault unlocked")
			}
		})
	}
}

// §12.5: the host's deletion (account cancellation) has the same
// semantics on a running vault.
func TestDeleteByHost(t *testing.T) {
	f := newFixture(t)
	vid := f.m.VaultID()
	if err := f.m.Delete(context.Background()); err != nil {
		t.Fatal(err)
	}
	if exists(t, f.store, store.StateKey(vid)) || exists(t, f.store, store.HeaderKey(vid, testRelease.PCR0)) {
		t.Fatal("storage left")
	}
	if f.relay.mailboxDeleted != 1 {
		t.Fatalf("relay mailbox deleted %d times", f.relay.mailboxDeleted)
	}
}

// failingStore fails deletes of one key once.
type failingStore struct {
	store.Store
	failKey string
	failed  bool
}

func (s *failingStore) Delete(ctx context.Context, key string, v store.Version) error {
	if key == s.failKey && !s.failed {
		s.failed = true
		return errors.New("crash")
	}
	return s.Store.Delete(ctx, key, v)
}

// §12.5: a crash after the marking flush, or in the middle of erasing,
// converges to deleted: the next unlock finishes the deletion instead of
// opening the vault.
func TestDeleteCrashConverges(t *testing.T) {
	for _, crashAt := range []string{"after-mark", "mid-erase"} {
		t.Run(crashAt, func(t *testing.T) {
			f := newFixture(t)
			vid := f.m.VaultID()
			if crashAt == "after-mark" {
				f.m.opt.Hooks.AfterFlush = func() error { return errors.New("crash") }
			} else {
				fs := &failingStore{Store: f.store, failKey: store.HeaderKey(vid, testRelease.PCR0)}
				f.m.opt.Store = fs
			}
			f.m.mu.Lock()
			f.m.beginDelete("app", time.Now())
			f.m.mu.Unlock()
			_ = f.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
			if !exists(t, f.store, store.HeaderKey(vid, testRelease.PCR0)) {
				t.Fatal("the marker is gone before the crash point")
			}
			// Half-deleted: the vault never runs again.
			if m, _, err := f.unlock(testPIN, 0, 0); err == nil || m != nil {
				t.Fatal("a half-deleted vault opened")
			}
			for _, k := range []string{store.StateKey(vid), store.HeaderKey(vid, testRelease.PCR0)} {
				if exists(t, f.store, k) {
					t.Fatalf("%s left after convergence", k)
				}
			}
		})
	}
}

// EraseStored is idempotent and removes the member index only when it
// names this vault.
func TestEraseStoredIdempotent(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_, _ = st.Put(ctx, store.StateKey("v1"), []byte("s"), "")
	_, _ = st.Put(ctx, store.HeaderKey("v1", "aa"), []byte("h"), "")
	_, _ = st.Put(ctx, store.HeaderKey("v1", "bb"), []byte("h"), "")
	_, _ = st.Put(ctx, store.UserKey(UserIndexHash("u1")), []byte("v1"), "")
	_, _ = st.Put(ctx, store.UserKey(UserIndexHash("u2")), []byte("v9"), "")
	for i := 0; i < 2; i++ {
		if err := EraseStored(ctx, st, "v1", "u1", []string{"bb"}, "aa", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range []string{store.StateKey("v1"), store.HeaderKey("v1", "aa"), store.HeaderKey("v1", "bb"), store.UserKey(UserIndexHash("u1"))} {
		if exists(t, st, k) {
			t.Fatalf("%s left", k)
		}
	}
	if err := EraseStored(ctx, st, "v1", "u2", nil, "aa", "", ""); err != nil || !exists(t, st, store.UserKey(UserIndexHash("u2"))) {
		t.Fatal("another vault's index removed")
	}
}
