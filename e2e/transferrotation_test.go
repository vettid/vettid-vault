//go:build devenclave && e2e

package e2e

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/vault/store"
)

// VAULT-MESSAGING §11.14.10 "The vault's keys after a transfer", "The rest,
// after the new phone's first unlock": ik, kem and the wake key rotate in
// the state write that follows the relay accepting the old phone's
// device.unlinked{transferred}; the connection follows identity.rotate.

// peerIK is the identity key the peer pinned for the member's vault.
func (w *tkWorld) peerIK() string {
	w.t.Helper()
	g, err := w.p.dev.Op(ctxT(w.t, 30*time.Second), "connection.get", map[string]any{"connection_id": w.pConn})
	if err != nil {
		w.t.Fatal(err)
	}
	return string(g["ik"])
}

// awaitPeerIK waits until the peer pinned an identity key other than was.
func (w *tkWorld) awaitPeerIK(was string) string {
	w.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if ik := w.peerIK(); ik != was {
			return ik
		}
		time.Sleep(100 * time.Millisecond)
	}
	w.t.Fatal("the peer did not follow identity.rotate")
	return ""
}

// rotatedCount counts identity.rotated in the member's History, as d.
func (w *tkWorld) rotatedCount(d *client.Device) int {
	w.t.Helper()
	o, err := d.AuditList(ctxT(w.t, 30*time.Second), map[string]any{"q": "identity.rotated"}, false)
	if err != nil {
		w.t.Fatal(err)
	}
	return strings.Count(string(o["entries"]), `"identity.rotated"`)
}

// The move finishes: the held statement, the old phone's notice, then the
// rotation; the peer follows identity.rotate to the vault's new ik and
// signs in under K1 in the session under it.
func TestTransferRotatesVaultKeys(t *testing.T) {
	w := newTKWorld(t, 0x8b)
	ik0 := w.peerIK()
	b := w.move(w.a, "new-phone-tk-k", 0x9b)
	k1 := w.key(b.dev)
	if ik := w.peerIK(); ik != ik0 {
		t.Fatal("the vault's ik rotated at the approval")
	}
	w.finish(b)
	waitEvent(t, w.p.dev, "connection.authenticate.key", has("key", k1))
	waitEvent(t, w.a.dev, "device.unlinked", has("reason", "transferred"))
	w.awaitPeerIK(ik0)
	if res := w.auth(b.dev); !strings.Contains(res, `"key_changed":false`) || !strings.Contains(res, k1) {
		t.Fatalf("after the rotation: %s", res)
	}
	if n := w.rotatedCount(b.dev); n != 1 {
		t.Fatalf("identity.rotated %d times", n)
	}
}

// Crashes around the notice's 201 and the rotation's state write: the
// rotation is made once, after the notice was accepted, and the peer
// follows it.
func TestTransferRotationCrashE2E(t *testing.T) {
	for _, c := range []struct {
		name string
		seed byte
		// deliver: the notice reaches the relay before the crash.
		deliver bool
		// hook: the crash is injected at the notice's deposit.
		hook bool
		// block: after the notice, nothing reaches the new phone before the
		// crash (its rekey and identity.rotate stay undelivered).
		block bool
	}{
		{"before the 201", 0x8c, false, true, false},
		{"after the 201, before the rotation's write", 0x8d, true, true, false},
		{"after the rotation's write", 0x8e, true, false, false},
		{"after the rotation's write, nothing delivered to the new phone", 0x8f, true, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			sf := &stateFaults{}
			w := newTKWorld(t, c.seed, func(s store.Store) store.Store { sf.Store = s; return sf })
			ik0 := w.peerIK()
			oldMB := w.a.dev.RelayAddr().Mailbox
			b := w.move(w.a, "new-phone-tk-x", c.seed+0x10)
			fired := make(chan struct{})
			if c.hook {
				var once atomic.Bool
				h := depositHook(func(ctx context.Context, url, mb, tok string, p []byte,
					next func(context.Context, string, string, string, []byte) (string, error)) (string, error) {
					if mb != oldMB || !once.CompareAndSwap(false, true) {
						return next(ctx, url, mb, tok, p)
					}
					// Every state write fails from here until the crash.
					if !c.deliver {
						sf.arm(1 << 30)
						close(fired)
						return "", errors.New("connection reset")
					}
					id, err := next(ctx, url, mb, tok, p)
					sf.arm(1 << 30)
					close(fired)
					return id, err
				})
				w.aw.deposit.Store(&h)
			}
			if c.block {
				bMB := b.dev.RelayAddr().Mailbox
				var noticed atomic.Bool
				h := depositHook(func(ctx context.Context, url, mb, tok string, p []byte,
					next func(context.Context, string, string, string, []byte) (string, error)) (string, error) {
					if mb == oldMB {
						id, err := next(ctx, url, mb, tok, p)
						noticed.Store(true)
						return id, err
					}
					if mb == bMB && noticed.Load() {
						return "", errors.New("connection reset")
					}
					return next(ctx, url, mb, tok, p)
				})
				w.aw.deposit.Store(&h)
			}
			w.aw.lock(b)
			_, _ = w.aw.unlock(b, acPIN, client.UnlockOptions{}, "")
			if c.hook {
				select {
				case <-fired:
				case <-time.After(60 * time.Second):
					t.Fatal("the notice was not deposited")
				}
				time.Sleep(500 * time.Millisecond) // the drain's write fails
				if c.deliver {
					waitEvent(t, w.a.dev, "device.unlinked", has("reason", "transferred"))
				}
			} else {
				// The crash comes as soon as the peer followed identity.rotate,
				// with the new phone's rekey still in flight.
				waitEvent(t, w.a.dev, "device.unlinked", has("reason", "transferred"))
				w.awaitPeerIK(ik0)
			}
			w.aw.instanceOf(b).Manager(b.vid).Crash()
			w.aw.deposit.Store(nil)
			sf.arm(0)
			if c.hook && w.peerIK() != ik0 {
				t.Fatal("identity.rotate left before the rotation's write")
			}
			if r := w.aw.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !r.OK {
				t.Fatalf("unlock after the crash: %+v", r)
			}
			if !c.deliver {
				waitEvent(t, w.a.dev, "device.unlinked", has("reason", "transferred"))
			}
			ik1 := w.awaitPeerIK(ik0)
			if res := w.auth(b.dev); !strings.Contains(res, `"key_changed":false`) {
				t.Fatalf("after the rotation: %s", res)
			}
			if n := w.rotatedCount(b.dev); n != 1 {
				t.Fatalf("identity.rotated %d times", n)
			}
			if w.peerIK() != ik1 {
				t.Fatal("rotated again")
			}
		})
	}
}
