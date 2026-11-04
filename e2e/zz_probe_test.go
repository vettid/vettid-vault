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
)

// Probe: crash after the rotation's write while the new phone's rekey and
// identity.rotate are still undelivered.
func TestProbeRotationCrashRekeyInFlight(t *testing.T) {
	for _, c := range []struct {
		name  string
		seed  byte
		block bool
	}{{"blocked", 0xa1, true}, {"race", 0xa3, false}} {
		t.Run(c.name, func(t *testing.T) {
			w := newTKWorld(t, c.seed)
			ik0 := w.peerIK()
			oldMB := w.a.dev.RelayAddr().Mailbox
			b := w.move(w.a, "new-phone-probe", c.seed+0x10)
			bMB := b.dev.RelayAddr().Mailbox
			var noticed atomic.Bool
			var blockedN atomic.Int32
			h := depositHook(func(ctx context.Context, url, mb, tok string, p []byte,
				next func(context.Context, string, string, string, []byte) (string, error)) (string, error) {
				if mb == oldMB {
					id, err := next(ctx, url, mb, tok, p)
					noticed.Store(true)
					return id, err
				}
				if c.block && mb == bMB && noticed.Load() {
					blockedN.Add(1)
					return "", errors.New("connection reset")
				}
				return next(ctx, url, mb, tok, p)
			})
			w.aw.deposit.Store(&h)
			w.aw.lock(b)
			if r := w.aw.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !r.OK {
				t.Fatalf("unlock: %+v", r)
			}
			w.awaitPeerIK(ik0)
			t.Logf("blocked deposits to the new phone: %d", blockedN.Load())
			w.aw.instanceOf(b).Manager(b.vid).Crash()
			w.aw.deposit.Store(nil)
			if r := w.aw.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !r.OK {
				t.Fatalf("unlock after the crash: %+v", r)
			}
			res := w.auth(b.dev)
			if !strings.Contains(res, `"key_changed":false`) {
				t.Fatalf("after: %s", res)
			}
			if n := w.rotatedCount(b.dev); n != 1 {
				t.Fatalf("identity.rotated %d", n)
			}
			_ = time.Second
		})
	}
}

// Control: the same crash right after an unlock, with no rotation in it.
func TestProbeControlCrashAfterUnlock(t *testing.T) {
	w := newTKWorld(t, 0xa5)
	ik0 := w.peerIK()
	b := w.move(w.a, "new-phone-ctl", 0xb5)
	w.finish(b)
	w.awaitPeerIK(ik0)
	if res := w.auth(b.dev); !strings.Contains(res, `"key_changed":false`) {
		t.Fatalf("first: %s", res)
	}
	w.aw.lock(b)
	if r := w.aw.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !r.OK {
		t.Fatalf("unlock: %+v", r)
	}
	time.Sleep(300 * time.Millisecond)
	w.aw.instanceOf(b).Manager(b.vid).Crash()
	if r := w.aw.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !r.OK {
		t.Fatalf("unlock after the crash: %+v", r)
	}
	if res := w.auth(b.dev); !strings.Contains(res, `"key_changed":false`) {
		t.Fatalf("after: %s", res)
	}
}

// Does a later lock and unlock recover the stuck session?
func TestProbeRaceThenRelock(t *testing.T) {
	w := newTKWorld(t, 0xa7)
	ik0 := w.peerIK()
	b := w.move(w.a, "new-phone-rl", 0xb7)
	w.finish(b)
	w.awaitPeerIK(ik0)
	w.aw.instanceOf(b).Manager(b.vid).Crash()
	if r := w.aw.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !r.OK {
		t.Fatalf("unlock after the crash: %+v", r)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	_, err := b.dev.CredentialUnlock(ctx, credPW)
	cancel()
	t.Logf("credential.unlock after the crash: %v", err)
	for i := 0; i < 2; i++ {
		w.aw.lock(b)
		if r := w.aw.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !r.OK {
			t.Fatalf("relock unlock: %+v", r)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		_, err := b.dev.CredentialUnlock(ctx, credPW)
		cancel()
		t.Logf("credential.unlock after relock %d: %v", i+1, err)
	}
}
