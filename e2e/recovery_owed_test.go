//go:build devenclave && e2e

package e2e

import (
	"crypto/rand"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// §11.14.6 step 6, §11.14.10: a recovery whose rotation of the vault's keys
// could not be made still completes; the rotation is owed. The enclave runs
// the manager at once, and an immediate retry would hand the recovered
// phone a vault_bundle with the old identity key and rotate before its
// first handshake, which would then fail. The retry waits for the pairing,
// and then happens.
func TestRecoveryRotationOwedWaitsForThePairing(t *testing.T) {
	// Only the recovery's own rotation fails (its first draw); every later
	// draw works, so an early retry would succeed.
	var draws atomic.Int32
	recKeyRand = func(n int) ([]byte, error) {
		if draws.Add(1) == 1 {
			return nil, errors.New("no entropy")
		}
		b := make([]byte, n)
		_, err := rand.Read(b)
		return b, err
	}
	defer func() { recKeyRand = nil }()
	rr := newRecR(t)
	a, b := rr.setup("member-owed")
	rr.advance(10 * time.Minute)
	r, _ := rr.open(b, acPIN, recPW)
	if !r.OK {
		t.Fatalf("the recovery failed with its rotation: %+v", r)
	}

	ctx := ctxT(t, 20*time.Second)
	// count reads the audit log as the recovered phone: it is the vault's
	// holder once it has paired, so before that no read is possible; the
	// manager's own record answers instead.
	count := func(ev string) int {
		o, err := b.dev.AuditList(ctx, map[string]any{"q": ev}, false)
		if err != nil {
			return 0
		}
		return strings.Count(string(o["entries"]), `"`+ev+`"`)
	}
	// (The enclave has started the manager by now: the retry did not run.)
	if m := rr.instanceOf(a).Manager(a.vid); m == nil {
		t.Fatal("no running vault")
	}
	if err := b.dev.CompleteRecoveryHandshake(ctx); err != nil {
		t.Fatalf("the recovered phone's first handshake: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for count("identity.rotated") == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if count("identity.rotated") != 1 {
		t.Fatalf("not rotated after the pairing: %d", count("identity.rotated"))
	}
}
