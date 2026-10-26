//go:build devenclave && e2e

package e2e

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vault/store"
)

// headerFaults lets the next pass header writes through and then fails
// the next fail ones before storing.
type headerFaults struct {
	store.Store
	mu         sync.Mutex
	pass, fail int
}

func (s *headerFaults) set(pass, fail int) {
	s.mu.Lock()
	s.pass, s.fail = pass, fail
	s.mu.Unlock()
}

func (s *headerFaults) Put(ctx context.Context, key string, data []byte, ifMatch store.Version) (store.Version, error) {
	if strings.Contains(key, "/header/") {
		s.mu.Lock()
		switch {
		case s.pass > 0:
			s.pass--
		case s.fail > 0:
			s.fail--
			s.mu.Unlock()
			return "", errors.New("injected header write failure")
		}
		s.mu.Unlock()
	}
	return s.Store.Put(ctx, key, data, ifMatch)
}

// A phone that could not tell (VAULT-MESSAGING §11.14.6) with the same
// identity: its open of R1 stores steps 1 and 2 and not step 3 (retry);
// R1 is replaced; the same identity registers R2 with a new attested key
// and opens it. The repeat through the `next` wrap answers ok, the phone
// pairs with ctx = R2 and unlocks with its new key; the earlier key is
// refused.
func TestRecoveryRSameIdentityNewKey(t *testing.T) {
	hf := &headerFaults{}
	rr := newRecRStore(t, 0, func(s store.Store) store.Store { hf.Store = s; return hf })
	a, b := rr.setup("member-rebind")
	a1 := b.att
	hf.set(1, 1) // step 1 stored; step 3's header write fails
	r, _ := rr.open(b, acPIN, recPW)
	if r.OK || r.Code != vault.OpenRetry || !r.AttemptUsed || r.Used != 1 {
		t.Fatalf("open stopped after step 2: %+v", r)
	}
	hf.set(0, 0)
	// A new recovery replaces R1; the same identity registers for it with
	// a new attested key.
	qr, resp := rr.request(a)
	if resp.Clear.NotBefore.IsZero() {
		t.Fatalf("clear not_before: %+v", resp.Clear)
	}
	rr.advance(25 * time.Hour)
	a2 := enclavetest.NewAndroidAttester(0x66, enclavetest.AndroidOptions{})
	b.att = a2
	rr.register(b, qr)
	r, _ = rr.open(b, acPIN, recPW)
	if !r.OK || r.AttemptUsed {
		t.Fatalf("repeat for R2: %+v", r)
	}
	ctx := ctxT(t, 20*time.Second)
	if err := b.dev.CompleteRecoveryHandshake(ctx); err != nil {
		if m := rr.instanceOf(a).Manager(a.vid); m != nil {
			for _, e := range m.Audit() {
				t.Logf("audit %s %s", e.Event, e.PeerID)
			}
		}
		t.Fatalf("handshake with ctx = R2: %v", err)
	}
	if err := b.dev.CredentialFetch(ctx); err != nil {
		t.Fatalf("credential.get as the holder: %v", err)
	}
	rr.lock(b)
	if u := rr.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !u.OK {
		t.Fatalf("unlock with the new key: %+v", u)
	}
	rr.lock(b)
	b.att = a1
	if u, err := rr.unlock(b, acPIN, client.UnlockOptions{}, ""); err == nil && u.OK {
		t.Fatal("the earlier attested key unlocked")
	}
	b.att = a2
	if u := rr.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !u.OK {
		t.Fatalf("unlock with the new key again: %+v", u)
	}
}
