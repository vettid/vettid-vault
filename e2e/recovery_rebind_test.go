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
	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/countertest"
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

// A lost ok whose completion is finished by the unlock (VAULT-MESSAGING
// 0.63.1, §11.14.2, §11.14.6 "A lost ok"): the open stores steps 1 and 2
// and its step-3 header write fails (retry, the answer the phone never
// acts on); the phone's unlock completes step 3 and ends the recovery in
// the same header write. A later open of that recovery is refused (no
// readable answer, no recovery_attempt marker) and uses no attempt; the
// phone pairs, and after that no unlock carries the bundle.
func TestRecoveryRLostOKUnlockEndsTheRecovery(t *testing.T) {
	hf := &headerFaults{}
	rr := newRecRStore(t, 0, func(s store.Store) store.Store { hf.Store = s; return hf })
	_, b := rr.setup("member-lost-ends")
	hf.set(1, 1) // step 1 stored; step 3's header write fails
	r, _ := rr.open(b, acPIN, recPW)
	if r.OK || r.Code != vault.OpenRetry || !r.AttemptUsed {
		t.Fatalf("open stopped after step 2: %+v", r)
	}
	hf.set(0, 0)
	creates := rr.bucket.Calls(countertest.OpPutCreate)
	if u := rr.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !u.OK || len(u.VaultBundle) == 0 {
		t.Fatalf("lost-ok unlock: %+v", u)
	}
	rr.lock(b)
	// The open again: the recovery has ended.
	e, in := rr.enclave(b, "", false)
	_, m, err := b.dev.VerifyManifest(rr.w.Served(), rr.trust)
	if err != nil {
		t.Fatal(err)
	}
	req, err := b.dev.BuildRecoveryOpen(b.guid, acPIN, recPW, e, m, b.att)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rr.w.Post(ctxT(t, 60*time.Second), in, enclave.OpRecoveryOpen, b.vid, b.guid, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Code == enclave.CodeRecoveryAttempt {
		t.Fatalf("the open after the completion used an attempt: %s %+v", resp.Code, resp.Clear)
	}
	if or, err := b.dev.OpenRecoveryOpenResult(resp.Envelope); err == nil {
		t.Fatalf("the open after the completion was answered: %+v", or)
	}
	if n := rr.bucket.Calls(countertest.OpPutCreate); n != creates {
		t.Fatalf("the open after the completion wrote %d counter records", n-creates)
	}
	// Pairing, then no bundle.
	if u := rr.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !u.OK || len(u.VaultBundle) == 0 {
		t.Fatalf("lost-ok unlock before the pairing: %+v", u)
	}
	ctx := ctxT(t, 20*time.Second)
	if err := b.dev.CompleteRecoveryHandshake(ctx); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if err := b.dev.CredentialFetch(ctx); err != nil {
		t.Fatalf("credential.get as the holder: %v", err)
	}
	rr.lock(b)
	if u := rr.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !u.OK || len(u.VaultBundle) > 0 {
		t.Fatalf("an unlock after the pairing: %+v", u)
	}
}
