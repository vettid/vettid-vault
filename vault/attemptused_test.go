package vault

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/vettid/vettid-vault/internal/countertest"
	"github.com/vettid/vettid-vault/vault/store"
)

// attempt_used (VAULT-MESSAGING 0.34.0 §11.14.6) through RecoveryOpen: true
// if and only if the spend happened, whatever goes wrong after it.

func (f *openFixture) used() int {
	f.t.Helper()
	v, err := f.m.counter().Status(context.Background(), 1)
	if err != nil {
		f.t.Fatal(err)
	}
	return v.Used
}

// A spend whose outcome the counter cannot classify (the token stored and
// an error answered, and the version cannot be read back): lost, the
// attempt counts, attempt_lost with attempt_used.
func TestAttemptUsedLostSpend(t *testing.T) {
	f := newOpenFixture(t)
	f.bucket.StoreThenFail(countertest.OpPutCreate, 1)
	f.bucket.FailNext(countertest.OpGetVersion, 1)
	m, out := f.open(testPIN, rPW)
	if m != nil || out.Code != OpenAttemptLost || !out.AttemptUsed() || out.Used != 1 {
		t.Fatalf("lost spend: %+v", out)
	}
	if f.used() != 1 {
		t.Fatal("the lost attempt was not counted")
	}
}

// The read after a confirmed spend cannot be made: attempt_lost, used.
func TestAttemptUsedFailedConfirm(t *testing.T) {
	f := newOpenFixture(t)
	var spent atomic.Bool
	f.bucket.SetHook(func(op, _ string) {
		switch {
		case op == countertest.OpPutCreate:
			spent.Store(true)
		case op == countertest.OpGetRetention && spent.Load():
			f.bucket.FailNext(countertest.OpList, 100) // every list from here: the confirm
		}
	})
	m, out := f.open(testPIN, rPW)
	f.bucket.SetHook(nil)
	f.bucket.FailNext(countertest.OpList, 0)
	if m != nil || out.Code != OpenAttemptLost || !out.AttemptUsed() {
		t.Fatalf("failed confirm: %+v", out)
	}
	if f.used() != 1 {
		t.Fatal("the attempt was not counted")
	}
}

// The right pair opens the wrap, then the stored state does not decrypt
// under the opener's DEK (step 6): stored_mismatch with attempt_used;
// before the spend (a state that cannot be read) vault_missing without.
func TestAttemptUsedStoredDataAfterTheSpend(t *testing.T) {
	f := newOpenFixture(t)
	ctx := context.Background()
	sk := store.StateKey(f.vid)
	sb, sv, err := f.st.Get(ctx, sk)
	if err != nil {
		t.Fatal(err)
	}
	// Before the spend: no state at all.
	if err := f.st.Delete(ctx, sk, sv); err != nil {
		t.Fatal(err)
	}
	if m, out := f.open(testPIN, rPW); m != nil || out.Code != CodeMissing || out.AttemptUsed() {
		t.Fatalf("missing state: %+v", out)
	}
	if f.used() != 0 {
		t.Fatal("a missing state used an attempt")
	}
	// After the spend: the ciphertext damaged past its clear prefix.
	bad := append([]byte(nil), sb...)
	bad[len(bad)-1] ^= 1
	if _, err := f.st.Put(ctx, sk, bad, ""); err != nil {
		t.Fatal(err)
	}
	m, out := f.open(testPIN, rPW)
	if m != nil || out.Code != OpenStoredMismatch || !out.AttemptUsed() || out.Used != 1 {
		t.Fatalf("damaged state: %+v", out)
	}
}

// The wrap opens and the state decrypts, but the vault's keys in it cannot
// be loaded (step 6): vault_missing with attempt_used.
func TestAttemptUsedVaultMissingAfterTheSpend(t *testing.T) {
	f := newOpenFixtureWith(t, func(f *openFixture) {
		f.m.mu.Lock()
		f.m.st.Relay.Seed = nil
		f.m.dirty = true
		_ = f.m.persist(context.Background(), false)
		f.m.mu.Unlock()
		f.m.Crash()
	})
	m, out := f.open(testPIN, rPW)
	if m != nil || out.Code != CodeMissing || !out.AttemptUsed() || out.Used != 1 {
		t.Fatalf("keys not loadable: %+v", out)
	}
}

// A right pair whose completion fails after step 1 (the relay
// registration, then the storing of steps 2 and 3): retry with
// attempt_used; the repeat through the next wrap has none.
func TestAttemptUsedRetryAfterStep1(t *testing.T) {
	f := newOpenFixture(t)
	f.st.failState = 1
	m, out := f.open(testPIN, rPW)
	if m != nil || out.Code != OpenRetry || !out.AttemptUsed() {
		t.Fatalf("failed steps 2 and 3: %+v", out)
	}
	m, out = f.open(testPIN, rPW)
	if m == nil || !out.OK || out.AttemptUsed() {
		t.Fatalf("repeat: %+v", out)
	}
	_ = m.Lock(context.Background())
}
