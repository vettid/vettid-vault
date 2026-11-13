package vault

import (
	"context"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/vault/store"
)

// §11.8 (VAULT-MESSAGING 0.90.8): the rules of an unlock's count before its
// PIN test that the outcome tests alone do not pin.

// orderStore records, with onDeriveUnlockKey, the order of header puts and
// PIN derivations.
type orderStore struct {
	store.Store
	log *[]string
}

func (o *orderStore) Put(ctx context.Context, key string, data []byte, ifMatch store.Version) (store.Version, error) {
	v, err := o.Store.Put(ctx, key, data, ifMatch)
	if strings.Contains(key, "/header/") {
		if err != nil {
			*o.log = append(*o.log, "header-failed")
		} else {
			*o.log = append(*o.log, "header")
		}
	}
	return v, err
}

func traceDerives(t *testing.T, log *[]string) {
	t.Helper()
	onDeriveUnlockKey = func() { *log = append(*log, "derive") }
	t.Cleanup(func() { onDeriveUnlockKey = nil })
}

// No PIN is derived before the count is stored: a failed count write derives
// nothing; on success the first derivation follows the count's header put.
func TestUnlockDerivesNoPINBeforeTheStoredCount(t *testing.T) {
	for _, fails := range []bool{true, false} {
		f := newRFixture(t)
		f.flush()
		if err := f.m.Lock(context.Background()); err != nil {
			t.Fatal(err)
		}
		var log []string
		traceDerives(t, &log)
		if fails {
			f.st.mu.Lock()
			f.st.failHeader = 1
			f.st.mu.Unlock()
		}
		f.opts.Store = &orderStore{Store: f.opts.Store, log: &log}
		m, out := f.unlock(testPIN, testSecret)
		if m != nil {
			m.Crash()
		}
		if fails {
			for _, e := range log {
				if e == "derive" {
					t.Fatalf("a PIN derived after a failed count write: %v (%s)", log, out.Code)
				}
			}
			continue
		}
		if len(log) < 2 || log[0] != "header" || log[1] != "derive" {
			t.Fatalf("the count's header put does not come first: %v", log)
		}
	}
}

// countedTwice is a locked vault whose stored header holds 2 counted wrong
// PINs.
func countedTwice(t *testing.T) *rFixture {
	t.Helper()
	f := newRFixture(t)
	f.flush()
	if err := f.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		f.mustRefuse("000000", testSecret, CodeBadPIN)
	}
	if h := f.storedHeader(); h.Backoff.Failures != 2 {
		t.Fatalf("setup: %d counted", h.Backoff.Failures)
	}
	return f
}

// A right PIN resets the count on outcomes the other tests do not reach:
// a retry after the PIN (the ok's header write fails), a state rollback
// found once the state opens, and a state that does not open.
func TestUnlockRightPINOutcomesResetTheCount(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(f *rFixture)
		min   uint64
		code  string
	}{
		{"retry after the PIN", func(f *rFixture) {
			f.st.mu.Lock()
			f.st.passHeader, f.st.failHeader = 1, 1 // the count passes; the ok's write fails
			f.st.mu.Unlock()
		}, 0, CodeRetry},
		{"state rollback", nil, 1 << 40, CodeRollback},
		{"a state that does not open", func(f *rFixture) {
			ctx := context.Background()
			key := store.StateKey(f.vid)
			b, v, err := f.st.Store.Get(ctx, key)
			if err != nil {
				t.Fatal(err)
			}
			b = append([]byte(nil), b...)
			b[len(b)-1] ^= 1
			if _, err := f.st.Store.Put(ctx, key, b, v); err != nil {
				t.Fatal(err)
			}
		}, 0, CodeMissing},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := countedTwice(t)
			if c.setup != nil {
				c.setup(f)
			}
			m, out := UnlockAlt(context.Background(), AltUnlockParams{Options: f.opts, VaultID: f.vid, PIN: testPIN,
				UnlockSecret: testSecret, pinOnly: true, MinStateSeq: c.min})
			if m != nil || out.Code != c.code {
				t.Fatalf("%+v", out)
			}
			h := f.storedHeader()
			if h.Backoff != (Backoff{}) || out.HeaderSeq != h.HeaderSeq {
				t.Fatalf("stored backoff %+v seq %d, reported %d", h.Backoff, h.HeaderSeq, out.HeaderSeq)
			}
		})
	}
}

// wrong_release after a right PIN resets the count.
func TestUnlockWrongReleaseResetsTheCount(t *testing.T) {
	f := newRFixture(t)
	f.m.mu.Lock()
	f.m.st.SealedRelease = "a release this vault has left"
	f.m.dirty = true
	f.m.mu.Unlock()
	f.flush()
	if err := f.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mustRefuse("000000", testSecret, CodeBadPIN)
	if _, out := f.unlock(testPIN, testSecret); out.Code != CodeWrongRelease {
		t.Fatalf("%+v", out)
	}
	if h := f.storedHeader(); h.Backoff != (Backoff{}) {
		t.Fatalf("not reset: %+v", h.Backoff)
	}
}

// A retry after the PIN whose reset write also fails carries the count
// write's header_seq, and the raised count stays (the safe side).
func TestUnlockRetryWhoseResetFailsCarriesTheCountsSeq(t *testing.T) {
	f := countedTwice(t)
	before := f.storedHeader().HeaderSeq
	f.st.mu.Lock()
	f.st.passHeader, f.st.failHeader = 1, 2 // the count passes; the ok's write and the reset fail
	f.st.mu.Unlock()
	m, out := f.unlock(testPIN, testSecret)
	if m != nil || out.Code != CodeRetry {
		t.Fatalf("%+v", out)
	}
	h := f.storedHeader()
	if h.HeaderSeq != before+1 || out.HeaderSeq != h.HeaderSeq || h.Backoff.Failures != 3 {
		t.Fatalf("stored seq %d (before %d) failures %d, reported %d", h.HeaderSeq, before, h.Backoff.Failures, out.HeaderSeq)
	}
}

// resetCount leaves a header written since the count as it is, even one that
// still holds the same count: only the header the count stored is reset.
func TestResetCountLeavesAHeaderWrittenSince(t *testing.T) {
	f := newRFixture(t)
	f.flush()
	if err := f.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	hkey := store.HeaderKey(f.vid, testRelease.PCR0)
	_, countedVer, err := f.st.Get(ctx, hkey)
	if err != nil {
		t.Fatal(err)
	}
	counted := Backoff{Failures: 1}
	// A header written since, with the same count.
	h := f.storedHeader()
	h.Backoff = counted
	h.HeaderSeq++
	b, err := sealHeader(ctx, f.opts.Sealer, h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Put(ctx, hkey, b, countedVer); err != nil {
		t.Fatal(err)
	}
	p := AltUnlockParams{Options: f.opts, VaultID: f.vid}
	p.Options.defaults()
	p.Release = testRelease
	resetCount(ctx, p, hkey, countedVer, counted, &AltUnlockOutcome{})
	if got := f.storedHeader(); got.Backoff != counted || got.HeaderSeq != h.HeaderSeq {
		t.Fatalf("a header written since was reset: %+v seq %d", got.Backoff, got.HeaderSeq)
	}
}
