package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/vettid/vettid-vault/vault/store"
)

// headerFailStore fails header writes while fail is set.
type headerFailStore struct {
	store.Store
	fail atomic.Bool
}

func (s *headerFailStore) Put(ctx context.Context, key string, data []byte, ifMatch store.Version) (store.Version, error) {
	if s.fail.Load() && strings.Contains(key, "header") {
		return "", errors.New("store down")
	}
	return s.Store.Put(ctx, key, data, ifMatch)
}

// A replacement stopped after step 2 (the state under DEK_1 stored, the
// header with the new key not) is resumed by the next unlock (openPromote).
// That unlock does not make the key the vault's before the host confirms
// the row names it, and not before the state is stored again.
func TestUnlockAltPromoteNeedsConfirmation(t *testing.T) {
	d := newDevFixture(t)
	hs := &headerFailStore{Store: d.store}
	d.m.opt.Store = hs
	c := &confirmer{}
	d.m.opt.ConfirmAppKey, d.m.opt.AppKeyRetry = c.confirm, quickKeyRetry
	key := testAppKeyDER(t, 0x45)
	rep := nextWithKey(t, d.m, key)
	d.m.mu.Lock()
	err := d.m.beginReplace(context.Background(), rep)
	if err == nil {
		hs.fail.Store(true) // step 3's header write
		err = d.m.persist(context.Background(), false)
	}
	d.m.mu.Unlock()
	if err == nil {
		t.Fatal("step 3 stored")
	}
	d.m.Crash()
	if h := storedHeader(t, d); h.Next == nil || bytes.Equal(h.AppKey, key) {
		t.Fatalf("not stopped after step 2: %+v", h.Next)
	}
	// The host cannot confirm: the unlock is refused and nothing is stored.
	down := &confirmer{fail: func(int) error { return errors.New("host down") }}
	opts := d.opts
	opts.ConfirmAppKey, opts.AppKeyRetry = down.confirm, quickKeyRetry
	ok := func(*UnlockKey) (json.RawMessage, error) { return json.RawMessage(`{}`), nil }
	hv := storedHeader(t, d).HeaderSeq
	m, out := altUnlock(d, opts, testPIN, ok)
	if m != nil || out.OK {
		t.Fatalf("unlocked: %+v", out)
	}
	if down.n() == 0 || !bytes.Equal(down.calls[0].Key, key) || down.calls[0].Mode != AppKeyModeNext {
		t.Fatalf("confirmations %+v", down.calls)
	}
	if h := storedHeader(t, d); bytes.Equal(h.AppKey, key) || h.HeaderSeq < hv {
		t.Fatalf("the header names the unconfirmed key: %+v", h)
	}
	// The host is back: the unlock resumes the replacement and confirms once.
	opts.ConfirmAppKey = c.confirm
	before := c.n()
	m, out = altUnlock(d, opts, testPIN, ok)
	if m == nil || !out.OK {
		t.Fatalf("unlock: %+v", out)
	}
	defer m.Crash()
	if h := storedHeader(t, d); !bytes.Equal(h.AppKey, key) || h.Next != nil {
		t.Fatalf("not promoted: %+v", h)
	}
	if c.n() != before+1 || c.calls[before].Mode != AppKeyModeNext {
		t.Fatalf("confirmations %+v", c.calls)
	}
}

// A recovery stopped after step 2 is resumed by resumeRecovery: the
// phone's app key does not become the vault's before the host confirms the
// row names it.
func TestRecoveryOpenResumeNeedsConfirmation(t *testing.T) {
	f := newOpenFixture(t)
	c := &confirmer{}
	f.opts.ConfirmAppKey, f.opts.AppKeyRetry = c.confirm, quickKeyRetry
	f.st.passHeader, f.st.failHeader = 1, 1 // step 1 written; step 3's header write fails
	m, out := f.open(testPIN, rPW)
	if m != nil || out.Code != OpenRetry {
		t.Fatalf("failed step 3: %+v", out)
	}
	key := []byte("phone-app-key")
	if c.n() != 1 || !bytes.Equal(c.calls[0].Key, key) || c.calls[0].Mode != AppKeyModeNext {
		t.Fatalf("step 1 confirmations %+v", c.calls)
	}
	if h := f.storedHeader(); h.Next == nil || f.storedStateVersion() != h.Next.DEKVersion || bytes.Equal(h.AppKey, key) {
		t.Fatal("not stopped after step 2")
	}
	down := &confirmer{fail: func(int) error { return errors.New("host down") }}
	f.opts.ConfirmAppKey = down.confirm
	m, out = f.open(testPIN, rPW)
	if m != nil || out.OK || out.Code != OpenRetry {
		t.Fatalf("resume without the host: %+v", out)
	}
	if down.n() == 0 || !bytes.Equal(down.calls[0].Key, key) {
		t.Fatalf("the resume did not ask the host: %+v", down.calls)
	}
	if h := f.storedHeader(); bytes.Equal(h.AppKey, key) || h.Next == nil {
		t.Fatalf("the header names the unconfirmed key: %+v", h)
	}
	f.opts.ConfirmAppKey = c.confirm
	m, out = f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("resume: %+v", out)
	}
	defer m.Crash()
	if h := f.storedHeader(); !bytes.Equal(h.AppKey, key) || h.Next != nil {
		t.Fatalf("not completed: %+v", h)
	}
}

// A recovery open whose step 1 fails after the confirmation ends with the
// vault zeroized and no report: the orphan app_key_next is cleared by an
// event sent at once.
func TestRecoveryOpenFailedStepOneClearsTheOrphan(t *testing.T) {
	f := newOpenFixture(t)
	c := &confirmer{}
	var mu sync.Mutex
	var evs []LifecycleEvent
	f.opts.ConfirmAppKey, f.opts.AppKeyRetry = c.confirm, quickKeyRetry
	f.opts.Lifecycle = func(ev LifecycleEvent) { mu.Lock(); evs = append(evs, ev); mu.Unlock() }
	f.st.failHeader = 1 // step 1's header write
	m, out := f.open(testPIN, rPW)
	if m != nil || out.Code != OpenRetry {
		t.Fatalf("open: %+v", out)
	}
	if c.n() != 1 {
		t.Fatalf("confirmations %d", c.n())
	}
	mu.Lock()
	defer mu.Unlock()
	var cleared []LifecycleEvent
	for _, ev := range evs {
		if ev.Event == EventAppKeyNextClear {
			cleared = append(cleared, ev)
		}
	}
	if len(cleared) != 1 || cleared[0].HeaderSeq == 0 {
		t.Fatalf("events %+v", evs)
	}
}
