package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/suite"
)

// confirmer records the app key confirmations and answers from fail.
type confirmer struct {
	mu    sync.Mutex
	calls []AppKeyConfirm
	fail  func(n int) error // n counts from 1; nil: ok
}

func (c *confirmer) confirm(_ context.Context, r AppKeyConfirm) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, r)
	if c.fail != nil {
		return c.fail(len(c.calls))
	}
	return nil
}

func (c *confirmer) n() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.calls) }

var quickKeyRetry = &AppKeyRetry{Budget: 200 * time.Millisecond, First: time.Millisecond, Cap: 5 * time.Millisecond}

// storedHdr is the header object as stored.
func storedHdr(t *testing.T, st store.Store, o Options, vid string) *Header {
	t.Helper()
	blob, _, err := st.Get(context.Background(), store.HeaderKey(vid, testRelease.PCR0))
	if err != nil {
		t.Fatal(err)
	}
	h, err := unsealHeader(context.Background(), o.Sealer, blob, vid, testRelease.PCR0)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// storedAppKey is the app key and seq in the header object as stored.
func storedAppKey(t *testing.T, f *fixture) ([]byte, uint64) {
	t.Helper()
	h := storedHdr(t, f.store, f.opts, f.vid)
	return h.AppKey, h.AppKeySeq
}

// A replacement's step 1 names the next app key; the host confirms the row
// names it (app_key_next) before the vault holds the replacement, and the
// app_key_next event follows the confirmation.
func TestBeginReplaceConfirmsNextKey(t *testing.T) {
	f := newFixture(t)
	c := &confirmer{}
	f.m.opt.ConfirmAppKey, f.m.opt.AppKeyRetry = c.confirm, quickKeyRetry
	var order []string
	f.m.opt.Lifecycle = func(ev LifecycleEvent) {
		if ev.Event == EventAppKeyNext {
			order = append(order, "event")
		}
	}
	key := testAppKeyDER(t, 0x41)
	rep := nextWithKey(t, f.m, key)
	f.m.mu.Lock()
	err := f.m.beginReplace(context.Background(), rep)
	f.m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if c.n() != 2 { // before step 1, and again after it is stored
		t.Fatalf("%d confirmations", c.n())
	}
	got := c.calls[0]
	if got.Mode != AppKeyModeNext || !bytes.Equal(got.Key, key) || got.Seq != rep.next.AppKeySeq || got.HeaderSeq != rep.next.HeaderSeq || got.VaultID != f.vid {
		t.Fatalf("confirmation %+v", got)
	}
	if len(order) != 1 {
		t.Fatalf("event %v", order)
	}
}

// The confirmation is made before the step-1 header is written (D2).
func TestConfirmBeforeStepOne(t *testing.T) {
	f := newFixture(t)
	var storedAtConfirm *Header
	c := &confirmer{}
	f.m.opt.ConfirmAppKey = func(ctx context.Context, r AppKeyConfirm) error {
		if storedAtConfirm == nil { // the first confirmation; the second follows step 1
			storedAtConfirm = storedHdr(t, f.store, f.opts, f.vid)
		}
		return c.confirm(ctx, r)
	}
	rep := nextWithKey(t, f.m, testAppKeyDER(t, 0x41))
	f.m.mu.Lock()
	err := f.m.beginReplace(context.Background(), rep)
	f.m.mu.Unlock()
	if err != nil || storedAtConfirm == nil || storedAtConfirm.Next != nil {
		t.Fatalf("err %v, header at the confirmation %+v", err, storedAtConfirm)
	}
	if h := storedHdr(t, f.store, f.opts, f.vid); h.Next == nil {
		t.Fatal("step 1 not stored after the confirmation")
	}
}

// The header's own key stays known whatever abandoned replacements were
// confirmed since: it is not confirmed again (a request that would write
// the old key as app_key_next over a pending one).
func TestHeaderKeyStaysPinned(t *testing.T) {
	f := newFixture(t)
	cur := testAppKeyDER(t, 0x40)
	f.m.mu.Lock()
	f.m.hdr.AppKey, f.m.hdr.AppKeySeq = cur, 1
	f.m.pin(cur, 1)
	for i := 0; i < 6; i++ {
		f.m.ack(testAppKeyDER(t, byte(0x50+2*i)), uint64(2+i)) // abandoned replacements
	}
	got := f.m.ackedAppKey(cur, 1)
	f.m.mu.Unlock()
	if !got {
		t.Fatal("the header's key was pushed out")
	}
}

// nextWithKey is a replacement of the running vault whose next part names
// key as the next app key.
func nextWithKey(t *testing.T, m *Manager, key []byte) *replacement {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	kdf := m.hdr.KDF
	rep, err := m.nextFor(ReplaceTransfer, testPIN, testSecret, kdf, nil, m.now())
	if err != nil {
		t.Fatal(err)
	}
	rep.next.AppKey, rep.next.AppKeySeq = append([]byte(nil), key...), m.hdr.AppKeySeq+1
	rep.promoteFn = m.replacementPromoteFn(rep.next)
	return rep
}

// Not confirmed: no replacement, no app_key_next event, a clear for any
// app_key_next the host did write, and the key is not the vault's.
func TestBeginReplaceNotConfirmed(t *testing.T) {
	for name, fail := range map[string]func(int) error{
		"unreachable": func(int) error { return errors.New("host down") },
		"refused":     func(int) error { return ErrAppKeyRefused },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			c := &confirmer{fail: fail}
			f.m.opt.ConfirmAppKey, f.m.opt.AppKeyRetry = c.confirm, quickKeyRetry
			var evs []string
			f.m.opt.Lifecycle = func(ev LifecycleEvent) { evs = append(evs, ev.Event) }
			key := testAppKeyDER(t, 0x41)
			rep := nextWithKey(t, f.m, key)
			f.m.mu.Lock()
			err := f.m.beginReplace(context.Background(), rep)
			next, repl := f.m.hdr.Next, f.m.repl
			f.m.mu.Unlock()
			if !errors.Is(err, errRetry) || next != nil || repl != nil {
				t.Fatalf("err %v next %v repl %v", err, next, repl)
			}
			// No app_key_next event; only the clear of a possible orphan.
			for _, e := range evs {
				if e != EventAppKeyNextClear {
					t.Fatalf("events %v", evs)
				}
			}
			if name == "refused" && c.n() != 1 {
				t.Fatalf("a refusal was retried: %d", c.n())
			}
			if name == "unreachable" && c.n() < 2 {
				t.Fatalf("not retried: %d", c.n())
			}
			if k, _ := storedAppKey(t, f); bytes.Equal(k, key) {
				t.Fatal("the header names the unconfirmed key")
			}
			// D2: the confirmation comes BEFORE step 1, so no stored header
			// names the key as `next` either.
			if h := storedHdr(t, f.store, f.opts, f.vid); h.Next != nil {
				t.Fatalf("step 1 stored with an unconfirmed key: %+v", h.Next)
			}
		})
	}
}

// A confirmation that fails twice and then succeeds is retried.
func TestConfirmRetries(t *testing.T) {
	f := newFixture(t)
	c := &confirmer{fail: func(n int) error {
		if n < 3 {
			return errors.New("busy")
		}
		return nil
	}}
	f.m.opt.ConfirmAppKey, f.m.opt.AppKeyRetry = c.confirm, quickKeyRetry
	rep := nextWithKey(t, f.m, testAppKeyDER(t, 0x41))
	f.m.mu.Lock()
	err := f.m.beginReplace(context.Background(), rep)
	f.m.mu.Unlock()
	if err != nil || c.n() != 4 { // 3 for the first confirmation, 1 after step 1
		t.Fatalf("err %v after %d", err, c.n())
	}
}

// Any other path that moves the app key (a legacy transfer, a recovery
// that sets the key directly, a rotation) writes no state and no header
// until the host confirms the row names the key.
func TestSetAppKeyNeedsConfirmation(t *testing.T) {
	f := newFixture(t)
	c := &confirmer{fail: func(int) error { return errors.New("host down") }}
	f.m.opt.ConfirmAppKey, f.m.opt.AppKeyRetry = c.confirm, quickKeyRetry
	key := testAppKeyDER(t, 0x42)
	f.m.mu.Lock()
	sv, hv, seq, hseq := f.m.stateVer, f.m.headerVer, f.m.st.StateSeq, f.m.hdr.HeaderSeq
	f.m.setAppKey(key)
	err := f.m.persist(context.Background(), false)
	nothing := f.m.stateVer == sv && f.m.headerVer == hv && f.m.st.StateSeq == seq && f.m.hdr.HeaderSeq == hseq
	f.m.mu.Unlock()
	if err == nil || !nothing {
		t.Fatalf("persisted without a confirmation: err %v, nothing stored %v", err, nothing)
	}
	if k, _ := storedAppKey(t, f); bytes.Equal(k, key) {
		t.Fatal("the header names the unconfirmed key")
	}
	// The host is back: the same flush now goes through, after exactly one
	// confirmation of the key and the header_seq of the write.
	c.fail = nil
	f.m.mu.Lock()
	f.m.dirty = true
	err = f.m.persist(context.Background(), false)
	f.m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	last := c.calls[len(c.calls)-1]
	if last.Mode != AppKeyModeNext || !bytes.Equal(last.Key, key) || last.Seq != 1 || last.HeaderSeq != f.m.hdr.HeaderSeq {
		t.Fatalf("confirmation %+v, header_seq %d", last, f.m.hdr.HeaderSeq)
	}
	if k, s := storedAppKey(t, f); !bytes.Equal(k, key) || s != 1 {
		t.Fatalf("stored key seq %d", s)
	}
	before := c.n()
	f.m.mu.Lock()
	f.m.dirty = true
	err = f.m.persist(context.Background(), false)
	f.m.mu.Unlock()
	if err != nil || c.n() != before {
		t.Fatalf("a key the header names is confirmed again: %v %d %d", err, c.n(), before)
	}
}

// Without ConfirmAppKey nothing adopts a key (fail closed).
func TestNoConfirmAppKeyFailsClosed(t *testing.T) {
	f := newFixture(t)
	f.m.opt.ConfirmAppKey = nil
	f.m.mu.Lock()
	f.m.setAppKey(testAppKeyDER(t, 0x42))
	err := f.m.persist(context.Background(), false)
	f.m.mu.Unlock()
	if !errors.Is(err, errNoConfirmAppKey) {
		t.Fatalf("err %v", err)
	}
}

// A replacement promoted at step 3 whose next key was never confirmed in
// this process (resumed at an unlock after a crash) is confirmed before
// the header that makes it the vault's is written; nothing is stored (the gate runs before step 2).
func TestPromotedKeyConfirmedBeforeHeader(t *testing.T) {
	f := newFixture(t)
	c := &confirmer{}
	f.m.opt.ConfirmAppKey, f.m.opt.AppKeyRetry = c.confirm, quickKeyRetry
	key := testAppKeyDER(t, 0x43)
	rep := nextWithKey(t, f.m, key)
	f.m.mu.Lock()
	f.m.repl = rep // a resumed replacement: no beginReplace in this process
	f.m.hdr.Next = rep.next
	f.m.dirty = true
	c.fail = func(int) error { return errors.New("host down") }
	sv, seq := f.m.stateVer, f.m.st.StateSeq
	err := f.m.persist(context.Background(), false)
	same := f.m.stateVer == sv && f.m.st.StateSeq == seq
	f.m.mu.Unlock()
	if err == nil {
		t.Fatal("persisted")
	}
	if !same || c.n() == 0 {
		t.Fatalf("the state was written before the key was confirmed (same %v, %d confirmations)", same, c.n())
	}
	if k, _ := storedAppKey(t, f); bytes.Equal(k, key) {
		t.Fatal("the header names the unconfirmed key")
	}
}

// Enrollment: the vault's first header names the app key; the host
// confirms the row (app_key) before anything is stored.
func TestEnrollConfirmsAppKey(t *testing.T) {
	for _, down := range []bool{true, false} {
		st := store.NewMemory()
		c := &confirmer{}
		if down {
			c.fail = func(int) error { return errors.New("host down") }
		}
		var relay *stubRelay
		opts := Options{Store: st, Sealer: testSealer{key: bytes.Repeat([]byte{7}, 32)}, Release: testRelease, MarkDeleting: NoHostMark,
			ConfirmAppKey: c.confirm, AppKeyRetry: quickKeyRetry,
			Relay: func(base string, key ed25519.PrivateKey) Relay {
				relay = &stubRelay{base: base, key: key}
				return relay
			}}
		k, err := MinKDF()
		if err != nil {
			t.Fatal(err)
		}
		kem, _ := suite.NewPrivateKey(bytes.Repeat([]byte{0x33}, 32))
		relayPK := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x32}, 32)).Public().(ed25519.PublicKey)
		appKey := testAppKeyDER(t, 0x44)
		vid := "0123456789abcdef0123456789abcdef"
		m, err := Create(context.Background(), CreateParams{Options: opts, VaultID: vid, UserGUID: "u1", PIN: testPIN, UnlockSecret: testSecret, KDF: k,
			RelayURL: "https://relay.example.org", Provisional: true,
			App: &EnrollApp{IK: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, 32)).Public().(ed25519.PublicKey), KEM: kem.Public(),
				Relay: PeerRelay{URL: "https://relay.example.org", Mailbox: "m", PK: relayPK}, APIKey: appKey}})
		if down {
			if err == nil {
				t.Fatal("enrolled without a confirmation")
			}
			if _, _, gerr := st.Get(context.Background(), store.StateKey(vid)); !errors.Is(gerr, store.ErrNotFound) {
				t.Fatalf("something stored: %v", gerr)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if c.n() != 1 || c.calls[0].Mode != AppKeyModeEnroll || !bytes.Equal(c.calls[0].Key, appKey) || c.calls[0].Seq != 1 {
			t.Fatalf("confirmations %+v", c.calls)
		}
		m.Crash()
	}
}

// A step 1 that fails after the host's confirmation (or whose confirmation
// is not known) leaves a confirmed key on the row that no stored header
// names. The vault tells the parent at once, with the attempted
// header_seq, to clear it, and does not take the key as confirmed. (A
// failed open or approval ends without another report.)
func TestFailedStepOneClearsTheOrphanNext(t *testing.T) {
	for name, setup := range map[string]func(f *fixture, hs *headerFailStore, c *confirmer){
		"confirm unanswered": func(f *fixture, hs *headerFailStore, c *confirmer) {
			c.fail = func(int) error { return errors.New("answer lost") }
		},
		"header write fails": func(f *fixture, hs *headerFailStore, c *confirmer) { hs.fail.Store(true) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			hs := &headerFailStore{Store: f.store}
			f.m.opt.Store = hs
			c := &confirmer{}
			f.m.opt.ConfirmAppKey, f.m.opt.AppKeyRetry = c.confirm, quickKeyRetry
			cur := testAppKeyDER(t, 0x40)
			f.m.hdr.AppKey, f.m.hdr.AppKeySeq = cur, 1
			f.m.pin(cur, 1)
			var evs []LifecycleEvent
			f.m.opt.Lifecycle = func(ev LifecycleEvent) { evs = append(evs, ev) }
			key := testAppKeyDER(t, 0x41)
			rep := nextWithKey(t, f.m, key)
			setup(f, hs, c)
			f.m.mu.Lock()
			err := f.m.beginReplace(context.Background(), rep)
			acked := f.m.ackedAppKey(key, 2)
			f.m.mu.Unlock()
			if !errors.Is(err, errRetry) {
				t.Fatalf("err %v", err)
			}
			if len(evs) != 1 || evs[0].Event != EventAppKeyNextClear || evs[0].HeaderSeq != rep.next.HeaderSeq ||
				!bytes.Equal(evs[0].AppKey, key) || evs[0].AppKeySeq != 2 {
				t.Fatalf("events %+v", evs)
			}
			// The flush sends it once more (a link that was down dropped
			// it), then forgets it.
			f.m.mu.Lock()
			f.m.reportAppKey()
			f.m.reportAppKey()
			f.m.mu.Unlock()
			if len(evs) != 2 || evs[1].Event != EventAppKeyNextClear || evs[1].HeaderSeq != evs[0].HeaderSeq {
				t.Fatalf("not sent again once: %+v", evs)
			}
			if acked {
				t.Fatal("the key is still taken as confirmed")
			}
		})
	}
}

// A key confirmed again (the phone retries the same replacement at the same
// header_seq) is not removed by the earlier attempt's pending clear.
func TestConfirmedAgainForgetsThePendingClear(t *testing.T) {
	f := newFixture(t)
	c := &confirmer{}
	f.m.opt.ConfirmAppKey, f.m.opt.AppKeyRetry = c.confirm, quickKeyRetry
	var evs []LifecycleEvent
	f.m.opt.Lifecycle = func(ev LifecycleEvent) { evs = append(evs, ev) }
	key := testAppKeyDER(t, 0x41)
	rep := nextWithKey(t, f.m, key)
	f.m.mu.Lock()
	f.m.clearOrphanNext(rep.next) // an earlier attempt's orphan
	err := f.m.confirmKey(context.Background(), AppKeyModeNext, key, rep.next.AppKeySeq, rep.next.HeaderSeq)
	f.m.reportAppKey()
	f.m.mu.Unlock()
	if err != nil || len(evs) != 1 {
		t.Fatalf("err %v events %+v (only the first send)", err, evs)
	}
}

// stampHost models the row's app_key_next entry and its stamp for a split
// brain: this instance (the winner) and another (the loser) confirm the same
// key at the same header_seq; the loser's clear removes the entry only if it
// carries the loser's stamp.
type stampHost struct {
	att, loserAtt, ctr int64
	present            bool
	calls              int
	loserClearBefore   bool // the loser's clear lands before the winner's re-confirm
}

func (h *stampHost) confirm(_ context.Context, _ AppKeyConfirm) error {
	h.calls++
	if h.calls == 2 && h.loserClearBefore {
		h.loserClear()
	}
	h.ctr++
	h.att, h.present = h.ctr, true // a live confirm replaces or recreates with a later stamp
	if h.calls == 1 {
		// the loser confirms later: its stamp replaces ours
		h.ctr++
		h.loserAtt, h.att = h.ctr, h.ctr
	}
	return nil
}

func (h *stampHost) loserClear() {
	if h.present && h.att == h.loserAtt {
		h.present = false
	}
}

// The split brain where the loser confirms after the winner: the winner
// re-confirms after step 1 is stored, so the loser's clear, before or after
// that, leaves the winner's entry with the winner's stamp.
func TestReconfirmAfterStepOneKeepsEntryAgainstLoserClear(t *testing.T) {
	for _, before := range []bool{false, true} {
		f := newFixture(t)
		h := &stampHost{loserClearBefore: before}
		f.m.opt.ConfirmAppKey, f.m.opt.AppKeyRetry = h.confirm, quickKeyRetry
		rep := nextWithKey(t, f.m, testAppKeyDER(t, 0x41))
		f.m.mu.Lock()
		err := f.m.beginReplace(context.Background(), rep)
		f.m.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		h.loserClear() // the loser's header write failed; its clear
		if !h.present || h.att == h.loserAtt || h.calls != 2 {
			t.Fatalf("before=%v: present %v att %d loser %d calls %d", before, h.present, h.att, h.loserAtt, h.calls)
		}
	}
}

// A failed re-confirmation: no step 2 (the replacement is not held), the
// answer is retry, and no orphan clear is sent (the stored header names the key).
func TestReconfirmFailureStopsBeforeStepTwo(t *testing.T) {
	f := newFixture(t)
	c := &confirmer{fail: func(n int) error {
		if n >= 2 {
			return errors.New("host down")
		}
		return nil
	}}
	f.m.opt.ConfirmAppKey, f.m.opt.AppKeyRetry = c.confirm, quickKeyRetry
	var evs []LifecycleEvent
	f.m.opt.Lifecycle = func(ev LifecycleEvent) { evs = append(evs, ev) }
	rep := nextWithKey(t, f.m, testAppKeyDER(t, 0x41))
	f.m.mu.Lock()
	err := f.m.beginReplace(context.Background(), rep)
	held := f.m.repl
	f.m.mu.Unlock()
	if !errors.Is(err, errRetry) || held != nil {
		t.Fatalf("err %v held %v", err, held)
	}
	for _, ev := range evs {
		if ev.Event == EventAppKeyNextClear || ev.Event == EventAppKeyNext {
			t.Fatalf("event %s after a failed re-confirmation", ev.Event)
		}
	}
	if h := storedHdr(t, f.store, f.opts, f.vid); h.Next == nil {
		t.Fatal("step 1 should be stored")
	}
}

// conflictHeaderStore answers a header write with the store's version
// conflict: another instance stored the header (a split brain).
type conflictHeaderStore struct{ store.Store }

func (s conflictHeaderStore) Put(ctx context.Context, key string, data []byte, ifMatch store.Version) (store.Version, error) {
	if strings.Contains(key, "header") {
		return "", store.ErrConflict
	}
	return s.Store.Put(ctx, key, data, ifMatch)
}

// A step 1 that loses to another instance's header (split brain) sends no
// orphan clear: the row's entry for that key and header_seq may be the
// winner's.
func TestSplitBrainStepOneSendsNoClear(t *testing.T) {
	f := newFixture(t)
	f.m.opt.Store = conflictHeaderStore{f.store}
	c := &confirmer{}
	f.m.opt.ConfirmAppKey, f.m.opt.AppKeyRetry = c.confirm, quickKeyRetry
	var evs []LifecycleEvent
	f.m.opt.Lifecycle = func(ev LifecycleEvent) { evs = append(evs, ev) }
	key := testAppKeyDER(t, 0x41)
	rep := nextWithKey(t, f.m, key)
	f.m.mu.Lock()
	err := f.m.beginReplace(context.Background(), rep)
	f.m.reportAppKey()
	f.m.mu.Unlock()
	if !errors.Is(err, ErrSplitBrain) {
		t.Fatalf("err %v", err)
	}
	if len(evs) != 0 {
		t.Fatalf("events after a split brain: %+v", evs)
	}
}
