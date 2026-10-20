package vault

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vault/store"
)

// VAULT-MESSAGING 0.51.0 §12.5: the host's mark before step 2, its
// 2-minute bound, a state that records deleting never runs, step 4's
// retries, and the resume (delete_resume) that is never an authority.

// fastRetry keeps a deletion's schedules short (the real ones are 1 s,
// 15 s, 2 minutes and 60 s).
var fastRetry = &DeleteRetry{First: 5 * time.Millisecond, Cap: 20 * time.Millisecond, Mark: 200 * time.Millisecond, Erase: 200 * time.Millisecond}

// putFailStore fails the Put of one key while n > 0.
type putFailStore struct {
	store.Store
	mu  sync.Mutex
	key string
	n   int
}

func (s *putFailStore) Put(ctx context.Context, key string, data []byte, v store.Version) (store.Version, error) {
	s.mu.Lock()
	fail := key == s.key && s.n > 0
	if fail {
		s.n--
	}
	s.mu.Unlock()
	if fail {
		return "", errors.New("store unreachable")
	}
	return s.Store.Put(ctx, key, data, v)
}

// delFailStore fails every Delete of one key while n > 0 (n < 0: always).
type delFailStore struct {
	store.Store
	mu  sync.Mutex
	key string
	n   int
}

func (s *delFailStore) Delete(ctx context.Context, key string, v store.Version) error {
	s.mu.Lock()
	fail := key == s.key && s.n != 0
	if fail && s.n > 0 {
		s.n--
	}
	s.mu.Unlock()
	if fail {
		return errors.New("store unreachable")
	}
	return s.Store.Delete(ctx, key, v)
}

// headerDeleting reads the stored header sealed to the test release:
// whether it exists and whether it records Deleting.
func (f *fixture) headerDeleting() (bool, bool) {
	f.t.Helper()
	b, _, err := f.store.Get(context.Background(), store.HeaderKey(f.vid, testRelease.PCR0))
	if errors.Is(err, store.ErrNotFound) {
		return false, false
	}
	if err != nil {
		f.t.Fatal(err)
	}
	h, err := PeekHeader(context.Background(), f.opts.Sealer, b, f.vid, testRelease.PCR0)
	if err != nil {
		f.t.Fatal(err)
	}
	return true, h.Deleting
}

type eventLog struct {
	mu sync.Mutex
	ev []string
}

func (l *eventLog) add(ev LifecycleEvent) { l.mu.Lock(); l.ev = append(l.ev, ev.Event); l.mu.Unlock() }
func (l *eventLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.ev...)
}

// Step 2 waits for the host's ok: when MarkDeleting is asked, the header
// records Deleting and nothing of step 2 (mailbox deletion, notices) has
// left; after the ok the deletion runs to `deleted`.
func TestMarkDeletingBeforeStep2(t *testing.T) {
	d := newDevFixture(t)
	var events eventLog
	d.m.opt.Lifecycle = events.add
	var asked []string
	d.m.opt.MarkDeleting = func(_ context.Context, vid string) error {
		asked = append(asked, vid)
		if exists, marked := d.headerDeleting(); !exists || !marked {
			t.Error("asked before the header's mark was stored")
		}
		if d.relay.mailboxDeleted != 0 || d.depositsTo(d.devPeer.Relay.Mailbox) != 0 {
			t.Error("step 2 began before the host's ok")
		}
		return nil
	}
	d.m.mu.Lock()
	d.m.beginDelete("app", time.Now())
	d.m.mu.Unlock()
	if err := d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0] != d.vid {
		t.Fatalf("MarkDeleting asked %v", asked)
	}
	if d.relay.mailboxDeleted != 1 || d.depositsTo(d.devPeer.Relay.Mailbox) == 0 {
		t.Fatal("step 2 did not run after the ok")
	}
	if ev := events.all(); len(ev) == 0 || ev[len(ev)-1] != "deleted" {
		t.Fatalf("lifecycle %v", ev)
	}
}

// Without the host's ok within the bound the vault ends locked, reports
// `locked`, keeps state and header marked and delivers nothing; the
// member's next unlock finishes the deletion (P19).
func TestMarkDeletingBound(t *testing.T) {
	d := newDevFixture(t)
	var events eventLog
	d.m.opt.Lifecycle = events.add
	d.m.opt.DeleteRetry = fastRetry
	var mu sync.Mutex
	var at []time.Time
	d.m.opt.MarkDeleting = func(context.Context, string) error {
		mu.Lock()
		at = append(at, time.Now())
		mu.Unlock()
		return errors.New("parent: error")
	}
	d.m.mu.Lock()
	d.m.beginDelete("app", time.Now())
	d.m.mu.Unlock()
	start := time.Now()
	err := d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	took := time.Since(start)
	if !errors.Is(err, ErrNotMarked) {
		t.Fatalf("err %v", err)
	}
	if took < fastRetry.Mark || took > fastRetry.Mark+fastRetry.Cap+500*time.Millisecond {
		t.Fatalf("gave up after %v (bound %v)", took, fastRetry.Mark)
	}
	if len(at) < 4 {
		t.Fatalf("asked %d times", len(at))
	}
	// From First, doubling, never more than Cap between requests.
	for i := 2; i < len(at); i++ {
		if gap := at[i].Sub(at[i-1]); gap > fastRetry.Cap+50*time.Millisecond {
			t.Fatalf("gap %d is %v", i, gap)
		}
	}
	if !d.m.Locked() {
		t.Fatal("still running")
	}
	if d.relay.mailboxDeleted != 0 || d.depositsTo(d.devPeer.Relay.Mailbox) != 0 {
		t.Fatal("step 2 ran without the host's ok")
	}
	if exists, marked := d.headerDeleting(); !exists || !marked {
		t.Fatal("the header's mark is gone")
	}
	if !exists(t, d.store, store.StateKey(d.vid)) {
		t.Fatal("the state is gone")
	}
	if ev := events.all(); len(ev) == 0 || ev[len(ev)-1] != "locked" || containsStr(ev, "deleted") {
		t.Fatalf("lifecycle %v", ev)
	}
	// The member's unlock converges: the header records Deleting.
	if m, _, err := d.unlock(testPIN, 0, 0); err == nil || m != nil {
		t.Fatal("a marked vault opened")
	}
	if exists(t, d.store, store.StateKey(d.vid)) || exists(t, d.store, store.HeaderKey(d.vid, testRelease.PCR0)) {
		t.Fatal("not erased by the unlock")
	}
}

// The real schedules: from 1 s doubling to 15 s, 2 minutes for the mark
// and 60 s for step 4.
func TestDeleteRetryDefaults(t *testing.T) {
	m := &Manager{}
	if r := m.deleteRetry(); r != (DeleteRetry{First: time.Second, Cap: 15 * time.Second, Mark: 2 * time.Minute, Erase: 60 * time.Second}) {
		t.Fatalf("%+v", r)
	}
	m.opt.DeleteRetry = &DeleteRetry{Mark: time.Second}
	if r := m.deleteRetry(); r.Mark != time.Second || r.First != time.Second || r.Erase != 60*time.Second {
		t.Fatalf("%+v", r)
	}
}

// retryFor's waits double from first up to most, and it stops at the
// budget with the last error, or at the first success.
func TestRetryFor(t *testing.T) {
	var at []time.Time
	start := time.Now()
	err := retryFor(context.Background(), 300*time.Millisecond, 10*time.Millisecond, 80*time.Millisecond, func(ctx context.Context) error {
		at = append(at, time.Now())
		if _, ok := ctx.Deadline(); !ok {
			t.Error("a call without the budget's deadline")
		}
		return errors.New("no")
	})
	if err == nil || time.Since(start) < 300*time.Millisecond || time.Since(start) > 600*time.Millisecond {
		t.Fatalf("err %v after %v", err, time.Since(start))
	}
	want := []time.Duration{10, 20, 40, 80, 80}
	for i := 1; i < len(at) && i <= len(want); i++ {
		gap := at[i].Sub(at[i-1])
		if w := want[i-1] * time.Millisecond; gap < w || gap > w+40*time.Millisecond {
			t.Fatalf("gap %d: %v, want about %v", i, gap, w)
		}
	}
	n := 0
	if err := retryFor(context.Background(), time.Second, time.Millisecond, time.Millisecond, func(context.Context) error {
		n++
		if n < 3 {
			return errors.New("no")
		}
		return nil
	}); err != nil || n != 3 {
		t.Fatalf("err %v after %d calls", err, n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := retryFor(ctx, time.Minute, time.Second, time.Second, func(context.Context) error { return errors.New("no") }); err == nil {
		t.Fatal("a cancelled retry succeeded")
	}
}

// Crash point: the marking flush stored the state but not the header. No
// step 2 leaves; a lock then flushes the mark and tells nobody; an unlock
// of the state-only mark does not start the vault but completes step 1
// (header, then the host's mark) and runs steps 2 to 5 with the keys the
// state holds, reporting `deleted` and never `unlocked`.
func TestStateMarkedHeaderNot(t *testing.T) {
	for _, then := range []string{"crash", "lock", "next-batch"} {
		t.Run(then, func(t *testing.T) {
			d := newDevFixture(t)
			fs := &putFailStore{Store: d.store, key: store.HeaderKey(d.vid, testRelease.PCR0), n: 1}
			d.m.opt.Store = fs
			var events eventLog
			d.m.opt.Lifecycle = events.add
			marks := 0
			mark := func(context.Context, string) error {
				marks++
				if exists, marked := d.headerDeleting(); !exists || !marked {
					t.Error("asked before the header's mark was stored")
				}
				if d.relay.mailboxDeleted != 0 {
					t.Error("step 2 began before the host's ok")
				}
				return nil
			}
			d.m.opt.MarkDeleting = mark
			d.m.mu.Lock()
			d.m.beginDelete("app", time.Now())
			d.m.mu.Unlock()
			if err := d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err == nil {
				t.Fatal("the header write did not fail")
			}
			if _, marked := d.headerDeleting(); marked {
				t.Fatal("the header was marked")
			}
			if d.relay.mailboxDeleted != 0 || d.depositsTo(d.devPeer.Relay.Mailbox) != 0 || marks != 0 {
				t.Fatal("something of the deletion left after a failed marking flush")
			}
			switch then {
			case "crash":
				d.m.Crash()
			case "lock":
				if err := d.m.Lock(context.Background()); err != nil {
					t.Fatal(err)
				}
				if d.depositsTo(d.devPeer.Relay.Mailbox) != 0 || d.relay.mailboxDeleted != 0 || marks != 0 {
					t.Fatal("a lock delivered the deletion's notices")
				}
				if _, marked := d.headerDeleting(); !marked {
					t.Fatal("the lock did not flush the mark")
				}
				if ev := events.all(); len(ev) == 0 || ev[len(ev)-1] != "locked" {
					t.Fatalf("lifecycle %v", ev)
				}
				return // the header records Deleting: TestDeleteCrashConverges
			case "next-batch":
				// The run loop's next batch, with nothing collected:
				// the header is written before the host is asked.
				if err := d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
					t.Fatal(err)
				}
				if marks != 1 || d.relay.mailboxDeleted != 1 || exists(t, d.store, store.StateKey(d.vid)) {
					t.Fatalf("not finished: %d marks", marks)
				}
				return
			}
			var unlockEvents eventLog
			d.opts.Lifecycle = unlockEvents.add
			d.opts.MarkDeleting = mark
			if m, _, err := d.unlock(testPIN, 0, 0); err == nil || m != nil {
				t.Fatal("a vault whose state records deleting opened")
			}
			if marks != 1 {
				t.Fatalf("MarkDeleting asked %d times", marks)
			}
			if d.relay.mailboxDeleted != 1 || d.depositsTo(d.devPeer.Relay.Mailbox) == 0 {
				t.Fatal("the notices and the mailbox deletion did not happen")
			}
			if exists(t, d.store, store.StateKey(d.vid)) || exists(t, d.store, store.HeaderKey(d.vid, testRelease.PCR0)) {
				t.Fatal("not erased")
			}
			if ev := unlockEvents.all(); len(ev) != 1 || ev[0] != "deleted" {
				t.Fatalf("lifecycle %v", ev)
			}
		})
	}
}

// The unlock of a state-only mark without the host's ok: the header is
// marked, nothing is delivered, and `locked` (never `unlocked`) is
// reported; the state and header stay for the next unlock.
func TestStateMarkedUnlockWithoutOK(t *testing.T) {
	d := newDevFixture(t)
	d.m.opt.Store = &putFailStore{Store: d.store, key: store.HeaderKey(d.vid, testRelease.PCR0), n: 1}
	d.m.mu.Lock()
	d.m.beginDelete("app", time.Now())
	d.m.mu.Unlock()
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	d.m.Crash()
	var events eventLog
	d.opts.Lifecycle = events.add
	d.opts.DeleteRetry = fastRetry
	d.opts.MarkDeleting = func(context.Context, string) error { return errors.New("no") }
	if m, _, err := d.unlock(testPIN, 0, 0); err == nil || m != nil {
		t.Fatal("opened")
	}
	if d.relay.mailboxDeleted != 0 || d.depositsTo(d.devPeer.Relay.Mailbox) != 0 {
		t.Fatal("delivered without the host's ok")
	}
	if exists, marked := d.headerDeleting(); !exists || !marked {
		t.Fatal("the header was not marked")
	}
	if ev := events.all(); len(ev) != 1 || ev[0] != "locked" {
		t.Fatalf("lifecycle %v", ev)
	}
}

// beginDelete on a state already marked completes step 1 rather than
// doing nothing: the header is marked and the deletion is pending.
func TestBeginDeleteAlreadyMarked(t *testing.T) {
	f := newFixture(t)
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	f.m.st.Deleting = &Deletion{At: time.Now(), Via: "app"}
	f.m.hdr.Deleting, f.m.deletePending = false, false
	f.m.beginDelete("host", time.Now())
	if !f.m.hdr.Deleting || !f.m.deletePending || f.m.st.Deleting.Via != "app" {
		t.Fatalf("header %v pending %v via %s", f.m.hdr.Deleting, f.m.deletePending, f.m.st.Deleting.Via)
	}
}

// Step 4: a store error is retried in the process; after the bound the
// process ends without reporting, and the marker stays for the resume.
func TestEraseRetry(t *testing.T) {
	for _, n := range []int{2, -1} {
		f := newFixture(t)
		var events eventLog
		f.m.opt.Lifecycle = events.add
		f.m.opt.DeleteRetry = fastRetry
		f.m.opt.Store = &delFailStore{Store: f.store, key: store.HeaderKey(f.vid, testRelease.PCR0), n: n}
		f.m.mu.Lock()
		f.m.beginDelete("app", time.Now())
		f.m.mu.Unlock()
		start := time.Now()
		err := f.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
		ev := events.all()
		if n > 0 {
			if err != nil || !containsStr(ev, "deleted") || exists(t, f.store, store.HeaderKey(f.vid, testRelease.PCR0)) {
				t.Fatalf("retried erase: err %v, lifecycle %v", err, ev)
			}
			continue
		}
		if err == nil || containsStr(ev, "deleted") || containsStr(ev, "locked") {
			t.Fatalf("failed erase: err %v, lifecycle %v", err, ev)
		}
		if time.Since(start) < fastRetry.Erase {
			t.Fatalf("gave up after %v", time.Since(start))
		}
		if exists, marked := f.headerDeleting(); !exists || !marked {
			t.Fatal("the marker is gone")
		}
		if !f.m.Locked() {
			t.Fatal("still running")
		}
	}
}

// resumeFixture is a vault and the inputs of ResumeDelete.
func resumeCase(t *testing.T) (*fixture, func() string) {
	f := newFixture(t)
	if err := f.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := f.store.Put(ctx, store.UserKey(UserIndexHash("u1")), []byte(f.vid), ""); err != nil {
		t.Fatal(err)
	}
	return f, func() string { return ResumeDelete(ctx, f.store, f.opts.Sealer, testRelease.PCR0, f.vid, "u1") }
}

// Every row of §12.5's resume table, and that the message alone never
// erases a vault the enclave can read as live (P20).
func TestResumeDelete(t *testing.T) {
	ctx := context.Background()
	idx := store.UserKey(UserIndexHash("u1"))
	all := func(f *fixture) []string {
		return []string{store.StateKey(f.vid), store.HeaderKey(f.vid, testRelease.PCR0), idx}
	}
	t.Run("header records deleting", func(t *testing.T) {
		f, resume := resumeCase(t)
		// A deletion stopped after its marking flush and host mark.
		f.m.opt.MarkDeleting = func(context.Context, string) error { return errors.New("stop") }
		f.m.opt.DeleteRetry = &DeleteRetry{Mark: time.Nanosecond}
		m, _, err := f.unlock(testPIN, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		m.opt.MarkDeleting, m.opt.DeleteRetry = f.m.opt.MarkDeleting, f.m.opt.DeleteRetry
		m.mu.Lock()
		m.beginDelete("app", time.Now())
		m.mu.Unlock()
		if err := m.ProcessBatch(ctx, &fakeCollector{}, nil); !errors.Is(err, ErrNotMarked) {
			t.Fatalf("err %v", err)
		}
		if got := resume(); got != ResumeFinished {
			t.Fatalf("outcome %s", got)
		}
		for _, k := range all(f) {
			if exists(t, f.store, k) {
				t.Fatalf("%s left", k)
			}
		}
		if got := resume(); got != ResumeErased {
			t.Fatalf("again: %s", got) // idempotent: now nothing is left
		}
	})
	t.Run("header records no deletion", func(t *testing.T) {
		f, resume := resumeCase(t)
		if got := resume(); got != ResumeLive {
			t.Fatalf("outcome %s", got)
		}
		for _, k := range all(f) {
			if !exists(t, f.store, k) {
				t.Fatalf("%s erased", k)
			}
		}
		if m, _, err := f.unlock(testPIN, 0, 0); err != nil || m == nil {
			t.Fatal("the live vault no longer opens")
		}
	})
	t.Run("no header, no state", func(t *testing.T) {
		f, resume := resumeCase(t)
		_ = EraseStored(ctx, f.store, f.vid, "", nil, testRelease.PCR0, "", "")
		if got := resume(); got != ResumeErased || exists(t, f.store, idx) {
			t.Fatalf("outcome %s", got)
		}
		// An index naming another vault is not touched.
		_, _ = f.store.Put(ctx, idx, []byte("othervault"), "")
		if got := resume(); got != ResumeErased || !exists(t, f.store, idx) {
			t.Fatalf("another vault's index: %s", got)
		}
	})
	t.Run("no header, a state", func(t *testing.T) {
		f, resume := resumeCase(t)
		_, v, _ := f.store.Get(ctx, store.HeaderKey(f.vid, testRelease.PCR0))
		_ = f.store.Delete(ctx, store.HeaderKey(f.vid, testRelease.PCR0), v)
		if got := resume(); got != ResumeState {
			t.Fatalf("outcome %s", got)
		}
		if !exists(t, f.store, store.StateKey(f.vid)) || !exists(t, f.store, idx) {
			t.Fatal("erased")
		}
	})
	t.Run("unreadable header", func(t *testing.T) {
		f, resume := resumeCase(t)
		// A header the enclave cannot unseal: garbage, or sealed under
		// a key that is not the release's (what a forger can write).
		hk := store.HeaderKey(f.vid, testRelease.PCR0)
		forged := *f
		forged.opts.Sealer = testSealer{key: make([]byte, 32)}
		for _, blob := range [][]byte{[]byte("not a header"), forgedDeletingHeader(t, &forged)} {
			_, v, _ := f.store.Get(ctx, hk)
			if _, err := f.store.Put(ctx, hk, blob, v); err != nil {
				t.Fatal(err)
			}
			if got := resume(); got != ResumeUnreadable {
				t.Fatalf("outcome %s", got)
			}
			for _, k := range all(f) {
				if !exists(t, f.store, k) {
					t.Fatalf("%s erased", k)
				}
			}
		}
	})
	t.Run("store unreadable", func(t *testing.T) {
		f, _ := resumeCase(t)
		got := ResumeDelete(ctx, errStore{f.store}, f.opts.Sealer, testRelease.PCR0, f.vid, "u1")
		if got != ResumeUnreadable {
			t.Fatalf("outcome %s", got)
		}
		for _, k := range all(f) {
			if !exists(t, f.store, k) {
				t.Fatalf("%s erased", k)
			}
		}
	})
}

// forgedDeletingHeader is the vault's header with Deleting set, sealed
// under f's sealer.
func forgedDeletingHeader(t *testing.T, f *fixture) []byte {
	t.Helper()
	ctx := context.Background()
	h := *f.m.hdr
	h.Deleting = true
	b, err := sealHeader(ctx, f.opts.Sealer, &h)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// errStore fails every read.
type errStore struct{ store.Store }

func (errStore) Get(context.Context, string) ([]byte, store.Version, error) {
	return nil, "", errors.New("store unreachable")
}

// A recovery's open that finds a state recording deleting (its header
// without the mark) does not start the vault: the deletion is finished
// and the open is dropped, as for a missing vault (0.51.0, §12.5).
func TestRecoveryOpenStateMarked(t *testing.T) {
	var dek []byte
	f := newOpenFixtureWith(t, func(f *openFixture) { dek = append([]byte(nil), f.m.dek...) })
	ctx := context.Background()
	b, v, err := f.st.Get(ctx, store.StateKey(f.vid))
	if err != nil {
		t.Fatal(err)
	}
	ver, _ := StateDEKVersion(b)
	pt, seq, err := decryptState(dek, f.vid, b)
	if err != nil {
		t.Fatal(err)
	}
	var st State
	if err := json.Unmarshal(pt, &st); err != nil {
		t.Fatal(err)
	}
	st.Deleting = &Deletion{At: f.clock, Via: "app"}
	pt, _ = json.Marshal(&st)
	nb, err := encryptState(dek, ver, f.vid, seq, pt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Put(ctx, store.StateKey(f.vid), nb, v); err != nil {
		t.Fatal(err)
	}
	var events eventLog
	marks := 0
	f.opts.Lifecycle = events.add
	f.opts.MarkDeleting = func(context.Context, string) error { marks++; return nil }
	m, out := f.open(testPIN, rPW)
	if m != nil || !out.Drop || out.OK {
		t.Fatalf("open: %+v", out)
	}
	if marks != 1 {
		t.Fatalf("MarkDeleting asked %d times", marks)
	}
	if exists(t, f.st, store.StateKey(f.vid)) || exists(t, f.st, store.HeaderKey(f.vid, testRelease.PCR0)) {
		t.Fatal("not erased")
	}
	if ev := events.all(); len(ev) != 1 || ev[0] != "deleted" {
		t.Fatalf("lifecycle %v", ev)
	}
}
