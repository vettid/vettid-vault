package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/vaultipc"
	"github.com/vettid/vettid-vault/vault"
)

// The "parent unreachable" rule (§12.3; VAULT-HOST-PROTOCOL §13 point 1):
// every vault is locked once 120 s have passed without a Ping from the
// parent, connected or not. These tests run checkParent, the check that
// maintain makes every 10 s, on a clock of their own.

const window = 120 * time.Second

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeVaults stands for the vault processes: the vaults running, and
// LockAllWithin.
type fakeVaults struct {
	mu     sync.Mutex
	ids    []string
	locked int // LockAllWithin calls that found a vault
	// fail is the error LockAllWithin reports for a vault (none: locked).
	fail map[string]error
}

func (v *fakeVaults) Vaults() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.ids...)
}

func (v *fakeVaults) LockAllWithin(context.Context, time.Duration) map[string]error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.ids) > 0 {
		v.locked++
	}
	ended := map[string]error{}
	for _, id := range v.ids {
		ended[id] = v.fail[id]
	}
	v.ids = nil
	return ended
}

func (v *fakeVaults) unlock(id string) {
	v.mu.Lock()
	v.ids = append(v.ids, id)
	v.mu.Unlock()
}

func (v *fakeVaults) locks() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.locked
}

// watched is a supervisor reduced to its link, its clock and the check.
type watched struct {
	t      *testing.T
	s      *Supervisor
	clk    *testClock
	vaults *fakeVaults
	at     time.Duration // since the start
	conn   *hostproto.Conn
	parent *hostproto.Conn

	logMu   sync.Mutex
	logs    []string // the messages of the log records the parent got
	stopped []string // "vault_id reason" of each Stopped the parent got
}

func (w *watched) stoppedSeen() []string {
	w.logMu.Lock()
	defer w.logMu.Unlock()
	out := append([]string(nil), w.stopped...)
	sort.Strings(out)
	return out
}

func (w *watched) logged(msg string) int {
	w.logMu.Lock()
	defer w.logMu.Unlock()
	n := 0
	for _, m := range w.logs {
		if m == msg {
			n++
		}
	}
	return n
}

func newWatched(t *testing.T) *watched {
	clk := &testClock{t: time.Unix(1_800_000_000, 0)}
	l := &link{}
	l.hear(clk.now())
	s := &Supervisor{cfg: Config{DownLock: window}, link: l, now: clk.now, activity: map[string]time.Time{}}
	s.log = slog.New(&logHandler{l: l, level: slog.LevelError + 1}) // quiet
	return &watched{t: t, s: s, clk: clk, vaults: &fakeVaults{}}
}

// connect gives the supervisor a control connection to a parent that
// reads and answers nothing of its own accord.
func (w *watched) connect() {
	a, b := net.Pipe()
	w.conn = hostproto.NewConnOptions(a, w.s.handle, nil, w.s.connOptions())
	w.parent = hostproto.NewConn(b, nil, func(f *hostproto.Frame) {
		w.logMu.Lock()
		defer w.logMu.Unlock()
		switch {
		case f.Kind == hostproto.KindLog && len(f.Fields) >= 2:
			w.logs = append(w.logs, string(f.Fields[1]))
		case f.Kind == hostproto.KindStopped && len(f.Fields) == 2:
			w.stopped = append(w.stopped, string(f.Fields[0])+" "+string(f.Fields[1]))
		}
	})
	w.s.link.set(w.conn)
	w.t.Cleanup(w.conn.Close)
	w.t.Cleanup(w.parent.Close)
}

// lose ends the connection as Run sees it.
func (w *watched) lose() {
	w.parent.Close()
	<-w.conn.Done()
	w.s.link.set(nil)
}

// ping is the parent's Ping, read by the supervisor before it returns.
func (w *watched) ping() {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := w.parent.Call(ctx, hostproto.KindPing); err != nil {
		w.t.Fatalf("ping at %v: %v", w.at, err)
	}
}

// run advances the clock to `to` in steps of 10 s, checking at each as
// maintain does; at each step do (if any) runs first.
func (w *watched) run(to time.Duration, do func(at time.Duration)) {
	for w.at < to {
		w.clk.add(10 * time.Second)
		w.at += 10 * time.Second
		if do != nil {
			do(w.at)
		}
		w.s.checkParent(context.Background(), w.vaults)
	}
}

func (w *watched) want(locks int, what string) {
	w.t.Helper()
	if got := w.vaults.locks(); got != locks {
		w.t.Fatalf("at %v, %s: %d locks, want %d", w.at, what, got, locks)
	}
}

// A parent that stays connected and says nothing: every vault is locked
// 120 s after its last Ping, at the first check after that and not
// before, and the connection is ended as lost.
func TestSilentParentLocks(t *testing.T) {
	w := newWatched(t)
	w.connect()
	w.vaults.unlock("aaaa")
	w.run(60*time.Second, nil)
	w.ping() // at 60 s: the last one
	w.run(180*time.Second, nil)
	w.want(0, "120 s after the last ping")
	select {
	case <-w.conn.Done():
		t.Fatal("connection ended before the parent was unreachable")
	default:
	}
	w.run(190*time.Second, nil)
	w.want(1, "the first check after 120 s without a ping")
	select {
	case <-w.conn.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the silent connection was kept")
	}
	// Nothing runs and nothing more happens. The parent stays unreachable
	// until it pings: checks that find no vault do not change that, no
	// call is made to it, and a vault that turns up under it (an unlock
	// that was half way when the others were locked) is locked by the
	// next check, not 120 s later.
	w.run(600*time.Second, nil)
	w.want(1, "no vault running")
	w.connect()
	if _, err := w.s.link.call(context.Background(), hostproto.KindStoreGet, []byte("vaults/v/state")); !errors.Is(err, errDown) {
		t.Fatalf("a call to a parent that has not pinged, after checks with no vault running: %v", err)
	}
	w.vaults.unlock("bbbb")
	w.run(610*time.Second, nil)
	w.want(2, "a vault that turned up under an unreachable parent")
	// It pings (on a new connection: that check ended the last one too):
	// reachable, and a vault has the whole time again.
	w.connect()
	w.ping()
	if _, err := w.s.link.call(context.Background(), hostproto.KindStoreGet, []byte("vaults/v/state")); err != nil {
		t.Fatalf("a call after the parent's ping: %v", err)
	}
	w.vaults.unlock("cccc")
	w.run(730*time.Second, nil)
	w.want(2, "120 s after the ping")
	w.run(740*time.Second, nil)
	w.want(3, "no further ping")
}

// The parent counts a vault as running, and renews its lease, until it is
// told otherwise. The vaults that were locked or killed while it was
// unreachable are told to it when its next Ping is read (their own events
// found no connection; a killed process sends none), before it is
// reachable again, and kept if they cannot be told then.
func TestStoppedVaultsAreTold(t *testing.T) {
	w := newWatched(t)
	w.connect()
	w.ping()
	w.vaults.fail = map[string]error{"killed": context.DeadlineExceeded, "split": vault.ErrSplitBrain}
	for _, id := range []string{"locked", "killed", "split"} {
		w.vaults.unlock(id)
	}
	w.run(130*time.Second, nil)
	w.want(1, "no ping")
	<-w.conn.Done()
	w.s.link.set(nil) // as Run does
	if got := w.stoppedSeen(); len(got) != 0 {
		t.Fatalf("told to a parent that is gone: %v", got)
	}
	// A new connection alone tells nothing; the ping on it does.
	w.connect()
	w.run(200*time.Second, nil)
	if got := w.stoppedSeen(); len(got) != 0 {
		t.Fatalf("told before the ping: %v", got)
	}
	w.ping()
	if err := w.conn.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"killed error", "locked locked", "split split_brain"}
	deadline := time.Now().Add(10 * time.Second)
	for len(w.stoppedSeen()) < len(want) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := w.stoppedSeen(); !reflect.DeepEqual(got, want) {
		t.Fatalf("stopped vaults told: %v, want %v", got, want)
	}
	// Once only.
	w.ping()
	_ = w.conn.Flush(context.Background())
	time.Sleep(20 * time.Millisecond)
	if got := w.stoppedSeen(); len(got) != len(want) {
		t.Fatalf("told again: %v", got)
	}
	// Without a connection at the ping they are kept for the next.
	l := &link{}
	l.stop("aaaa", hostproto.StopLocked)
	l.ping(time.Unix(1_800_000_000, 0))
	if len(l.stopped) != 1 {
		t.Fatalf("kept: %v", l.stopped)
	}
}

// Pings arriving: nothing is ever locked, over a day of them, and with
// pings as late as 110 s.
func TestPingsKeepVaults(t *testing.T) {
	w := newWatched(t)
	w.connect()
	w.vaults.unlock("aaaa")
	w.run(24*time.Hour, func(at time.Duration) {
		if at%(20*time.Second) == 0 {
			w.ping()
		}
	})
	w.want(0, "a ping every 20 s for a day")
	w.run(25*time.Hour, func(at time.Duration) {
		if at%(110*time.Second) == 0 {
			w.ping()
		}
	})
	w.want(0, "a ping every 110 s for an hour")
	select {
	case <-w.conn.Done():
		t.Fatal("connection ended")
	default:
	}
}

// The connection is lost and comes back, and the pings go on: nothing is
// locked. They stop: locked 120 s after the last.
func TestReconnectWithPings(t *testing.T) {
	w := newWatched(t)
	w.connect()
	w.vaults.unlock("aaaa")
	w.ping()
	w.run(30*time.Second, nil)
	w.lose()
	w.run(60*time.Second, nil)
	w.connect()
	w.run(80*time.Second, nil)
	w.ping()
	w.run(200*time.Second, nil)
	w.want(0, "pings after the reconnect")
	w.run(210*time.Second, nil)
	w.want(1, "120 s after the last ping")
}

// A new connection alone changes nothing: a parent that dials again and
// again without a Ping has its vaults locked 120 s after its last Ping,
// not after its last connection.
func TestReconnectWithoutPings(t *testing.T) {
	w := newWatched(t)
	w.connect()
	w.vaults.unlock("aaaa")
	w.ping() // at 0
	w.run(120*time.Second, func(at time.Duration) {
		if at%(30*time.Second) == 0 {
			w.lose()
			w.connect()
		}
	})
	w.want(0, "120 s after the last ping")
	w.run(130*time.Second, nil)
	w.want(1, "connections without a ping")
}

// A lost connection, as before this rule: locked within 120 s of the loss
// (here the last Ping was 10 s before it), and no later.
func TestLostConnectionLocks(t *testing.T) {
	w := newWatched(t)
	w.connect()
	w.vaults.unlock("aaaa")
	w.run(50*time.Second, nil)
	w.ping()
	w.run(60*time.Second, nil)
	w.lose()
	w.run(170*time.Second, nil)
	w.want(0, "110 s after the loss")
	w.run(180*time.Second, nil)
	w.want(1, "120 s after the loss")
}

// Before the first Ping: the time counts from when a vault runs, not from
// the supervisor's start or the session's, so an unlock that the parent
// forwards before its first Ping is not locked at once. A parent that
// never pings at all (none does: the S10 parent pings every 20 s like
// this one) has every vault locked 120 s after it was unlocked.
func TestBeforeTheFirstPing(t *testing.T) {
	w := newWatched(t)
	w.run(300*time.Second, nil) // no parent for five minutes
	w.connect()
	w.run(310*time.Second, nil)
	w.vaults.unlock("aaaa") // forwarded before the first ping
	w.run(320*time.Second, nil)
	w.want(0, "an unlock before the first ping")
	w.ping()
	w.run(440*time.Second, nil)
	w.want(0, "120 s after the first ping")
	w.run(450*time.Second, nil)
	w.want(1, "no second ping")

	w = newWatched(t)
	w.connect()
	w.run(20*time.Second, nil)
	w.vaults.unlock("aaaa")
	w.run(140*time.Second, nil)
	w.want(0, "120 s after the unlock")
	w.run(150*time.Second, nil)
	w.want(1, "a parent that never pings")
}

// The supervisor's own reader at the request limit (128 of the parent's
// requests in flight) reads nothing, so a Ping the parent did send waits
// in the socket. That time is not counted as the parent's silence; once
// the reader goes on, the Ping is read. It is left out only up to 120 s:
// a reader that never goes on does not keep vaults unlocked.
func TestReaderAtLimitIsNotSilence(t *testing.T) {
	w := newWatched(t)
	hold := make(chan struct{})
	a, b := net.Pipe()
	w.conn = hostproto.NewConnOptions(a, func(ctx context.Context, f *hostproto.Frame) [][]byte {
		if f.Kind != hostproto.KindPing {
			<-hold
		}
		return w.s.handle(ctx, f)
	}, nil, w.s.connOptions())
	w.parent = hostproto.NewConn(b, nil, nil)
	w.s.link.set(w.conn)
	defer w.conn.Close()
	defer w.parent.Close()
	w.vaults.unlock("aaaa")
	w.ping() // at 0
	w.run(10*time.Second, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < hostproto.MaxInflight+1; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = w.parent.Call(ctx, hostproto.KindQueue, nil, nil) }()
	}
	stalled := func() bool {
		w.s.link.mu.Lock()
		defer w.s.link.mu.Unlock()
		return !w.s.link.waitSince.IsZero()
	}
	for !stalled() {
		if ctx.Err() != nil {
			t.Fatal("the reader did not reach its limit")
		}
		time.Sleep(time.Millisecond)
	}
	pinged := make(chan struct{})
	go func() { defer close(pinged); _, _ = w.parent.Call(ctx, hostproto.KindPing) }() // sent, not read
	w.run(240*time.Second, nil)
	w.want(0, "230 s with the reader at its limit")
	if got := w.s.link.silent(w.clk.now(), window); got != 120*time.Second {
		t.Fatalf("silence counted: %v, want 120 s (240 s less the 120 s that may be left out)", got)
	}
	close(hold)
	wg.Wait()
	<-pinged
	if got := w.s.link.silent(w.clk.now(), window); got != 0 {
		t.Fatalf("silence after the waiting ping was read: %v", got)
	}
	w.run(360*time.Second, nil)
	w.want(0, "120 s after the ping that had waited")
	w.run(370*time.Second, nil)
	w.want(1, "no further ping")

	// The reader waits and never goes on: locked all the same, 240 s
	// after the last ping.
	l := &link{}
	t0 := time.Unix(1_800_000_000, 0)
	l.hear(t0)
	l.waiting(t0.Add(10*time.Second), true)
	if got := l.silent(t0.Add(240*time.Second), window); got > window {
		t.Fatalf("at 240 s: %v", got)
	}
	if got := l.silent(t0.Add(250*time.Second), window); got <= window {
		t.Fatalf("at 250 s: %v", got)
	}
	// Waiting that ended is left out too; a ping starts the count again.
	l.waiting(t0.Add(100*time.Second), false)
	if got := l.silent(t0.Add(150*time.Second), window); got != 60*time.Second {
		t.Fatalf("after a wait of 90 s: %v", got)
	}
	l.hear(t0.Add(150 * time.Second))
	if got := l.silent(t0.Add(160*time.Second), window); got != 10*time.Second {
		t.Fatalf("after a ping: %v", got)
	}
}

// A parent that stops reading. Logging never waits for it: records that
// do not fit are dropped and counted, and the count is told once there is
// somebody to tell.
func TestLoggingNeverWaits(t *testing.T) {
	w := newWatched(t)
	a, b := net.Pipe() // nobody reads b
	defer b.Close()
	// No write timeout on this one: nothing but the logger's own rule
	// can let it return.
	conn := hostproto.NewConn(a, w.s.handle, nil)
	defer conn.Close()
	w.s.link.set(conn)
	// The connection holds 256 frames, and one more once the writer has
	// taken its first: fill it.
	held := 0
	for tries := 0; held < 257; tries++ {
		if w.s.link.logRecord(hostproto.Strings("INFO", "record")...) {
			held++
		} else if tries > 10000 {
			t.Fatalf("the connection took %d records", held)
		} else {
			time.Sleep(100 * time.Microsecond)
		}
	}
	before := w.s.link.logDropped.Load()
	log := slog.New(&logHandler{l: w.s.link, level: slog.LevelError})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			w.s.link.logRecord(hostproto.Strings("INFO", "record")...)
		}
		log.Error("one through the logger")
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("logging waits for a parent that does not read")
	}
	dropped := w.s.link.logDropped.Load()
	if dropped-before != 1001 {
		t.Fatalf("%d of 1,001 records dropped", dropped-before)
	}
	// The report is a record too: dropped here, kept while there is no
	// connection, told to the next parent that reads.
	w.s.reportDropped()
	dropped++
	if w.s.droppedTold != 0 || w.s.link.logDropped.Load() != dropped {
		t.Fatalf("report on a full queue: told %d, dropped %d", w.s.droppedTold, w.s.link.logDropped.Load())
	}
	conn.Close()
	w.s.link.set(nil)
	w.s.reportDropped()
	if w.s.droppedTold != 0 {
		t.Fatal("the count was told to nobody")
	}
	w.connect()
	w.s.reportDropped()
	if w.s.droppedTold != dropped {
		t.Fatalf("told %d of %d", w.s.droppedTold, dropped)
	}
	if err := w.conn.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	for n := 0; w.logged("log records dropped: the parent was not reading") != 1; n++ {
		if n > 5000 {
			t.Fatal("the parent did not get the count")
		}
		time.Sleep(time.Millisecond)
	}
}

// A parent that stops reading: a lifecycle event is not dropped, it
// waits, but only until the write timeout ends the connection; from then
// the parent is on the 120 s clock like any other that is gone.
func TestParentStopsReading(t *testing.T) {
	w := newWatched(t)
	a, b := net.Pipe() // nobody reads b
	defer b.Close()
	opt := w.s.connOptions()
	if opt.WriteTimeout != 60*time.Second {
		t.Fatalf("write timeout %v", opt.WriteTimeout)
	}
	opt.WriteTimeout = 2 * time.Second
	start := time.Now()
	conn := hostproto.NewConnOptions(a, w.s.handle, nil, opt)
	defer conn.Close()
	w.s.link.set(conn)
	w.vaults.unlock("aaaa")
	for held, tries := 0, 0; held < 257; tries++ { // as in TestLoggingNeverWaits
		if w.s.link.logRecord(hostproto.Strings("INFO", "record")...) {
			held++
		} else if tries > 10000 {
			t.Fatalf("the connection took %d records", held)
		} else {
			time.Sleep(100 * time.Microsecond)
		}
	}
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		w.s.link.notify(hostproto.KindLifecycle, hostproto.Strings("locked", "aaaa", "r", "r", "1")...)
	}()
	select {
	case <-sent:
		select {
		case <-conn.Done():
			t.Fatalf("the connection ended %v after its start, before the event could be seen to wait", time.Since(start))
		default:
			t.Fatal("a lifecycle event was dropped while the connection lived")
		}
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case <-sent:
	case <-time.After(20 * time.Second):
		t.Fatal("the supervisor waits for a parent that does not read")
	}
	<-conn.Done()
	if d := time.Since(start); d < opt.WriteTimeout {
		t.Fatalf("connection ended after %v, before the write timeout", d)
	}
	// As Run does on a lost connection; then the rule.
	w.s.link.set(nil)
	w.run(120*time.Second, nil)
	w.want(0, "120 s")
	w.run(130*time.Second, nil)
	w.want(1, "a parent that stopped reading")
}

// Half way to the lock the supervisor says so, once for each time the
// count started, and names no vault.
func TestWarnsBeforeTheLock(t *testing.T) {
	const warning = "no ping from the parent: every vault is locked if none comes"
	w := newWatched(t)
	w.s.log = slog.New(&logHandler{l: w.s.link, level: slog.LevelWarn})
	w.connect()
	w.vaults.unlock("aaaa")
	got := func(want int, what string) {
		t.Helper()
		if err := w.conn.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for w.logged(warning) < want && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		time.Sleep(20 * time.Millisecond) // one too many would arrive now
		if n := w.logged(warning); n != want {
			t.Fatalf("at %v, %s: %d warnings, want %d", w.at, what, n, want)
		}
	}
	w.ping()
	w.run(60*time.Second, nil)
	got(0, "60 s without a ping")
	w.run(110*time.Second, nil)
	got(1, "over 60 s without a ping, five checks")
	w.ping()
	w.run(170*time.Second, nil)
	got(1, "60 s after another ping")
	w.run(230*time.Second, nil)
	got(2, "over 60 s after it")
	w.want(0, "120 s after the last ping")
	w.run(240*time.Second, nil)
	w.want(1, "no further ping")
	w.logMu.Lock()
	defer w.logMu.Unlock()
	for _, m := range w.logs {
		if m != warning && m != "parent unreachable: locking every vault" && m != "parent unreachable: every vault locked" {
			t.Errorf("unexpected record %q", m)
		}
	}
}

// lockProc starts a process that stands for a vault's (it only sleeps)
// and gives it to h as that vault's, with a channel on which the test
// answers the supervisor's Lock as a vault process does: the final flush
// (a store write through the supervisor's link), then the answer. With
// hang it never answers. Like a vault process, it ends when its channel
// closes.
func lockProc(t *testing.T, h *procHost, id string, hang bool, flushed func(error, time.Duration)) *vproc {
	t.Helper()
	cmd := exec.Command("sleep", "600")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	p := &vproc{h: h, vaultID: id, cmd: cmd, exited: make(chan struct{})}
	p.conn = hostproto.NewConn(a, nil, nil)
	child := hostproto.NewConn(b, func(ctx context.Context, f *hostproto.Frame) [][]byte {
		if f.Kind != vaultipc.KindLock {
			return nil
		}
		if hang {
			<-ctx.Done()
			return nil
		}
		t0 := time.Now()
		_, err := h.s.link.call(context.WithoutCancel(ctx), hostproto.KindStorePut, []byte("vaults/"+id+"/state"), []byte("x"), nil)
		flushed(err, time.Since(t0))
		return hostproto.Strings(hostproto.StatusOK)
	}, nil)
	go func() { <-child.Done(); _ = cmd.Process.Kill() }()
	go func() {
		_ = cmd.Wait()
		p.conn.Close()
		close(p.exited)
		h.exited(p)
	}()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-p.exited })
	h.mu.Lock()
	h.procs[id] = p
	h.mu.Unlock()
	return p
}

// The case the rule is for: the host has lost its path to the store and
// the tables, and the parent's process lives. Its pings stop; it still
// accepts the supervisor's new connection and answers the hello; a store
// request gets no answer. Every vault is locked at once all the same: no
// call is made to a parent that is gone until it pings again, whatever
// connection there is, and the vaults lock side by side. (Before: the
// connection was closed, Run dialled again, and from the second vault on
// each final flush waited 60 s, one vault after another.)
func TestSilentParentThatReconnects(t *testing.T) {
	const vaults = 60
	w := newWatched(t)
	h := &procHost{s: w.s, procs: map[string]*vproc{}}
	h.cfg.defaults()
	w.connect()
	w.ping()
	var mu sync.Mutex
	var slowest time.Duration
	failed := 0
	for i := 0; i < vaults; i++ {
		lockProc(t, h, fmt.Sprintf("vault-%02d", i), false, func(err error, took time.Duration) {
			mu.Lock()
			defer mu.Unlock()
			if errors.Is(err, errDown) {
				failed++
			}
			slowest = max(slowest, took)
		})
	}
	// Run's loop, reduced: whenever the connection ends, a new one, to a
	// parent that reads and answers nothing but its hello (here: the link
	// is set).
	stop := make(chan struct{})
	var told atomic.Int64 // vaults the parent was told have stopped
	reconnected := make(chan *hostproto.Conn, 16)
	go func() {
		conn := w.conn
		for {
			select {
			case <-stop:
				return
			case <-conn.Done():
			}
			w.s.link.set(nil)
			a, b := net.Pipe()
			conn = hostproto.NewConnOptions(a, w.s.handle, nil, w.s.connOptions())
			peer := hostproto.NewConn(b, func(ctx context.Context, f *hostproto.Frame) [][]byte { <-ctx.Done(); return nil }, func(f *hostproto.Frame) {
				if f.Kind == hostproto.KindStopped && len(f.Fields) == 2 && string(f.Fields[1]) == hostproto.StopLocked {
					told.Add(1)
				}
			})
			t.Cleanup(conn.Close)
			t.Cleanup(peer.Close)
			w.s.link.set(conn)
			reconnected <- peer
		}
	}()
	defer close(stop)
	w.clk.add(130 * time.Second)
	t0 := time.Now()
	w.s.checkParent(context.Background(), h)
	took := time.Since(t0)
	mu.Lock()
	t.Logf("%d vaults locked in %v; %d final flushes failed at once, the slowest after %v (a store call waits %v)",
		vaults, took.Round(time.Millisecond), failed, slowest.Round(time.Microsecond), callTimeout)
	if failed != vaults || slowest > time.Second {
		t.Fatalf("%d of %d final flushes failed at once; the slowest took %v", failed, vaults, slowest)
	}
	mu.Unlock()
	if n := len(h.Vaults()); n != 0 || took > lockAllWithin {
		t.Fatalf("%d vaults still run after %v", n, took)
	}
	// The new connection is there, and still no call is made on it: only
	// a Ping makes the parent reachable again.
	select {
	case w.parent = <-reconnected:
	case <-time.After(10 * time.Second):
		t.Fatal("no new connection")
	}
	if w.s.link.get() == nil {
		t.Fatal("no connection")
	}
	if _, err := w.s.link.call(context.Background(), hostproto.KindStoreGet, []byte("vaults/v/state")); !errors.Is(err, errDown) {
		t.Fatalf("a call to a parent that has not pinged: %v", err)
	}
	if told.Load() != 0 {
		t.Fatalf("%d stopped vaults told before the ping", told.Load())
	}
	w.ping()
	for deadline := time.Now().Add(10 * time.Second); told.Load() != vaults; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the parent was told of %d of %d stopped vaults", told.Load(), vaults)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := w.s.link.call(ctx, hostproto.KindStoreGet, []byte("vaults/v/state")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a call after the parent's ping was not sent: %v", err)
	}
}

// A vault process that does not answer the lock is killed when the time
// is up: every vault is gone by then, however many there are and whatever
// they wait for.
func TestLockAllWithinKills(t *testing.T) {
	w := newWatched(t)
	h := &procHost{s: w.s, procs: map[string]*vproc{}}
	h.cfg.defaults()
	var ps []*vproc
	for i := 0; i < 20; i++ {
		ps = append(ps, lockProc(t, h, fmt.Sprintf("vault-%02d", i), i%2 == 0, func(error, time.Duration) {}))
	}
	const within = 500 * time.Millisecond
	t0 := time.Now()
	ended := h.LockAllWithin(context.Background(), within)
	took := time.Since(t0)
	killed := 0
	for _, err := range ended {
		if err != nil {
			killed++
		}
	}
	if len(ended) != 20 || killed != 10 {
		t.Fatalf("%d vaults ended, %d of them killed; want 20 and 10", len(ended), killed)
	}
	if took < within || took > within+5*time.Second {
		t.Fatalf("took %v with a limit of %v", took, within)
	}
	if n := len(h.Vaults()); n != 0 {
		t.Fatalf("%d vaults still run", n)
	}
	for _, p := range ps {
		select {
		case <-p.exited:
		default:
			t.Fatalf("the process of %s still runs", p.vaultID)
		}
	}
}

// The order when the parent's Ping is read after it was unreachable: the
// Ping is counted at once; the reports of the vaults that stopped are
// queued; only then is the parent reachable again. So no call can open a
// vault before the report of its earlier run is on its way, and a queue
// that is full delays the reports and the calls, not the count.
func TestPingOrder(t *testing.T) {
	w := newWatched(t)
	a, b := net.Pipe() // nobody reads b yet
	defer b.Close()
	conn := hostproto.NewConn(a, w.s.handle, nil)
	defer conn.Close()
	w.s.link.set(conn)
	w.s.link.lost()
	w.s.link.stop("aaaa", hostproto.StopLocked)
	for held, tries := 0, 0; held < 257; tries++ { // the queue is full
		if w.s.link.logRecord(hostproto.Strings("INFO", "record")...) {
			held++
		} else if tries > 10000 {
			t.Fatalf("the connection took %d records", held)
		} else {
			time.Sleep(100 * time.Microsecond)
		}
	}
	w.clk.add(100 * time.Second)
	done := make(chan struct{})
	go func() { defer close(done); w.s.link.ping(w.clk.now()) }()
	// Counted, though the report still waits for the queue...
	for deadline := time.Now().Add(10 * time.Second); w.s.link.silent(w.clk.now(), window) != 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the ping is not counted while its reports wait")
		}
	}
	// ...and while it waits the parent is not reachable.
	time.Sleep(50 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("the report did not wait for the queue")
	default:
	}
	if w.s.link.up() != nil {
		t.Fatal("the parent is reachable before the reports are queued")
	}
	if _, err := w.s.link.call(context.Background(), hostproto.KindStoreGet, []byte("vaults/aaaa/state")); !errors.Is(err, errDown) {
		t.Fatalf("a call before the reports are queued: %v", err)
	}
	// The parent reads: the report goes, then the parent is reachable.
	stopped := make(chan struct{})
	peer := hostproto.NewConn(b, nil, func(f *hostproto.Frame) {
		if f.Kind == hostproto.KindStopped {
			close(stopped)
		}
	})
	defer peer.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the ping did not finish")
	}
	if w.s.link.up() == nil {
		t.Fatal("the parent is not reachable after its ping")
	}
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("the report did not arrive")
	}
}
