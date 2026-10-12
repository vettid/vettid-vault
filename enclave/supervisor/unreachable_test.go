package supervisor

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
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

// fakeVaults stands for the instance: the vaults running, and LockAll.
type fakeVaults struct {
	mu     sync.Mutex
	ids    []string
	locked int // LockAll calls that found a vault
}

func (v *fakeVaults) Vaults() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.ids...)
}

func (v *fakeVaults) LockAll(context.Context) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.ids) > 0 {
		v.locked++
	}
	v.ids = nil
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
	w.parent = hostproto.NewConn(b, nil, nil)
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
	// Nothing runs: nothing more happens, and a vault unlocked later has
	// the whole time again.
	w.run(600*time.Second, nil)
	w.want(1, "no vault running")
	w.vaults.unlock("bbbb")
	w.run(720*time.Second, nil)
	w.want(1, "120 s after the vault started")
	w.run(730*time.Second, nil)
	w.want(2, "a vault unlocked under a silent parent")
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
// do not fit are dropped and counted. A lifecycle event waits, but only
// until the write timeout ends the connection, and from then the parent
// is on the 120 s clock like any other that is gone.
func TestParentStopsReading(t *testing.T) {
	w := newWatched(t)
	a, b := net.Pipe() // nobody reads b
	defer b.Close()
	opt := w.s.connOptions()
	if opt.WriteTimeout != 60*time.Second {
		t.Fatalf("write timeout %v", opt.WriteTimeout)
	}
	opt.WriteTimeout = 500 * time.Millisecond
	start := time.Now()
	conn := hostproto.NewConnOptions(a, w.s.handle, nil, opt)
	defer conn.Close()
	w.s.link.set(conn)
	w.vaults.unlock("aaaa")
	log := slog.New(&logHandler{l: w.s.link, level: slog.LevelError}) // as the supervisor's, without the console lines of lower levels
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
	case <-conn.Done():
		t.Skip("too slow to tell: the write timeout came first")
	case <-time.After(10 * time.Second):
		t.Fatal("logging waits for a parent that does not read")
	}
	// The connection holds 256 frames, and one more once the writer has
	// taken its first.
	dropped := w.s.link.logDropped.Load()
	if dropped != 1001-257 && dropped != 1001-256 {
		t.Fatalf("%d records dropped, want all but the 257 the connection holds", dropped)
	}
	// A lifecycle event is not dropped: it waits for the connection.
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		w.s.link.notify(hostproto.KindLifecycle, hostproto.Strings("locked", "aaaa", "r", "r", "1")...)
	}()
	select {
	case <-sent:
		select {
		case <-conn.Done():
			t.Skip("too slow to tell: the write timeout came first")
		default:
			t.Fatal("a lifecycle event was dropped while the connection lived")
		}
	case <-time.After(50 * time.Millisecond):
	}
	select {
	case <-sent:
	case <-time.After(10 * time.Second):
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
	// The count of dropped records is logged once it changed.
	w.s.reportDropped()
	if w.s.droppedTold != dropped {
		t.Fatalf("dropped records reported: %d of %d", w.s.droppedTold, dropped)
	}
}
