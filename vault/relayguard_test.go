package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func allZeroKey(k ed25519.PrivateKey) bool { return len(k) > 0 && bytes.Count(k, []byte{0}) == len(k) }

// A long poll blocked on a relay that never answers is ended by Close at
// the transport: Close returns well within its bound, the call has ended
// before the key copy is wiped, and the poll reports ErrRelayClosed.
func TestRelayCloseEndsABlockedCollect(t *testing.T) {
	arrived := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		select {
		case arrived <- struct{}{}:
		default:
		}
		<-req.Context().Done() // never answers
	}))
	defer srv.Close()
	var allEnded []bool
	testRelayClosedHook = func(e bool) { allEnded = append(allEnded, e) }
	defer func() { testRelayClosedHook = nil }()
	r := NewClientRelay(srv.URL, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)), srv.Client(), nil)
	c := r.NewPollCollector(30 * time.Second)
	errc := make(chan error, 1)
	go func() { _, err := c.Next(context.Background()); errc <- err }()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("the poll did not reach the relay")
	}
	start := time.Now()
	r.Close()
	if took := time.Since(start); took > relayCloseWait/2 {
		t.Fatalf("Close took %v: the blocked poll was not cut off", took)
	}
	if err := recvErr(t, errc); !errors.Is(err, ErrRelayClosed) {
		t.Fatalf("the poll returned %v, want ErrRelayClosed", err)
	}
	if len(allEnded) != 1 || !allEnded[0] {
		t.Fatalf("close wiped with a call still in flight: %v", allEnded)
	}
	if !allZeroKey(r.key) {
		t.Fatal("the relay's key copy was not wiped")
	}
}

// A call that does not end within the bound (it ignores its context) does
// not keep the key: Close wipes it anyway, and the call's late result is
// not used.
func TestRelayCloseFailsSecure(t *testing.T) {
	old := relayCloseWait
	relayCloseWait = 100 * time.Millisecond
	defer func() { relayCloseWait = old }()
	var allEnded []bool
	testRelayClosedHook = func(e bool) { allEnded = append(allEnded, e) }
	defer func() { testRelayClosedHook = nil }()
	r := NewClientRelay("https://relay.example", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)), nil, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	res := make(chan error, 1)
	go func() {
		_, err := guarded(r, context.Background(), func(context.Context) (string, error) {
			close(entered)
			<-release // ignores its context: a request that does not end
			return "answer", nil
		})
		res <- err
	}()
	waitClosed(t, entered)
	start := time.Now()
	r.Close()
	if took := time.Since(start); took > time.Second {
		t.Fatalf("Close took %v, past its bound", took)
	}
	if !keySeedWiped(r.key) || allZeroKey(r.key[ed25519.SeedSize:]) {
		t.Fatal("on the timeout path the seed must be wiped and the public half left")
	}
	if len(allEnded) != 1 || allEnded[0] {
		t.Fatalf("hook = %v, want one close that timed out", allEnded)
	}
	close(release)
	if err := <-res; !errors.Is(err, ErrRelayClosed) {
		t.Fatalf("the late answer was used: %v", err)
	}
}

// An answer that arrives after Close, even a success, is not used; and a
// call made after Close does not run.
func TestRelayAnswerAfterCloseDropped(t *testing.T) {
	r := NewClientRelay("https://relay.example", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)), nil, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	res := make(chan error, 1)
	go func() {
		_, err := guarded(r, context.Background(), func(c context.Context) (string, error) {
			close(entered)
			<-c.Done() // ended by Close, then answers anyway
			<-release
			return "answer", nil
		})
		res <- err
	}()
	waitClosed(t, entered)
	done := make(chan struct{})
	go func() { r.Close(); close(done) }()
	time.Sleep(50 * time.Millisecond)
	close(release)
	<-done
	if err := <-res; !errors.Is(err, ErrRelayClosed) {
		t.Fatalf("an answer after Close was used: %v", err)
	}
	ran := false
	_, err := guarded(r, context.Background(), func(context.Context) (string, error) { ran = true; return "", nil })
	if !errors.Is(err, ErrRelayClosed) || ran {
		t.Fatalf("a call after Close ran (%v) or was not refused: %v", ran, err)
	}
	if _, err := r.MintOpenToken(time.Minute, ""); !errors.Is(err, ErrRelayClosed) {
		t.Fatalf("MintOpenToken after Close: %v", err)
	}
}

// WithKey's relays share the parent's guard: closing the parent ends their
// calls and wipes their key copies too.
func TestRelayCloseCoversDerivedRelays(t *testing.T) {
	r := NewClientRelay("https://relay.example", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32)), nil, nil)
	d := r.WithKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))).(*ClientRelay)
	r.Close()
	if !allZeroKey(d.key) {
		t.Fatal("the derived relay's key copy was not wiped")
	}
	if _, err := d.MintOpenToken(time.Minute, ""); !errors.Is(err, ErrRelayClosed) {
		t.Fatalf("the derived relay still works: %v", err)
	}
}

// The relay keeps its own copy of the key: wiping the caller's key (as the
// vault's keyset.destroy does) leaves the relay's untouched until Close.
func TestRelayKeepsItsOwnKeyCopy(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, 32))
	r := NewClientRelay("https://relay.example", key, nil, nil)
	if &r.key[0] == &key[0] {
		t.Fatal("the relay shares the caller's key bytes")
	}
	clear(key)
	if allZeroKey(r.key) {
		t.Fatal("wiping the caller's key wiped the relay's")
	}
}

// waitClosed waits for c to close, failing rather than hanging.
func waitClosed(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(5 * time.Second):
		t.Fatal("the call did not start")
	}
}

// recvErr waits for a call's result, failing rather than hanging.
func recvErr(t *testing.T, c <-chan error) error {
	t.Helper()
	select {
	case err := <-c:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("the call did not return")
		return nil
	}
}

// destroySpy is a Sealer that records, when zeroize destroys it (before
// the vault's keys), whether a relay's guard had already cancelled its
// calls (the guard's context; a call's own follows it at once).
type destroySpy struct {
	Sealer
	ctx       context.Context
	destroyed bool
	cancelled bool
}

func (d *destroySpy) Destroy() {
	d.destroyed = true
	d.cancelled = d.ctx.Err() != nil
	if x, ok := d.Sealer.(interface{ Destroy() }); ok {
		x.Destroy()
	}
}

// zeroize (Crash) cancels every relay's calls before it destroys the
// vault's secrets, and wipes the relays' own key copies last, after them.
func TestZeroizeCancelsFirstWipesCopiesLast(t *testing.T) {
	f := newFixture(t)
	cr := NewClientRelay("https://relay.example", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{13}, 32)), nil, nil)
	entered := make(chan struct{})
	go func() {
		_, _ = guarded(cr, context.Background(), func(c context.Context) (int, error) { close(entered); <-c.Done(); return 0, nil })
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the call did not start")
	}
	spy := &destroySpy{ctx: cr.g.ctx}
	var afterKeys []bool
	f.m.mu.Lock()
	spy.Sealer = f.m.opt.Sealer
	f.m.opt.Sealer = spy
	f.m.track(cr)
	// The hook runs inside zeroize, on this goroutine, under m.mu.
	testRelayClosedHook = func(bool) { afterKeys = append(afterKeys, f.m.keys == nil) }
	f.m.mu.Unlock()
	defer func() { testRelayClosedHook = nil }()
	f.m.Crash()
	if !spy.destroyed || !spy.cancelled {
		t.Fatalf("the relay's calls were not cancelled before the secrets were destroyed (destroyed %v, cancelled %v)", spy.destroyed, spy.cancelled)
	}
	if len(afterKeys) != 1 || !afterKeys[0] {
		t.Fatalf("the relay's key copy was not wiped last: %v", afterKeys)
	}
	if !allZeroKey(cr.key) {
		t.Fatal("the relay's key copy was kept")
	}
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	if f.m.relays != nil {
		t.Fatal("the closed relays were kept")
	}
}

// zeroize waits for the relays of every family against one deadline: two
// families with a stuck call each (recovery open's inherited key, delete)
// take one bound, not two.
func TestZeroizeOneDeadlineForEveryFamily(t *testing.T) {
	old := relayCloseWait
	relayCloseWait = time.Second
	defer func() { relayCloseWait = old }()
	f := newFixture(t)
	release := make(chan struct{})
	defer close(release)
	var rs []*ClientRelay
	for i := byte(0); i < 2; i++ {
		r := NewClientRelay("https://relay.example", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{20 + i}, 32)), nil, nil)
		entered := make(chan struct{})
		go func() {
			_, _ = guarded(r, context.Background(), func(context.Context) (int, error) { close(entered); <-release; return 0, nil })
		}()
		waitClosed(t, entered)
		rs = append(rs, r)
	}
	f.m.mu.Lock()
	for _, r := range rs {
		f.m.track(r)
	}
	f.m.mu.Unlock()
	start := time.Now()
	f.m.Crash()
	if took := time.Since(start); took > 1600*time.Millisecond {
		t.Fatalf("zeroize took %v: one bound per family", took)
	}
	for _, r := range rs {
		if !keySeedWiped(r.key) {
			t.Fatal("a key copy was kept")
		}
	}
}

// Release takes a relay out of the Manager's list and its family's.
func TestReleaseForgetsTheRelay(t *testing.T) {
	f := newFixture(t)
	r := NewClientRelay("https://relay.example", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{14}, 32)), nil, nil)
	d := r.WithKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{15}, 32))).(*ClientRelay)
	f.m.mu.Lock()
	f.m.track(r)
	f.m.track(d)
	before := len(f.m.relays)
	f.m.release(d)
	after := len(f.m.relays)
	kept := slices.Contains(f.m.relays, Relay(d))
	f.m.mu.Unlock()
	if after != before-1 || kept {
		t.Fatalf("the Manager kept the released relay (%d relays, then %d)", before, after)
	}
	r.fam.mu.Lock()
	g := len(r.fam.guards)
	r.fam.mu.Unlock()
	if g != 1 {
		t.Fatalf("the family keeps %d guards, want 1", g)
	}
}

// closedCollector's Next reports the relay closed (the vault zeroized
// mid-collect), counting its calls.
type closedCollector struct {
	mu sync.Mutex
	n  int
}

func (c *closedCollector) Next(context.Context) ([]Message, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return nil, ErrRelayClosed
}
func (c *closedCollector) Ack(context.Context, string) error { return nil }
func (c *closedCollector) Close() error                      { return nil }

// Run returns at once when a collect finds the relay closed: no retry wait.
func TestRunStopsOnRelayClosed(t *testing.T) {
	f := newFixture(t)
	cc := &closedCollector{}
	f.m.mu.Lock()
	f.m.opt.PollWait = time.Millisecond // no first-poll spread
	f.m.collector = cc
	f.m.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- f.m.Run(context.Background()) }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrRelayClosed) {
			t.Fatalf("Run returned %v, want ErrRelayClosed", err)
		}
	case <-time.After(500 * time.Millisecond):
		f.m.Crash()
		<-done
		t.Fatal("Run went on after the relay was closed")
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.n != 1 {
		t.Fatalf("%d collects after the relay was closed, want 1", cc.n)
	}
}

// The collectors' other calls are guarded too: a poll's Ack, and the
// opening of a WebSocket stream, are refused once the relay is closed.
func TestRelayCloseGuardsAckAndStreamOpen(t *testing.T) {
	hits := 0
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	r := NewClientRelay(srv.URL, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{16}, 32)), srv.Client(), nil)
	c := r.NewPollCollector(time.Second)
	r.Close()
	if err := c.Ack(context.Background(), "m1"); !errors.Is(err, ErrRelayClosed) {
		t.Fatalf("Ack after Close returned %v", err)
	}
	if _, err := r.Collector(context.Background(), true); !errors.Is(err, ErrRelayClosed) {
		t.Fatalf("the stream opened after Close: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Fatalf("%d requests reached the relay after Close", hits)
	}
}

// Release closes one relay of a family and wipes its key copy alone: the
// others go on.
func TestRelayReleaseIsOneRelay(t *testing.T) {
	r := NewClientRelay("https://relay.example", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)), nil, nil)
	d := r.WithKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))).(*ClientRelay)
	d.Release()
	if !allZeroKey(d.key) || allZeroKey(r.key) {
		t.Fatal("Release did not wipe the released relay's copy alone")
	}
	if _, err := d.MintOpenToken(time.Minute, ""); !errors.Is(err, ErrRelayClosed) {
		t.Fatalf("the released relay still works: %v", err)
	}
	if _, err := r.MintOpenToken(time.Minute, ""); err != nil {
		t.Fatalf("its family stopped working: %v", err)
	}
}

// A family's Close waits for all its relays' calls against one deadline:
// two stuck calls take one bound, not two.
func TestRelayFamilyCloseOneBound(t *testing.T) {
	old := relayCloseWait
	relayCloseWait = 200 * time.Millisecond
	defer func() { relayCloseWait = old }()
	r := NewClientRelay("https://relay.example", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)), nil, nil)
	d := r.WithKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{10}, 32))).(*ClientRelay)
	release := make(chan struct{})
	defer close(release)
	for _, x := range []*ClientRelay{r, d} {
		entered := make(chan struct{})
		go func() {
			_, _ = guarded(x, context.Background(), func(context.Context) (int, error) { close(entered); <-release; return 0, nil })
		}()
		waitClosed(t, entered)
	}
	start := time.Now()
	r.Close()
	if took := time.Since(start); took > 350*time.Millisecond {
		t.Fatalf("the family's Close took %v: one bound per relay", took)
	}
	if !keySeedWiped(r.key) || !keySeedWiped(d.key) {
		t.Fatal("a key copy was kept")
	}
}

// Dropping the pending relay key releases its relay, whose copy is wiped.
func TestDropPendingRelayReleases(t *testing.T) {
	f := newFixture(t)
	pr := NewClientRelay("https://relay.example", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32)), nil, nil)
	f.m.mu.Lock()
	f.m.rk.pending = pr
	f.m.dropPendingRelay()
	f.m.mu.Unlock()
	if !allZeroKey(pr.key) {
		t.Fatal("the dropped pending relay's key copy was kept")
	}
}

// Crash while Run's collect is blocked in a real long poll ends the poll
// at once (the collect returns ErrRelayClosed), and the relay's key copy
// is wiped only after the call has ended.
func TestCrashDuringALongPoll(t *testing.T) {
	arrived := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet || strings.Contains(req.URL.Path, "collect") || req.URL.Query().Has("wait") {
			select {
			case arrived <- struct{}{}:
			default:
			}
			<-req.Context().Done()
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	f := newFixture(t)
	var allEnded []bool
	testRelayClosedHook = func(e bool) { allEnded = append(allEnded, e) }
	defer func() { testRelayClosedHook = nil }()
	f.m.mu.Lock()
	cr := NewClientRelay(srv.URL, f.m.keys.relay, srv.Client(), nil)
	f.m.relay = f.m.track(cr)
	f.m.collector = cr.NewPollCollector(30 * time.Second)
	c := f.m.collector
	f.m.mu.Unlock()
	errc := make(chan error, 1)
	go func() { _, err := c.Next(context.Background()); errc <- err }()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("the long poll did not reach the relay")
	}
	start := time.Now()
	f.m.Crash()
	if took := time.Since(start); took > relayCloseWait/2 {
		t.Fatalf("Crash took %v during a long poll", took)
	}
	if err := recvErr(t, errc); !errors.Is(err, ErrRelayClosed) {
		t.Fatalf("the collect returned %v, want ErrRelayClosed", err)
	}
	if len(allEnded) == 0 || !allEnded[0] {
		t.Fatalf("the key copy was wiped with the call in flight: %v", allEnded)
	}
	if !allZeroKey(cr.key) {
		t.Fatal("the relay's key copy was kept")
	}
}

// Close during relayclient's retry backoff (after a 503) ends the call:
// no further request is signed and sent.
func TestRelayCloseDuringRetryBackoff(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	first := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		select {
		case first <- struct{}{}:
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"code":"unavailable"}`))
	}))
	defer srv.Close()
	r := NewClientRelay(srv.URL, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{12}, 32)), srv.Client(), nil)
	errc := make(chan error, 1)
	go func() { _, err := r.Register(context.Background()); errc <- err }()
	select {
	case <-first:
	case <-time.After(5 * time.Second):
		t.Fatal("Register did not reach the relay")
	}
	r.Close()
	if err := recvErr(t, errc); !errors.Is(err, ErrRelayClosed) {
		t.Fatalf("Register returned %v, want ErrRelayClosed", err)
	}
	// Past the latest the first retry would have been sent: relayclient's
	// first backoff is 250 ms with up to 250 ms of jitter, the second 500.
	time.Sleep(1500 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if requests != 1 {
		t.Fatalf("%d requests: the retry was sent after Close", requests)
	}
}

// keySeedWiped reports whether a key copy's seed half is all zero (on the
// timeout path only the seed is wiped).
func keySeedWiped(k ed25519.PrivateKey) bool {
	return allZeroKey(k[:ed25519.SeedSize])
}

// A collect of the old mailboxes that finds the relay closed returns
// ErrRelayClosed at once, without going on to the current mailbox.
func TestMultiCollectorStopsOnRelayClosed(t *testing.T) {
	cur := &closedCollector{}
	main := &countCollector{}
	for _, tc := range []struct {
		name string
		old  Collector
	}{{"old closed", cur}} {
		c := &multiCollector{parts: []*collectPart{{mailbox: "old", c: tc.old}, {mailbox: "cur", c: main, main: true}},
			from: map[string]*collectPart{}, now: time.Now, idle: time.Millisecond, gone: func(string) {},
			stopped: func(string) bool { return false }, given: func(string, []string) {}}
		if _, err := c.Next(context.Background()); !errors.Is(err, ErrRelayClosed) {
			t.Fatalf("%s: Next returned %v, want ErrRelayClosed", tc.name, err)
		}
		if main.n != 0 {
			t.Fatalf("%s: the current mailbox was collected after the relay was closed", tc.name)
		}
	}
}

// countCollector returns nothing, counting its collects.
type countCollector struct{ n int }

func (c *countCollector) Next(context.Context) ([]Message, error) { c.n++; return nil, nil }
func (c *countCollector) Ack(context.Context, string) error       { return nil }
func (c *countCollector) Close() error                            { return nil }
