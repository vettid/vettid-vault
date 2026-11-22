package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
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
	<-arrived
	start := time.Now()
	r.Close()
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("Close took %v: the blocked poll was not cut off", took)
	}
	if err := <-errc; !errors.Is(err, ErrRelayClosed) {
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
	<-entered
	start := time.Now()
	r.Close()
	if took := time.Since(start); took > time.Second {
		t.Fatalf("Close took %v, past its bound", took)
	}
	if !allZeroKey(r.key) {
		t.Fatal("the key copy was kept for a call that did not end")
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
	<-entered
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

// closeSpy is a Relay that records, when zeroize closes it, whether the
// vault's relay key was still whole: the relay must be cut off first.
type closeSpy struct {
	*stubRelay
	m      *Manager
	mu     sync.Mutex
	closed bool
	whole  bool
}

func (c *closeSpy) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.whole = c.m.keys != nil && !allZeroKey(c.m.keys.relay)
}

// zeroize (Crash) closes every Relay the Manager made before it destroys
// the keys.
func TestZeroizeClosesRelaysBeforeTheKeys(t *testing.T) {
	f := newFixture(t)
	spy := &closeSpy{stubRelay: f.relay, m: f.m}
	f.m.mu.Lock()
	f.m.track(spy)
	f.m.mu.Unlock()
	f.m.Crash()
	spy.mu.Lock()
	defer spy.mu.Unlock()
	if !spy.closed {
		t.Fatal("zeroize did not close the relay")
	}
	if !spy.whole {
		t.Fatal("the relay was closed after the keys were destroyed")
	}
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	if f.m.relays != nil {
		t.Fatal("the closed relays were kept")
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
		<-entered
	}
	start := time.Now()
	r.Close()
	if took := time.Since(start); took > 350*time.Millisecond {
		t.Fatalf("the family's Close took %v: one bound per relay", took)
	}
	if !allZeroKey(r.key) || !allZeroKey(d.key) {
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
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("Crash took %v during a long poll", took)
	}
	if err := <-errc; !errors.Is(err, ErrRelayClosed) {
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
	<-first
	r.Close()
	if err := <-errc; !errors.Is(err, ErrRelayClosed) {
		t.Fatalf("Register returned %v, want ErrRelayClosed", err)
	}
	time.Sleep(300 * time.Millisecond) // past any backoff the retry would have used
	mu.Lock()
	defer mu.Unlock()
	if requests != 1 {
		t.Fatalf("%d requests: the retry was sent after Close", requests)
	}
}
