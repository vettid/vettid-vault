package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// parkServer is an HTTP/2 server that allows streams concurrent streams
// per connection (0: the server's default) and holds every GET /park
// until release, as the relay holds a long-poll; other requests are
// answered at once.
type parkServer struct {
	*httptest.Server
	parked  atomic.Int32
	conns   atomic.Int32 // connections accepted
	release chan struct{}
}

func newParkServer(t *testing.T, ca *testCA, streams int) *parkServer {
	p := &parkServer{release: make(chan struct{})}
	p.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/park" {
			p.parked.Add(1)
			defer p.parked.Add(-1)
			select {
			case <-p.release:
			case <-r.Context().Done():
			}
		}
		_, _ = io.WriteString(w, r.Proto)
	}))
	p.EnableHTTP2 = true
	p.TLS = &tls.Config{Certificates: []tls.Certificate{ca.leaf(t, "relay.example")}}
	if streams > 0 {
		p.Config.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: streams}
	}
	p.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			p.conns.Add(1)
		}
	}
	p.StartTLS()
	t.Cleanup(p.Close)
	return p
}

// pool returns a transport to p with the given bounds (0: the defaults).
func (p *parkServer) pool(t *testing.T, ca *testCA, maxConns, minStreams int) *Transport {
	var dials atomic.Int32
	tr, err := New(Config{Dialer: dialer(p.Listener.Addr().String(), &dials), MaxConns: maxConns, MinStreams: minStreams,
		Hosts: []Host{{Name: "relay.example", Roots: ca.pool, HTTP2: true}}})
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// park starts n parked requests; the returned function waits for all of
// them and reports any that failed.
func park(t *testing.T, c *http.Client, n int) (wait func()) {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if p, err := get(c, "https://relay.example/park"); err != nil || p != "HTTP/2.0" {
				t.Errorf("parked request: %q %v", p, err)
			}
		}()
	}
	return wg.Wait
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(30 * time.Second); !ok(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// TestGrowthAtStreamLimit is the measurement of VAULT-RELAY-SCALING §9.2
// as a test, with the relay's numbers: 900 vaults hold a long-poll each
// against a host that allows 128 streams per connection. Every one must
// be running at the host together (none waits for another to end), on
// the fewest connections that can carry them, and a quick request (a
// deposit, an ack) must still go out at once. Run it on every Go update:
// the pool stands on net/http's ClientConn.
func TestGrowthAtStreamLimit(t *testing.T) {
	const vaults, streams = 900, 128
	ca := newCA(t, "test root")
	s := newParkServer(t, ca, streams)
	tr := s.pool(t, ca, 0, 0)
	c := tr.Client(60 * time.Second)

	start := time.Now()
	wait := park(t, c, vaults)
	eventually(t, "every long-poll to be held by the server", func() bool { return s.parked.Load() == vaults })
	t.Logf("%d long-polls held after %v", vaults, time.Since(start))
	st := tr.Stats("relay.example")
	least := (vaults + streams - 1) / streams
	if st.Conns != least || st.Dialed != uint64(least) || int(s.conns.Load()) != least {
		t.Errorf("%d connections (%d dialed, %d at the server) for %d requests at %d streams; want %d", st.Conns, st.Dialed, s.conns.Load(), vaults, streams, least)
	}
	if st.Streams != streams || st.InFlight != vaults || st.Waiting != 0 || st.RefusedMaxConns != 0 || st.RefusedMinStreams != 0 {
		t.Errorf("stats %+v", st)
	}

	// Quick requests while every long-poll is held.
	var slowest time.Duration
	for i := 0; i < 8; i++ {
		t0 := time.Now()
		if p, err := get(c, "https://relay.example/quick"); err != nil || p != "HTTP/2.0" {
			t.Fatalf("quick request: %q %v", p, err)
		}
		slowest = max(slowest, time.Since(t0))
	}
	t.Logf("slowest of 8 quick requests beside %d held long-polls: %v", vaults, slowest)
	after := tr.Stats("relay.example")
	if slowest > time.Second || after.Waited != st.Waited || after.Dialed != st.Dialed {
		t.Errorf("quick requests waited: slowest %v, %d waited, %d dialed", slowest, after.Waited-st.Waited, after.Dialed-st.Dialed)
	}
	if s.parked.Load() != vaults {
		t.Errorf("%d long-polls held after the quick requests", s.parked.Load())
	}
	close(s.release)
	wait()
}

// TestMaxConns: at the bound, with every stream in use, requests wait
// (and are counted) until a stream is free or their context ends; no
// further connection opens.
func TestMaxConns(t *testing.T) {
	const streams, conns, extra = 32, 3, 10
	ca := newCA(t, "test root")
	s := newParkServer(t, ca, streams)
	tr := s.pool(t, ca, conns, 0)
	c := tr.Client(60 * time.Second)

	wait := park(t, c, streams*conns+extra)
	eventually(t, "the waiting requests", func() bool {
		st := tr.Stats("relay.example")
		return s.parked.Load() == streams*conns && st.Waiting == extra && st.RefusedMaxConns == extra
	})
	// A request that cannot wait fails with its context's error.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://relay.example/quick", strings.NewReader("x"))
	if _, err := c.Do(req); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("request at the bound: %v", err)
	}
	st := tr.Stats("relay.example")
	if st.Conns != conns || st.Dialed != conns || int(s.conns.Load()) != conns || st.InFlight != streams*conns ||
		st.RefusedMaxConns != extra+1 || st.RefusedMinStreams != 0 || st.WaitMax < 100*time.Millisecond {
		t.Errorf("stats at the bound: %+v, %d connections at the server", st, s.conns.Load())
	}
	// The waiting requests run as streams become free.
	close(s.release)
	wait()
	st = tr.Stats("relay.example")
	if st.Dialed != conns || st.Waiting != 0 || st.InFlight != 0 {
		t.Errorf("stats afterwards: %+v", st)
	}
	if st = tr.Stats("relay.example"); st.WaitMax != 0 {
		t.Errorf("the longest wait was not reset: %v", st.WaitMax)
	}
}

// TestMinStreams: a host that announces fewer streams than MinStreams
// gets one connection, however many requests there are (it would
// otherwise choose how few vaults share a connection); the rest wait.
func TestMinStreams(t *testing.T) {
	const streams, requests = 8, 30
	ca := newCA(t, "test root")
	s := newParkServer(t, ca, streams)
	tr := s.pool(t, ca, 0, 0)
	c := tr.Client(60 * time.Second)

	wait := park(t, c, requests)
	eventually(t, "the waiting requests", func() bool {
		st := tr.Stats("relay.example")
		return s.parked.Load() == streams && st.Waiting == requests-streams && st.RefusedMinStreams == requests-streams
	})
	time.Sleep(50 * time.Millisecond) // nothing more may happen
	st := tr.Stats("relay.example")
	if st.Conns != 1 || st.Dialed != 1 || s.conns.Load() != 1 || st.Streams != streams || st.InFlight != streams || st.RefusedMaxConns != 0 {
		t.Errorf("stats %+v, %d connections at the server", st, s.conns.Load())
	}
	close(s.release)
	wait()
}

// TestStreamLimitIsRead holds the library to what settle assumes: before
// a new connection is used, the limit the host announced can be read from
// it, also when the host announces none (the library then allows 1000) or
// exactly the library's own first assumption.
func TestStreamLimitIsRead(t *testing.T) {
	ca := newCA(t, "test root")
	for _, tc := range []struct{ announce, want int }{{1, 1}, {31, 31}, {h2Unsettled, h2Unsettled}, {128, 128}, {250, 250}} {
		s := newParkServer(t, ca, tc.announce)
		tr := s.pool(t, ca, 0, 0)
		if p, err := get(tr.Client(10*time.Second), "https://relay.example/quick"); err != nil || p != "HTTP/2.0" {
			t.Fatalf("announce %d: %q %v", tc.announce, p, err)
		}
		if st := tr.Stats("relay.example"); st.Streams != tc.want || st.Conns != 1 {
			t.Errorf("announce %d: stats %+v", tc.announce, st)
		}
	}
}

// TestReconnect: requests on a connection that is lost fail (the vault
// retries them, as before); the next request opens a new connection.
func TestReconnect(t *testing.T) {
	ca := newCA(t, "test root")
	s := newParkServer(t, ca, 128)
	tr := s.pool(t, ca, 0, 0)
	c := tr.Client(30 * time.Second)

	var failed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := get(c, "https://relay.example/park"); err != nil {
				failed.Add(1)
			}
		}()
	}
	eventually(t, "the long-polls", func() bool { return s.parked.Load() == 5 })
	s.CloseClientConnections()
	wg.Wait()
	if failed.Load() != 5 {
		t.Errorf("%d of 5 requests failed with their connection", failed.Load())
	}
	for i := 0; i < 3; i++ {
		if p, err := get(c, "https://relay.example/quick"); err != nil || p != "HTTP/2.0" {
			t.Fatalf("request after the loss: %q %v", p, err)
		}
	}
	if st := tr.Stats("relay.example"); st.Conns != 1 || st.Dialed != 2 || st.InFlight != 0 {
		t.Errorf("stats %+v", st)
	}
	tr.CloseIdle()
	if st := tr.Stats("relay.example"); st.Conns != 0 {
		t.Errorf("stats after CloseIdle: %+v", st)
	}
}

// TestDialFails: when no connection can be opened, every request that
// waited for it fails with the dial's error instead of dialing again.
func TestDialFails(t *testing.T) {
	ca := newCA(t, "test root")
	errDown := errors.New("forwarder down")
	var dials atomic.Int32
	gate := make(chan struct{})
	tr, err := New(Config{Hosts: []Host{{Name: "relay.example", Roots: ca.pool, HTTP2: true}},
		Dialer: DialerFunc(func(context.Context, string, uint16) (net.Conn, error) {
			dials.Add(1)
			<-gate
			return nil, errDown
		})})
	if err != nil {
		t.Fatal(err)
	}
	c := tr.Client(10 * time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := get(c, "https://relay.example/x"); !errors.Is(err, errDown) {
				t.Errorf("request: %v", err)
			}
		}()
	}
	eventually(t, "the requests to wait for the dial", func() bool { return tr.Stats("relay.example").Waiting == 20 })
	close(gate)
	wg.Wait()
	if n := dials.Load(); n != 1 {
		t.Errorf("%d dials for 20 requests waiting together", n)
	}
}
