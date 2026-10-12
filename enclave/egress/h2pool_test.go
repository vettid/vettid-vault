package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math/rand/v2"
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
	for end := time.Now().Add(20 * time.Second); !ok(); time.Sleep(5 * time.Millisecond) {
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
// further connection opens. (The rate at which connections are opened
// would allow six here: it is the bound that holds.)
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
	// Reading the stats changes nothing (the parent may ask at any rate).
	if again := tr.Stats("relay.example"); again != st || st.WaitMax < 100*time.Millisecond {
		t.Errorf("stats read twice: %+v, then %+v", st, again)
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

// TestStreamLimitIsRead holds the library to what the pool assumes: the
// limit the host announced can be read from a connection with a free
// stream, also when the host announces exactly the library's own first
// assumption (then it is trusted once the host has answered a request,
// and that first request does not wait for it: android.googleapis.com
// announces 100).
func TestStreamLimitIsRead(t *testing.T) {
	ca := newCA(t, "test root")
	for _, tc := range []struct{ announce, want int }{{1, 1}, {31, 31}, {32, 32}, {h2Unsettled, h2Unsettled}, {128, 128}, {250, 250}} {
		s := newParkServer(t, ca, tc.announce)
		tr := s.pool(t, ca, 0, 0)
		t0 := time.Now()
		for i := 0; i < 2; i++ {
			if p, err := get(tr.Client(10*time.Second), "https://relay.example/quick"); err != nil || p != "HTTP/2.0" {
				t.Fatalf("announce %d: %q %v", tc.announce, p, err)
			}
		}
		if d := time.Since(t0); d > h2Settle/2 {
			t.Errorf("announce %d: two requests on a new connection took %v", tc.announce, d)
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

// TestDialFails: when no connection can be opened, a failed dial fails
// the request that started it and every request that was waiting when it
// started; they do not each dial in turn (and wait as long each time).
// Dials are one at a time, and count toward the rate like any other.
func TestDialFails(t *testing.T) {
	ca := newCA(t, "test root")
	errDown := errors.New("forwarder down")
	var dials, now, most atomic.Int32
	gate := make(chan struct{})
	tr, err := New(Config{Hosts: []Host{{Name: "relay.example", Roots: ca.pool, HTTP2: true}}, MaxConns: 2,
		Dialer: DialerFunc(func(context.Context, string, uint16) (net.Conn, error) {
			dials.Add(1)
			most.Store(max(most.Load(), now.Add(1)))
			defer now.Add(-1)
			<-gate
			return nil, errDown
		})})
	if err != nil {
		t.Fatal(err)
	}
	c := tr.Client(10 * time.Second)
	burst := func(n int) func() {
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := get(c, "https://relay.example/x"); !errors.Is(err, errDown) {
					t.Errorf("request: %v", err)
				}
			}()
		}
		return wg.Wait
	}
	wait := burst(200)
	eventually(t, "the requests to wait for the dial", func() bool { return tr.Stats("relay.example").Waiting == 200 })
	if n := dials.Load(); n != 1 {
		t.Errorf("%d dials for 200 requests waiting together", n)
	}
	close(gate)
	wait()
	// The first dial was started by the first request, before the
	// others were waiting; the second fails all of them.
	if n := dials.Load(); n > 3 || most.Load() != 1 {
		t.Errorf("%d dials for 200 requests, %d at a time", n, most.Load())
	}
	// Failed dials draw on the rate: four are allowed at once here.
	t0 := time.Now()
	for dials.Load() < 6 {
		burst(1)()
	}
	if d := time.Since(t0); d < 500*time.Millisecond {
		t.Errorf("6 failed dials within %v of each other", d)
	}
}

// TestFillFirst: a request goes to the first connection with a free
// stream, not to the newest or the emptiest, so the connections stay as
// full, and as few, as they can be.
func TestFillFirst(t *testing.T) {
	ca := newCA(t, "test root")
	s := newRawSrv(t, ca, 32)
	tr := s.pool(t, ca, 0, 0)
	c := tr.Client(30 * time.Second)
	wait := fire(c, 40, 20*time.Second)
	eventually(t, "40 requests on two connections", func() bool { return s.parked() == 40 && len(s.all()) == 2 })
	first, second := s.all()[0], s.all()[1]
	if first.nOpen() != 32 || second.nOpen() != 8 {
		t.Fatalf("%d and %d requests on the two connections", first.nOpen(), second.nOpen())
	}
	// Five streams of the first connection end; the next five requests
	// take them.
	first.mu.Lock()
	var ids []uint32
	for id := range first.open {
		if len(ids) < 5 {
			ids = append(ids, id)
		}
	}
	first.mu.Unlock()
	for _, id := range ids {
		first.respond(id)
	}
	eventually(t, "five answers", func() bool { return tr.Stats("relay.example").InFlight == 35 })
	wait2 := fire(c, 5, 20*time.Second)
	eventually(t, "five more requests", func() bool { return s.parked() == 40 })
	if first.nOpen() != 32 || second.nOpen() != 8 {
		t.Errorf("after five more: %d and %d requests on the two connections; want 32 and 8", first.nOpen(), second.nOpen())
	}
	s.respondAll()
	if ok, bad, sample := wait(); ok != 40 || bad != 0 {
		t.Errorf("first requests: %d ok, %d failed (%s)", ok, bad, sample)
	}
	if ok, bad, sample := wait2(); ok != 5 || bad != 0 {
		t.Errorf("later requests: %d ok, %d failed (%s)", ok, bad, sample)
	}
}

// fastPing makes a pool notice a silent connection within a second.
func fastPing(tr *Transport) *h2Pool {
	p := tr.hosts["relay.example"].h2
	p.tr.HTTP2.SendPingTimeout, p.tr.HTTP2.PingTimeout = 300*time.Millisecond, 300*time.Millisecond
	return p
}

// TestSilentConnections: connections that stay open but send nothing
// more (the host is gone without closing them; the peer's TCP may still
// acknowledge) must not keep their place: requests that time out on them
// hold their streams until a ping is answered, so without the HTTP/2 ping
// the pool was full of them for good. With it they are closed, and the
// pool serves again.
func TestSilentConnections(t *testing.T) {
	const conns, streams = 3, 32
	ca := newCA(t, "test root")
	s := newRawSrv(t, ca, streams)
	tr := s.pool(t, ca, conns, 0)
	if h2 := tr.hosts["relay.example"].h2.tr.HTTP2; h2 == nil || h2.SendPingTimeout != h2PingIdle || h2.PingTimeout != h2PingTimeout {
		t.Fatalf("the pool's connections are not pinged: %+v", h2)
	}
	fastPing(tr)
	c := tr.Client(30 * time.Second)
	wait := fire(c, conns*streams, 5*time.Second)
	eventually(t, "every stream in use", func() bool { return s.parked() == conns*streams })
	for _, rc := range s.all() {
		rc.silent.Store(true)
	}
	s.park.Store(false) // new connections answer at once
	t0 := time.Now()
	if ok, bad, _ := wait(); ok != 0 || bad != conns*streams {
		t.Errorf("requests on connections that went silent: %d ok, %d failed", ok, bad)
	}
	t.Logf("silent connections closed, their %d requests failed, after %v", conns*streams, time.Since(t0).Round(time.Millisecond))
	if d := time.Since(t0); d > 3*time.Second {
		t.Errorf("silent connections were found after %v, not by the ping", d)
	}
	if ok, bad, sample := fire(c, conns*streams, 3*time.Second)(); bad != 0 {
		t.Errorf("next requests: %d ok, %d failed (%s)", ok, bad, sample)
	}
	if st := tr.Stats("relay.example"); st.InFlight != 0 || st.Waiting != 0 || st.Conns > conns {
		t.Errorf("stats afterwards: %+v", st)
	}
}

// TestStalledConnections: connections that answer pings but no request
// are closed once they have held requests for longer than a request
// lives without answering any, whatever else happens.
func TestStalledConnections(t *testing.T) {
	const conns, streams = 3, 32
	ca := newCA(t, "test root")
	s := newRawSrv(t, ca, streams)
	tr := s.pool(t, ca, conns, 0)
	fastPing(tr).stall = time.Second
	c := tr.Client(30 * time.Second)
	wait := fire(c, conns*streams, 20*time.Second)
	eventually(t, "every stream in use", func() bool { return s.parked() == conns*streams })
	for _, rc := range s.all() {
		rc.stuck.Store(true)
	}
	s.park.Store(false)
	time.Sleep(1200 * time.Millisecond) // pinged and answered meanwhile: the connections stay
	if st := tr.Stats("relay.example"); st.Conns != conns || st.InFlight != conns*streams {
		t.Fatalf("stalled connections: %+v", st)
	}
	t0 := time.Now()
	if ok, bad, sample := fire(c, 10, 3*time.Second)(); ok != 10 {
		t.Errorf("requests beside stalled connections: %d ok, %d failed (%s)", ok, bad, sample)
	}
	t.Logf("10 requests beside %d stalled connections answered after %v", conns, time.Since(t0).Round(time.Millisecond))
	if ok, bad, _ := wait(); ok != 0 || bad != conns*streams {
		t.Errorf("requests on the stalled connections: %d ok, %d failed", ok, bad)
	}
}

// TestDrainingDoesNotCount: connections the host is closing (GOAWAY)
// take no new requests and do not count toward the bound while their
// requests end, so new requests do not wait for them.
func TestDrainingDoesNotCount(t *testing.T) {
	const conns, streams = 2, 32
	ca := newCA(t, "test root")
	s := newRawSrv(t, ca, streams)
	tr := s.pool(t, ca, conns, 0)
	c := tr.Client(30 * time.Second)
	wait := fire(c, conns*streams-2, 20*time.Second)
	eventually(t, "the requests", func() bool { return s.parked() == conns*streams-2 })
	// A full connection that is closing cannot be told from a full one
	// until one of its requests has ended (the library does not say).
	closing := func(conns []*rawConn) {
		for _, rc := range conns {
			rc.mu.Lock()
			last := rc.lastID
			rc.mu.Unlock()
			rc.goAway(last, 0)
			rc.respond(last)
		}
	}
	closing(s.all())
	wait2 := fire(c, conns*streams, 20*time.Second)
	eventually(t, "the next requests on new connections", func() bool { return s.parked() == 2*conns*streams-4 })
	if st := tr.Stats("relay.example"); st.Conns != 2*conns || st.Draining != conns || st.Waiting != 0 {
		t.Errorf("stats while draining: %+v", st)
	}
	// Not without end: at twice the bound requests wait.
	closing(s.all()[conns:])
	refused := tr.Stats("relay.example").RefusedMaxConns
	wait3 := fire(c, 3, time.Second)
	eventually(t, "requests waiting at twice the bound", func() bool { return tr.Stats("relay.example").RefusedMaxConns == refused+3 })
	if ok, bad, _ := wait3(); ok != 0 || bad != 3 || len(s.all()) != 2*conns {
		t.Errorf("at twice the bound: %d ok, %d failed, %d connections", ok, bad, len(s.all()))
	}
	s.respondAll()
	if ok, bad, sample := wait(); bad != 0 {
		t.Errorf("requests on the closing connections: %d ok, %d failed (%s)", ok, bad, sample)
	}
	if ok, bad, sample := wait2(); bad != 0 {
		t.Errorf("requests on the new connections: %d ok, %d failed (%s)", ok, bad, sample)
	}
}

// TestDialRate, one side: a host that closes every connection at its
// first request does not get a connection per request: after a burst of
// twice MaxConns, two a second.
func TestDialRate(t *testing.T) {
	const conns = 3
	ca := newCA(t, "test root")
	s := newRawSrv(t, ca, 128)
	s.closeAtOnce.Store(true)
	tr := s.pool(t, ca, conns, 0)
	c := tr.Client(30 * time.Second)
	t0 := time.Now()
	requests := 0
	for time.Since(t0) < 2*time.Second {
		_, _, _ = fire(c, 20, 200*time.Millisecond)()
		requests += 20
	}
	el := time.Since(t0).Seconds()
	n := int(s.accepted.Load())
	t.Logf("%d requests in %.1f s to a host that closes at once: %d connections", requests, el, n)
	if most := 2*conns + int(el*h2DialRate) + 1; n > most || n < 2*conns {
		t.Errorf("%d connections in %.1f s; want %d to %d", n, el, 2*conns, most)
	}
	if st := tr.Stats("relay.example"); st.RefusedMaxConns == 0 {
		t.Errorf("no request was counted as waiting for the rate: %+v", st)
	}
}

// TestDialRate, the other side: when the host closes every connection
// while 900 vaults hold a long-poll, and again as soon as they are back,
// all of them hold a poll again within about a second each time (each
// polls again 250 to 500 ms after its failure, as the relay client does).
func TestMassReconnect(t *testing.T) {
	const vaults = 900
	ca := newCA(t, "test root")
	s := newParkServer(t, ca, 128)
	tr := s.pool(t, ca, 0, 0)
	c := tr.Client(80 * time.Second)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < vaults; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				_, _ = get(c, "https://relay.example/park")
				select {
				case <-stop:
					return
				case <-time.After(250*time.Millisecond + time.Duration(rand.IntN(250))*time.Millisecond):
				}
			}
		}()
	}
	eventually(t, "every long-poll", func() bool { return s.parked.Load() == vaults })
	for round := 1; round <= 3; round++ {
		before := tr.Stats("relay.example")
		s.CloseClientConnections()
		t0 := time.Now()
		eventually(t, "the loss", func() bool { return s.parked.Load() < vaults })
		eventually(t, "every long-poll again", func() bool { return s.parked.Load() == vaults })
		d, st := time.Since(t0), tr.Stats("relay.example")
		t.Logf("loss %d of every connection: %d long-polls held again after %v on %d connections (%d opened)", round, vaults, d.Round(10*time.Millisecond), st.Conns, st.Dialed-before.Dialed)
		if d > 3*time.Second || st.RefusedMaxConns != 0 || st.Conns != 8 {
			t.Errorf("loss %d: recovered after %v, stats %+v", round, d, st)
		}
	}
	close(stop)
	close(s.release)
	wg.Wait()
}

// TestUnprocessedIsResent: a request the host says it did not process is
// sent once more instead of failing (the library's pool did the same).
// It also holds the library to the error texts the pool knows these by.
func TestUnprocessedIsResent(t *testing.T) {
	ca := newCA(t, "test root")
	s := newRawSrv(t, ca, 128)
	tr := s.pool(t, ca, 0, 0)
	c := tr.Client(30 * time.Second)
	// A GOAWAY that names 50 held requests as not processed.
	wait := fire(c, 50, 10*time.Second)
	eventually(t, "the requests", func() bool { return s.parked() == 50 })
	cur := s.all()[0]
	cur.goAway(0, 0)
	cur.mu.Lock()
	cur.open = map[uint32]bool{}
	cur.mu.Unlock()
	eventually(t, "the requests again, on a new connection", func() bool { return s.parked() == 50 && len(s.all()) == 2 })
	s.respondAll()
	if ok, bad, sample := wait(); ok != 50 {
		t.Errorf("GOAWAY naming 50 requests as not processed: %d ok, %d failed (%s)", ok, bad, sample)
	}
	// Refused streams, with a body to send again.
	s.park.Store(false)
	for i := 0; i < 3; i++ {
		s.all()[1].refuse.Store(1)
		r, err := c.Post("https://relay.example/x", "text/plain", strings.NewReader("body"))
		if err != nil {
			t.Fatalf("refused stream %d: %v", i, err)
		}
		r.Body.Close()
	}
	// Twice refused is an error: one more try, not more.
	s.all()[1].refuse.Store(2)
	if _, err := c.Get("https://relay.example/x"); err == nil || !unprocessed(errors.Unwrap(err)) {
		t.Errorf("request refused twice: %v", err)
	}
	// A connection that stopped taking requests between a request's
	// taking a stream and its being sent (the pool's connections are
	// picked under a lock, so this is made by hand).
	p := tr.hosts["relay.example"].h2
	cc, err := p.tr.NewClientConn(context.Background(), "https", p.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	eventually(t, "the stream limit", func() bool { return cc.Available() == 128 })
	if err := cc.Reserve(); err != nil {
		t.Fatal(err)
	}
	last := s.all()[len(s.all())-1]
	last.goAway(0, 0)
	eventually(t, "the GOAWAY", func() bool { return cc.Available() == 0 })
	req0, _ := http.NewRequest(http.MethodGet, "https://relay.example/x", nil)
	if _, err := cc.RoundTrip(req0); err == nil || err.Error() != "http2: client conn not usable" || !unprocessed(err) {
		t.Errorf("request on a connection that stopped taking requests: %v", err)
	}
	// A body that cannot be sent again is not.
	s.all()[1].refuse.Store(1)
	req, _ := http.NewRequest(http.MethodPost, "https://relay.example/x", io.NopCloser(strings.NewReader("body")))
	if _, err := c.Do(req); err == nil {
		t.Error("a request whose body cannot be sent again was sent again")
	}
	if st := tr.Stats("relay.example"); st.InFlight != 0 || st.Waiting != 0 {
		t.Errorf("stats afterwards: %+v", st)
	}
}

// TestLateSettings: a host that announces its stream limit late (after
// the pool stopped expecting it) and then allows one stream gets one
// connection all the same: a connection that has not announced a limit
// carries fewer than MinStreams requests and justifies no other.
func TestLateSettings(t *testing.T) {
	ca := newCA(t, "test root")
	s := newRawSrv(t, ca, 1)
	s.settingsDelay.Store(int64(h2Settle + 300*time.Millisecond))
	tr := s.pool(t, ca, 0, 0)
	c := tr.Client(30 * time.Second)
	wait := fire(c, 200, 3*time.Second)
	time.Sleep(h2Settle + time.Second)
	st := tr.Stats("relay.example")
	if st.Conns != 1 || s.accepted.Load() != 1 || s.parked() >= DefaultMinStreams || st.RefusedMinStreams == 0 {
		t.Errorf("late SETTINGS announcing 1: %d connections, %d requests at the host, stats %+v", s.accepted.Load(), s.parked(), st)
	}
	_, _, _ = wait()
	if s.accepted.Load() != 1 {
		t.Errorf("%d connections in the end", s.accepted.Load())
	}
}

// TestLateSettingsBelowAssumed: a limit announced late and below the
// library's assumption is reported by no hook (availability falls). The
// requests waiting for it must still be woken.
func TestLateSettingsBelowAssumed(t *testing.T) {
	ca := newCA(t, "test root")
	s := newRawSrv(t, ca, 50)
	s.settingsDelay.Store(int64(h2Settle + 300*time.Millisecond))
	tr := s.pool(t, ca, 0, 0)
	c := tr.Client(30 * time.Second)
	wait := fire(c, 120, 20*time.Second)
	eventually(t, "every request at the host", func() bool { return s.parked() == 120 })
	if st := tr.Stats("relay.example"); st.Streams != 50 || st.Conns != 3 || st.Waiting != 0 {
		t.Errorf("stats %+v", st)
	}
	s.respondAll()
	if ok, bad, sample := wait(); bad != 0 {
		t.Errorf("%d ok, %d failed (%s)", ok, bad, sample)
	}
}

// TestTick: a waiting request looks again every h2Tick even if nothing
// wakes it.
func TestTick(t *testing.T) {
	ca := newCA(t, "test root")
	s := newRawSrv(t, ca, 32)
	tr := s.pool(t, ca, 1, 0)
	p := tr.hosts["relay.example"].h2
	c := tr.Client(30 * time.Second)
	wait := fire(c, 33, 20*time.Second)
	eventually(t, "one request waiting at the bound", func() bool { return s.parked() == 32 && tr.Stats("relay.example").Waiting == 1 })
	p.mu.Lock()
	p.max = 2 // nothing tells the waiting request
	p.mu.Unlock()
	t0 := time.Now()
	eventually(t, "the waiting request", func() bool { return s.parked() == 33 })
	if d := time.Since(t0); d > 2*h2Tick {
		t.Errorf("woken after %v", d)
	}
	s.respondAll()
	_, _, _ = wait()
	eventually(t, "the ticker to stop", func() bool {
		p.wakeMu.Lock()
		defer p.wakeMu.Unlock()
		return !p.ticking
	})
}

// TestDrainingIsBounded: a host that lowers the stream limit of every
// connection once it is full, and keeps one request on each (it then
// looks as if it were closing: no free stream, below its limit), is let
// off the count for max connections once; each is closed after h2Drain.
// It is not given twice the bound for as long as it likes.
func TestDrainingIsBounded(t *testing.T) {
	const conns, streams = 2, 32
	ca := newCA(t, "test root")
	s := newRawSrv(t, ca, streams)
	tr := s.pool(t, ca, conns, 0)
	p := tr.hosts["relay.example"].h2
	p.drainFor = 500 * time.Millisecond
	c := tr.Client(30 * time.Second)
	wait := fire(c, 600, 6*time.Second)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { // the host: a full connection is told 1, and all but one of its requests answered
		defer close(done)
		told := map[*rawConn]bool{}
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
			for _, rc := range s.all() {
				if !told[rc] && rc.nOpen() == streams {
					told[rc] = true
					rc.settings(1)
					rc.mu.Lock()
					var ids []uint32
					for id := range rc.open {
						ids = append(ids, id)
					}
					rc.mu.Unlock()
					for _, id := range ids[1:] {
						rc.respond(id)
					}
				}
			}
		}
	}()
	eventually(t, "twice the bound, while the first connections are let off", func() bool { return tr.Stats("relay.example").Conns == 2*conns })
	// From then on: the bound.
	time.Sleep(p.drainFor + 2*h2Tick)
	most := 0
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		st := tr.Stats("relay.example")
		most = max(most, st.Conns)
		if st.Draining != 0 {
			t.Fatalf("a connection is let off again: %+v", st)
		}
	}
	if most > conns || s.accepted.Load() <= 2*conns {
		t.Errorf("up to %d connections open at a time after the first were let off (%d accepted in all); want %d at most, and new ones for those closed", most, s.accepted.Load(), conns)
	}
	close(stop)
	<-done
	s.park.Store(false)
	s.respondAll()
	_, _, _ = wait()
}

// TestOneStream: at a limit of one stream the connection is busy and
// free in turn; it must not be taken for dead between the two readings
// (it was, and a new one opened each time).
func TestOneStream(t *testing.T) {
	ca := newCA(t, "test root")
	s := newRawSrv(t, ca, 1)
	s.park.Store(false)
	tr := s.pool(t, ca, 0, 0)
	c := tr.Client(30 * time.Second)
	var wg sync.WaitGroup
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 150; i++ {
				if r, err := c.Get("https://relay.example/q"); err != nil {
					t.Errorf("request: %v", err)
				} else {
					r.Body.Close()
				}
			}
		}()
	}
	wg.Wait()
	if st := tr.Stats("relay.example"); s.accepted.Load() != 1 || st.Streams != 1 {
		t.Errorf("%d connections for a host with one stream; stats %+v", s.accepted.Load(), st)
	}
}
