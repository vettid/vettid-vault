package egress

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// h2Pool is the shared HTTP/2 connections to one host.
//
// A request takes a stream on the first connection that has one free, so
// the connections fill in order and as many vaults as possible share each.
// Only when every connection's streams are in use is another opened, one
// at a time, and never more than max (at a time, and in ten seconds); nor
// when a connection announced fewer than minStreams streams. Then
// requests wait for a stream, until their context ends.
//
// The standard library's own pool is not used for HTTP/2: it opens as
// many connections as the host's announced stream limit makes it, and
// does not tell what the limit is. http.ClientConn (Go 1.26) is one
// connection, with its free and used streams.
type h2Pool struct {
	tr         *http.Transport // dials and speaks HTTP/2; its own pool stays empty
	addr       string
	max        int
	minStreams int

	mu      sync.Mutex
	conns   []*h2Conn
	dial    *h2Dial     // the dial in progress, if any
	opened  []time.Time // when the last max connections were opened
	dialed  uint64
	waited  uint64
	atMax   uint64
	atMin   uint64
	waitMax time.Duration

	waiting atomic.Int64
	wakeMu  sync.Mutex
	wake    chan struct{} // closed when a stream may have become free
}

type h2Conn struct {
	cc *http.ClientConn
	// limit is the stream limit the host announced, as last seen while
	// the connection had a free stream.
	limit int
}

type h2Dial struct {
	done chan struct{}
	err  error
}

// Stats describes the shared HTTP/2 connections to one host.
type Stats struct {
	// Conns is the number of open connections; Dialed counts every
	// connection opened since the start.
	Conns  int
	Dialed uint64
	// Streams is the smallest stream limit an open connection announced
	// (0 without a connection).
	Streams int
	// InFlight is the number of requests on a stream; Waiting the number
	// waiting for one.
	InFlight int
	Waiting  int
	// Waited counts the requests that had to wait for a stream (for a
	// new connection, or at a bound); WaitMax is the longest such wait
	// since the previous call of Stats.
	Waited  uint64
	WaitMax time.Duration
	// RefusedMaxConns and RefusedMinStreams count the requests that
	// waited because no further connection was allowed: MaxConns were
	// open (or had been opened within ten seconds), or the host
	// announced fewer than MinStreams streams.
	RefusedMaxConns   uint64
	RefusedMinStreams uint64
}

// h2DialTimeout bounds opening a connection (the forwarder's dial and the
// TLS handshake). At most max connections are opened in any h2DialWindow.
const (
	h2DialTimeout = 15 * time.Second
	h2DialWindow  = 10 * time.Second
)

func newH2Pool(tr *http.Transport, host string, max, minStreams int) *h2Pool {
	return &h2Pool{tr: tr, addr: net.JoinHostPort(host, "443"), max: max, minStreams: minStreams, wake: make(chan struct{})}
}

// RoundTrip sends r on a shared connection. A request that fails with its
// connection is not sent again here: the relay client signs and sends it
// anew.
func (p *h2Pool) RoundTrip(r *http.Request) (*http.Response, error) {
	c, err := p.acquire(r.Context())
	if err != nil {
		if r.Body != nil {
			r.Body.Close()
		}
		return nil, err
	}
	return c.cc.RoundTrip(r)
}

// acquire returns a connection with a stream reserved on it (released by
// the one RoundTrip that follows).
func (p *h2Pool) acquire(ctx context.Context) (*h2Conn, error) {
	var since time.Time
	counted := false
	for {
		w := p.wakeChan()
		p.mu.Lock()
		k := p.pickLocked(time.Now())
		first := k.c == nil && since.IsZero()
		if first {
			since = time.Now()
			p.waited++
			p.waiting.Add(1)
		}
		if k.c == nil && k.refused != nil && !counted {
			*k.refused++
			counted = true
		}
		if k.c != nil && !since.IsZero() {
			p.waitMax = max(p.waitMax, time.Since(since))
			p.waiting.Add(-1)
		}
		p.mu.Unlock()
		for _, cc := range k.dead {
			cc.Close()
		}
		if k.c != nil {
			return k.c, nil
		}
		if first {
			continue // a stream freed before this request counted as waiting woke no one
		}
		var done <-chan struct{}
		var later <-chan time.Time
		if k.dial != nil {
			done = k.dial.done
		}
		var t *time.Timer
		if k.after > 0 {
			t = time.NewTimer(k.after)
			later = t.C
		}
		err := error(nil)
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-w:
		case <-later:
		case <-done:
			err = k.dial.err // a failed dial fails the requests that waited for it
		}
		if t != nil {
			t.Stop()
		}
		if err != nil {
			p.waiting.Add(-1)
			p.mu.Lock()
			p.waitMax = max(p.waitMax, time.Since(since))
			p.mu.Unlock()
			return nil, err
		}
	}
}

// picked is what pickLocked found: the connection c with a stream
// reserved, or else what to wait for: the dial in progress, or, when a
// bound forbids another connection, that bound's counter (and after, if
// the bound ends by itself). dead are connections to close, outside the
// lock.
type picked struct {
	c       *h2Conn
	dial    *h2Dial
	refused *uint64
	after   time.Duration
	dead    []*http.ClientConn
}

// pickLocked reserves a stream on the first connection that has one, and
// starts a dial if none has and the bounds allow it.
func (p *h2Pool) pickLocked(now time.Time) (k picked) {
	live := p.conns[:0]
	least := 0
	for _, x := range p.conns {
		free, used := x.cc.Available(), x.cc.InFlight()
		if x.cc.Err() != nil || free == 0 && used == 0 {
			// Closed, or no longer usable (the host said GOAWAY, or
			// it sat idle too long) and its last request has ended.
			k.dead = append(k.dead, x.cc)
			continue
		}
		live = append(live, x)
		if free > 0 {
			x.limit = free + used
			if k.c == nil && x.cc.Reserve() == nil {
				k.c = x
			}
		}
		if least == 0 || x.limit < least {
			least = x.limit
		}
	}
	clear(p.conns[len(live):])
	p.conns = live
	switch {
	case k.c != nil:
		return k
	case p.dial != nil:
		k.dial = p.dial
		return k
	case len(p.conns) >= p.max:
		// A connection the host is closing counts until its requests
		// have ended: the bound is on connections, whatever the host
		// does.
		k.refused = &p.atMax
		return k
	case len(p.conns) > 0 && least < p.minStreams:
		k.refused = &p.atMin
		return k
	case len(p.opened) >= p.max && now.Sub(p.opened[0]) < h2DialWindow:
		// Nor does a host that closes its connections at once get a
		// new one per request.
		k.refused, k.after = &p.atMax, h2DialWindow-now.Sub(p.opened[0])
		return k
	}
	p.dial = &h2Dial{done: make(chan struct{})}
	go p.open(p.dial)
	k.dial = p.dial
	return k
}

// open dials one connection. It does not use a request's context: every
// waiting request is waiting for this connection.
func (p *h2Pool) open(d *h2Dial) {
	ctx, cancel := context.WithTimeout(context.Background(), h2DialTimeout)
	cc, err := p.tr.NewClientConn(ctx, "https", p.addr)
	cancel()
	limit := 0
	if err == nil {
		limit = settle(cc)
	}
	p.mu.Lock()
	if err == nil {
		p.conns = append(p.conns, &h2Conn{cc: cc, limit: limit})
		p.dialed++
		if len(p.opened) >= p.max {
			p.opened = p.opened[:copy(p.opened, p.opened[1:])]
		}
		p.opened = append(p.opened, time.Now())
	}
	d.err = err
	p.dial = nil
	p.mu.Unlock()
	close(d.done)
	if err == nil {
		cc.SetStateHook(p.changed)
	}
}

// h2Unsettled is the stream limit the library assumes until the host's
// SETTINGS frame, its first, arrives; h2Settle is how long a new
// connection waits for it.
const (
	h2Unsettled = 100
	h2Settle    = time.Second
)

// settle returns the stream limit the host announced on a new connection,
// before any request uses it: requests sent on the library's assumption
// would queue inside the connection if the host allows fewer, where
// nothing counts them and the limit can no longer be read. The library
// does not say when the frame arrived, so a host that announces exactly
// h2Unsettled streams costs every new connection the whole wait (the
// relay's load balancer announces 128; TestStreamLimitIsRead holds this
// to the library).
func settle(cc *http.ClientConn) int {
	for end := time.Now().Add(h2Settle); cc.Available() == h2Unsettled && cc.Err() == nil && time.Now().Before(end); {
		time.Sleep(time.Millisecond)
	}
	return cc.Available()
}

// changed is a connection's state hook: a stream became free or the
// connection closed. The library may call it from inside any call on the
// connection, so it must not take p.mu.
func (p *h2Pool) changed(*http.ClientConn) {
	if p.waiting.Load() == 0 {
		return
	}
	p.wakeMu.Lock()
	close(p.wake)
	p.wake = make(chan struct{})
	p.wakeMu.Unlock()
}

// wakeChan is taken before looking for a stream, so that a stream freed
// during the look is not missed.
func (p *h2Pool) wakeChan() chan struct{} {
	p.wakeMu.Lock()
	defer p.wakeMu.Unlock()
	return p.wake
}

func (p *h2Pool) stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := Stats{Dialed: p.dialed, Waiting: int(p.waiting.Load()), Waited: p.waited, WaitMax: p.waitMax,
		RefusedMaxConns: p.atMax, RefusedMinStreams: p.atMin}
	p.waitMax = 0
	for _, x := range p.conns {
		if x.cc.Err() != nil {
			continue
		}
		s.Conns++
		s.InFlight += x.cc.InFlight()
		if s.Streams == 0 || x.limit < s.Streams {
			s.Streams = x.limit
		}
	}
	return s
}

// closeIdle closes the connections without a request.
func (p *h2Pool) closeIdle() {
	p.mu.Lock()
	var idle []*http.ClientConn
	live := p.conns[:0]
	for _, x := range p.conns {
		if x.cc.InFlight() == 0 {
			idle = append(idle, x.cc)
			continue
		}
		live = append(live, x)
	}
	clear(p.conns[len(live):])
	p.conns = live
	p.mu.Unlock()
	for _, cc := range idle {
		cc.Close()
	}
}
