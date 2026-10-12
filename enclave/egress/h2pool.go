package egress

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// h2Pool is the shared HTTP/2 connections to one host.
//
// A request takes a stream on the first connection that has one free, so
// the connections fill in order and as many vaults as possible share each.
// Only when every connection's streams are in use is another opened, one
// at a time, and never more than max; nor when a connection announced
// fewer than minStreams streams, or has not yet said how many it allows.
// Then requests wait for a stream, in the order they came, until their
// context ends.
//
// A connection the host is closing (GOAWAY) takes no new requests and
// does not count toward max while its last requests end; at most max of
// those are kept, and new connections are opened at a bounded rate, so
// the host does not choose the number of connections either way. A
// connection that answers nothing is closed: by the HTTP/2 ping when the
// host is gone, and after h2Stall without an answer in any case.
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
	stall      time.Duration

	mu      sync.Mutex
	conns   []*h2Conn
	dial    *h2Dial // the dial in progress, if any
	tokens  float64 // connections that may be opened now
	tokenAt time.Time
	dialed  uint64
	waited  uint64
	atMax   uint64
	atMin   uint64
	// The longest wait of the current minute and of the one before.
	waitMinute        int64
	waitCur, waitPrev time.Duration

	wakeMu  sync.Mutex
	waiters []chan struct{} // requests waiting for a stream, oldest first
	counted int             // the first so many are counted as refused a connection
}

type h2Conn struct {
	cc *http.ClientConn
	// limit is the stream limit the host announced; exact once it has
	// been read from the connection, which the library allows only while
	// a stream is free.
	limit int
	exact bool
	// answered: a response has arrived, so the host's SETTINGS frame
	// has too (it comes first). late: it had not arrived after h2Settle.
	answered atomic.Bool
	late     atomic.Bool
	// since is when the connection last answered a request, or was given
	// one while it had none (Unix nanoseconds).
	since atomic.Int64
}

type h2Dial struct {
	done chan struct{}
	err  error
}

// Stats describes the shared HTTP/2 connections to one host.
type Stats struct {
	// Conns is the number of open connections, Draining those of them
	// that the host is closing; Dialed counts every connection opened
	// since the start.
	Conns    int
	Draining int
	Dialed   uint64
	// Streams is the smallest stream limit an open connection announced
	// (0 if none has).
	Streams int
	// InFlight is the number of requests on a stream; Waiting the number
	// waiting for one.
	InFlight int
	Waiting  int
	// Waited counts the requests that had to wait for a stream (for a
	// new connection, or at a bound); WaitMax is the longest such wait
	// in the current minute and the one before.
	Waited  uint64
	WaitMax time.Duration
	// RefusedMaxConns and RefusedMinStreams count the requests that
	// waited because no further connection was allowed: MaxConns were
	// open (or too many had just been opened), or the host announced
	// fewer than MinStreams streams (or none within a second).
	RefusedMaxConns   uint64
	RefusedMinStreams uint64
}

const (
	// h2DialTimeout bounds opening a connection (the forwarder's dial,
	// itself bounded at 10 s, and the TLS handshake).
	h2DialTimeout = 15 * time.Second
	// New connections are opened at h2DialRate a second at most, after
	// a burst of twice max: a host cannot make the enclave open one per
	// request by closing them, and the loss of every connection twice
	// over is still replaced at once.
	h2DialRate = 2.0
	// h2Stall is how long a connection may hold requests without
	// answering any before it is closed: longer than any request lives
	// (80 s, the relay client of the supervisor).
	h2Stall = 90 * time.Second
	// The HTTP/2 ping (net/http's HTTP2Config): after h2PingIdle
	// without a frame from the host the connection is pinged, and
	// closed if the ping is not answered within h2PingTimeout. A
	// connection whose host is gone without a FIN would otherwise hold
	// its requests, and their streams after them, for good. 15 s is
	// below a long-poll's 20 to 25 s, so a lost connection is found
	// before the polls on it would have ended, and a connection that
	// carries a few vaults' polls is pinged at most once a poll; one
	// that carries many is never idle that long and is never pinged.
	h2PingIdle    = 15 * time.Second
	h2PingTimeout = 10 * time.Second
	// h2Unsettled is the stream limit the library assumes until the
	// host's SETTINGS frame, its first, arrives; the library does not
	// say when it did. A connection that still reads h2Unsettled and
	// has not answered a request may not have said anything yet: it
	// carries one request (so a host that announces exactly
	// h2Unsettled, as android.googleapis.com does, costs no wait: the
	// answer settles it), after h2Settle fewer than minStreams, and it
	// justifies no further connection.
	h2Unsettled = 100
	h2Settle    = time.Second
)

func newH2Pool(tr *http.Transport, host string, max, minStreams int) *h2Pool {
	tr.HTTP2 = &http.HTTP2Config{SendPingTimeout: h2PingIdle, PingTimeout: h2PingTimeout}
	return &h2Pool{tr: tr, addr: net.JoinHostPort(host, "443"), max: max, minStreams: minStreams, stall: h2Stall,
		tokens: float64(2 * max), tokenAt: time.Now()}
}

// RoundTrip sends r on a shared connection. A request the host did not
// process (its connection was being closed, or it refused the stream) is
// sent once more, as the library's pool did; any
// other failure is the caller's to retry.
func (p *h2Pool) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx := r.Context()
	for again := false; ; again = true {
		c, err := p.acquire(ctx)
		if err != nil {
			if r.Body != nil {
				r.Body.Close()
			}
			return nil, err
		}
		resp, err := c.cc.RoundTrip(r)
		if err == nil {
			c.since.Store(time.Now().UnixNano())
			if c.answered.CompareAndSwap(false, true) {
				p.wakeOne() // its stream limit can be trusted now
			}
			return resp, nil
		}
		if again || !unprocessed(err) || ctx.Err() != nil {
			return nil, err
		}
		if r.Body != nil && r.Body != http.NoBody {
			if r.GetBody == nil {
				return nil, err
			}
			body, gerr := r.GetBody()
			if gerr != nil {
				return nil, err
			}
			r = r.Clone(ctx)
			r.Body = body
		}
	}
}

// unprocessed reports whether err says that the host did not process the
// request, so that sending it again cannot repeat it (RFC 9113 §8.7): the
// connection stopped taking requests before this one was sent, the host's
// GOAWAY named it as not processed, or the host refused the stream. The
// library does not export these errors; TestUnprocessedIsResent holds
// their texts to it.
func unprocessed(err error) bool {
	s := err.Error()
	return s == "http2: client conn not usable" || s == "http2: Transport received Server's graceful shutdown GOAWAY" ||
		strings.HasPrefix(s, "stream error: stream ID ") && strings.Contains(s, "; REFUSED_STREAM")
}

// acquire returns a connection with a stream reserved on it (released by
// the one RoundTrip that follows).
func (p *h2Pool) acquire(ctx context.Context) (*h2Conn, error) {
	var since time.Time
	var me chan struct{}
	var mine *h2Dial // the dial this request started
	// leave ends the wait: this request's place in the queue goes, and
	// the next one is woken in its stead, as a stream it was woken for
	// (or others freed with it) may still be free.
	leave := func() {
		p.unqueue(me)
		p.mu.Lock()
		p.noteWaitLocked(time.Since(since))
		p.mu.Unlock()
		p.wakeOne()
	}
	for {
		p.mu.Lock()
		k := p.pickLocked(time.Now())
		if k.c == nil && me == nil {
			p.waited++
		}
		if k.c == nil && k.refused != nil && me != nil {
			*k.refused += p.uncounted()
		}
		p.mu.Unlock()
		for _, cc := range k.dead {
			cc.Close()
		}
		if k.c != nil {
			if me != nil {
				leave()
			}
			return k.c, nil
		}
		if k.mine {
			mine = k.dial
		}
		if me == nil {
			// Queue, and look once more: a stream freed before this
			// request was in the queue woke no one.
			since, me = time.Now(), p.queue()
			continue
		}
		var done <-chan struct{}
		if mine != nil {
			done = mine.done
		}
		var later <-chan time.Time
		var t *time.Timer
		if k.after > 0 {
			t = time.NewTimer(k.after)
			later = t.C
		}
		err := error(nil)
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-me:
		case <-later:
		case <-done:
			// A failed dial fails the request that started it; the
			// others try again within their own time.
			err, mine = mine.err, nil
		}
		if t != nil {
			t.Stop()
		}
		if err != nil {
			leave()
			return nil, err
		}
	}
}

// picked is what pickLocked found: the connection c with a stream
// reserved, or else what to wait for: the dial in progress (mine if this
// call started it), or, when a bound forbids another connection, that
// bound's counter (and after, if the bound ends by itself). dead are
// connections to close, outside the lock.
type picked struct {
	c       *h2Conn
	dial    *h2Dial
	mine    bool
	refused *uint64
	after   time.Duration
	dead    []*http.ClientConn
}

// state reads a connection: its streams in use and free, and whether
// they were read together (the library gives them one at a time; streams
// are taken only under p.mu, so a count that is the same before and
// after did not change).
func (x *h2Conn) state() (used, free int, steady bool) {
	used = x.cc.InFlight()
	free = x.cc.Available()
	after := x.cc.InFlight()
	return after, free, used == after
}

// pickLocked reserves a stream on the first connection that has one, and
// starts a dial if none has and the bounds allow it.
func (p *h2Pool) pickLocked(now time.Time) (k picked) {
	live := p.conns[:0]
	counted, small, unsettled, late := 0, false, false, false
	for _, x := range p.conns {
		used, free, steady := x.state()
		switch {
		case x.cc.Err() != nil, steady && used == 0 && free == 0:
			// Closed, or no longer usable (the host said GOAWAY, or
			// it sat idle too long) and its last request has ended.
			k.dead = append(k.dead, x.cc)
			continue
		case used > 0 && now.Sub(time.Unix(0, x.since.Load())) > p.stall:
			// It holds requests and has answered none for longer
			// than a request lives: closing it fails them, and
			// frees the place.
			k.dead = append(k.dead, x.cc)
			continue
		}
		live = append(live, x)
		settled := steady && (free+used != h2Unsettled || x.answered.Load())
		if settled && free > 0 {
			x.limit, x.exact = free+used, true
		}
		room := free > 0
		if !x.exact {
			// One request may go at once: no host allows fewer, and
			// its answer shows that the limit has been announced.
			most := 1
			if x.late.Load() {
				most = max(p.minStreams-1, 1)
			}
			room = room && used < most
		}
		if room && k.c == nil && x.cc.Reserve() == nil {
			if used == 0 {
				x.since.Store(now.UnixNano())
			}
			k.c = x
		}
		switch {
		case x.exact && steady && free == 0 && used < x.limit:
			// Draining: the host is closing it.
		case x.exact:
			small = small || x.limit < p.minStreams
			counted++
		case settled:
			// The limit came while the connection carried more than
			// it allows: it is below minStreams, then.
			small = true
			counted++
		default:
			unsettled, late = true, late || x.late.Load()
			counted++
		}
	}
	clear(p.conns[len(live):])
	p.conns = live
	p.tokens = min(float64(2*p.max), p.tokens+now.Sub(p.tokenAt).Seconds()*h2DialRate)
	p.tokenAt = now
	switch {
	case k.c != nil:
	case p.dial != nil:
		k.dial = p.dial
	case unsettled && !late:
		// A new connection that has not announced its streams yet (a
		// moment, as a rule): wait for that, as for a dial.
	case counted >= p.max, len(p.conns) >= 2*p.max:
		k.refused = &p.atMax
	case small, unsettled:
		k.refused = &p.atMin
	case p.tokens < 1:
		k.refused, k.after = &p.atMax, time.Duration((1-p.tokens)/h2DialRate*float64(time.Second))+time.Millisecond
	default:
		p.dial = &h2Dial{done: make(chan struct{})}
		go p.open(p.dial)
		k.dial, k.mine = p.dial, true
	}
	return k
}

// open dials one connection. It does not use a request's context: other
// requests wait for this connection too.
func (p *h2Pool) open(d *h2Dial) {
	ctx, cancel := context.WithTimeout(context.Background(), h2DialTimeout)
	cc, err := p.tr.NewClientConn(ctx, "https", p.addr)
	cancel()
	var x *h2Conn
	if err == nil {
		x = &h2Conn{cc: cc}
		x.since.Store(time.Now().UnixNano())
		cc.SetStateHook(p.changed)
	}
	p.mu.Lock()
	if err == nil {
		p.conns = append(p.conns, x)
		p.dialed++
		p.tokens--
	}
	d.err = err
	p.dial = nil
	p.mu.Unlock()
	close(d.done)
	p.wakeOne()
	if err != nil {
		return
	}
	// The requests waiting for the host's stream limit are woken when
	// it shows; the library does not tell (unless the limit is above
	// its assumption).
	for end := time.Now().Add(h2Settle); cc.Err() == nil; time.Sleep(time.Millisecond) {
		if used, free, steady := x.state(); steady && used+free != h2Unsettled || x.answered.Load() {
			break
		}
		if time.Now().After(end) {
			x.late.Store(true)
			break
		}
	}
	p.wakeOne()
}

// changed is a connection's state hook: a stream became free or the
// connection closed. The library may call it from inside any call on the
// connection, so it must not take p.mu.
func (p *h2Pool) changed(*http.ClientConn) { p.wakeOne() }

// wakeOne wakes the request that has waited longest. If it gets a stream
// it wakes the next (acquire), so that streams freed together are all
// taken, and a stream freed alone wakes one request, not all of them.
func (p *h2Pool) wakeOne() {
	p.wakeMu.Lock()
	if len(p.waiters) > 0 {
		select {
		case p.waiters[0] <- struct{}{}:
		default:
		}
	}
	p.wakeMu.Unlock()
}

func (p *h2Pool) queue() chan struct{} {
	me := make(chan struct{}, 1)
	p.wakeMu.Lock()
	p.waiters = append(p.waiters, me)
	p.wakeMu.Unlock()
	return me
}

func (p *h2Pool) unqueue(me chan struct{}) {
	p.wakeMu.Lock()
	for i, w := range p.waiters {
		if w == me {
			p.waiters = append(p.waiters[:i], p.waiters[i+1:]...)
			if i < p.counted {
				p.counted--
			}
			break
		}
	}
	p.wakeMu.Unlock()
}

// uncounted returns how many waiting requests have not been counted as
// refused a connection, and marks them counted: when a bound forbids
// another connection, every request waiting then is waiting for that.
func (p *h2Pool) uncounted() uint64 {
	p.wakeMu.Lock()
	defer p.wakeMu.Unlock()
	n := len(p.waiters) - p.counted
	p.counted = len(p.waiters)
	return uint64(n)
}

// noteWaitLocked records a wait that ended.
func (p *h2Pool) noteWaitLocked(d time.Duration) {
	p.turnMinuteLocked()
	p.waitCur = max(p.waitCur, d)
}

func (p *h2Pool) turnMinuteLocked() {
	m := time.Now().Unix() / 60
	if m == p.waitMinute {
		return
	}
	if m == p.waitMinute+1 {
		p.waitPrev = p.waitCur
	} else {
		p.waitPrev = 0
	}
	p.waitCur, p.waitMinute = 0, m
}

// stats does not change anything: whoever asks, and however often, the
// next reader sees the same.
func (p *h2Pool) stats() Stats {
	p.wakeMu.Lock()
	waiting := len(p.waiters)
	p.wakeMu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.turnMinuteLocked()
	s := Stats{Dialed: p.dialed, Waiting: waiting, Waited: p.waited, WaitMax: max(p.waitCur, p.waitPrev),
		RefusedMaxConns: p.atMax, RefusedMinStreams: p.atMin}
	for _, x := range p.conns {
		used, free, _ := x.state()
		if x.cc.Err() != nil {
			continue
		}
		s.Conns++
		s.InFlight += used
		if !x.exact {
			continue
		}
		if free == 0 && used < x.limit {
			s.Draining++
		}
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
