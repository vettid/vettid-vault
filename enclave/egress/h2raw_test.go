package egress

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A raw HTTP/2 server: frames by hand, so that a test controls SETTINGS,
// GOAWAY, RST_STREAM and silence. It does not decode request headers.

const (
	frData, frHeaders, frRST, frSettings, frPing, frGoAway = 0, 1, 3, 4, 6, 7
)

type rawConn struct {
	s      *rawSrv
	c      net.Conn
	wmu    sync.Mutex
	mu     sync.Mutex
	open   map[uint32]bool
	lastID uint32
	silent atomic.Bool  // send nothing more (the connection stays open and is read)
	stuck  atomic.Bool  // answer pings, but no request
	refuse atomic.Int32 // refuse this many of the next requests (REFUSED_STREAM)
}

func (c *rawConn) frame(typ, flags byte, sid uint32, p []byte) {
	if c.silent.Load() {
		return
	}
	b := make([]byte, 9+len(p))
	b[0], b[1], b[2] = byte(len(p)>>16), byte(len(p)>>8), byte(len(p))
	b[3], b[4] = typ, flags
	binary.BigEndian.PutUint32(b[5:], sid)
	copy(b[9:], p)
	c.wmu.Lock()
	_, _ = c.c.Write(b)
	c.wmu.Unlock()
}

func (c *rawConn) settings(maxStreams int) {
	p := make([]byte, 6)
	binary.BigEndian.PutUint16(p, 3)
	binary.BigEndian.PutUint32(p[2:], uint32(maxStreams))
	c.frame(frSettings, 0, 0, p)
}

func (c *rawConn) respond(sid uint32) {
	c.mu.Lock()
	ok := c.open[sid]
	delete(c.open, sid)
	c.mu.Unlock()
	if ok && !c.stuck.Load() {
		c.frame(frHeaders, 0x5, sid, []byte{0x88}) // :status 200, END_STREAM|END_HEADERS
	}
}

func (c *rawConn) respondAll() {
	c.mu.Lock()
	var ids []uint32
	for id := range c.open {
		ids = append(ids, id)
	}
	c.mu.Unlock()
	for _, id := range ids {
		c.respond(id)
	}
}

func (c *rawConn) goAway(last uint32, code uint32) {
	p := make([]byte, 8)
	binary.BigEndian.PutUint32(p, last)
	binary.BigEndian.PutUint32(p[4:], code)
	c.frame(frGoAway, 0, 0, p)
}

func (c *rawConn) nOpen() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.open)
}

type rawSrv struct {
	ln            net.Listener
	announce      atomic.Int32 // MAX_CONCURRENT_STREAMS; -1: never send SETTINGS
	settingsDelay atomic.Int64 // ns before the first SETTINGS
	park          atomic.Bool  // hold requests until respondAll
	closeAtOnce   atomic.Bool  // close a connection at its first request
	accepted      atomic.Int32
	mu            sync.Mutex
	conns         []*rawConn
}

func newRawSrv(t *testing.T, ca *testCA, announce int) *rawSrv {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{ca.leaf(t, "relay.example")}, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	s := &rawSrv{ln: ln}
	s.announce.Store(int32(announce))
	s.park.Store(true)
	t.Cleanup(func() { ln.Close(); s.closeAll() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.accepted.Add(1)
			rc := &rawConn{s: s, c: c, open: map[uint32]bool{}}
			s.mu.Lock()
			s.conns = append(s.conns, rc)
			s.mu.Unlock()
			go rc.serve()
		}
	}()
	return s
}

func (s *rawSrv) all() []*rawConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*rawConn(nil), s.conns...)
}

func (s *rawSrv) closeAll() {
	for _, c := range s.all() {
		c.c.Close()
	}
	s.mu.Lock()
	s.conns = nil
	s.mu.Unlock()
}

func (s *rawSrv) parked() int {
	n := 0
	for _, c := range s.all() {
		n += c.nOpen()
	}
	return n
}

func (s *rawSrv) respondAll() {
	for _, c := range s.all() {
		c.respondAll()
	}
}

func (c *rawConn) serve() {
	defer c.c.Close()
	pre := make([]byte, 24)
	if _, err := io.ReadFull(c.c, pre); err != nil {
		return
	}
	if a := c.s.announce.Load(); a >= 0 {
		if d := c.s.settingsDelay.Load(); d > 0 {
			go func() { time.Sleep(time.Duration(d)); c.settings(int(c.s.announce.Load())) }()
		} else {
			c.settings(int(a))
		}
	}
	h := make([]byte, 9)
	for {
		if _, err := io.ReadFull(c.c, h); err != nil {
			return
		}
		n := int(h[0])<<16 | int(h[1])<<8 | int(h[2])
		p := make([]byte, n)
		if _, err := io.ReadFull(c.c, p); err != nil {
			return
		}
		sid := binary.BigEndian.Uint32(h[5:]) & 0x7fffffff
		switch h[3] {
		case frSettings:
			if h[4]&1 == 0 {
				c.frame(frSettings, 1, 0, nil)
			}
		case frPing:
			if h[4]&1 == 0 {
				c.frame(frPing, 1, 0, p)
			}
		case frHeaders:
			if c.refuse.Add(-1) >= 0 {
				c.frame(frRST, 0, sid, []byte{0, 0, 0, 7})
				continue
			}
			if c.s.closeAtOnce.Load() {
				return
			}
			c.mu.Lock()
			c.open[sid] = true
			c.lastID = max(c.lastID, sid)
			c.mu.Unlock()
			if !c.s.park.Load() {
				c.respond(sid)
			}
		case frRST:
			c.mu.Lock()
			delete(c.open, sid)
			c.mu.Unlock()
		}
	}
}

func (s *rawSrv) pool(t *testing.T, ca *testCA, maxConns, minStreams int) *Transport {
	var dials atomic.Int32
	tr, err := New(Config{Dialer: dialer(s.ln.Addr().String(), &dials), MaxConns: maxConns, MinStreams: minStreams,
		Hosts: []Host{{Name: "relay.example", Roots: ca.pool, HTTP2: true}}})
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// fire starts n GETs with the given timeout; returns a wait func giving (ok, failed, sample error).
func fire(c *http.Client, n int, timeout time.Duration) func() (int, int, string) {
	var ok, bad atomic.Int32
	var sample atomic.Value
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://relay.example/park", nil)
			r, err := c.Do(req)
			if err != nil {
				bad.Add(1)
				sample.Store(err.Error())
				return
			}
			io.Copy(io.Discard, r.Body)
			r.Body.Close()
			ok.Add(1)
		}()
	}
	return func() (int, int, string) {
		wg.Wait()
		s, _ := sample.Load().(string)
		return int(ok.Load()), int(bad.Load()), s
	}
}
