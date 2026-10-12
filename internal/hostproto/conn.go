package hostproto

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ErrClosed is returned once the connection has failed or been closed.
var ErrClosed = errors.New("hostproto: connection closed")

// ErrFull is returned by TryNotify when the frame would have to wait for
// the writer.
var ErrFull = errors.New("hostproto: outgoing queue full")

// Handler answers a request frame with the reply's fields (the first being
// a status). It runs on its own goroutine.
type Handler func(ctx context.Context, f *Frame) [][]byte

// Notifier receives notification frames in order, on the reader goroutine:
// it must not block for long.
type Notifier func(f *Frame)

// Conn multiplexes requests, replies and notifications in both directions
// over one connection. One goroutine reads, one writes; frames are written
// whole, in order, in chunks of at most ChunkSize bytes.
type Conn struct {
	c        net.Conn
	opt      Options
	onReq    Handler
	onNotify Notifier
	out      chan []byte
	done     chan struct{}
	once     sync.Once
	ctx      context.Context
	cancel   context.CancelFunc
	nextID   atomic.Uint64
	sem      chan struct{}
	// unwritten counts frames queued for the writer and not yet written
	// (Flush).
	unwritten atomic.Int64

	mu      sync.Mutex
	pending map[uint64]chan *Frame
	err     error
}

// MaxInflight bounds concurrently handled peer requests.
const MaxInflight = 128

// Options are what a side asks of its connection beyond the protocol. The
// zero value asks nothing (NewConn).
type Options struct {
	// WriteTimeout bounds the writing of one frame. A frame that is not
	// written in that time ends the connection, as any write error does:
	// a peer that has stopped reading cannot hold the senders for ever.
	// 0: no bound.
	WriteTimeout time.Duration
	// OnWait, if set, is told when the reader starts (true) and stops
	// (false) waiting because MaxInflight requests of the peer are being
	// handled: in between, nothing the peer sends is read. It runs on the
	// reader and must not block.
	OnWait func(waiting bool)
}

// NewConn starts the reader and writer goroutines.
func NewConn(c net.Conn, onReq Handler, onNotify Notifier) *Conn {
	return NewConnOptions(c, onReq, onNotify, Options{})
}

// NewConnOptions is NewConn with options.
func NewConnOptions(c net.Conn, onReq Handler, onNotify Notifier, opt Options) *Conn {
	ctx, cancel := context.WithCancel(context.Background())
	x := &Conn{c: c, opt: opt, onReq: onReq, onNotify: onNotify, out: make(chan []byte, 256), done: make(chan struct{}),
		ctx: ctx, cancel: cancel, sem: make(chan struct{}, MaxInflight), pending: map[uint64]chan *Frame{}}
	go x.readLoop()
	go x.writeLoop()
	return x
}

// Done is closed when the connection has ended.
func (x *Conn) Done() <-chan struct{} { return x.done }

// Err returns why the connection ended.
func (x *Conn) Err() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.err
}

// Close ends the connection. Frames still queued are dropped: Flush first
// to deliver them.
func (x *Conn) Close() { x.fail(ErrClosed) }

// Flush waits until every frame queued so far (notifications in
// particular: Notify only queues) has been written, the connection has
// ended, or ctx is done.
func (x *Conn) Flush(ctx context.Context) error {
	t := time.NewTicker(2 * time.Millisecond)
	defer t.Stop()
	for x.unwritten.Load() > 0 {
		select {
		case <-x.done:
			return ErrClosed
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	return nil
}

func (x *Conn) fail(err error) {
	x.once.Do(func() {
		x.mu.Lock()
		x.err = err
		for id, ch := range x.pending {
			close(ch)
			delete(x.pending, id)
		}
		x.mu.Unlock()
		x.cancel()
		close(x.done)
		_ = x.c.Close()
	})
}

// send queues a frame for the writer. With wait it blocks while the queue
// is full (for at most WriteTimeout, if one is set: the writer then gets a
// frame out or ends the connection); without, it returns ErrFull.
func (x *Conn) send(f *Frame, wait bool) error {
	b, err := f.Marshal()
	if err != nil {
		return err
	}
	x.unwritten.Add(1)
	if !wait {
		select {
		case x.out <- b:
			return nil
		case <-x.done:
			x.unwritten.Add(-1)
			return ErrClosed
		default:
			x.unwritten.Add(-1)
			return ErrFull
		}
	}
	select {
	case x.out <- b:
		return nil
	case <-x.done:
		x.unwritten.Add(-1)
		return ErrClosed
	}
}

func (x *Conn) writeLoop() {
	for {
		select {
		case b := <-x.out:
			if x.opt.WriteTimeout > 0 {
				_ = x.c.SetWriteDeadline(time.Now().Add(x.opt.WriteTimeout))
			}
			err := WriteChunked(x.c, b)
			x.unwritten.Add(-1)
			if err != nil {
				x.fail(err)
				return
			}
		case <-x.done:
			return
		}
	}
}

func (x *Conn) readLoop() {
	for {
		f, err := ReadFrame(x.c)
		if err != nil {
			x.fail(err)
			return
		}
		switch {
		case f.Kind == KindReply:
			x.mu.Lock()
			ch := x.pending[f.ID]
			delete(x.pending, f.ID)
			x.mu.Unlock()
			if ch != nil {
				ch <- f
			}
		case f.ID == 0:
			if x.onNotify != nil {
				x.onNotify(f)
			}
		default:
			if !x.slot() {
				return
			}
			go func(f *Frame) {
				defer func() { <-x.sem }()
				var fields [][]byte
				if x.onReq != nil {
					fields = x.onReq(x.ctx, f)
				}
				if len(fields) == 0 {
					fields = Strings(StatusInvalid)
				}
				_ = x.send(&Frame{Kind: KindReply, ID: f.ID, Fields: fields}, true)
			}(f)
		}
	}
}

// slot takes one of the MaxInflight places for a request of the peer,
// waiting for one if all are taken (false: the connection ended first).
func (x *Conn) slot() bool {
	select {
	case x.sem <- struct{}{}:
		return true
	default:
	}
	if x.opt.OnWait != nil {
		x.opt.OnWait(true)
		defer x.opt.OnWait(false)
	}
	select {
	case x.sem <- struct{}{}:
		return true
	case <-x.done:
		return false
	}
}

// Call sends a request and waits for its reply's fields.
func (x *Conn) Call(ctx context.Context, kind Kind, fields ...[]byte) ([][]byte, error) {
	id := x.nextID.Add(1)
	ch := make(chan *Frame, 1)
	x.mu.Lock()
	if x.err != nil {
		x.mu.Unlock()
		return nil, ErrClosed
	}
	x.pending[id] = ch
	x.mu.Unlock()
	if err := x.send(&Frame{Kind: kind, ID: id, Fields: fields}, true); err != nil {
		x.mu.Lock()
		delete(x.pending, id)
		x.mu.Unlock()
		return nil, err
	}
	select {
	case f, ok := <-ch:
		if !ok || len(f.Fields) == 0 {
			return nil, ErrClosed
		}
		return f.Fields, nil
	case <-ctx.Done():
		x.mu.Lock()
		delete(x.pending, id)
		x.mu.Unlock()
		return nil, ctx.Err()
	case <-x.done:
		return nil, ErrClosed
	}
}

// Notify sends a notification. It waits while the outgoing queue is full.
func (x *Conn) Notify(kind Kind, fields ...[]byte) error {
	return x.send(&Frame{Kind: kind, Fields: fields}, true)
}

// TryNotify sends a notification if the outgoing queue has room for it now
// and returns ErrFull otherwise: it never waits for the peer.
func (x *Conn) TryNotify(kind Kind, fields ...[]byte) error {
	return x.send(&Frame{Kind: kind, Fields: fields}, false)
}
