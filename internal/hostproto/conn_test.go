package hostproto

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// A peer that stops reading: a frame that cannot be written within
// WriteTimeout ends the connection, which frees every sender that was
// waiting; TryNotify never waits at all.
func TestWriteTimeout(t *testing.T) {
	a, b := net.Pipe() // nobody reads b
	defer b.Close()
	const timeout = 300 * time.Millisecond
	start := time.Now()
	x := NewConnOptions(a, nil, nil, Options{WriteTimeout: timeout})
	defer x.Close()
	// The queue takes 256 frames and the writer holds one more.
	n, full := 0, 0
	for full < 1000 && n < 257 {
		switch err := x.TryNotify(KindLog, Strings("info", "x")...); {
		case err == nil:
			n++
		case errors.Is(err, ErrFull):
			full++ // the writer has not taken its frame yet
			time.Sleep(100 * time.Microsecond)
		default:
			t.Fatalf("TryNotify: %v", err)
		}
	}
	if err := x.TryNotify(KindLog, Strings("info", "x")...); n != 257 || !errors.Is(err, ErrFull) {
		t.Fatalf("%d frames queued, then %v", n, err)
	}
	if filled := time.Since(start); filled >= timeout {
		t.Skipf("too slow to tell: the queue took %v to fill", filled)
	}
	select {
	case <-x.Done():
		t.Fatal("connection ended before the write timeout")
	default:
	}
	// Senders that wait are held until the connection ends, no longer.
	errs := make(chan error, 2)
	go func() { errs <- x.Notify(KindLifecycle, Strings("locked", "v", "r", "r", "1")...) }()
	go func() {
		_, err := x.Call(context.Background(), KindStoreGet, []byte("k"))
		errs <- err
	}()
	for i := 0; i < 2; i++ {
		select {
		case err := <-errs:
			if !errors.Is(err, ErrClosed) {
				t.Fatalf("waiting sender: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("a sender is still waiting for a peer that does not read")
		}
	}
	if d := time.Since(start); d < timeout {
		t.Fatalf("connection ended after %v, before the write timeout", d)
	}
	<-x.Done()
	if err := x.Err(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("connection ended with %v", err)
	}
	if err := x.TryNotify(KindLog, Strings("info", "x")...); !errors.Is(err, ErrClosed) {
		t.Fatalf("TryNotify after the end: %v", err)
	}
}

// The timeout is for one frame: a peer that reads slowly but reads is not
// cut off, however long the whole queue takes.
func TestWriteTimeoutSlowReader(t *testing.T) {
	a, b := net.Pipe()
	const timeout = 400 * time.Millisecond
	got := make(chan struct{}, 64)
	server := NewConn(b, nil, func(*Frame) {
		time.Sleep(20 * time.Millisecond)
		got <- struct{}{}
	})
	defer server.Close()
	x := NewConnOptions(a, nil, nil, Options{WriteTimeout: timeout})
	defer x.Close()
	start := time.Now()
	for i := 0; i < 40; i++ {
		if err := x.Notify(KindLog, Strings("info", "x")...); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 40; i++ {
		select {
		case <-got:
		case <-x.Done():
			t.Fatalf("connection ended after %d frames: %v", i, x.Err())
		case <-time.After(10 * time.Second):
			t.Fatal("frames not delivered")
		}
	}
	if d := time.Since(start); d < timeout {
		t.Fatalf("40 frames in %v: the test did not outlast the timeout", d)
	}
}

// At MaxInflight requests of the peer in flight the reader waits and reads
// nothing (not even a request that would be answered at once); OnWait says
// when that starts and ends.
func TestReaderAtLimit(t *testing.T) {
	a, b := net.Pipe()
	hold := make(chan struct{})
	waits := make(chan bool, 8)
	var mu sync.Mutex
	pings := 0
	server := NewConnOptions(b, func(_ context.Context, f *Frame) [][]byte {
		if f.Kind == KindPing {
			mu.Lock()
			pings++
			mu.Unlock()
			return Strings(StatusOK, "0")
		}
		<-hold
		return Strings(StatusOK)
	}, nil, Options{OnWait: func(on bool) { waits <- on }})
	defer server.Close()
	client := NewConn(a, nil, nil)
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	call := func(k Kind) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, err := client.Call(ctx, k); err != nil || string(r[0]) != StatusOK {
				t.Errorf("call %#x: %v %q", byte(k), err, r)
			}
		}()
	}
	// One more than the limit: the reader has read it and waits for a place.
	for i := 0; i < MaxInflight+1; i++ {
		call(KindQueue)
	}
	select {
	case on := <-waits:
		if !on {
			t.Fatal("OnWait(false) first")
		}
	case <-ctx.Done():
		t.Fatal("the reader did not wait at the limit")
	}
	// A ping sent now is not read.
	call(KindPing)
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	if pings != 0 {
		t.Fatal("a request was read while the reader waited")
	}
	mu.Unlock()
	close(hold)
	select {
	case on := <-waits:
		if on {
			t.Fatal("OnWait(true) twice")
		}
	case <-ctx.Done():
		t.Fatal("the reader did not go on")
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if pings != 1 {
		t.Fatalf("%d pings handled", pings)
	}
}

// A connection that ends while its reader waits says so too.
func TestReaderAtLimitClosed(t *testing.T) {
	a, b := net.Pipe()
	hold := make(chan struct{})
	defer close(hold)
	waits := make(chan bool, 8)
	server := NewConnOptions(b, func(context.Context, *Frame) [][]byte { <-hold; return nil }, nil,
		Options{OnWait: func(on bool) { waits <- on }})
	client := NewConn(a, nil, nil)
	defer client.Close()
	for i := 0; i < MaxInflight+1; i++ {
		go func() { _, _ = client.Call(context.Background(), KindQueue) }()
	}
	for _, want := range []bool{true, false} {
		select {
		case on := <-waits:
			if on != want {
				t.Fatalf("OnWait(%v), want %v", on, want)
			}
		case <-time.After(20 * time.Second):
			t.Fatalf("no OnWait(%v)", want)
		}
		server.Close()
	}
}
