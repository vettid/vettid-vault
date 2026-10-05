package hostproto

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func TestFrameRoundTrip(t *testing.T) {
	f := &Frame{Kind: KindStorePut, ID: 7, Fields: [][]byte{[]byte("vaults/a/state"), bytes.Repeat([]byte{1}, 70000), nil}}
	b, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	g, err := ReadFrame(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if g.Kind != f.Kind || g.ID != 7 || len(g.Fields) != 3 || !bytes.Equal(g.Fields[1], f.Fields[1]) || len(g.Fields[2]) != 0 {
		t.Fatal("round trip")
	}
	if g.Field(5) != nil || string(g.Field(0)) != "vaults/a/state" {
		t.Fatal("Field")
	}
}

func TestParseRejects(t *testing.T) {
	good, _ := (&Frame{Kind: KindPing, ID: 1, Fields: Strings("a", "bc")}).Marshal()
	body := good[4:]
	for name, b := range map[string][]byte{
		"short":     body[:5],
		"truncated": body[:len(body)-1],
		"trailing":  append(append([]byte(nil), body...), 0),
		"count":     append(append([]byte{}, body[:9]...), 0xff, 0xff),
	} {
		if _, err := Parse(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	big := make([]byte, 4)
	big[0] = 0x7f
	if _, err := ReadFrame(bytes.NewReader(big)); err != ErrTooBig {
		t.Fatalf("oversized length: %v", err)
	}
	if _, err := (&Frame{Fields: make([][]byte, MaxFields+1)}).Marshal(); err == nil {
		t.Fatal("too many fields")
	}
}

// recWriter records the size of every Write.
type recWriter struct {
	mu    sync.Mutex
	sizes []int
	buf   bytes.Buffer
}

func (r *recWriter) Write(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sizes = append(r.sizes, len(b))
	return r.buf.Write(b)
}

func TestChunkedWrites(t *testing.T) {
	var w recWriter
	if err := WriteFrame(&w, &Frame{Kind: KindQueue, ID: 1, Fields: [][]byte{make([]byte, 100_000)}}); err != nil {
		t.Fatal(err)
	}
	for _, s := range w.sizes {
		if s > ChunkSize {
			t.Fatalf("write of %d bytes", s)
		}
	}
	var w2 recWriter
	n, err := ChunkedWriter{&w2}.Write(make([]byte, 3*ChunkSize+5))
	if err != nil || n != 3*ChunkSize+5 || len(w2.sizes) != 4 {
		t.Fatalf("chunked writer %d %v %v", n, err, w2.sizes)
	}
}

func TestConnCallNotify(t *testing.T) {
	a, b := net.Pipe()
	notes := make(chan *Frame, 4)
	server := NewConn(b, func(_ context.Context, f *Frame) [][]byte {
		if f.Kind == KindStoreGet {
			return [][]byte{[]byte(StatusOK), append([]byte("got "), f.Field(0)...), []byte("v1")}
		}
		return nil
	}, func(f *Frame) { notes <- f })
	client := NewConn(a, nil, nil)
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := client.Call(ctx, KindStoreGet, []byte("k"))
			if err != nil || string(r[0]) != StatusOK || string(r[1]) != "got k" {
				t.Errorf("call: %v %q", err, r)
			}
		}()
	}
	wg.Wait()
	// Unknown requests get an "invalid" reply.
	r, err := client.Call(ctx, KindPing)
	if err != nil || string(r[0]) != StatusInvalid {
		t.Fatalf("ping: %v %q", err, r)
	}
	if err := client.Notify(KindLog, Strings("info", "hello")...); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-notes:
		if f.Kind != KindLog || string(f.Field(1)) != "hello" {
			t.Fatal("notification")
		}
	case <-ctx.Done():
		t.Fatal("no notification")
	}
	// A closed peer fails pending and later calls.
	server.Close()
	<-client.Done()
	if _, err := client.Call(ctx, KindStoreGet, []byte("k")); err == nil {
		t.Fatal("call after close")
	}
}

func FuzzParse(f *testing.F) {
	good, _ := (&Frame{Kind: KindLifecycle, ID: 0, Fields: Strings("locked", "v", "r", "r", "1")}).Marshal()
	f.Add(good[4:])
	f.Add([]byte{})
	f.Add(make([]byte, headerLen))
	f.Fuzz(func(t *testing.T, b []byte) {
		fr, err := Parse(b)
		if err != nil {
			return
		}
		m, err := fr.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(m[4:], b) {
			t.Fatal("re-encoding differs")
		}
	})
}

func TestStopExpected(t *testing.T) {
	for r, want := range map[string]bool{
		StopLocked: true, "moved": true, "deleted": true, "idle": true,
		StopSplitBrain: false, StopError: false, "": false, "LOCKED": false, "crashed": false,
	} {
		if StopExpected(r) != want {
			t.Errorf("%q: %v", r, !want)
		}
	}
}

// Notify only queues: a vault process that closes its channel right after
// its last notification (the lifecycle "locked" of the member's lock) must
// Flush first, or the frames still queued are lost.
func TestFlushBeforeClose(t *testing.T) {
	a, b := net.Pipe()
	var mu sync.Mutex
	got := 0
	server := NewConn(b, nil, func(f *Frame) {
		time.Sleep(time.Millisecond) // a slow reader keeps frames queued
		mu.Lock()
		got++
		mu.Unlock()
	})
	defer server.Close()
	client := NewConn(a, nil, nil)
	for i := 0; i < 100; i++ {
		if err := client.Notify(KindLifecycle, Strings("locked", "v", "r", "r", "1")...); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	client.Close()
	<-server.Done()
	mu.Lock()
	defer mu.Unlock()
	if got != 100 {
		t.Fatalf("%d of 100 notifications delivered", got)
	}
	// Flush on a closed connection returns at once.
	if err := client.Flush(ctx); err != nil && err != ErrClosed {
		t.Fatal(err)
	}
}
