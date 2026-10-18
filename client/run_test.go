package client

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Run, the one collecting loop (VAULT-MESSAGING §8.1, AGENT-PLAN AV2).

// answering runs the stand-in vault in the background: it answers every
// request from the device with a response echoing the request's id,
// unless hold is set, until the test ends.
func answering(t *testing.T, v *fakeVault, hold *atomic.Bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() { cancel(); <-done })
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			if hold == nil || !hold.Load() {
				v.answerAll()
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
}

// answerAll answers everything in the vault's mailbox (one goroutine).
func (v *fakeVault) answerAll() {
	now := time.Now()
	for _, m := range v.r.take(v.mailbox()) {
		env, err := envelope.Parse(m.Payload)
		if err != nil {
			continue
		}
		in, _, err := v.kr.Open(env, now)
		if err != nil || in.Re != "" {
			continue
		}
		id, _ := envelope.NewULID(now)
		body := strictjson.NewBuilder().String("echo", in.ID).Bytes()
		raw, err := v.kr.Current().Seal(&envelope.Inner{ID: id, Type: in.Type, TS: now, Re: in.ID, Status: envelope.StatusOK, Body: body})
		if err != nil {
			continue
		}
		v.r.put(v.dev.Mailbox, v.relayPK(), raw)
	}
}

func echoOf(t *testing.T, r *Response) string {
	t.Helper()
	o, err := strictjson.ParseObject(r.Body())
	if err != nil {
		t.Error(err)
		return ""
	}
	s, _ := o.String("echo")
	return s
}

func startRun(t *testing.T, d *Device) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	res := make(chan error, 1)
	go func() { res <- d.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		d.mu.Lock()
		running := d.running
		d.mu.Unlock()
		if running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Run did not start")
		}
		time.Sleep(time.Millisecond)
	}
	var once sync.Once
	var err error
	stop = func() error {
		once.Do(func() { cancel(); err = <-res })
		return err
	}
	t.Cleanup(func() { _ = stop() })
	return stop
}

// concurrent sends n requests from n goroutines and checks that each
// caller gets the response to its own request.
func concurrent(t *testing.T, d *Device, n int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, err := d.Send(ctx, "vault.status", []byte(fmt.Sprintf(`{"n":%d}`, i)))
			if err != nil {
				t.Error(err)
				return
			}
			r, err := d.AwaitResponse(ctx, id)
			if err != nil {
				t.Errorf("caller %d: %v", i, err)
				return
			}
			if got := echoOf(t, r); got != id {
				t.Errorf("caller %d got the response to %s, want %s", i, got, id)
			}
		}(i)
	}
	wg.Wait()
}

// While Run collects, concurrent callers each get their own response,
// with and without Persist, and never two collects at once.
func TestRunConcurrentCallers(t *testing.T) {
	for _, persist := range []bool{false, true} {
		t.Run(fmt.Sprintf("persist=%v", persist), func(t *testing.T) {
			r, v, d := pair(t)
			if persist {
				d.cfg.Persist = keep(new([]byte), nil)
			}
			r.mu.Lock()
			r.longPoll = true
			r.mu.Unlock()
			answering(t, v, nil)
			startRun(t, d)
			concurrent(t, d, 16)
			r.mu.Lock()
			max := r.maxCollects
			r.mu.Unlock()
			if max != 1 {
				t.Fatalf("%d collects at once, want 1", max)
			}
		})
	}
}

// Without Run, concurrent callers collect themselves, as before, and
// each still gets its own response; a caller whose response arrived in
// another caller's Poll returns without a long poll of its own.
func TestNoRunConcurrentCallers(t *testing.T) {
	r, v, d := pair(t)
	d.cfg.PollWait = 2 * time.Second
	r.mu.Lock()
	r.longPoll = true
	r.mu.Unlock()
	answering(t, v, nil)
	concurrent(t, d, 8)

	// Two requests answered in one batch: one caller's Poll collects
	// both; the other, waiting for that Poll, finds its response then.
	var hold atomic.Bool
	hold.Store(true)
	_, v2, d2 := pair(t)
	d2.cfg.PollWait = 2 * time.Second
	answering(t, v2, &hold)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ids := make([]string, 2)
	for i := range ids {
		var err error
		if ids[i], err = d2.Send(ctx, "vault.status", []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	for len(v2.r.pending(v2.mailbox())) < 2 {
		time.Sleep(time.Millisecond)
	}
	hold.Store(false)
	for len(v2.r.pending(v2.dev.Mailbox)) < 2 {
		time.Sleep(time.Millisecond)
	}
	v2.r.mu.Lock()
	v2.r.longPoll = true
	v2.r.mu.Unlock()
	start := time.Now()
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			if r, err := d2.AwaitResponse(ctx, id); err != nil || echoOf(t, r) != id {
				t.Errorf("AwaitResponse %s: %v", id, err)
			}
		}(id)
	}
	wg.Wait()
	if el := time.Since(start); el > 1500*time.Millisecond {
		t.Fatalf("took %v: a caller long-polled for a response already collected", el)
	}
}

// A waiting call's context ends it at once while Run runs; Run goes on.
// When Run stops, a call still waiting collects itself and gets its
// response.
func TestRunCancellationAndStop(t *testing.T) {
	r, v, d := pair(t)
	r.mu.Lock()
	r.longPoll = true
	r.mu.Unlock()
	var hold atomic.Bool
	hold.Store(true)
	answering(t, v, &hold)
	stop := startRun(t, d)

	ctx, cancel := context.WithCancel(context.Background())
	id, err := d.Send(ctx, "vault.status", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	res := make(chan error, 1)
	go func() { _, err := d.AwaitResponse(ctx, id); res <- err }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-res:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("AwaitResponse: %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a cancelled waiter did not return")
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel2()
	id2, err := d.Send(ctx2, "vault.status", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan *Response, 1)
	go func() {
		r, err := d.AwaitResponse(ctx2, id2)
		if err != nil {
			t.Error(err)
		}
		got <- r
	}()
	time.Sleep(50 * time.Millisecond)
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: %v, want context.Canceled", err)
	}
	d.mu.Lock()
	running := d.running
	d.mu.Unlock()
	if running {
		t.Fatal("still running")
	}
	hold.Store(false) // answered only now, with Run stopped
	select {
	case r := <-got:
		if r == nil || echoOf(t, r) != id2 {
			t.Fatal("wrong response")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("waiter did not collect after Run stopped")
	}
}

// A second Run while one runs is refused.
func TestRunTwice(t *testing.T) {
	_, _, d := pair(t)
	startRun(t, d)
	if err := d.Run(context.Background()); !errors.Is(err, ErrRunning) {
		t.Fatalf("Run: %v, want ErrRunning", err)
	}
}

// Persist errors under Run: they go to RunError, Run retries, and the
// waiting call gets its response only after the batch is saved.
func TestRunPersistErrors(t *testing.T) {
	r, v, d := pair(t)
	r.mu.Lock()
	r.longPoll = true
	r.mu.Unlock()
	var mu sync.Mutex
	fails, saves := 2, 0
	d.cfg.Persist = func([]byte) error {
		mu.Lock()
		defer mu.Unlock()
		if fails > 0 {
			fails--
			return errors.New("disk full")
		}
		saves++
		return nil
	}
	var runErrs atomic.Int32
	d.cfg.RunError = func(err error) {
		if strings.Contains(err.Error(), "disk full") {
			runErrs.Add(1)
		}
	}
	answering(t, v, nil)
	startRun(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	resp, err := d.Request(ctx, "vault.status", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	s := saves
	mu.Unlock()
	if s == 0 || runErrs.Load() != 2 || !resp.OK() {
		t.Fatalf("response with %d saves and %d Persist errors reported, want ≥1 and 2", s, runErrs.Load())
	}
}

// Poll waits for the Poll in progress, but only as long as its context.
func TestPollCancellableWhileBusy(t *testing.T) {
	_, _, d := pair(t)
	if err := d.acquire(context.Background()); err != nil { // a Poll in progress
		t.Fatal(err)
	}
	defer d.release()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := d.Poll(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Poll: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("Poll did not honour its context while waiting")
	}
}

// A panic while handling propagates out of Poll without leaving the
// device locked: the Poll permit and the lock are free afterwards, and
// the message, not yet seen, is handled by the next Poll.
func TestHandlePanicDoesNotHang(t *testing.T) {
	for _, persist := range []bool{false, true} {
		t.Run(fmt.Sprintf("persist=%v", persist), func(t *testing.T) {
			_, v, d := pair(t)
			if persist {
				d.cfg.Persist = keep(new([]byte), nil)
			}
			var once atomic.Bool
			testHandleHook = func(relayclient.Message) {
				if once.CompareAndSwap(false, true) {
					panic("handler bug")
				}
			}
			t.Cleanup(func() { testHandleHook = nil })
			v.send("test.ping", []byte(`{}`))
			func() {
				defer func() {
					if p := recover(); p != "handler bug" {
						t.Fatalf("recovered %v", p)
					}
				}()
				_ = d.Poll(context.Background())
				t.Fatal("no panic")
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := d.acquire(ctx); err != nil {
				t.Fatal("Poll permit still held after the panic")
			}
			d.release()
			d.mu.Lock()
			batching := d.batching
			d.mu.Unlock()
			if batching {
				t.Fatal("batching left set")
			}
			ev, err := d.WaitEvent(ctx, "test.ping", nil)
			if err != nil || ev == nil {
				t.Fatalf("message not handled after the panic: %v", err)
			}
		})
	}
}

// While Run runs, a direct Poll is refused.
func TestPollWhileRunning(t *testing.T) {
	_, _, d := pair(t)
	startRun(t, d)
	if err := d.Poll(context.Background()); !errors.Is(err, ErrRunning) {
		t.Fatalf("Poll: %v, want ErrRunning", err)
	}
}

// Without Run, a waiting call whose Polls fail backs off instead of
// collecting again at once.
func TestWaiterBacksOffOnErrors(t *testing.T) {
	r, _, d := pair(t)
	r.mu.Lock()
	r.failCollect = true
	r.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = d.WaitEvent(ctx, "never", nil)
	r.mu.Lock()
	n := r.collectCalls
	r.mu.Unlock()
	// 0.25 s doubling with full jitter: about a dozen attempts in 2 s at
	// most, against thousands without a backoff.
	if n > 30 {
		t.Fatalf("%d collects in 2 s", n)
	}
}

// Without Run, concurrent callers never collect two at a time; and a
// waiter in the middle of its own Poll when Run starts still gets its
// response.
func TestNoRunOneCollectAndRunStartsMidPoll(t *testing.T) {
	r, v, d := pair(t)
	d.cfg.PollWait = time.Second
	r.mu.Lock()
	r.longPoll = true
	r.mu.Unlock()
	answering(t, v, nil)
	concurrent(t, d, 8)
	r.mu.Lock()
	max := r.maxCollects
	r.mu.Unlock()
	if max != 1 {
		t.Fatalf("%d collects at once without Run, want 1", max)
	}

	var hold atomic.Bool
	hold.Store(true)
	_, v2, d2 := pair(t)
	v2.r.mu.Lock()
	v2.r.longPoll = true
	v2.r.mu.Unlock()
	answering(t, v2, &hold)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	id, err := d2.Send(ctx, "vault.status", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan error, 1)
	go func() {
		r, err := d2.AwaitResponse(ctx, id)
		if err == nil && echoOf(t, r) != id {
			err = errors.New("wrong response")
		}
		got <- err
	}()
	for { // the waiter is long-polling
		v2.r.mu.Lock()
		c := v2.r.collects
		v2.r.mu.Unlock()
		if c == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	startRun(t, d2)
	hold.Store(false)
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("waiter hung after Run started mid-poll")
	}
}
