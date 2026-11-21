package client

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

func zeroed(b []byte) bool { return bytes.Count(b, []byte{0}) == len(b) }

// Close wipes what the Device holds: held and buffered messages, the
// agent's grants, the device's keys and every byte slice of its state.
func TestCloseWipes(t *testing.T) {
	_, _, d := pair(t)
	secret := []byte(`{"value":"s3cret"}`)
	ev := &envelope.Inner{ID: "01HZZZZZZZZZZZZZZZZZZZZZZZ", Type: "test.ping", TS: time.Now(), Body: append([]byte(nil), secret...)}
	held := &envelope.Inner{ID: "01HZZZZZZZZZZZZZZZZZZZZZZY", Type: "test.ping", TS: time.Now(), Body: append([]byte(nil), secret...)}
	d.mu.Lock()
	d.events = append(d.events, ev)
	d.held = append(d.held, held)
	d.leashGrants = append([]byte(nil), secret...)
	grants := d.leashGrants
	d.st.AppKey = []byte("app-key-scalar-bytes")
	seeds := [][]byte{d.st.IKSeed, d.st.KEMSeed, d.st.RelaySeed, d.st.AppKey}
	ik, relayKey, kem := d.ik, d.relayKey, d.kem
	hasSession := d.keyring.Current() != nil
	d.mu.Unlock()
	if !hasSession {
		t.Fatal("no session to destroy: the fixture is not paired")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"event": ev.Body, "held": held.Body, "grants": grants, "ik": ik, "relay key": relayKey} {
		if len(b) == 0 || !zeroed(b) {
			t.Errorf("%s not wiped", name)
		}
	}
	for i, s := range seeds {
		if len(s) == 0 || !zeroed(s) {
			t.Errorf("state secret %d not wiped", i)
		}
	}
	if _, err := kem.Seed(); !errors.Is(err, suite.ErrDestroyed) {
		t.Error("the KEM key was not destroyed")
	}
	if d.keyring.Current() != nil {
		t.Error("the session keys were not destroyed")
	}
	if _, err := d.Save(); !errors.Is(err, ErrClosed) {
		t.Errorf("Save after Close: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Errorf("a second Close: %v", err)
	}
}

// After Close, every method with an error result returns ErrClosed, and
// none panics, even with zero arguments: the Device's keys are wiped and
// its relay client is not to be used, so nothing may get further. A new
// method without the check (directly, or through Op, Request, the sends
// and waits) fails here.
func TestCloseEveryMethodRefuses(t *testing.T) {
	_, _, d := pair(t)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	informational := map[string]bool{"Close": true, "PersistError": true, "Refused": true}
	dv := reflect.ValueOf(d)
	errT := reflect.TypeFor[error]()
	n := 0
	for i := range dv.NumMethod() {
		name := dv.Type().Method(i).Name
		mt := dv.Method(i).Type()
		if mt.IsVariadic() {
			t.Fatalf("%s is variadic: extend the test", name)
		}
		args := make([]reflect.Value, mt.NumIn())
		for k := range args {
			if at := mt.In(k); at == reflect.TypeFor[context.Context]() {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				args[k] = reflect.ValueOf(ctx)
			} else {
				args[k] = reflect.Zero(at)
			}
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s panics after Close: %v", name, r)
				}
			}()
			out := dv.Method(i).Call(args)
			for k := range mt.NumOut() {
				if mt.Out(k) != errT || informational[name] {
					continue
				}
				n++
				if out[k].IsNil() {
					t.Errorf("%s returns no error after Close", name)
				} else if err := out[k].Interface().(error); !errors.Is(err, ErrClosed) {
					t.Errorf("%s returns %v after Close, not ErrClosed: it reached something before the check", name, err)
				}
			}
		}()
	}
	if n < 150 {
		t.Fatalf("only %d methods with an error result: the test is broken", n)
	}
}

// Close during Run ends Run's long poll at once, and a call waiting for a
// response gets ErrClosed; Close returns once Run has. Run under -race.
func TestCloseDuringRun(t *testing.T) {
	r, _, d := pair(t)
	r.mu.Lock()
	r.longPoll = true // an empty collect waits, as a relay does
	r.mu.Unlock()
	d.cfg.PollWait = 30 * time.Second // a long poll Close must cut short
	runErr := make(chan error, 1)
	go func() { runErr <- d.Run(context.Background()) }()
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
		time.Sleep(5 * time.Millisecond)
	}
	var wg sync.WaitGroup
	reqErr := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := d.WaitEvent(context.Background(), "never.sent", nil)
		reqErr <- err
	}()
	time.Sleep(50 * time.Millisecond) // Run is in its long poll, the waiter waiting
	start := time.Now()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("Close took %v: the long poll was not cut short", took)
	}
	select {
	case err := <-runErr:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("Run returned %v, want ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	wg.Wait()
	if err := <-reqErr; !errors.Is(err, ErrClosed) {
		t.Fatalf("the waiting call returned %v, want ErrClosed", err)
	}
	if err := d.Run(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Run after Close: %v", err)
	}
	if err := d.Poll(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Poll after Close: %v", err)
	}
}

// Close without Run, while a call collects for itself, ends that call.
func TestCloseDuringOwnPoll(t *testing.T) {
	r, _, d := pair(t)
	r.mu.Lock()
	r.longPoll = true // an empty collect waits, as a relay does
	r.mu.Unlock()
	d.cfg.PollWait = 30 * time.Second
	errc := make(chan error, 1)
	go func() {
		_, err := d.WaitEvent(context.Background(), "never.sent", nil)
		errc <- err
	}()
	time.Sleep(100 * time.Millisecond) // in its own long poll
	done := make(chan struct{})
	go func() { _ = d.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked on the waiter's poll")
	}
	select {
	case err := <-errc:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("the waiting call returned %v, want ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting call did not return")
	}
}

// waitClosed waits for Close's wipe to finish.
func waitClosed(t *testing.T, d *Device) {
	t.Helper()
	d.mu.Lock()
	done := d.closeDone
	d.mu.Unlock()
	if done == nil {
		t.Fatal("Close did not start")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the wipe did not finish")
	}
}

// Close from a Persist, PersistBatch or RunError callback returns at once
// (it would otherwise wait for the Poll or Run that called it), and the
// wipe is done when that Poll ends.
func TestCloseFromCallbacks(t *testing.T) {
	ctx := context.Background()
	for _, c := range []string{"Persist in Poll", "PersistBatch in Poll", "Persist in Run", "RunError"} {
		t.Run(c, func(t *testing.T) {
			_, v, d := pair(t)
			returned := make(chan error, 1)
			closeOnce := sync.Once{}
			closeHere := func() {
				closeOnce.Do(func() {
					go func() {
						time.Sleep(5 * time.Second)
						select {
						case returned <- errors.New("Close blocked in the callback"):
						default:
						}
					}()
					returned <- d.Close()
				})
			}
			switch c {
			case "Persist in Poll", "Persist in Run":
				d.cfg.Persist = func([]byte) error { closeHere(); return nil }
			case "PersistBatch in Poll":
				d.cfg.PersistBatch = func([]byte, []*envelope.Inner) error { closeHere(); return nil }
			case "RunError":
				d.cfg.RunError = func(error) { closeHere() }
				d.cfg.Persist = func([]byte) error { return errors.New("disk full") }
			}
			v.send("test.ping", []byte(`{}`))
			var pollErr error
			if c == "Persist in Run" || c == "RunError" {
				rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				pollErr = d.Run(rctx)
			} else {
				pollErr = d.Poll(ctx)
			}
			if err := <-returned; err != nil {
				t.Fatal(err)
			}
			waitClosed(t, d)
			if c != "Persist in Poll" && c != "PersistBatch in Poll" && !errors.Is(pollErr, ErrClosed) {
				t.Fatalf("Run returned %v, want ErrClosed", pollErr)
			}
			d.mu.Lock()
			wiped := zeroed(d.ik) && d.st.Vault == nil
			d.mu.Unlock()
			if !wiped {
				t.Fatal("not wiped after the callback's Poll ended")
			}
			if err := d.Poll(ctx); !errors.Is(err, ErrClosed) {
				t.Fatalf("Poll after Close: %v", err)
			}
		})
	}
}

// A second Close returns only once the first has wiped: the first is held
// after it set closed and before it wipes (testCloseWaitHook), and the
// second, which sees closed, must wait for it.
func TestCloseTwiceWaits(t *testing.T) {
	_, _, d := pair(t)
	entered, release := make(chan struct{}), make(chan struct{})
	testCloseWaitHook = func() { close(entered); <-release }
	defer func() { testCloseWaitHook = nil }()
	first, second := make(chan struct{}), make(chan struct{})
	go func() { _ = d.Close(); close(first) }()
	<-entered
	go func() { _ = d.Close(); close(second) }()
	select {
	case <-second:
		t.Fatal("the second Close returned before the first had wiped")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	for _, c := range []chan struct{}{first, second} {
		select {
		case <-c:
		case <-time.After(5 * time.Second):
			t.Fatal("Close did not return")
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.st.Vault != nil || !zeroed(d.ik) {
		t.Fatal("not wiped")
	}
}

// A Poll that Close cuts short returns ErrClosed, not the cancel.
func TestClosedPollReportsErrClosed(t *testing.T) {
	r, _, d := pair(t)
	r.mu.Lock()
	r.longPoll = true
	r.mu.Unlock()
	d.cfg.PollWait = 30 * time.Second
	errc := make(chan error, 1)
	go func() { errc <- d.Poll(context.Background()) }()
	time.Sleep(100 * time.Millisecond)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; !errors.Is(err, ErrClosed) {
		t.Fatalf("Poll returned %v, want ErrClosed", err)
	}
}

// Each method that uses the Device's keys, run concurrently with Close,
// either finishes before it or returns ErrClosed, and never reads a key
// as Close wipes it (go test -race reports that).
func TestCloseRacesKeyUsers(t *testing.T) {
	ctx := context.Background()
	users := map[string]func(ctx context.Context, d *Device) error{
		"OpenToken":       func(ctx context.Context, d *Device) error { _, err := d.OpenToken(); return err },
		"IdentityKey":     func(ctx context.Context, d *Device) error { _ = d.IdentityKey(); return nil },
		"RelayAddr":       func(ctx context.Context, d *Device) error { _ = d.RelayAddr(); return nil },
		"KEMKey":          func(ctx context.Context, d *Device) error { _ = d.KEMKey(); return nil },
		"Save":            func(ctx context.Context, d *Device) error { _, err := d.Save(); return err },
		"AppKey":          func(ctx context.Context, d *Device) error { _, _, err := d.AppKey(); return err },
		"UnlockSecret":    func(ctx context.Context, d *Device) error { _ = d.UnlockSecret(); return nil },
		"RenewVaultToken": func(ctx context.Context, d *Device) error { return d.RenewVaultToken(ctx) },
		"Send": func(ctx context.Context, d *Device) error {
			_, err := d.Send(ctx, "test.ping", []byte(`{}`))
			return err
		},
		"UploadBytes": func(ctx context.Context, d *Device) error { _, err := d.UploadBytes(ctx, []byte("data")); return err },
		"CallStart": func(ctx context.Context, d *Device) error {
			c, err := d.CallStart(ctx, "conn-1", "audio", "sdp")
			if c != nil {
				c.Destroy()
			}
			return err
		},
		"LeashGrants": func(ctx context.Context, d *Device) error { _ = d.LeashGrants(); return nil },
		"signShare":   func(ctx context.Context, d *Device) error { _, err := d.signShare([]byte("m")); return err },
		"borrowRelay": func(ctx context.Context, d *Device) error {
			_, done, err := d.borrowRelay("https://relay.example")
			if err == nil {
				done()
			}
			return err
		},
		"Alt": func(ctx context.Context, d *Device) error { _ = d.Alt(); return nil },
		"Deliver": func(ctx context.Context, d *Device) error {
			d.Deliver(ctx, relayclientMessage())
			return nil
		},
	}
	for name, use := range users {
		t.Run(name, func(t *testing.T) {
			for range 40 {
				_, _, d := pair(t)
				d.mu.Lock()
				d.leashGrants = []byte(`{"grant_seq":1,"grants":[{"grant_id":"g1"}]}`)
				d.mu.Unlock()
				var wg sync.WaitGroup
				stop := make(chan struct{})
				started := make(chan struct{})
				var startOnce sync.Once
				for range 4 {
					wg.Add(1)
					go func() {
						// The user runs in a loop across Close, so its key
						// reads overlap the wipe; before Close it may fail for
						// its own reasons (no app key, no answer): only a
						// panic or a race matters here.
						defer wg.Done()
						first := true
						for {
							cctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
							_ = use(cctx, d)
							cancel()
							if first {
								startOnce.Do(func() { close(started) })
								first = false
							}
							select {
							case <-stop:
								return
							default:
							}
						}
					}()
				}
				<-started
				_ = d.Close()
				close(stop)
				wg.Wait()
				if err := use(ctx, d); err != nil && !errors.Is(err, ErrClosed) {
					t.Fatalf("after Close: %v", err)
				}
			}
		})
	}
}

// Close also wipes the outbox, the phone key and the vault record, and
// drops them.
func TestCloseWipesStateRecords(t *testing.T) {
	_, _, d := pair(t)
	d.mu.Lock()
	d.st.PhoneKey = []byte("phone-key-bytes")
	d.st.Outbox = append(d.st.Outbox, OutboxEntry{Kind: "token", RelayURL: "u", Mailbox: "m", Payload: []byte("sealed-payload")})
	held := [][]byte{d.st.PhoneKey, d.st.Outbox[len(d.st.Outbox)-1].Payload, d.st.Vault.IK, d.st.Vault.RelayPK}
	d.mu.Unlock()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	for i, b := range held {
		if len(b) == 0 || !zeroed(b) {
			t.Errorf("state buffer %d not wiped", i)
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.st.Vault != nil || d.st.Outbox != nil {
		t.Error("the vault record or the outbox was kept")
	}
}

// relayclientMessage is a collected message that opens to nothing.
func relayclientMessage() relayclient.Message {
	return relayclient.Message{MsgID: "m1", Payload: []byte("not an envelope")}
}

// Close in the middle of OpenToken (fired from the relay client's clock,
// which minting reads) cannot wipe the relay key under the mint: the token
// is signed with the real key, or OpenToken refuses. Deterministic, unlike
// the race test: it finds a check made outside the lock.
func TestCloseMidOpenToken(t *testing.T) {
	_, _, d := pair(t)
	pk := d.RelayAddr().PK
	var once sync.Once
	closed := make(chan struct{})
	d.own.Now = func() time.Time {
		once.Do(func() {
			go func() { _ = d.Close(); close(closed) }()
			time.Sleep(100 * time.Millisecond) // time for Close to wipe, if it can
		})
		return time.Now()
	}
	tok, err := d.OpenToken()
	<-closed
	if err != nil {
		if !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
		return
	}
	if _, err := relayauth.VerifyToken(tok, pk); err != nil {
		t.Fatalf("the token was signed with a wiped key: %v", err)
	}
}

// A Close while a callback runs elsewhere, and while another goroutine is
// about to give back the poll semaphore, is still wiped: the release that
// follows sees the pending wipe, and a later Close returns.
func TestCloseDuringCallbackAndRelease(t *testing.T) {
	ctx := context.Background()
	_, v, d := pair(t)
	d.cfg.Persist = func([]byte) error { return nil }
	inRelease, letGo := make(chan struct{}), make(chan struct{})
	var once sync.Once
	testReleaseHook = func() { once.Do(func() { close(inRelease); <-letGo }) }
	defer func() { testReleaseHook = nil }()
	v.send("test.ping", []byte(`{}`))
	delivered := make(chan struct{})
	go func() {
		d.Deliver(ctx, v.r.take(v.dev.Mailbox)[0])
		close(delivered)
	}()
	<-inRelease                       // Deliver holds the semaphore, about to give it back
	d.callbacks.Add(1)                // a callback runs on another goroutine
	if err := d.Close(); err != nil { // the in-callback path: returns at once
		t.Fatal(err)
	}
	close(letGo)
	<-delivered
	d.callbacks.Add(-1)
	waitClosed(t, d)
	done := make(chan struct{})
	go func() { _ = d.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a later Close hung: the wipe was lost")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.st.Vault != nil || !zeroed(d.ik) {
		t.Fatal("not wiped")
	}
}

// A callback that panics (and is recovered by the caller) leaves the
// callback count right, so a later Close waits as usual.
func TestCallbackPanicKeepsTheCount(t *testing.T) {
	_, _, d := pair(t)
	func() {
		defer func() { _ = recover() }()
		d.inCallback(func() { panic("boom") })
	}()
	if n := d.callbacks.Load(); n != 0 {
		t.Fatalf("callbacks = %d after a panic, want 0", n)
	}
}

// blocks reports whether f is still running after a while, and then
// whether it returns once release is called.
func blocks(t *testing.T, f func(), release func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
		t.Fatal("it did not wait")
	case <-time.After(100 * time.Millisecond):
	}
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("it did not finish once released")
	}
}

// Each key user takes the Device's lock: while the lock is held it waits.
// Deterministic, unlike the race test; but it does not show the key is
// used inside that lock hold (a use after the unlock still waits here):
// the race test, which sees the wipe under -race, covers that.
func TestKeyUsersTakeTheLock(t *testing.T) {
	for name, use := range map[string]func(d *Device){
		"OpenToken":   func(d *Device) { _, _ = d.OpenToken() },
		"IdentityKey": func(d *Device) { _ = d.IdentityKey() },
		"RelayAddr":   func(d *Device) { _ = d.RelayAddr() },
		"signShare":   func(d *Device) { _, _ = d.signShare([]byte("m")) },
		"borrowRelay": func(d *Device) {
			if _, done, err := d.borrowRelay("https://relay.example"); err == nil {
				done()
			}
		},
		"LeashGrants": func(d *Device) { _ = d.LeashGrants() },
		"Alt":         func(d *Device) { _ = d.Alt() },
	} {
		t.Run(name, func(t *testing.T) {
			_, _, d := pair(t)
			d.mu.Lock()
			blocks(t, func() { use(d) }, d.mu.Unlock)
		})
	}
}

// borrowRelay hands out a copy of the relay key, not the Device's bytes:
// wiping the copy leaves the Device's key, and Close leaves the copy.
func TestBorrowRelayCopies(t *testing.T) {
	_, _, d := pair(t)
	c, done, err := d.borrowRelay("https://relay.example")
	if err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	own := d.relayKey
	d.mu.Unlock()
	if !bytes.Equal(c.Key, own) || &c.Key[0] == &own[0] {
		t.Fatal("not an equal copy in its own memory")
	}
	key := c.Key
	done()
	if !zeroed(key) || zeroed(own) {
		t.Fatal("done did not wipe the copy alone")
	}
}

// Close waits for a Poll holding the semaphore, and for Run, before it
// wipes.
func TestCloseWaitsForPollAndRun(t *testing.T) {
	t.Run("the semaphore", func(t *testing.T) {
		_, _, d := pair(t)
		d.sem <- struct{}{} // a Poll in progress
		blocks(t, func() { _ = d.Close() }, func() { <-d.sem })
	})
	t.Run("Run", func(t *testing.T) {
		_, _, d := pair(t)
		runDone := make(chan struct{})
		d.mu.Lock()
		d.running, d.runDone = true, runDone
		d.mu.Unlock()
		blocks(t, func() { _ = d.Close() }, func() {
			d.mu.Lock()
			d.running = false
			d.mu.Unlock()
			close(runDone)
		})
	})
}

// After Close the key references are dropped, so crypto/ed25519 can let
// go of its expanded copies, and a due Persist is skipped.
func TestCloseDropsKeysAndSkipsPersist(t *testing.T) {
	_, _, d := pair(t)
	persisted := 0
	d.cfg.Persist = func([]byte) error { persisted++; return nil }
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	ik, rk, ownKey := d.ik, d.relayKey, d.own.Key
	d.mu.Unlock()
	if ik != nil || rk != nil || ownKey != nil {
		t.Fatal("a key reference was kept")
	}
	if err := d.saveLocked(); !errors.Is(err, ErrClosed) || persisted != 0 {
		t.Fatalf("save after Close: %v, %d persisted", err, persisted)
	}
}

// LeashGrants returns its own copies, and wipes the copy it parsed, not
// the Device's set: a second read still sees the grant, and Close wiping
// the Device's set leaves what was returned. (The race with Close's wipe
// of the set is the race test's LeashGrants entry.)
func TestLeashGrantsCopies(t *testing.T) {
	_, _, d := pair(t)
	d.mu.Lock()
	d.leashGrants = []byte(`{"grant_seq":1,"grants":[{"grant_id":"g1"}]}`)
	d.mu.Unlock()
	gs := d.LeashGrants()
	if len(gs) != 1 {
		t.Fatalf("%d grants", len(gs))
	}
	if again := d.LeashGrants(); len(again) != 1 {
		t.Fatal("reading the grants changed the Device's own set")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if string(gs[0]) != `{"grant_id":"g1"}` {
		t.Fatalf("the returned grant was changed: %q", gs[0])
	}
	if d.LeashGrants() != nil {
		t.Fatal("grants after Close")
	}
}

// A call waiting through a failing collect's backoff returns at once when
// Close comes, not when the backoff (up to 30 s) ends.
func TestCloseEndsAWaitersBackoff(t *testing.T) {
	r, _, d := pair(t)
	r.mu.Lock()
	r.failCollect = true
	r.mu.Unlock()
	testBackoff = 30 * time.Second // as a backoff grown to its cap
	defer func() { testBackoff = 0 }()
	errc := make(chan error, 1)
	go func() {
		_, err := d.WaitEvent(context.Background(), "never.sent", nil)
		errc <- err
	}()
	time.Sleep(300 * time.Millisecond) // a failed collect: the waiter is in its backoff
	start := time.Now()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("the waiter returned %v, want ErrClosed", err)
		}
		if took := time.Since(start); took > time.Second {
			t.Fatalf("the waiter took %v after Close", took)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiter did not return")
	}
}

// collectBytes returns every non-empty byte slice reachable from v.
func collectBytes(v reflect.Value, out *[][]byte) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			collectBytes(v.Elem(), out)
		}
	case reflect.Struct:
		for i := range v.NumField() {
			collectBytes(v.Field(i), out)
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			if v.Len() > 0 {
				*out = append(*out, v.Bytes())
			}
			return
		}
		for i := range v.Len() {
			collectBytes(v.Index(i), out)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			collectBytes(v.MapIndex(k), out)
		}
	}
}

// Dropping or replacing the vault record wipes its last sessions snapshot
// (the session keys a Save exported), not just the record.
func TestDropVaultWipesSessions(t *testing.T) {
	_, _, d := pair(t)
	d.mu.Lock()
	d.export() // the snapshot a Save would write
	var bs [][]byte
	collectBytes(reflect.ValueOf(&d.st.Vault.Sessions), &bs)
	if len(bs) == 0 {
		d.mu.Unlock()
		t.Fatal("no sessions snapshot: the fixture is not paired")
	}
	d.dropVaultLocked()
	vault := d.st.Vault
	d.mu.Unlock()
	if vault != nil {
		t.Fatal("the record was kept")
	}
	for i, b := range bs {
		if !zeroed(b) {
			t.Fatalf("sessions buffer %d not wiped", i)
		}
	}
}
