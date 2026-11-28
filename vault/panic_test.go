package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// catch runs f and describes its panic as RunRecovered does.
func catch(f func()) (pe *PanicError) {
	defer func() {
		if r := recover(); r != nil {
			pe = DescribePanic(r)
		}
	}()
	f()
	return nil
}

// fakeRuntime implements runtime.Error without being the runtime's.
type fakeRuntime string

func (f fakeRuntime) Error() string { return string(f) }
func (fakeRuntime) RuntimeError()   {}

//go:noinline
func indexPanic(i int) int {
	var a []int
	return a[i]
}

// A panic is told by where it happened and its type, and a runtime error
// by its own text; the value of any other panic is never kept (it could
// hold vault data).
func TestPanicErrorSaysWhereNotWhat(t *testing.T) {
	pe := catch(func() { _ = indexPanic(3) })
	if pe == nil || pe.Type != "runtime.boundsError" || !strings.Contains(pe.Runtime, "index out of range [N]") {
		t.Fatalf("bounds: %+v", pe)
	}
	if len(pe.Frames) == 0 || !strings.HasPrefix(pe.Frames[0], "vault.indexPanic panic_test.go:") {
		t.Fatalf("frames: %q", pe.Frames)
	}
	if !errors.Is(pe, ErrPanic) {
		t.Fatal("not ErrPanic")
	}
	// A runtime error's numbers may come from vault data: only its words.
	if pe.Runtime != "runtime error: index out of range [N] with length N" {
		t.Fatalf("bounds text: %q", pe.Runtime)
	}
	s := make([]byte, 7, 9)
	n := 12
	if pe := catch(func() { _ = s[:n] }); pe.Runtime != "runtime error: slice bounds out of range [:N] with capacity N" {
		t.Fatalf("slice text: %q", pe.Runtime)
	}
	// Only the runtime's own errors: a type that merely implements
	// runtime.Error keeps nothing of its text.
	if pe := catch(func() { panic(fakeRuntime("pin 424242")) }); pe.Runtime != "" || pe.Type != "vault.fakeRuntime" {
		t.Fatalf("fake runtime error: %+v", pe)
	}
	for _, v := range []any{"pin 424242", fmt.Errorf("key %x", []byte{0xde, 0xad}), struct{ Secret string }{"424242"}} {
		pe := catch(func() { panic(v) })
		got := fmt.Sprintf("%s %s %q %s", pe.Type, pe.Runtime, pe.Frames, pe.Error())
		if pe.Runtime != "" || strings.Contains(got, "424242") || strings.Contains(got, "dead") {
			t.Fatalf("%T: the value is kept: %s", v, got)
		}
	}
	var deep func(int)
	deep = func(n int) {
		if n == 0 {
			_ = indexPanic(1)
		}
		deep(n - 1)
	}
	if pe := catch(func() { deep(20) }); len(pe.Frames) != maxPanicFrames {
		t.Fatalf("frames kept: %d", len(pe.Frames))
	}
}

// A panic in one of the vault's goroutines (Manager.Go) zeroizes it and is
// handed on with where it happened; also when it left the manager's lock
// held, which Crash does not wait for beyond crashLockWait.
func TestAGoroutinePanicEndsTheVault(t *testing.T) {
	for _, held := range []bool{false, true} {
		got := make(chan *PanicError, 1)
		m := &Manager{opt: Options{OnPanic: func(pe *PanicError) { got <- pe }}}
		m.Go(func() {
			if held {
				m.mu.Lock() // and never unlocked
			}
			_ = indexPanic(5)
		})
		select {
		case pe := <-got:
			if len(pe.Frames) == 0 || !strings.HasPrefix(pe.Frames[0], "vault.indexPanic panic_test.go:") {
				t.Fatalf("held %v: frames %q", held, pe.Frames)
			}
			for _, f := range pe.Frames {
				if strings.HasPrefix(f, "vault.(*Manager).Go.") {
					t.Fatalf("the helper's own frame: %q", pe.Frames)
				}
			}
		case <-time.After(crashLockWait + 3*time.Second):
			t.Fatalf("held %v: not reported", held)
		}
		if !held {
			// Told first, zeroized right after.
			deadline := time.Now().Add(5 * time.Second)
			for !m.Locked() && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if !m.Locked() {
				t.Fatal("not zeroized")
			}
		}
	}
}

// A runtime error behind a pointer (a failed type assertion) is the
// runtime's own too.
func TestARuntimePointerErrorKeepsItsText(t *testing.T) {
	var x any = 1
	pe := catch(func() { _ = x.(string) })
	if pe.Type != "*runtime.TypeAssertionError" || !strings.Contains(pe.Runtime, "interface conversion") {
		t.Fatalf("%+v", pe)
	}
}

// After a goroutine's panic nothing of the vault is stored (the state may
// be half changed), Run returns the panic whatever ended the loop, and the
// zeroize does not wait for OnPanic (whose log may wait for a full channel).
func TestAGoroutinePanicStoresNothingAndIsWhatRunReturns(t *testing.T) {
	pe := &PanicError{Type: "runtime.plainError"}
	m := &Manager{st: &State{}}
	m.panicErr.Store(pe)
	if err := m.persist(context.Background(), false); !errors.Is(err, ErrLocked) {
		t.Fatalf("persist after a panic: %v", err)
	}
	if err := m.writeHeaderWith(context.Background(), true); !errors.Is(err, ErrLocked) {
		t.Fatalf("header after a panic: %v", err)
	}
	var got *PanicError
	locked := &Manager{locked: true}
	locked.panicErr.Store(pe)
	if err := locked.Run(context.Background()); !errors.As(err, &got) || got != pe {
		t.Fatalf("Run returned %v", err)
	}
	if err := (&Manager{locked: true}).Run(context.Background()); !errors.Is(err, ErrLocked) {
		t.Fatalf("no panic: Run returned %v", err)
	}

	release := make(chan struct{})
	defer close(release)
	told := make(chan struct{})
	b := &Manager{opt: Options{OnPanic: func(*PanicError) { close(told); <-release }}}
	b.Go(func() { _ = indexPanic(2) })
	<-told
	deadline := time.Now().Add(crashLockWait)
	for !b.Locked() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !b.Locked() || !b.Panicked() {
		t.Fatal("not zeroized while OnPanic was still running")
	}
}

// Nor does the attachments runner act on the vault's word after a panic:
// no pass (erase, discard, upload) and no object written.
func TestAfterAPanicTheAttachmentsRunnerDoesNothing(t *testing.T) {
	m := &Manager{st: &State{}}
	r := &attRunner{lastRun: map[string]time.Time{}}
	m.att = r
	m.panicErr.Store(&PanicError{Type: "runtime.plainError"})
	if _, _, ok := m.attPassLocked(r); ok {
		t.Fatal("a pass ran after a panic")
	}
	if _, err := m.putObject(r, "k", []byte("x")); !errors.Is(err, ErrLocked) {
		t.Fatalf("an object written after a panic: %v", err)
	}
}

// A panic under the manager's lock is recorded before the lock goes to a
// waiter (unlockOnPanic), so the waiter (another batch, the attachments
// pass) stores and sends nothing of the half-changed state; it is
// described where it happened.
func TestAPanicUnderTheLockIsRecordedBeforeAWaiterGetsIt(t *testing.T) {
	m := &Manager{}
	waiting := make(chan struct{})
	sawPanic := make(chan bool, 1)
	repanicked := false
	func() {
		defer func() { repanicked = recover() != nil }()
		m.mu.Lock()
		defer m.unlockOnPanic()
		go func() {
			close(waiting)
			m.mu.Lock()
			sawPanic <- m.Panicked()
			m.mu.Unlock()
		}()
		<-waiting
		time.Sleep(20 * time.Millisecond) // the waiter is blocked on the lock
		_ = indexPanic(4)
	}()
	if !<-sawPanic {
		t.Fatal("the waiter got the lock before the panic was recorded")
	}
	if !repanicked {
		t.Fatal("unlockOnPanic stopped the panic instead of passing it on")
	}
	if pe := m.RecordedPanic(); pe == nil || len(pe.Frames) == 0 || !strings.HasPrefix(pe.Frames[0], "vault.indexPanic") {
		t.Fatalf("recorded %+v", pe)
	}
	// A panic seen but not described yet already stops writes and is what Run returns.
	n := &Manager{}
	n.MarkPanicking()
	if !n.Panicked() || !errors.Is(n.withPanic(ErrLocked), ErrPanic) {
		t.Fatal("a panic marked is not yet in force")
	}
}

// Crash with the manager's lock held elsewhere returns within its bound.
func TestCrashWithTheLockHeldReturnsWithinItsBound(t *testing.T) {
	m := &Manager{}
	m.mu.Lock()
	defer m.mu.Unlock()
	began := time.Now()
	m.Crash()
	if d := time.Since(began); d < crashLockWait || d > crashLockWait+2*time.Second {
		t.Fatalf("returned after %v", d)
	}
}

// The attachments runner's shape (Fable's probe): a region locked inline
// that panics, under a deferred cleanup that takes the lock. The cleanup
// does not take it (the panic holds it), so the goroutine's recover runs
// and the panic is reported, described where it happened.
func TestAPanicInAnInlineLockedRegionIsReported(t *testing.T) {
	got := make(chan *PanicError, 1)
	m := &Manager{opt: Options{OnPanic: func(pe *PanicError) { got <- pe }}}
	m.Go(func() {
		defer func() {
			if r := recover(); r != nil {
				m.recordFromCleanup(r)
				panic(r)
			}
			m.mu.Lock()
			m.dirty = false // the cleanup's work, under the lock
			m.mu.Unlock()
		}()
		m.mu.Lock()
		_ = indexPanic(3) // no deferred unlock: the lock stays held
		m.mu.Unlock()
	})
	select {
	case pe := <-got:
		if len(pe.Frames) == 0 || !strings.HasPrefix(pe.Frames[0], "vault.indexPanic") {
			t.Fatalf("frames %q", pe.Frames)
		}
	case <-time.After(crashLockWait + 3*time.Second):
		t.Fatal("a panic under an inline lock hung before its recover")
	}
}
