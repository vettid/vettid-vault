package vault

import (
	"errors"
	"fmt"
	"path"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ErrPanic reports a vault goroutine (the run loop or one of Manager.Go's)
// that panicked: the vault was zeroized without a flush.
var ErrPanic = errors.New("vault: a goroutine of the vault panicked")

// PanicError is ErrPanic with what may be logged of the panic: the
// value's type, the text of one of the Go runtime's own errors with its
// numbers replaced by N (an index or a length may come from vault data),
// and the frames of this module where it happened, as function names and
// lines. Never the value of another panic, which could hold vault data.
type PanicError struct {
	Type    string   // the panic value's type, e.g. runtime.boundsError
	Runtime string   // a Go runtime error's text, its numbers N; "" for any other value
	Frames  []string // "function file:line", innermost first, at most maxPanicFrames
}

func (e *PanicError) Error() string { return ErrPanic.Error() + ": " + e.Type }

func (e *PanicError) Unwrap() error { return ErrPanic }

// maxPanicFrames bounds the frames a PanicError keeps.
const maxPanicFrames = 8

// modulePrefix selects the frames of this module.
const modulePrefix = "github.com/vettid/vettid-vault/"

// digits are the numbers a runtime error's text may carry.
var digits = regexp.MustCompile(`[0-9]+`)

// DescribePanic describes r, the value recovered by the deferred function
// that calls it (directly: the frames skipped are its own, runtime.Callers'
// and that function's).
func DescribePanic(r any) *PanicError { return describePanic(r, 1) }

// describePanic is DescribePanic for a caller extra frames further from the
// deferred function (recordFromCleanup: one).
func describePanic(r any, extra int) *PanicError {
	e := &PanicError{Type: fmt.Sprintf("%T", r)}
	if re, ok := r.(runtime.Error); ok && fromRuntime(r) {
		e.Runtime = digits.ReplaceAllString(re.Error(), "N")
	}
	pcs := make([]uintptr, 64)
	n := runtime.Callers(3+extra, pcs) // past runtime.Callers, describePanic, its callers and the deferred function
	frames := runtime.CallersFrames(pcs[:n])
	for {
		f, more := frames.Next()
		if strings.HasPrefix(f.Function, modulePrefix) && !recoverFrame(f.Function) {
			e.Frames = append(e.Frames, strings.TrimPrefix(f.Function, modulePrefix)+" "+path.Base(f.File)+":"+strconv.Itoa(f.Line))
			if len(e.Frames) == maxPanicFrames {
				break
			}
		}
		if !more {
			break
		}
	}
	return e
}

// recoverFrame reports a frame of the recovering helpers themselves.
func recoverFrame(fn string) bool {
	fn = strings.TrimPrefix(fn, modulePrefix)
	return strings.HasPrefix(fn, "enclave.RunRecovered") || strings.HasPrefix(fn, "vault.(*Manager).Go.")
}

// fromRuntime reports whether r is one of the Go runtime's own errors (a
// value of a type of package runtime), not a type that only implements
// runtime.Error.
func fromRuntime(r any) bool {
	t := reflect.TypeOf(r)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t.PkgPath() == "runtime"
}

// RecordPanic records pe as the vault's panic (the first one stands), so
// that nothing more is stored or sent (Panicked) and Run returns it; the
// run loop's recover (enclave.RunRecovered) calls it before its Crash.
func (m *Manager) RecordPanic(pe *PanicError) {
	m.panicking.Store(true)
	m.panicErr.CompareAndSwap(nil, pe)
}

// MarkPanicking marks a panic seen and not described yet: Panicked is
// true from here.
func (m *Manager) MarkPanicking() { m.panicking.Store(true) }

// RecordedPanic is the panic recorded where it happened (unlockOnPanic), if
// any: a recover further up describes a re-panic, whose frames are not the
// panic's own.
func (m *Manager) RecordedPanic() *PanicError { return m.panicErr.Load() }

// unlockOnPanic is the deferred unlock of every m.mu site of the package
// (TestNoPlainDeferredUnlocks): a panic under the lock is
// recorded before the lock goes to a waiter, which would otherwise store or
// send the half-changed state, then panics on to the goroutine's recover.
func (m *Manager) unlockOnPanic() {
	if r := recover(); r != nil {
		m.panicking.Store(true)
		m.panicErr.CompareAndSwap(nil, DescribePanic(r))
		m.mu.Unlock()
		panic(r)
	}
	m.mu.Unlock()
}

// Fail ends the vault after a panic outside its own goroutines (a request
// the vault process handles for the supervisor): as panicked, so recorded,
// zeroized within its bound, and told to Options.OnPanic.
func (m *Manager) Fail(pe *PanicError) {
	m.panicking.Store(true)
	m.panicked(pe)
}

// recordFromCleanup records r, recovered by a deferred cleanup that takes
// m.mu (the attachments runner's), which then panics on instead of
// cleaning up: the panic may have left m.mu held by this very goroutine (an
// inline-locked region), and taking it again would hang before the
// goroutine's recover; the vault ends, so the cleanup is moot. The panic is
// described without the cleanup's own frame.
func (m *Manager) recordFromCleanup(r any) {
	m.panicking.Store(true)
	m.panicErr.CompareAndSwap(nil, describePanic(r, 1))
}

// Go runs f in a goroutine of the vault's own. A panic in it zeroizes the
// vault (as Crash) and is handed to Options.OnPanic, which in a vault
// process logs it and ends the process as an error: never a silent end,
// never a vault left open with a goroutine gone.
func (m *Manager) Go(f func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				m.panicking.Store(true) // before the description, which takes a moment
				pe := DescribePanic(r)
				if rec := m.panicErr.Load(); rec != nil {
					pe = rec // described where it happened, under the lock
				}
				m.panicked(pe)
			}
		}()
		f()
	}()
}

// panicked handles a panic in one of the vault's goroutines. The panic is
// recorded first: from then on nothing is stored or sent (persist, the
// header write, an attachment's write and the outbox drain refuse while
// Panicked), so a state the panic left half changed never reaches the
// store, and Run returns it (withPanic), so that the vault's end is an
// error whatever ends the loop. The zeroize starts at once, in a goroutine
// of its own, and Options.OnPanic is told (a vault process ends as an
// error); the zeroize is waited for at most crashLockWait: a lock the panic
// left held (the manager's or another the zeroize takes) must not hang the
// end, and a vault process ends anyway, which wipes its memory.
func (m *Manager) panicked(pe *PanicError) {
	m.panicErr.CompareAndSwap(nil, pe)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = recover() }() // a zeroize that panics in turn changes nothing
		m.Crash()
	}()
	if h := m.opt.OnPanic; h != nil {
		h(pe)
	}
	select {
	case <-done:
	case <-time.After(crashLockWait):
	}
}

// Panicked reports whether one of the vault's goroutines panicked: the
// vault is (being) zeroized, and nothing more of it is stored or sent.
func (m *Manager) Panicked() bool { return m.panicking.Load() || m.panicErr.Load() != nil }

// withPanic is what Run returns: a goroutine's panic over err (the loop
// then ended because the panic zeroized the vault).
func (m *Manager) withPanic(err error) error {
	if pe := m.panicErr.Load(); pe != nil {
		return pe
	}
	if m.panicking.Load() {
		return ErrPanic // seen, not described yet
	}
	return err
}

// crashLockWait bounds Crash's wait for the manager's lock: a panic while
// it was held without a deferred unlock leaves it held for ever. It also
// gives up on a lock that is only busy (a network call under it): the
// guarantee after a panic is the vault process's end (OnPanic), which
// wipes its memory; the zeroize here is the best effort before it.
const crashLockWait = 2 * time.Second

// tryLockFor takes m.mu within d; false if it could not.
func (m *Manager) tryLockFor(d time.Duration) bool {
	end := time.Now().Add(d)
	for {
		if m.mu.TryLock() {
			return true
		}
		if !time.Now().Before(end) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Go runs f as one of the vault's own goroutines (Manager.Go), for a
// feature's background work; a session built with NewSession (tests) runs
// it as a plain goroutine.
func (s *Session) Go(f func()) {
	if s.m != nil {
		s.m.Go(f)
		return
	}
	go f()
}
