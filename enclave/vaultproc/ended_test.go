package vaultproc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/vaultipc"
	"github.com/vettid/vettid-vault/vault"
)

// A run loop that ended on its own: only a vault that locked itself exits
// ExitLocked (the supervisor's "reason: locked"); a panic, which zeroized
// it with no lifecycle "locked" and no vault.locking, is an error, and is
// logged with where it happened.
func TestRunEndedTellsAPanicFromALock(t *testing.T) {
	var buf bytes.Buffer
	pr := &proc{log: slog.New(slog.NewTextHandler(&buf, nil))}
	pe := &enclave.PanicError{Type: "runtime.boundsError", Runtime: "index out of range [3] with length 3", Frames: []string{"vault.f x.go:1", "vault.g y.go:2"}}
	for _, c := range []struct {
		err       error
		locked    bool
		code      int
		lockFirst bool
		log       string
	}{
		{pe, true, ExitError, false, "vault panicked"},
		{vault.ErrSplitBrain, true, ExitSplitBrain, false, "split brain"},
		{vault.ErrLocked, true, ExitLocked, false, ""},
		{errors.New("relay"), false, ExitError, true, "vault run loop ended"},
	} {
		buf.Reset()
		code, lockFirst := pr.runEnded(c.err, c.locked)
		if code != c.code || lockFirst != c.lockFirst {
			t.Fatalf("%v: %d %v", c.err, code, lockFirst)
		}
		if c.log == "" && buf.Len() != 0 || !strings.Contains(buf.String(), c.log) {
			t.Fatalf("%v: log %q", c.err, buf.String())
		}
	}
	buf.Reset()
	pr = &proc{log: slog.New(slog.NewTextHandler(&buf, nil))} // a panic is logged once per process
	pr.runEnded(pe, true)
	if !strings.Contains(buf.String(), `at0="vault.f x.go:1" at1="vault.g y.go:2"`) || !strings.Contains(buf.String(), "index out of range") {
		t.Fatalf("panic log: %q", buf.String())
	}
}

// A channel that ended under a running vault is an error, not a lock.
func TestAChannelEndedUnderARunningVaultIsNoLock(t *testing.T) {
	if channelEndedExit(true) != ExitChannel || channelEndedExit(false) != ExitLocked {
		t.Fatal("channel end exit codes")
	}
}

// A run loop that panicked as the supervisor's lock began: the panic is
// logged and the lock is answered as an error (not-deleted for a
// deletion), never as a lock done.
func TestALockMetByAPanicIsAnError(t *testing.T) {
	for _, c := range []struct{ reason, want string }{{"", hostproto.StatusError}, {vault.LockDelete, vaultipc.StatusNotDeleted}} {
		var buf bytes.Buffer
		pr := &proc{log: slog.New(slog.NewTextHandler(&buf, nil)), exit: make(chan int, 2)}
		ctx, cancel := context.WithCancel(context.Background())
		m := &vault.Manager{} // never opened: its loop panics at its start
		pr.mgr, pr.cancel, pr.runDone = m, cancel, make(chan error, 1)
		cancel() // the lock's cancel came first
		pr.run(ctx, m)
		if !strings.Contains(buf.String(), "vault panicked") || len(pr.exit) != 0 {
			t.Fatalf("%q: log %q, exits %d", c.reason, buf.String(), len(pr.exit))
		}
		// The lock that cancelled it reads the loop's end, which run left.
		if r := pr.lock(context.Background(), c.reason); string(r[0]) != c.want {
			t.Fatalf("%q: answered %q", c.reason, r[0])
		}
	}
}

// A channel that ended under a running vault zeroizes it and ends the
// process as an error; with no vault running (the supervisor's lock took
// it first), as a lock; an exit already decided stands.
func TestAChannelEndZeroizesARunningVault(t *testing.T) {
	m := &vault.Manager{}
	pr := &proc{mgr: m, exit: make(chan int, 2)}
	if code := pr.channelEnded(); code != ExitChannel || !m.Locked() {
		t.Fatalf("running: %d, locked %v", code, m.Locked())
	}
	if code := (&proc{exit: make(chan int, 2)}).channelEnded(); code != ExitLocked {
		t.Fatalf("none running: %d", code)
	}
	decided := &proc{mgr: &vault.Manager{}, exit: make(chan int, 2)}
	decided.exit <- ExitSplitBrain
	if code := decided.channelEnded(); code != ExitSplitBrain {
		t.Fatalf("decided: %d", code)
	}
}

// A panic in one of the vault's goroutines (Options.OnPanic) ends the
// process as an error, logged once though the run loop's end sees it too.
func TestAGoroutinePanicEndsTheProcessAsAnError(t *testing.T) {
	var buf bytes.Buffer
	pr := &proc{log: slog.New(slog.NewTextHandler(&buf, nil)), exit: make(chan int, 2)}
	pe := &vault.PanicError{Type: "runtime.plainError", Frames: []string{"vault.f x.go:1"}}
	pr.goroutinePanicked(pe)
	if code := <-pr.exit; code != ExitError {
		t.Fatalf("exit %d", code)
	}
	if code, _ := pr.runEnded(pe, true); code != ExitError {
		t.Fatalf("run end %d", code)
	}
	if n := strings.Count(buf.String(), "vault panicked"); n != 1 {
		t.Fatalf("logged %d times: %q", n, buf.String())
	}
}

// A supervisor request whose handling panics (here a lock that finds no run
// loop to stop): answered as failed, the manager being locked zeroized,
// the panic logged, and the process's end an error, never a silent exit.
func TestARequestThatPanicsEndsTheProcessAsAnError(t *testing.T) {
	var buf bytes.Buffer
	m := &vault.Manager{}
	pr := &proc{log: slog.New(slog.NewTextHandler(&buf, nil)), exit: make(chan int, 2), mgr: m}
	r := pr.handle(context.Background(), &hostproto.Frame{Kind: vaultipc.KindLock, Fields: hostproto.Strings("")})
	if len(r) == 0 || string(r[0]) != hostproto.StatusError {
		t.Fatalf("answered %q", r)
	}
	select {
	case code := <-pr.exit:
		if code != ExitError {
			t.Fatalf("exit %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no exit")
	}
	if !m.Panicked() || !strings.Contains(buf.String(), "vault panicked") {
		t.Fatalf("panicked %v, log %q", m.Panicked(), buf.String())
	}
	// A deletion's lock that panics is answered not-deleted.
	if r := (&proc{log: slog.New(slog.NewTextHandler(&buf, nil)), exit: make(chan int, 2)}).requestPanicked(
		&vault.PanicError{}, &hostproto.Frame{Kind: vaultipc.KindLock, Fields: hostproto.Strings(vault.LockDelete)}); string(r[0]) != vaultipc.StatusNotDeleted {
		t.Fatalf("delete lock answered %q", r)
	}
}

// The vault process's options carry OnPanic, which ends the process as an
// error.
func TestTheVaultOptionsEndTheProcessOnAPanic(t *testing.T) {
	pr := &proc{log: slog.New(slog.NewTextHandler(io.Discard, nil)), exit: make(chan int, 2)}
	o := pr.vaultOptions(enclave.Config{})
	if o.OnPanic == nil {
		t.Fatal("no OnPanic")
	}
	o.OnPanic(&vault.PanicError{Type: "runtime.plainError"})
	if code := <-pr.exit; code != ExitError {
		t.Fatalf("exit %d", code)
	}
}
