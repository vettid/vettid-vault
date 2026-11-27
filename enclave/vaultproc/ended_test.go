package vaultproc

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/enclave"
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
		{pe, true, ExitError, false, "vault run loop panicked"},
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
