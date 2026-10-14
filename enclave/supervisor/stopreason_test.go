package supervisor

import (
	"log/slog"
	"testing"

	"github.com/vettid/vettid-vault/enclave/vaultproc"
	"github.com/vettid/vettid-vault/internal/hostproto"
)

// A vault that locked itself (the member's lock) is a normal ending: INFO,
// not WARN. Crashes and split brain stay WARN.
func TestStopReason(t *testing.T) {
	for _, c := range []struct {
		code   int
		reason string
		lvl    slog.Level
	}{
		{vaultproc.ExitLocked, hostproto.StopLocked, slog.LevelInfo},
		{vaultproc.ExitSplitBrain, hostproto.StopSplitBrain, slog.LevelWarn},
		{vaultproc.ExitError, hostproto.StopError, slog.LevelWarn},
		{vaultproc.ExitChannel, hostproto.StopError, slog.LevelWarn},
		{-9, hostproto.StopError, slog.LevelWarn}, // killed
		{2, hostproto.StopError, slog.LevelWarn},  // Go runtime panic
	} {
		if r, l := stopReason(c.code); r != c.reason || l != c.lvl {
			t.Errorf("exit %d: %s %v", c.code, r, l)
		}
	}
}

// How a process ended, as the capacity report and the stop log name it.
func TestExitDetail(t *testing.T) {
	for code, want := range map[int]string{0: "exit 0", 2: "exit 2", vaultproc.ExitChannel: "exit 5", -9: "signal 9", -11: "signal 11"} {
		if got := exitDetail(code); got != want {
			t.Errorf("exitDetail(%d) = %q, want %q", code, got, want)
		}
	}
}
