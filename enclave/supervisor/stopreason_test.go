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
