package supervisor

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/vaultipc"
)

// A vault process's log record keeps its level: a Warn (a run loop that
// panicked) is logged at Warn, anything else at Info, and each value is cut
// to 120 bytes on its own.
func TestAVaultLogKeepsItsLevel(t *testing.T) {
	var buf bytes.Buffer
	s := &Supervisor{log: slog.New(slog.NewTextHandler(&buf, nil)), link: &link{}, now: time.Now, activity: map[string]time.Time{}}
	p := &vproc{h: &procHost{s: s}, vaultID: "aaaa"}
	for _, c := range []struct{ level, want string }{
		{"WARN", "level=WARN"}, {"ERROR", "level=WARN"}, {"INFO", "level=INFO"}, {"DEBUG", "level=INFO"}, {"OTHER", "level=INFO"},
	} {
		buf.Reset()
		p.notify(&hostproto.Frame{Kind: vaultipc.KindLog, Fields: hostproto.Strings(c.level, "m", "at0", strings.Repeat("x", 200))})
		if !strings.Contains(buf.String(), c.want) || !strings.Contains(buf.String(), "at0="+strings.Repeat("x", 120)+"\n") {
			t.Fatalf("%s: %q", c.level, buf.String())
		}
	}
}
