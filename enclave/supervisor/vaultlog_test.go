package supervisor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
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

// A vault process that answers its lock with an error (its run loop
// panicked as the lock began) sent no lifecycle "locked": the parent is
// told the vault stopped, as an error, and the lock reports the error.
func TestALockAnsweredWithAnErrorTellsTheParent(t *testing.T) {
	pa, pb := net.Pipe()
	got := make(chan *hostproto.Frame, 8)
	parent := hostproto.NewConn(pb, nil, func(f *hostproto.Frame) { got <- f })
	c := hostproto.NewConn(pa, nil, nil)
	t.Cleanup(func() { c.Close(); parent.Close() })
	l := &link{}
	l.set(c)
	s := &Supervisor{log: slog.New(slog.NewTextHandler(io.Discard, nil)), link: l, now: time.Now, activity: map[string]time.Time{}}
	h := &procHost{s: s, cfg: ProcConfig{LockTimeout: 5 * time.Second}, procs: map[string]*vproc{}}

	va, vb := net.Pipe()
	vault := hostproto.NewConn(vb, func(_ context.Context, f *hostproto.Frame) [][]byte {
		if f.Kind == vaultipc.KindLock {
			return hostproto.Strings(hostproto.StatusError)
		}
		return nil
	}, nil)
	t.Cleanup(vault.Close)
	p := &vproc{h: h, vaultID: "aaaa", exited: make(chan struct{})}
	p.conn = hostproto.NewConn(va, nil, nil)
	close(p.exited)
	h.procs["aaaa"] = p

	ran, err := h.LockReason(context.Background(), "aaaa", "")
	if !ran || !errors.Is(err, errEndedInLock) {
		t.Fatalf("lock: %v %v", ran, err)
	}
	select {
	case f := <-got:
		if f.Kind != hostproto.KindStopped || string(f.Fields[0]) != "aaaa" || string(f.Fields[1]) != hostproto.StopError {
			t.Fatalf("parent got %v %q", f.Kind, f.Fields)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the parent was not told")
	}
}
