package supervisor

import (
	"context"
	"net"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/vaultipc"
)

// reqProc is a vault process for procHost: a channel whose far end
// answers with reply (nil: never answers), and an OS process (sleep) that
// kill can end. exited closes when the channel or the process ends, as a
// vault process exits when its channel closes.
type reqProc struct {
	p     *vproc
	kinds atomic.Int64 // the last frame kind seen
	bound atomic.Value // the unlock_id a LockBound carried
}

func newReqProc(t *testing.T, h *procHost, id string, openedAt time.Time, reply func(f *hostproto.Frame) [][]byte) *reqProc {
	t.Helper()
	fp := &reqProc{}
	a, b := net.Pipe()
	far := hostproto.NewConn(b, func(ctx context.Context, f *hostproto.Frame) [][]byte {
		fp.kinds.Store(int64(f.Kind))
		if f.Kind == vaultipc.KindLockBound && len(f.Fields) == 1 {
			fp.bound.Store(string(f.Fields[0]))
		}
		if reply == nil {
			<-ctx.Done() // never answers
			return nil
		}
		return reply(f)
	}, nil)
	conn := hostproto.NewConn(a, nil, nil)
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() {
		select {
		case <-conn.Done():
		case <-far.Done():
		}
		_ = cmd.Process.Kill()
	}()
	go func() {
		_ = cmd.Wait()
		far.Close()
		close(exited)
	}()
	t.Cleanup(func() { _ = cmd.Process.Kill(); conn.Close(); far.Close() })
	fp.p = &vproc{h: h, vaultID: id, conn: conn, cmd: cmd, exited: exited, openedAt: openedAt}
	h.procs[id] = fp.p
	return fp
}

func lockOK(*hostproto.Frame) [][]byte { return hostproto.Strings(hostproto.StatusOK) }

// VAULT-MESSAGING 0.29.0 §11.5 (release L) on the process host: an
// unconditional lock is ordered by enqueued_at against the opening (an
// equal or earlier time is stale; an opening of unknown time locks); a
// bound one is the vault process's to decide (stale or locked); a process
// that gives no answer, or a garbage one, is killed and the vault counts
// as locked; nothing running is not_running.
func TestProcHostLockRequest(t *testing.T) {
	opened := time.Date(2026, 10, 23, 12, 0, 0, 500_000_000, time.UTC)
	const uid = "0123456789abcdef0123456789abcdef"
	ctx := context.Background()
	for _, c := range []struct {
		name     string
		opened   time.Time
		unlockID string
		at       time.Time
		reply    func(*hostproto.Frame) [][]byte
		want     string
		running  bool // the process is still the vault's afterwards
		kind     hostproto.Kind
	}{
		{"unconditional, earlier", opened, "", opened.Add(-time.Millisecond), lockOK, enclave.CodeStale, true, 0},
		{"unconditional, equal", opened, "", opened, lockOK, enclave.CodeStale, true, 0},
		{"unconditional, later", opened, "", opened.Add(time.Millisecond), lockOK, enclave.CodeLocked, false, vaultipc.KindLock},
		{"unconditional, opening of unknown time", time.Time{}, "", opened, lockOK, enclave.CodeLocked, false, vaultipc.KindLock},
		{"bound, the current unlock", opened, uid, opened.Add(-time.Hour), lockOK, enclave.CodeLocked, false, vaultipc.KindLockBound},
		{"bound, another unlock", opened, uid, opened.Add(time.Hour),
			func(*hostproto.Frame) [][]byte { return hostproto.Strings(vaultipc.StatusStale) }, enclave.CodeStale, true, vaultipc.KindLockBound},
		{"bound, a garbage answer", opened, uid, opened, func(*hostproto.Frame) [][]byte { return hostproto.Strings("what") },
			enclave.CodeLocked, false, vaultipc.KindLockBound},
		{"bound, an empty answer", opened, uid, opened, func(*hostproto.Frame) [][]byte { return nil }, enclave.CodeLocked, false, vaultipc.KindLockBound},
		{"bound, no answer", opened, uid, opened, nil, enclave.CodeLocked, false, vaultipc.KindLockBound},
		{"unconditional, no answer", opened, "", opened.Add(time.Second), nil, enclave.CodeLocked, false, vaultipc.KindLock},
	} {
		h := newProcHost(&Supervisor{}, ProcConfig{LockTimeout: 200 * time.Millisecond})
		fp := newReqProc(t, h, "aaaa", c.opened, c.reply)
		got, _ := h.LockRequest(ctx, "aaaa", c.unlockID, c.at)
		if got != c.want {
			t.Fatalf("%s: %q, want %q", c.name, got, c.want)
		}
		if running := h.procs["aaaa"] == fp.p; running != c.running {
			t.Fatalf("%s: still the vault's process %v", c.name, running)
		}
		if k := hostproto.Kind(fp.kinds.Load()); k != c.kind {
			t.Fatalf("%s: the process was asked %#x, want %#x", c.name, k, c.kind)
		}
		if c.kind == vaultipc.KindLockBound && fp.bound.Load() != uid {
			t.Fatalf("%s: the process was not given the unlock_id", c.name)
		}
		if !c.running {
			select {
			case <-fp.p.exited:
			case <-time.After(10 * time.Second):
				t.Fatalf("%s: the process did not end", c.name)
			}
		}
	}
	// Nothing runs here.
	h := newProcHost(&Supervisor{}, ProcConfig{})
	for _, id := range []string{"", uid} {
		if got, err := h.LockRequest(ctx, "bbbb", id, opened); got != enclave.CodeNotRunning || err != nil {
			t.Fatalf("no process (%q): %q %v", id, got, err)
		}
	}
}
