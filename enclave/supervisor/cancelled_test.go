package supervisor

import (
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/vaultipc"
	"github.com/vettid/vettid-vault/vault"
)

// VAULT-MESSAGING 0.49.0 §11.5, VAULT-HOST-PROTOCOL 0.1.13 §7.2: the
// vault process's Lifecycle notification carries cancelled_recovery_id
// (vaultipc 10), and the supervisor passes it on to the parent on an
// unlocked or moved event only, as a ULID.
func TestLifecycleCancelledRecoveryIDCrossesVaultIPC(t *testing.T) {
	const rid = "01JB2Z6V9K3M4N5P6Q7R8S9T32"
	if v, err := strconv.Atoi(vaultipc.Version); err != nil || v < 10 { // 10 brought the field (11: MarkDeleting)
		t.Fatalf("vaultipc version %s", vaultipc.Version)
	}
	a, b := net.Pipe()
	got := make(chan *hostproto.Frame, 8)
	parent := hostproto.NewConn(b, nil, func(f *hostproto.Frame) { got <- f })
	c := hostproto.NewConn(a, nil, nil)
	t.Cleanup(func() { c.Close(); parent.Close() })
	l := &link{}
	l.set(c)
	s := &Supervisor{log: slog.New(slog.NewTextHandler(io.Discard, nil)), link: l, now: time.Now, activity: map[string]time.Time{}}
	p := &vproc{h: &procHost{s: s}, vaultID: "aaaa", userGUID: "u1"}
	send := func(ev vault.LifecycleEvent) {
		ev.VaultID, ev.Release, ev.VaultVersion, ev.StateVersion = "aaaa", "r", "r", 1
		p.notify(&hostproto.Frame{Kind: vaultipc.KindLifecycle, Fields: enclave.LifecycleFields(ev)})
	}
	next := func() *hostproto.Frame {
		t.Helper()
		select {
		case f := <-got:
			return f
		case <-time.After(5 * time.Second):
			t.Fatal("no lifecycle frame reached the parent")
		}
		return nil
	}
	for _, e := range []string{"unlocked", "moved"} {
		send(vault.LifecycleEvent{Event: e, CancelledRecoveryID: rid})
		f := next()
		if f.Kind != hostproto.KindLifecycle || len(f.Fields) != enclave.LifecycleFieldCount || string(f.Fields[0]) != e || string(f.Fields[14]) != rid {
			t.Fatalf("%s: %q", e, f.Fields)
		}
	}
	// Dropped: an id on another event, a malformed id, a frame of the old
	// length. The next good frame is the one that arrives.
	send(vault.LifecycleEvent{Event: "locked", CancelledRecoveryID: rid})
	send(vault.LifecycleEvent{Event: "unlocked", CancelledRecoveryID: "not-a-ulid"})
	old := enclave.LifecycleFields(vault.LifecycleEvent{Event: "unlocked", VaultID: "aaaa", Release: "r", VaultVersion: "r", StateVersion: 1})
	p.notify(&hostproto.Frame{Kind: vaultipc.KindLifecycle, Fields: old[:14]})
	send(vault.LifecycleEvent{Event: "locked"})
	if f := next(); string(f.Fields[0]) != "locked" || len(f.Fields[14]) != 0 {
		t.Fatalf("after the dropped frames: %q", f.Fields)
	}
}
