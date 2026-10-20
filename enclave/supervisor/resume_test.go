package supervisor

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/vaultipc"
	"github.com/vettid/vettid-vault/vault"
)

// VAULT-HOST-PROTOCOL 0.1.14 §6.1, P20: a delete_resume never runs beside
// another process of its vault. The check counts the opens under way and
// is one step with the reservation; other opens of the vault wait for a
// resume under way.
func TestResumeReservation(t *testing.T) {
	h := newProcHost(&Supervisor{}, ProcConfig{})
	ctx := context.Background()
	job := func(op string) *enclave.Job { return &enclave.Job{Op: op, VaultID: "aaaa"} }
	// A vault that runs, or opens, here: the resume is refused.
	h.procs["aaaa"] = &vproc{}
	if _, ok, _ := h.reserve(ctx, job(enclave.OpDeleteResume)); ok {
		t.Fatal("a resume beside a running process")
	}
	delete(h.procs, "aaaa")
	done, ok, err := h.reserve(ctx, job(enclave.OpUnlock))
	if !ok || err != nil {
		t.Fatal("an unlock was refused")
	}
	if _, ok, _ := h.reserve(ctx, job(enclave.OpDeleteResume)); ok {
		t.Fatal("a resume beside an opening process")
	}
	done()
	// A resume under way: a second is refused; an unlock waits for it.
	end, ok, _ := h.reserve(ctx, job(enclave.OpDeleteResume))
	if !ok {
		t.Fatal("a resume of a vault that does not run was refused")
	}
	if _, ok, _ := h.reserve(ctx, job(enclave.OpDeleteResume)); ok {
		t.Fatal("two resumes at once")
	}
	got := make(chan func())
	go func() {
		d, ok, err := h.reserve(ctx, job(enclave.OpEnroll))
		if !ok || err != nil {
			t.Error("the enroll was refused")
		}
		got <- d
	}()
	select {
	case <-got:
		t.Fatal("an enroll ran beside a resume")
	case <-time.After(50 * time.Millisecond):
	}
	end()
	select {
	case d := <-got:
		d()
	case <-time.After(5 * time.Second):
		t.Fatal("the enroll did not go on after the resume")
	}
	// A wait ends with its context.
	end, _, _ = h.reserve(ctx, job(enclave.OpDeleteResume))
	cctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, ok, err := h.reserve(cctx, job(enclave.OpUnlock)); ok || err == nil {
		t.Fatal("a cancelled wait opened")
	}
	end()
	if len(h.opening) != 0 || len(h.resuming) != 0 {
		t.Fatalf("left: %v %v", h.opening, h.resuming)
	}
}

// A resume's open locks nothing: the vault refused by the reservation is
// not touched (procHost.Open returns before its leading Lock).
func TestResumeOpenLocksNothing(t *testing.T) {
	h := newProcHost(&Supervisor{}, ProcConfig{})
	var locked atomic.Bool
	a, b := net.Pipe()
	proc := hostproto.NewConn(b, func(_ context.Context, f *hostproto.Frame) [][]byte {
		if f.Kind == vaultipc.KindLock {
			locked.Store(true)
		}
		return hostproto.Strings(hostproto.StatusOK)
	}, nil)
	conn := hostproto.NewConn(a, nil, nil)
	t.Cleanup(func() { conn.Close(); proc.Close() })
	exited := make(chan struct{})
	close(exited)
	h.procs["aaaa"] = &vproc{h: h, vaultID: "aaaa", conn: conn, exited: exited}
	res, mk, err := h.Open(context.Background(), &enclave.Job{Op: enclave.OpDeleteResume, VaultID: "aaaa"})
	if res != nil || mk != (enclave.Marker{}) || err != nil || locked.Load() || h.procs["aaaa"] == nil {
		t.Fatalf("res %v marker %+v err %v locked %v", res, mk, err, locked.Load())
	}
}

// VAULT-MESSAGING 0.51.0: a host deletion that ends locked without
// deleting (no host mark) is an error to the instance, which then erases
// without the DEK; any other lock is answered as before.
func TestLockDeleteNotDeleted(t *testing.T) {
	for _, c := range []struct {
		reason, reply string
		want          error
	}{
		{vault.LockDelete, vaultipc.StatusNotDeleted, errNotDeleted},
		{vault.LockDelete, hostproto.StatusOK, nil},
		{"", vaultipc.StatusNotDeleted, nil},
		{vault.LockDelete, vaultipc.StatusSplitBrain, vault.ErrSplitBrain},
	} {
		h := newProcHost(&Supervisor{}, ProcConfig{})
		a, b := net.Pipe()
		proc := hostproto.NewConn(b, func(context.Context, *hostproto.Frame) [][]byte { return hostproto.Strings(c.reply) }, nil)
		conn := hostproto.NewConn(a, nil, nil)
		exited := make(chan struct{})
		close(exited)
		h.procs["aaaa"] = &vproc{h: h, vaultID: "aaaa", conn: conn, exited: exited}
		ran, err := h.LockReason(context.Background(), "aaaa", c.reason)
		if !ran || !errors.Is(err, c.want) || (c.want == nil) != (err == nil) {
			t.Fatalf("%q %s: ran %v err %v", c.reason, c.reply, ran, err)
		}
		conn.Close()
		proc.Close()
	}
}
