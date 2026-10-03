// Package vaultproc is one vault's process inside the enclave
// (VAULT-MESSAGING §12.4, VAULT-PLAN §5.3 decision D4). The supervisor
// starts it (a re-executed mode of the enclave binary) for an enroll or
// unlock and hands it the decrypted request over a socketpair; the
// process unseals the header with its own Recipient key, derives the DEK,
// runs the vault manager and every feature handler, signs its own relay
// requests, and exits on lock, which frees all of its memory.
//
// It has no network, NSM or file access of its own: everything goes
// through the channel (internal/vaultipc), which the supervisor scopes to
// this vault.
package vaultproc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/seccomp"
	"github.com/vettid/vettid-vault/internal/vaultipc"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/nitro"
)

// Arg is argv[1] of a vault process.
const Arg = "__vault-process"

// ChannelFD is the channel's file descriptor in a vault process.
const ChannelFD = 3

// Exit codes.
const (
	ExitLocked     = 0
	ExitSplitBrain = 3
	ExitError      = 4
	ExitChannel    = 5
)

// Platform is what the binary pins for a vault process.
type Platform struct {
	// Config returns the release (or development) configuration.
	Config   func(instanceID string) enclave.Config
	Features func() []vault.Feature
	// PollWait overrides the long-poll wait (tests).
	PollWait time.Duration
	// RequireSeccomp makes the process exit if its syscall filter cannot
	// be installed (release builds).
	RequireSeccomp bool
}

// Main runs a vault process on ChannelFD and exits.
func Main(p Platform) {
	Harden()
	f := os.NewFile(ChannelFD, "vault-channel")
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		os.Exit(ExitChannel)
	}
	// From here on the process can create no sockets (no vsock to the
	// parent), trace nothing and read no other process's memory.
	if err := seccomp.Install(); err != nil && p.RequireSeccomp {
		os.Exit(ExitError)
	}
	os.Exit(Serve(c, p))
}

type proc struct {
	p    Platform
	ch   channel
	log  *slog.Logger
	conn *hostproto.Conn

	mu      sync.Mutex
	opened  bool
	mgr     *vault.Manager
	cancel  context.CancelFunc
	runDone chan error
	exit    chan int
}

// Serve runs the vault process on conn until it locks; it returns the exit
// code.
func Serve(c net.Conn, p Platform) int {
	pr := &proc{p: p, exit: make(chan int, 2)}
	pr.conn = hostproto.NewConn(c, pr.handle, nil)
	pr.ch = channel{c: pr.conn}
	pr.log = slog.New(&logHandler{conn: pr.conn})
	select {
	case code := <-pr.exit:
		pr.conn.Close()
		return code
	case <-pr.conn.Done():
		// The supervisor closed the channel (after a lock or a refused
		// open) or died: whatever runs here ends with the process.
		pr.mu.Lock()
		m := pr.mgr
		pr.mu.Unlock()
		if m != nil {
			m.Crash()
		}
		select {
		case code := <-pr.exit:
			return code
		default:
			return ExitLocked
		}
	}
}

func (pr *proc) handle(ctx context.Context, f *hostproto.Frame) [][]byte {
	switch f.Kind {
	case vaultipc.KindOpen:
		return pr.open(ctx, f.Fields)
	case vaultipc.KindLock:
		reason := ""
		if len(f.Fields) == 1 && (string(f.Fields[0]) == "" || string(f.Fields[0]) == "recovery") {
			reason = string(f.Fields[0])
		}
		return pr.lock(ctx, reason)
	}
	return nil
}

func (pr *proc) open(ctx context.Context, f [][]byte) [][]byte {
	pr.mu.Lock()
	if pr.opened {
		pr.mu.Unlock()
		return hostproto.Strings(hostproto.StatusInvalid)
	}
	pr.opened = true
	pr.mu.Unlock()
	if len(f) != 14 || string(f[0]) != vaultipc.Version || !altchan.ValidInstanceID(string(f[1])) {
		return hostproto.Strings(hostproto.StatusInvalid)
	}
	j, err := enclave.ParseJob(f[5:])
	if err != nil {
		return hostproto.Strings(hostproto.StatusInvalid)
	}
	defer j.Wipe()
	meas := nitro.Measurements{PCR0: string(f[2]), PCR1: string(f[3]), PCR2: string(f[4])}
	cfg := pr.p.Config(string(f[1]))
	sl := &statusLists{ch: pr.ch}
	vid := j.VaultID
	core, err := enclave.NewCore(enclave.CoreDeps{
		Config: cfg, Meas: meas, Store: chanStore{ch: pr.ch}, KMS: chanKMS{ch: pr.ch},
		AttestRecipient: func(pub []byte) ([]byte, error) { return pr.ch.attest(vaultipc.KindAttestRecipient, pub) },
		AttestVault: func(bundle, nonce []byte) ([]byte, error) {
			return pr.ch.attest(vaultipc.KindAttestVault, bundle, nonce)
		},
		StatusList: sl.get,
		// Long-poll only: the relay requests share the supervisor's
		// HTTP/2 connections (§12.2).
		Vault: vault.Options{HTTP: &http.Client{Transport: chanTransport{ch: pr.ch}, Timeout: 75 * time.Second}, WebSocket: false,
			PollWait: pr.p.PollWait},
		Features: pr.p.Features,
		Lifecycle: func(ev vault.LifecycleEvent) {
			if ev.VaultID != vid {
				return
			}
			_ = pr.conn.Notify(vaultipc.KindLifecycle, hostproto.Strings(ev.Event, ev.VaultID, ev.Release, ev.VaultVersion, fmt.Sprint(ev.StateVersion))...)
		},
	})
	if err != nil {
		return hostproto.Strings(hostproto.StatusError)
	}
	res, m := core.Open(ctx, j)
	running := "0"
	if m != nil {
		running = "1"
		rctx, cancel := context.WithCancel(context.Background())
		pr.mu.Lock()
		pr.mgr, pr.cancel, pr.runDone = m, cancel, make(chan error, 1)
		pr.mu.Unlock()
		go pr.run(rctx, m)
	}
	return [][]byte{[]byte(hostproto.StatusOK), res, []byte(running)}
}

// run runs the manager; a loop that ends on its own ends the process.
func (pr *proc) run(ctx context.Context, m *vault.Manager) {
	err := enclave.RunRecovered(ctx, m)
	pr.runDone <- err
	if ctx.Err() != nil {
		return // locked by the supervisor
	}
	switch {
	case errors.Is(err, vault.ErrSplitBrain):
		pr.log.Warn("split brain: newer state written elsewhere; zeroized without flushing")
		pr.exit <- ExitSplitBrain
	case m.Locked():
		pr.exit <- ExitLocked
	default:
		pr.log.Warn("vault run loop ended", "error", errText(err))
		lctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		_ = m.Lock(lctx)
		cancel()
		pr.exit <- ExitError
	}
}

// lock is §12.3 owner request (also memory pressure, lease loss, parent
// gone): finish the batch, flush, vault.locking, zeroize; the supervisor
// then closes the channel and the process exits.
func (pr *proc) lock(ctx context.Context, reason string) [][]byte {
	pr.mu.Lock()
	m, cancel, done := pr.mgr, pr.cancel, pr.runDone
	pr.mgr = nil
	pr.mu.Unlock()
	if m == nil {
		return hostproto.Strings(hostproto.StatusOK)
	}
	cancel()
	<-done
	if err := m.LockReason(ctx, reason); errors.Is(err, vault.ErrSplitBrain) {
		return hostproto.Strings(vaultipc.StatusSplitBrain)
	}
	return hostproto.Strings(hostproto.StatusOK)
}

// logHandler sends sanitized records to the supervisor.
type logHandler struct {
	conn  *hostproto.Conn
	attrs []slog.Attr
}

func (h *logHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *logHandler) Handle(_ context.Context, r slog.Record) error {
	f := [][]byte{[]byte(r.Level.String()), []byte(r.Message)}
	add := func(a slog.Attr) bool {
		if len(f) < hostproto.MaxFields-1 {
			f = append(f, []byte(a.Key), []byte(a.Value.String()))
		}
		return true
	}
	for _, a := range h.attrs {
		add(a)
	}
	r.Attrs(add)
	return h.conn.Notify(vaultipc.KindLog, f...)
}

func (h *logHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &logHandler{conn: h.conn, attrs: append(append([]slog.Attr(nil), h.attrs...), as...)}
}

func (h *logHandler) WithGroup(string) slog.Handler { return h }

func errText(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}
