package supervisor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/vaultipc"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/pushwire"
)

// ProcConfig configures the vault processes (VAULT-MESSAGING §12.4).
type ProcConfig struct {
	// Exec is the vault process's argv (the enclave binary re-executed
	// with vaultproc.Arg first).
	Exec []string
	// UIDBase, if not 0, runs each vault process under its own uid = gid,
	// UIDBase plus a counter that only grows for the life of the
	// supervisor: no id is ever given to a second process (needs root,
	// as the supervisor is in the enclave). When such a process ends, everything
	// still running under its id is killed before it is reported ended.
	// 0 keeps the supervisor's ids (development and tests), and none of
	// that applies.
	UIDBase int
	// MaxProcs bounds concurrent vault processes (default 1024).
	MaxProcs int
	// AddressSpace is RLIMIT_AS of a vault process (default 4 GiB).
	AddressSpace uint64
	// OpenFiles is RLIMIT_NOFILE (default 64).
	OpenFiles uint64
	// Tasks is RLIMIT_NPROC: the processes and threads that may run under
	// a vault process's uid at once (default 256). Applied only with
	// UIDBase, where the uid is the process's alone; RLIMIT_FSIZE is
	// always 0 (a vault process writes no file). A vault process makes
	// no process (its filter refuses it) and few threads: at most 7 were
	// measured, concurrent unlocks included, since its I/O is
	// non-blocking and GOMAXPROCS is 2. 256 leaves ample room for threads
	// blocked in system calls, and keeps the worst case of many runaway
	// vaults well inside the kernel's pid space (pid_max is 32768 on a
	// small enclave), which a higher limit such as 1024 would not.
	Tasks uint64
	// MemoryLimit is the process's GOMEMLIMIT (default 512 MiB).
	MemoryLimit uint64
	// LockTimeout bounds a lock before the process is killed (60 s).
	LockTimeout time.Duration
}

func (c *ProcConfig) defaults() {
	if c.MaxProcs == 0 {
		c.MaxProcs = 1024
	}
	if c.AddressSpace == 0 {
		c.AddressSpace = 4 << 30
	}
	if c.OpenFiles == 0 {
		c.OpenFiles = 64
	}
	if c.Tasks == 0 {
		c.Tasks = 256
	}
	if c.MemoryLimit == 0 {
		c.MemoryLimit = 512 << 20
	}
	if c.LockTimeout == 0 {
		c.LockTimeout = 60 * time.Second
	}
}

// procHost runs one OS process per vault (enclave.Host).
type procHost struct {
	s   *Supervisor
	cfg ProcConfig

	mu    sync.Mutex
	procs map[string]*vproc
	slots []bool
	// opening counts the opens of each vault under way (their processes
	// are in procs only once the open returns), and resuming holds the
	// delete_resume of a vault under way, closed when it ends
	// (VAULT-HOST-PROTOCOL 0.1.14 P20: a resume never runs beside
	// another process of its vault).
	opening  map[string]int
	resuming map[string]chan struct{}
}

// vproc is one vault process and what its channel may reach.
type vproc struct {
	h        *procHost
	vaultID  string
	userGUID string
	enroll   bool
	// blobBodies are the blob bodies the relay proxy carries for it now
	// (at most one per admitted transfer, §10.5.1).
	blobBodies int
	slot       int
	uid        int // its own uid and gid (UIDBase); 0 without
	cmd        *exec.Cmd
	conn       *hostproto.Conn
	exited     chan struct{}
	exitCode   int

	mu      sync.Mutex
	opening bool
	// prevRead are the two objects of the member's previous vault that an
	// enrollment may read while it opens (re-enrollment, §11.3): its state
	// and its header sealed to this release. Cleared when the open returns.
	prevRead []string
	relayKey ed25519.PublicKey
	stopping bool          // locked or killed by the supervisor
	egress   chan struct{} // one place per relay or push request in flight
	egressAt bool          // the limit was reached (counted once)
	// counterPrefix is the recovery counter prefix this process named
	// first, the only one it may use (release R).
	counterPrefix string
}

var _ enclave.Host = (*procHost)(nil)

func newProcHost(s *Supervisor, cfg ProcConfig) *procHost {
	cfg.defaults()
	return &procHost{s: s, cfg: cfg, procs: map[string]*vproc{}, slots: make([]bool, cfg.MaxProcs),
		opening: map[string]int{}, resuming: map[string]chan struct{}{}}
}

var (
	// errNotDeleted: a lock with the reason delete that left the vault
	// locked without deleting it (enclave.Instance then erases it without
	// the DEK, as for a vault that does not run).
	errNotDeleted = errors.New("supervisor: vault locked, not deleted")
	errNoSlot     = errors.New("supervisor: too many vault processes")
	errSpawn      = errors.New("supervisor: vault process failed to start")
	errNoUID      = errors.New("supervisor: no unused uid left for a vault process")
)

// maxVaultUID is the highest uid given to a vault process ((uid_t)-1 is
// not a uid).
const maxVaultUID = 1<<32 - 2

// sweepAfter sweeps the uid of a vault process that ended. If the sweep
// fails (/proc unreadable, processes still running after its last
// round), the uid is kept as unswept for the vault: it is never given to
// another process anyway, the failure is logged at WARN, and
// the vault's next process is not started until a sweep of every such
// uid succeeds (sweepPending). Other vaults are not affected.
func (s *Supervisor) sweepAfter(vaultID string, uid int) {
	err := sweepUID(uid)
	if err == nil {
		return
	}
	s.log.Warn("vault process left processes that could not be ended; its vault starts no new process until they are",
		"vault_id", vaultID, "uid", uid, "error", err.Error())
	s.unsweptMu.Lock()
	if s.unswept == nil {
		s.unswept = map[string][]int{}
	}
	s.unswept[vaultID] = append(s.unswept[vaultID], uid)
	s.unsweptMu.Unlock()
}

// sweepPending sweeps again the uids a vault's earlier processes left
// unswept and reports whether none is left.
// The sweeps run without the lock, so other vaults' starts never wait
// for them.
func (s *Supervisor) sweepPending(vaultID string) bool {
	s.unsweptMu.Lock()
	pending := append([]int(nil), s.unswept[vaultID]...)
	s.unsweptMu.Unlock()
	if len(pending) == 0 {
		return true
	}
	done := map[int]bool{}
	for _, uid := range pending {
		if sweepUID(uid) == nil {
			done[uid] = true
		}
	}
	s.unsweptMu.Lock()
	defer s.unsweptMu.Unlock()
	var left []int
	for _, uid := range s.unswept[vaultID] { // as it is now (a failure may have been added)
		if !done[uid] {
			left = append(left, uid)
		}
	}
	if len(left) == 0 {
		delete(s.unswept, vaultID)
		return true
	}
	s.unswept[vaultID] = left
	return false
}

// takeUID returns the next unused uid at or above base: one more than the
// last, for the life of the supervisor (the self-test's and the capacity
// test's process hosts draw from the same counter as the instance's).
// After about four thousand million starts there is none left, and no
// process is started.
func (s *Supervisor) takeUID(base int) (int, error) {
	n := s.uidNext.Add(1) - 1
	if base <= 0 || uint64(base) > maxVaultUID || n > maxVaultUID-uint64(base) {
		return 0, errNoUID
	}
	return base + int(n), nil
}

func (h *procHost) takeSlot() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, used := range h.slots {
		if !used {
			h.slots[i] = true
			return i
		}
	}
	return -1
}

func (h *procHost) freeSlot(i int) {
	h.mu.Lock()
	h.slots[i] = false
	h.mu.Unlock()
}

// spawn starts a vault process with its channel on fd 3, a minimal
// environment, no other inherited descriptors, its own user (UIDBase),
// rlimits, and death with the supervisor.
func (h *procHost) spawn(vaultID, userGUID string, enroll bool, extra ...string) (*vproc, error) {
	if len(h.cfg.Exec) == 0 {
		return nil, errSpawn
	}
	// On its own kernel the supervisor closes user namespaces before the
	// first vault process; one that could open them is not started.
	if h.s.cfg.OwnKernel && !h.s.userNSClosed.Load() {
		return nil, errSpawn
	}
	// Nor while the NSM is open to processes other than root.
	if h.s.cfg.OwnKernel && !h.s.nsmClosed.Load() {
		return nil, errSpawn
	}
	// Nor while a kernel setting could not be made.
	if h.s.cfg.OwnKernel && !h.s.kernelSet.Load() {
		return nil, errSpawn
	}
	// Nor, on the hardened kernel, unless it is locked down
	// (confidentiality).
	if h.s.cfg.KernelHardened && !h.s.lockedDown.Load() {
		return nil, errSpawn
	}
	// Nor while a previous process of the same vault left processes that
	// the sweep could not end (sweepAfter): they are tried again first.
	if !h.s.sweepPending(vaultID) {
		return nil, errSpawn
	}
	uid := 0
	if h.cfg.UIDBase > 0 {
		var err error
		if uid, err = h.s.takeUID(h.cfg.UIDBase); err != nil {
			return nil, err
		}
	}
	slot := h.takeSlot()
	if slot < 0 {
		return nil, errNoSlot
	}
	fds, err := socketpair()
	if err != nil {
		h.spawnFailed(vaultID, "socketpair", err)
		h.freeSlot(slot)
		return nil, errSpawn
	}
	parentEnd := os.NewFile(uintptr(fds[0]), "vault-channel")
	childEnd := os.NewFile(uintptr(fds[1]), "vault-channel-child")
	cmd := exec.Command(h.cfg.Exec[0], append(append([]string(nil), h.cfg.Exec[1:]...), extra...)...)
	cmd.Env = []string{"GOMEMLIMIT=" + strconv.FormatUint(h.cfg.MemoryLimit, 10), "GOMAXPROCS=2", "GOTRACEBACK=none"}
	cmd.Dir = "/"
	cmd.ExtraFiles = []*os.File{childEnd} // fd 3; everything else is close-on-exec
	cmd.SysProcAttr = procAttr(uid)
	// Started from the spawner thread, which never ends: the kernel sends
	// a child's parent-death signal (Pdeathsig) when the thread that
	// forked it ends, not the process, and the sweep ends threads.
	onSpawnerThread(func() { err = cmd.Start() })
	if err != nil {
		h.spawnFailed(vaultID, "start", err)
		childEnd.Close()
		parentEnd.Close()
		h.freeSlot(slot)
		return nil, errSpawn
	}
	childEnd.Close()
	// The limits are set right after the start (Go cannot set rlimits
	// between fork and exec, and setting them on the supervisor would
	// apply to it too). Nothing reaches the process before they are set:
	// its first input, the job, comes only after spawn returns.
	setLimits(cmd.Process.Pid, h.cfg, uid > 0)
	c, err := net.FileConn(parentEnd)
	parentEnd.Close()
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		h.freeSlot(slot)
		return nil, errSpawn
	}
	p := &vproc{h: h, vaultID: vaultID, userGUID: userGUID, enroll: enroll, slot: slot, uid: uid, cmd: cmd, exited: make(chan struct{})}
	// The uid in the log shows, across a capacity run, that no uid is
	// given twice.
	if h.s.log != nil { // nil only in tests that build a bare Supervisor
		h.s.log.Info("vault process started", "vault_id", vaultID, "uid", uid)
	}
	p.conn = hostproto.NewConn(c, p.handle, p.notify)
	go func() {
		err := cmd.Wait()
		p.exitCode = exitCode(err)
		p.conn.Close()
		if uid > 0 {
			// Whatever the process left running under its uid (a child it
			// started) ends before the process counts as ended.
			h.s.sweepAfter(p.vaultID, uid)
		}
		h.freeSlot(slot)
		close(p.exited)
		h.exited(p)
	}()
	return p, nil
}

// spawnFailed logs why a vault process could not be started. The request
// is still answered as any failure is (random bytes, §11.4); only the log
// says why.
func (h *procHost) spawnFailed(vaultID, step string, err error) {
	if h.s.log != nil { // nil only in tests that build a bare Supervisor
		h.s.log.Warn("vault process failed to start", "vault_id", vaultID, "step", step, "error", err.Error())
	}
}

func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return -int(ws.Signal())
		}
		return ee.ExitCode()
	}
	if err != nil {
		return -1
	}
	return 0
}

// exitDetail describes an exit code as exitCode reports it: "exit N",
// or "signal N" for a process ended by a signal.
func exitDetail(code int) string {
	if code < 0 {
		return "signal " + strconv.Itoa(-code)
	}
	return "exit " + strconv.Itoa(code)
}

// exited handles a process that ended: a vault that stopped on its own
// (split brain, internal lock, error) is reported to the parent.
func (h *procHost) exited(p *vproc) {
	h.mu.Lock()
	if h.procs[p.vaultID] == p {
		delete(h.procs, p.vaultID)
	}
	h.mu.Unlock()
	if h.s.xfers != nil {
		h.s.xfers.releaseAll(p) // its transfers ended with it
	}
	p.mu.Lock()
	stopping := p.stopping
	p.mu.Unlock()
	h.s.forget(p.vaultID)
	if stopping {
		// Stopped by the supervisor: a clean exit or the supervisor's own
		// SIGKILL is expected. Anything else (a Go panic exits 2, another
		// signal) is logged, since a stop that follows a failed request
		// would otherwise hide the crash that caused the failure.
		if p.exitCode != 0 && p.exitCode != -int(syscall.SIGKILL) {
			h.s.log.Warn("vault process ended abnormally while being stopped", "vault_id", p.vaultID, "exit", exitDetail(p.exitCode))
		}
		return
	}
	reason, lvl := stopReason(p.exitCode)
	h.s.log.Log(context.Background(), lvl, "vault process ended", "vault_id", p.vaultID, "uid", p.uid, "reason", reason, "code", p.exitCode)
	h.s.link.notify(hostproto.KindStopped, hostproto.Strings(p.vaultID, reason)...)
}

// stopReason maps a vault process's exit code to its Stopped reason and
// log level: a vault that locked itself (the member's lock, a move, a
// deletion) ended normally (INFO); split brain, errors and signals are WARN.
func stopReason(exitCode int) (string, slog.Level) {
	reason := hostproto.StopError
	switch exitCode {
	case 0: // vaultproc.ExitLocked
		reason = hostproto.StopLocked
	case 3: // vaultproc.ExitSplitBrain
		reason = hostproto.StopSplitBrain
	}
	if hostproto.StopExpected(reason) {
		return reason, slog.LevelInfo
	}
	return reason, slog.LevelWarn
}

// Open implements enclave.Host: lock a running process of the vault, start
// a new one, hand it the job, and keep it if the vault opened.
func (h *procHost) Open(ctx context.Context, j *enclave.Job) ([]byte, enclave.Marker, error) {
	done, ok, err := h.reserve(ctx, j)
	if err != nil {
		return nil, enclave.Marker{}, err
	}
	if !ok {
		return nil, enclave.Marker{}, nil // a resume of a vault that runs or opens here: nothing (P20)
	}
	defer done()
	if j.Op != enclave.OpDeleteResume {
		// A resume locks nothing: a vault that runs here was refused above.
		_, _ = h.Lock(ctx, j.VaultID)
	}
	m := h.s.inst.Load().Measurements()
	var prev []string
	if j.Op == enclave.OpEnroll {
		// Re-enrollment may read the member's previous vault (§11.3): only
		// the two objects that decide whether it may be replaced.
		if b, _, err := h.s.store().Get(ctx, enclave.UserIndexKey(j.UserGUID)); err == nil {
			prev = previousVaultKeys(string(b), j.VaultID, m.PCR0)
		}
	}
	p, err := h.spawn(j.VaultID, j.UserGUID, j.Op == enclave.OpEnroll)
	if err != nil {
		return nil, enclave.Marker{}, err
	}
	p.mu.Lock()
	p.prevRead = prev
	p.opening = true
	p.mu.Unlock()
	fields := append(hostproto.Strings(vaultipc.Version, h.s.instID, m.PCR0, m.PCR1, m.PCR2), j.Fields()...)
	octx, cancel := context.WithTimeout(ctx, vaultipc.OpenTimeout)
	r, err := p.conn.Call(octx, vaultipc.KindOpen, fields...)
	cancel()
	p.mu.Lock()
	p.opening = false
	p.prevRead = nil
	p.mu.Unlock()
	if err != nil || len(r) != 4 || string(r[0]) != hostproto.StatusOK {
		h.kill(p)
		return nil, enclave.Marker{}, errSpawn
	}
	res := append([]byte(nil), r[1]...)
	// Only the codes an op can carry (0.10.6, 0.16.0, release R).
	marker, ok := enclave.DecodeMarker(j.Op, r[3])
	if !ok {
		marker = enclave.Marker{}
	}
	if string(r[2]) != "1" {
		h.stop(p)
		return res, marker, nil
	}
	h.mu.Lock()
	h.procs[j.VaultID] = p
	h.mu.Unlock()
	h.s.touch(j.VaultID)
	return res, marker, nil
}

// reserve records an open of j's vault before its process starts, and
// returns its end. A delete_resume is refused (ok false) while a process
// of the vault runs or opens here, and every other open of the vault waits
// for a resume under way: the check and the spawn are one step under h.mu
// (VAULT-HOST-PROTOCOL 0.1.14 §6.1, P20).
func (h *procHost) reserve(ctx context.Context, j *enclave.Job) (done func(), ok bool, err error) {
	id := j.VaultID
	h.mu.Lock()
	defer h.mu.Unlock()
	if j.Op == enclave.OpDeleteResume {
		if h.procs[id] != nil || h.opening[id] > 0 || h.resuming[id] != nil {
			return nil, false, nil
		}
		ch := make(chan struct{})
		h.resuming[id] = ch
		return func() {
			h.mu.Lock()
			delete(h.resuming, id)
			h.mu.Unlock()
			close(ch)
		}, true, nil
	}
	for h.resuming[id] != nil {
		ch := h.resuming[id]
		h.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			h.mu.Lock()
			return nil, false, ctx.Err()
		}
		h.mu.Lock()
	}
	h.opening[id]++
	return func() {
		h.mu.Lock()
		if h.opening[id]--; h.opening[id] <= 0 {
			delete(h.opening, id)
		}
		h.mu.Unlock()
	}, true, nil
}

// stop ends a process that holds no unlocked vault (closing its channel
// makes it exit).
func (h *procHost) stop(p *vproc) {
	p.mu.Lock()
	p.stopping = true
	p.mu.Unlock()
	p.conn.Close()
	select {
	case <-p.exited:
	case <-time.After(5 * time.Second):
		h.kill(p)
	}
}

// kill ends a process at once (no flush).
func (h *procHost) kill(p *vproc) {
	p.mu.Lock()
	p.stopping = true
	p.mu.Unlock()
	_ = p.cmd.Process.Kill()
	<-p.exited
}

// Lock implements enclave.Host: the process flushes, sends vault.locking
// and zeroizes, then exits; a process that does not answer in time is
// killed (§12.3).
func (h *procHost) Lock(ctx context.Context, id string) (bool, error) {
	return h.LockReason(ctx, id, "")
}

// LockReason implements enclave.Host: Lock with a reason in vault.locking.
func (h *procHost) LockReason(ctx context.Context, id, reason string) (bool, error) {
	h.mu.Lock()
	p := h.procs[id]
	delete(h.procs, id)
	h.mu.Unlock()
	if p == nil {
		return false, nil
	}
	p.mu.Lock()
	p.stopping = true
	p.mu.Unlock()
	d := h.cfg.LockTimeout
	if reason == vault.LockDelete {
		// A deletion may wait 2 minutes for the host's mark and retry its
		// erase for 60 s more (VAULT-MESSAGING 0.51.0 §12.5).
		d = max(d, vaultipc.DeleteLockTimeout)
	}
	lctx, cancel := context.WithTimeout(ctx, d)
	r, err := p.conn.Call(lctx, vaultipc.KindLock, []byte(reason))
	cancel()
	if err != nil {
		h.kill(p)
		return true, err
	}
	h.stop(p)
	if len(r) > 0 && string(r[0]) == vaultipc.StatusSplitBrain {
		return true, vault.ErrSplitBrain
	}
	if len(r) > 0 && string(r[0]) == vaultipc.StatusNotDeleted && reason == vault.LockDelete {
		return true, errNotDeleted
	}
	return true, nil
}

// RecoveryRefusal implements enclave.Host: the running vault's process
// answers from its own state; nothing is locked (0.16.0).
func (h *procHost) RecoveryRefusal(ctx context.Context, id string) (bool, string) {
	h.mu.Lock()
	p := h.procs[id]
	h.mu.Unlock()
	if p == nil {
		return false, ""
	}
	rctx, cancel := context.WithTimeout(ctx, h.cfg.LockTimeout)
	defer cancel()
	r, err := p.conn.Call(rctx, vaultipc.KindRecoverable)
	if err != nil || len(r) != 2 || string(r[0]) != hostproto.StatusOK {
		return true, "" // unknown: the job decides from the header after the lock
	}
	switch why := string(r[1]); why {
	case "no_credential", "no_backup":
		return true, why
	}
	return true, ""
}

// Account implements enclave.Host: the snapshot goes to the vault's
// process (§11.13); without one it is dropped.
func (h *procHost) Account(ctx context.Context, id string, snapshot []byte) (bool, error) {
	h.mu.Lock()
	p := h.procs[id]
	h.mu.Unlock()
	if p == nil {
		return false, nil
	}
	actx, cancel := context.WithTimeout(ctx, h.cfg.LockTimeout)
	defer cancel()
	r, err := p.conn.Call(actx, vaultipc.KindAccount, snapshot)
	if err != nil {
		return true, err
	}
	return len(r) == 2 && string(r[1]) == "1", nil
}

// Vaults implements enclave.Host.
func (h *procHost) Vaults() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	ids := make([]string, 0, len(h.procs))
	for id := range h.procs {
		ids = append(ids, id)
	}
	return ids
}

// Close implements enclave.Host.
func (h *procHost) Close(ctx context.Context) {
	for _, id := range h.Vaults() {
		_, _ = h.Lock(ctx, id)
	}
}

// LockAllWithin locks every vault at once (the parent is unreachable,
// §12.3). Lock by lock it is Lock: the flush, vault.locking, the exit.
// After d a process that has not answered is killed, so every vault has
// locked or is gone by then; the call returns once the processes have
// ended (one that locked gets 5 s more to exit before it is killed too).
// It returns the vaults it ended, each with Lock's error (nil: locked;
// vault.ErrSplitBrain; any other: killed).
func (h *procHost) LockAllWithin(ctx context.Context, d time.Duration) map[string]error {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	var wg sync.WaitGroup
	var mu sync.Mutex
	ended := map[string]error{}
	for _, id := range h.Vaults() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ran, err := h.Lock(ctx, id); ran {
				mu.Lock()
				ended[id] = err
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return ended
}

// Kill kills a vault's process without a flush (tests, and a process that
// misbehaves).
func (h *procHost) Kill(id string) bool {
	h.mu.Lock()
	p := h.procs[id]
	delete(h.procs, id)
	h.mu.Unlock()
	if p == nil {
		return false
	}
	h.kill(p)
	return true
}

// Pid returns a vault process's pid (tests).
func (h *procHost) Pid(id string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if p := h.procs[id]; p != nil {
		return p.cmd.Process.Pid
	}
	return 0
}

// --- the channel, scoped to the process's vault (§12.4) ---

func deny() [][]byte { return hostproto.Strings(vaultipc.StatusDenied) }

// previousVaultKeys returns the objects of the vault named by the member's
// index that an enrollment of vaultID may read (§11.3): its state and its
// header sealed to release pcr0. None if the index names vaultID itself or
// no valid vault.
func previousVaultKeys(prev, vaultID, pcr0 string) []string {
	if prev == "" || prev == vaultID || strings.Contains(prev, "/") || !store.ValidKey("vaults/"+prev) {
		return nil
	}
	keys := []string{store.StateKey(prev), store.HeaderKey(prev, pcr0)}
	for _, k := range keys {
		if !store.ValidKey(k) {
			return nil
		}
	}
	return keys
}

// ownKey reports whether key is one of the process's own vault's objects.
func (p *vproc) ownKey(key string) bool {
	return store.ValidKey(key) && strings.HasPrefix(key, "vaults/"+p.vaultID+"/")
}

// indexKey reports whether key is the process's member's index object.
func (p *vproc) indexKey(key string) bool {
	return key == enclave.UserIndexKey(p.userGUID)
}

// mayRead scopes store reads: the own vault's objects, the own member's
// index, and the member's previous vault's state and header while an
// enrollment opens.
func (p *vproc) mayRead(key string) bool {
	if p.ownKey(key) || p.indexKey(key) {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.opening {
		return false
	}
	for _, k := range p.prevRead {
		if key == k {
			return true
		}
	}
	return false
}

// mayPut scopes store writes: the own vault's objects; the member's index
// only with the process's own vault id as its content, and only from an
// enrollment that is still opening (the one write of §11.3).
func (p *vproc) mayPut(key string, data []byte) bool {
	if p.ownKey(key) {
		return true
	}
	if !p.indexKey(key) || string(data) != p.vaultID {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.enroll && p.opening
}

// deleteIndex deletes the member's index object only if it names the
// process's own vault: the supervisor reads it itself, and deletes the
// version it read, which must be the one the process named.
func (p *vproc) deleteIndex(ctx context.Context, key string, ver store.Version) [][]byte {
	st := p.h.s.store()
	b, v, err := st.Get(ctx, key)
	if err != nil {
		return storeReply(err, nil)
	}
	if string(b) != p.vaultID {
		return deny()
	}
	if v != ver {
		return hostproto.Strings(hostproto.StatusConflict)
	}
	err = st.Delete(ctx, key, v)
	return storeReply(err, func() [][]byte { return hostproto.Strings(hostproto.StatusOK) })
}

func (p *vproc) handle(ctx context.Context, f *hostproto.Frame) [][]byte {
	s := p.h.s
	switch f.Kind {
	case vaultipc.KindStoreGet:
		if len(f.Fields) != 1 || !p.mayRead(string(f.Fields[0])) {
			return deny()
		}
		b, v, err := s.store().Get(ctx, string(f.Fields[0]))
		return storeReply(err, func() [][]byte { return [][]byte{[]byte(hostproto.StatusOK), b, []byte(v)} })
	case vaultipc.KindStorePut:
		if len(f.Fields) != 3 || !p.mayPut(string(f.Fields[0]), f.Fields[1]) {
			return deny()
		}
		v, err := s.store().Put(ctx, string(f.Fields[0]), f.Fields[1], store.Version(f.Fields[2]))
		return storeReply(err, func() [][]byte { return hostproto.Strings(hostproto.StatusOK, string(v)) })
	case vaultipc.KindStoreDelete:
		if len(f.Fields) != 2 {
			return deny()
		}
		if key := string(f.Fields[0]); p.indexKey(key) {
			return p.deleteIndex(ctx, key, store.Version(f.Fields[1]))
		}
		if !p.ownKey(string(f.Fields[0])) {
			return deny()
		}
		err := s.store().Delete(ctx, string(f.Fields[0]), store.Version(f.Fields[1]))
		return storeReply(err, func() [][]byte { return hostproto.Strings(hostproto.StatusOK) })
	case vaultipc.KindAttestRecipient:
		// Only an RSA key for KMS Recipient responses: never user_data,
		// which could forge an ETK descriptor's attestation.
		if len(f.Fields) != 1 || !rsaKey(f.Fields[0]) {
			return deny()
		}
		doc, err := s.cfg.NSM.Attest(nil, nil, f.Fields[0])
		if err != nil {
			return hostproto.Strings(hostproto.StatusError)
		}
		return [][]byte{[]byte(hostproto.StatusOK), doc}
	case vaultipc.KindAttestVault:
		// vault.enrolled (§11.3): only while enrolling, and the
		// supervisor computes user_data itself.
		p.mu.Lock()
		allowed := p.opening && p.enroll
		p.mu.Unlock()
		if len(f.Fields) != 2 || !allowed || len(f.Fields[0]) == 0 || len(f.Fields[0]) > 16<<10 || len(f.Fields[1]) > 512 {
			return deny()
		}
		ud := altchan.VaultUserData(f.Fields[0])
		doc, err := s.cfg.NSM.Attest(ud[:], f.Fields[1], nil)
		if err != nil {
			return hostproto.Strings(hostproto.StatusError)
		}
		return [][]byte{[]byte(hostproto.StatusOK), doc}
	case vaultipc.KindKMS:
		return p.kms(ctx, f.Fields)
	case vaultipc.KindHTTP:
		return p.http(ctx, f.Fields)
	case vaultipc.KindPush:
		return p.push(ctx, f.Fields)
	case vaultipc.KindTransfer:
		return p.transfer(ctx, f.Fields)
	case vaultipc.KindCounter:
		return p.counterCall(ctx, f.Fields)
	case vaultipc.KindHeavyPermit:
		return p.heavyCall(f.Fields)
	case vaultipc.KindMarkDeleting:
		return p.markDeleting(ctx, f.Fields)
	case vaultipc.KindStatusList:
		b, at, ok := s.status.rawList()
		if !ok {
			return hostproto.Strings(hostproto.StatusNotFound)
		}
		return [][]byte{[]byte(hostproto.StatusOK), b, []byte(at.UTC().Format(time.RFC3339Nano))}
	}
	// Every other kind (including Open and Lock, which only the
	// supervisor sends) is refused.
	return deny()
}

// markDeleting passes a vault process's MarkDeleting to the parent
// (VAULT-MESSAGING 0.51.0 §12.5, VAULT-HOST-PROTOCOL §5.6): only for the
// process's own vault, one request (60 s at most) per call; the process
// retries anything but ok.
func (p *vproc) markDeleting(ctx context.Context, f [][]byte) [][]byte {
	if len(f) != 1 || string(f[0]) != p.vaultID {
		return deny()
	}
	r, err := p.h.s.link.call(ctx, hostproto.KindMarkDeleting, []byte(p.vaultID))
	if err != nil || len(r) != 1 || string(r[0]) != hostproto.StatusOK {
		return hostproto.Strings(hostproto.StatusError)
	}
	return hostproto.Strings(hostproto.StatusOK)
}

func storeReply(err error, ok func() [][]byte) [][]byte {
	switch {
	case err == nil:
		return ok()
	case errors.Is(err, store.ErrNotFound):
		return hostproto.Strings(hostproto.StatusNotFound)
	case errors.Is(err, store.ErrConflict):
		return hostproto.Strings(hostproto.StatusConflict)
	}
	return hostproto.Strings(hostproto.StatusError)
}

func rsaKey(der []byte) bool {
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return false
	}
	r, ok := k.(*rsa.PublicKey)
	return ok && r.N.BitLen() >= 2048 && r.N.BitLen() <= 4096
}

func (p *vproc) kms(ctx context.Context, f [][]byte) [][]byte {
	s := p.h.s
	if len(f) != 4 || !enclave.InNamespace(s.encCfg, string(f[1])) {
		return deny()
	}
	k := s.kms
	arn := string(f[1])
	out := func(a, b []byte, err error) [][]byte {
		if err != nil {
			return hostproto.Strings(hostproto.StatusError)
		}
		return [][]byte{[]byte(hostproto.StatusOK), a, b}
	}
	switch string(f[0]) {
	case vaultipc.KMSGenerateDataKey:
		blob, cfr, err := k.GenerateDataKey(ctx, arn, f[2])
		return out(blob, cfr, err)
	case vaultipc.KMSDecrypt:
		cfr, err := k.Decrypt(ctx, arn, f[2], f[3])
		return out(cfr, nil, err)
	case vaultipc.KMSDescribeKey:
		b, err := k.DescribeKey(ctx, arn)
		return out(b, nil, err)
	case vaultipc.KMSGetKeyPolicy:
		b, err := k.GetKeyPolicy(ctx, arn)
		return out(b, nil, err)
	case vaultipc.KMSListGrants:
		b, err := k.ListGrants(ctx, arn)
		return out(b, nil, err)
	}
	return deny()
}

// http carries a relay request: https to an allowlisted relay host only;
// a signed request must verify under the one relay key this vault process
// has used (§12.4).
func (p *vproc) http(ctx context.Context, f [][]byte) [][]byte {
	s := p.h.s
	if len(f) != 4 || len(f[3]) > vaultipc.MaxBody {
		return deny()
	}
	method := string(f[0])
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete:
	default:
		return deny()
	}
	u, err := url.Parse(string(f[1]))
	if err != nil || u.Scheme != "https" || u.User != nil || !s.relayHost(u.Hostname()) || u.Port() != "" && u.Port() != "443" {
		return deny()
	}
	hdr, err := vaultipc.DecodeHeaders(f[2])
	if err != nil {
		return deny()
	}
	if strings.Contains(u.EscapedPath(), "%") || u.Path == "" || path.Clean(u.Path) != u.Path {
		// Only plain, clean paths: an escaped or uncleaned form of a path
		// (/v1/%62lob/, /v1//blob/, /v1/./blob/) would pass the checks
		// below and reach, or redirect to, another route.
		return deny()
	}
	endBody, ok := p.blobBody(method, u.Path, len(f[3]))
	if !ok {
		return deny()
	}
	defer endBody()
	if hdr.Get(relayauth.HeaderKey) != "" {
		sr, err := relayauth.ParseHeaders(hdr)
		if err != nil || sr.Verify(method, u.EscapedPath(), relayauth.BodyHash(f[3]), time.Now()) != nil {
			return deny()
		}
		p.mu.Lock()
		if p.relayKey == nil {
			p.relayKey = sr.Key
		}
		same := p.relayKey.Equal(sr.Key)
		p.mu.Unlock()
		if !same {
			return deny()
		}
	}
	rctx, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	var body io.Reader
	if f[3] != nil && method != http.MethodGet {
		body = bytes.NewReader(f[3])
	}
	req, err := http.NewRequestWithContext(rctx, method, u.String(), body)
	if err != nil {
		return deny()
	}
	req.Header = hdr
	release, ok := p.egressSlot(rctx)
	if !ok {
		return hostproto.Strings(hostproto.StatusError)
	}
	defer release()
	resp, err := s.relayHTTP.Do(req)
	if err != nil {
		s.relayFailed(ctx)
		return hostproto.Strings(hostproto.StatusError)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, vaultipc.MaxBody+1))
	if err != nil || len(b) > vaultipc.MaxBody {
		if err != nil {
			s.relayFailed(ctx)
		}
		return hostproto.Strings(hostproto.StatusError)
	}
	rh := http.Header{}
	for _, k := range []string{"Content-Type", "Retry-After"} {
		if v := resp.Header.Values(k); len(v) > 0 {
			rh[k] = v
		}
	}
	return [][]byte{[]byte(hostproto.StatusOK), []byte(strconv.Itoa(resp.StatusCode)), vaultipc.EncodeHeaders(rh), b}
}

// maxVaultEgress is how many relay and push requests one vault process
// may have in flight. The shared connections have a bounded number of
// streams (egress.DefaultMaxConns), and a vault process may send 128
// requests at a time over its channel, each for up to 75 s: without a
// limit of its own, a few faulty or compromised processes could hold
// every stream and make the other vaults wait. A vault needs few: its
// long-poll, and what its one run loop does besides, one request at a
// time (acks, deposits, claims, a registration), and a push wake. Eight
// leaves room for more than that.
const maxVaultEgress = 8

// egressSlot takes one of the vault's places for a request in flight. At
// the limit the request waits, as long as its own time allows (a burst is
// then late, not lost; a process that floods delays only itself), and is
// answered StatusError if that ends first. The first time a process is at
// its limit is counted (Supervisor.vaultLimit), once per process.
func (p *vproc) egressSlot(ctx context.Context) (release func(), ok bool) {
	p.mu.Lock()
	if p.egress == nil {
		p.egress = make(chan struct{}, maxVaultEgress)
	}
	ch := p.egress
	full := len(ch) == cap(ch) && !p.egressAt
	if full {
		p.egressAt = true
	}
	p.mu.Unlock()
	if full {
		// Counted for the instance, not logged: the supervisor's log goes
		// to the parent, which learns nothing per vault about relay
		// requests (VAULT-MESSAGING §2.2, §12.2.1).
		p.h.s.vaultLimit.Add(1)
	}
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, true
	case <-ctx.Done():
		return nil, false
	}
}

// relayFailed counts a relay request that got no answer (a connection
// lost, no stream in time, a timeout), unless its vault process gave it
// up.
func (s *Supervisor) relayFailed(ctx context.Context) {
	if ctx.Err() == nil {
		s.relayErrs.Add(1)
	}
}

// maxPushBody bounds a push gateway request (a registration: a 4 KiB
// token and the rest; a wake: a 6 KiB blob).
const maxPushBody = 16 << 10

// push carries a request to the channel's push gateway (0.24.0, §14.3):
// POST to /v1/register, /v1/confirm or /v1/wake of the pinned gateway URL
// only, signed (Relay Protocol §4.1) by a key that is not this process's
// relay key (PUSH-GATEWAY §3). For a registration the supervisor attaches the NSM
// attestation itself, with public_key = the signing key and user_data =
// the request's digest, which it computes: a vault process never obtains
// an attestation over user_data of its choosing (PUSH-GATEWAY §5.1). A
// confirmation (PUSH-GATEWAY 0.5.0 §5.1) and a wake carry none.
func (p *vproc) push(ctx context.Context, f [][]byte) [][]byte {
	s := p.h.s
	base := s.encCfg.PushURL
	if base == "" || len(f) != 3 || len(f[2]) > maxPushBody {
		return deny()
	}
	path := string(f[0])
	switch path {
	case pushwire.PathRegister, pushwire.PathConfirm, pushwire.PathWake:
	default:
		return deny()
	}
	in, err := vaultipc.DecodeHeaders(f[1])
	if err != nil {
		return deny()
	}
	sr, err := relayauth.ParseHeaders(in)
	bh := relayauth.BodyHash(f[2])
	if err != nil || sr.Verify(http.MethodPost, path, bh, time.Now()) != nil {
		return deny()
	}
	p.mu.Lock()
	relayKey := p.relayKey != nil && p.relayKey.Equal(sr.Key)
	p.mu.Unlock()
	if relayKey {
		return deny()
	}
	hdr := http.Header{}
	for _, k := range []string{relayauth.HeaderKey, relayauth.HeaderTimestamp, relayauth.HeaderSig} {
		hdr.Set(k, in.Get(k))
	}
	hdr.Set("Content-Type", "application/json")
	if path == pushwire.PathRegister {
		d := relayauth.Digest(http.MethodPost, path, sr.Timestamp, bh)
		doc, err := s.cfg.NSM.Attest(d[:], nil, sr.Key)
		if err != nil {
			return hostproto.Strings(hostproto.StatusError)
		}
		hdr.Set(pushwire.HeaderAttestation, base64.StdEncoding.EncodeToString(doc))
	}
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, strings.TrimSuffix(base, "/")+path, bytes.NewReader(f[2]))
	if err != nil {
		return deny()
	}
	req.Header = hdr
	release, ok := p.egressSlot(rctx)
	if !ok {
		return hostproto.Strings(hostproto.StatusError)
	}
	defer release()
	resp, err := s.relayHTTP.Do(req)
	if err != nil {
		return hostproto.Strings(hostproto.StatusError)
	}
	defer resp.Body.Close()
	// An answer longer than pushwire.MaxAnswer is passed on cut to
	// MaxAnswer+1 bytes, so the vault process sees that the gateway
	// answered (it counts toward push_registrations, VAULT-MESSAGING
	// 0.24.1 §14.1) and refuses the answer as oversized.
	b, err := io.ReadAll(io.LimitReader(resp.Body, pushwire.MaxAnswer+1))
	if err != nil {
		return hostproto.Strings(hostproto.StatusError)
	}
	rh := http.Header{}
	for _, k := range []string{"Content-Type", "Retry-After"} {
		if v := resp.Header.Values(k); len(v) > 0 {
			rh[k] = v
		}
	}
	return [][]byte{[]byte(hostproto.StatusOK), []byte(strconv.Itoa(resp.StatusCode)), vaultipc.EncodeHeaders(rh), b}
}

// notify takes a vault process's lifecycle events (its own vault only)
// and logs.
func (p *vproc) notify(f *hostproto.Frame) {
	s := p.h.s
	switch f.Kind {
	case vaultipc.KindLifecycle:
		if len(f.Fields) != enclave.LifecycleFieldCount || string(f.Fields[1]) != p.vaultID || len(f.Fields[5]) > 256 {
			return
		}
		backup, ok := enclave.ParseBackupField(string(f.Fields[7]))
		if !ok {
			return
		}
		name, ok := enclave.ParseNameFields(f.Fields[8], f.Fields[9], f.Fields[10])
		if !ok || (name != nil) != (string(f.Fields[0]) == vault.EventAccountName) {
			return
		}
		sv, err := strconv.Atoi(string(f.Fields[4]))
		if err != nil {
			return
		}
		seq, err := strconv.ParseUint(string(f.Fields[6]), 10, 53)
		if err != nil {
			return
		}
		next, hseq, cleared, ok := enclave.ParseNextFields(f.Fields[11], f.Fields[12], f.Fields[13])
		if !ok {
			return
		}
		cancelled, ok := enclave.ParseCancelledField(string(f.Fields[0]), f.Fields[14])
		if !ok {
			return
		}
		s.lifecycle(vault.LifecycleEvent{Event: string(f.Fields[0]), VaultID: p.vaultID, Release: string(f.Fields[2]),
			VaultVersion: string(f.Fields[3]), StateVersion: sv, AppKey: append([]byte(nil), f.Fields[5]...), AppKeySeq: seq,
			CredentialBackup: backup, Name: name, Next: next, HeaderSeq: hseq, NextCleared: cleared, CancelledRecoveryID: cancelled})
	case vaultipc.KindTransferDone:
		if len(f.Fields) == 1 && validTicket(f.Fields[0]) && s.xfers != nil {
			s.xfers.release(p, string(f.Fields[0]))
		}
	case vaultipc.KindLog:
		if len(f.Fields) < 2 {
			return
		}
		kv := []any{"vault_id", p.vaultID}
		for i := 2; i+1 < len(f.Fields) && i < 2+16; i += 2 {
			kv = append(kv, string(f.Fields[i]), truncate(string(f.Fields[i+1]), 120))
		}
		s.log.Info("vault: "+truncate(string(f.Fields[1]), 120), kv...)
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// transfer admits one blob transfer of this process (§10.5.1): at most
// its vault's 2 at once, and the instance's admission by memory.
func (p *vproc) transfer(ctx context.Context, f [][]byte) [][]byte {
	s := p.h.s
	if len(f) != 3 || !validTicket(f[0]) || s.xfers == nil {
		return deny()
	}
	prio, err1 := strconv.Atoi(string(f[1]))
	ms, err2 := strconv.Atoi(string(f[2]))
	if err1 != nil || err2 != nil || prio < 0 || prio > 2 || ms < 0 {
		return deny()
	}
	wait := min(time.Duration(ms)*time.Millisecond, maxTransferWait)
	wctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	if _, err := s.xfers.admit(wctx, p, string(f[0]), prio); err != nil {
		return hostproto.Strings(vaultipc.StatusBusy)
	}
	return hostproto.Strings(hostproto.StatusOK)
}

func validTicket(b []byte) bool {
	if len(b) == 0 || len(b) > 32 {
		return false
	}
	for _, c := range b {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z') {
			return false
		}
	}
	return true
}

// blobBodyThreshold is the largest blob upload a vault process may make
// without an admitted transfer.
const blobBodyThreshold = 1 << 20

// blobBody: the relay proxy carries a blob's body (a download, or an
// upload over 1 MiB) only within the transfers a process has been admitted
// (§10.5.1), one body per admitted transfer at a time, so that admission
// by memory cannot be bypassed. It returns the function that ends the
// body's request.
func (p *vproc) blobBody(method, urlPath string, n int) (func(), bool) {
	none := func() {}
	if !blobRoute(urlPath) {
		return none, true
	}
	if !(method == http.MethodGet || method == http.MethodPut && n > blobBodyThreshold) {
		return none, true
	}
	x := p.h.s.xfers
	if x == nil {
		return none, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.blobBodies >= x.held(p) {
		return none, false
	}
	p.blobBodies++
	return func() {
		p.mu.Lock()
		p.blobBodies--
		p.mu.Unlock()
	}, true
}

// blobRoute reports whether a (decoded, clean) path names the relay's blob
// routes: a "v1" segment followed by "blob" or "blobs" anywhere in it, so
// that a relay URL with a path prefix (https://host/x/v1/blob/...) is
// gated as well.
func blobRoute(urlPath string) bool {
	segs := strings.Split(urlPath, "/")
	for i := 0; i+1 < len(segs); i++ {
		if segs[i] == "v1" && (segs[i+1] == "blob" || segs[i+1] == "blobs") {
			return true
		}
	}
	return false
}
