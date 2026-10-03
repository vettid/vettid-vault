package supervisor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
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
)

// ProcConfig configures the vault processes (VAULT-MESSAGING §12.4).
type ProcConfig struct {
	// Exec is the vault process's argv (the enclave binary re-executed
	// with vaultproc.Arg first).
	Exec []string
	// UIDBase, if not 0, runs vault process i as uid = gid = UIDBase+i
	// (needs root, as PID 1 in the enclave is). 0 keeps the supervisor's
	// ids (development and tests).
	UIDBase int
	// MaxProcs bounds concurrent vault processes (default 1024).
	MaxProcs int
	// AddressSpace is RLIMIT_AS of a vault process (default 4 GiB).
	AddressSpace uint64
	// OpenFiles is RLIMIT_NOFILE (default 64).
	OpenFiles uint64
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
}

// vproc is one vault process and what its channel may reach.
type vproc struct {
	h        *procHost
	vaultID  string
	userGUID string
	enroll   bool
	prevRead string // read-only prefix of the member's previous vault (re-enrollment, §11.3)
	slot     int
	cmd      *exec.Cmd
	conn     *hostproto.Conn
	exited   chan struct{}
	exitCode int

	mu       sync.Mutex
	opening  bool
	relayKey ed25519.PublicKey
	stopping bool // locked or killed by the supervisor
}

var _ enclave.Host = (*procHost)(nil)

func newProcHost(s *Supervisor, cfg ProcConfig) *procHost {
	cfg.defaults()
	return &procHost{s: s, cfg: cfg, procs: map[string]*vproc{}, slots: make([]bool, cfg.MaxProcs)}
}

var (
	errNoSlot = errors.New("supervisor: too many vault processes")
	errSpawn  = errors.New("supervisor: vault process failed to start")
)

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
	slot := h.takeSlot()
	if slot < 0 {
		return nil, errNoSlot
	}
	fds, err := socketpair()
	if err != nil {
		h.freeSlot(slot)
		return nil, errSpawn
	}
	parentEnd := os.NewFile(uintptr(fds[0]), "vault-channel")
	childEnd := os.NewFile(uintptr(fds[1]), "vault-channel-child")
	cmd := exec.Command(h.cfg.Exec[0], append(append([]string(nil), h.cfg.Exec[1:]...), extra...)...)
	cmd.Env = []string{"GOMEMLIMIT=" + strconv.FormatUint(h.cfg.MemoryLimit, 10), "GOMAXPROCS=2", "GOTRACEBACK=none"}
	cmd.Dir = "/"
	cmd.ExtraFiles = []*os.File{childEnd} // fd 3; everything else is close-on-exec
	cmd.SysProcAttr = procAttr(h.cfg.UIDBase, slot)
	if err := cmd.Start(); err != nil {
		childEnd.Close()
		parentEnd.Close()
		h.freeSlot(slot)
		return nil, errSpawn
	}
	childEnd.Close()
	setLimits(cmd.Process.Pid, h.cfg)
	c, err := net.FileConn(parentEnd)
	parentEnd.Close()
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		h.freeSlot(slot)
		return nil, errSpawn
	}
	p := &vproc{h: h, vaultID: vaultID, userGUID: userGUID, enroll: enroll, slot: slot, cmd: cmd, exited: make(chan struct{})}
	p.conn = hostproto.NewConn(c, p.handle, p.notify)
	go func() {
		err := cmd.Wait()
		p.exitCode = exitCode(err)
		p.conn.Close()
		h.freeSlot(slot)
		close(p.exited)
		h.exited(p)
	}()
	return p, nil
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

// exited handles a process that ended: a vault that stopped on its own
// (split brain, internal lock, error) is reported to the parent.
func (h *procHost) exited(p *vproc) {
	h.mu.Lock()
	if h.procs[p.vaultID] == p {
		delete(h.procs, p.vaultID)
	}
	h.mu.Unlock()
	p.mu.Lock()
	stopping := p.stopping
	p.mu.Unlock()
	h.s.forget(p.vaultID)
	if stopping {
		return
	}
	reason := "error"
	switch p.exitCode {
	case 0:
		reason = "locked"
	case 3: // vaultproc.ExitSplitBrain
		reason = "split_brain"
	}
	h.s.log.Warn("vault process ended", "vault_id", p.vaultID, "reason", reason, "code", p.exitCode)
	h.s.link.notify(hostproto.KindStopped, hostproto.Strings(p.vaultID, reason)...)
}

// Open implements enclave.Host: lock a running process of the vault, start
// a new one, hand it the job, and keep it if the vault opened.
func (h *procHost) Open(ctx context.Context, j *enclave.Job) ([]byte, error) {
	_, _ = h.Lock(ctx, j.VaultID)
	prev := ""
	if j.Op == enclave.OpEnroll {
		// Re-enrollment may read the member's previous vault (§11.3).
		if b, _, err := h.s.store().Get(ctx, enclave.UserIndexKey(j.UserGUID)); err == nil {
			if id := string(b); id != j.VaultID && store.ValidKey("vaults/"+id) && !strings.Contains(id, "/") {
				prev = "vaults/" + id + "/"
			}
		}
	}
	p, err := h.spawn(j.VaultID, j.UserGUID, j.Op == enclave.OpEnroll)
	if err != nil {
		return nil, err
	}
	p.prevRead = prev
	p.mu.Lock()
	p.opening = true
	p.mu.Unlock()
	m := h.s.inst.Load().Measurements()
	fields := append(hostproto.Strings(vaultipc.Version, h.s.instID, m.PCR0, m.PCR1, m.PCR2), j.Fields()...)
	octx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	r, err := p.conn.Call(octx, vaultipc.KindOpen, fields...)
	cancel()
	p.mu.Lock()
	p.opening = false
	p.mu.Unlock()
	if err != nil || len(r) != 3 || string(r[0]) != hostproto.StatusOK {
		h.kill(p)
		return nil, errSpawn
	}
	res := append([]byte(nil), r[1]...)
	if string(r[2]) != "1" {
		h.stop(p)
		return res, nil
	}
	h.mu.Lock()
	h.procs[j.VaultID] = p
	h.mu.Unlock()
	h.s.touch(j.VaultID)
	return res, nil
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
	lctx, cancel := context.WithTimeout(ctx, h.cfg.LockTimeout)
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
	return true, nil
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

// mayRead and mayWrite scope the object store.
func (p *vproc) mayWrite(key string) bool {
	return store.ValidKey(key) && (strings.HasPrefix(key, "vaults/"+p.vaultID+"/") || key == enclave.UserIndexKey(p.userGUID))
}

func (p *vproc) mayRead(key string) bool {
	return p.mayWrite(key) || p.prevRead != "" && store.ValidKey(key) && strings.HasPrefix(key, p.prevRead)
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
		if len(f.Fields) != 3 || !p.mayWrite(string(f.Fields[0])) {
			return deny()
		}
		v, err := s.store().Put(ctx, string(f.Fields[0]), f.Fields[1], store.Version(f.Fields[2]))
		return storeReply(err, func() [][]byte { return hostproto.Strings(hostproto.StatusOK, string(v)) })
	case vaultipc.KindStoreDelete:
		if len(f.Fields) != 2 || !p.mayWrite(string(f.Fields[0])) {
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
	resp, err := s.relayHTTP.Do(req)
	if err != nil {
		return hostproto.Strings(hostproto.StatusError)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, vaultipc.MaxBody+1))
	if err != nil || len(b) > vaultipc.MaxBody {
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
		if len(f.Fields) != 5 || string(f.Fields[1]) != p.vaultID {
			return
		}
		sv, err := strconv.Atoi(string(f.Fields[4]))
		if err != nil {
			return
		}
		s.lifecycle(vault.LifecycleEvent{Event: string(f.Fields[0]), VaultID: p.vaultID, Release: string(f.Fields[2]),
			VaultVersion: string(f.Fields[3]), StateVersion: sv})
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
