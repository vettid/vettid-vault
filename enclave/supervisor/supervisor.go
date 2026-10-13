// Package supervisor is PID 1's work inside the enclave (VAULT-PLAN V3,
// decision D4): it owns the NSM, the ETKs and the alternate channel
// (package enclave), the egress transport and the KMS client, and runs one
// vault manager per unlocked vault.
//
// It talks to the parent over one control connection (package hostproto):
// queue messages in, responses, lifecycle events, descriptors and logs
// out, and storage and credential requests answered by the parent. The
// parent is untrusted (§13.3): it can drop, delay or replay what it
// forwards, and nothing it returns is taken on trust (stored objects are
// authenticated by the vault, KMS answers by TLS).
//
// Vault managers run as goroutines, isolated by recovery and accounting
// rather than by processes (docs/V3-NOTES.md, "Process model").
package supervisor

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/enclave/awskms"
	"github.com/vettid/vettid-vault/enclave/egress"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/devattest"
)

// Config configures the supervisor.
type Config struct {
	// Enclave returns the instance configuration once the parent has named
	// the instance.
	Enclave func(instanceID string) enclave.Config
	NSM     enclave.NSM
	// Control dials the parent's control port.
	Control func(ctx context.Context) (net.Conn, error)
	// Egress is the allowlisted HTTPS transport (relay, KMS, status list).
	Egress *egress.Transport
	// KMSEndpoint overrides https://kms.<region>.amazonaws.com (never in
	// release builds, whose egress allowlist has only the real host).
	KMSEndpoint string
	// StatusListURL overrides StatusListURL.
	StatusListURL string
	// Proc configures the vault processes (one per unlocked vault, D4).
	Proc ProcConfig
	// RelayHosts are the relay hosts vault processes may reach (through
	// the shared egress); default: the host of the instance's relay URL.
	RelayHosts []string
	// Harden makes the supervisor non-dumpable and tightens ptrace
	// (release and development binaries; not tests).
	Harden bool
	// MaxVaults caps the vaults running at once (least recently active
	// is locked first, §12.3); 0 = no cap.
	MaxVaults int
	// MemoryReserve: while the enclave's available memory is below it,
	// the least recently active vault is locked (§12.3 memory pressure);
	// 0 = no limit.
	MemoryReserve uint64
	// DownLock is how long the parent may be unreachable before every
	// vault is locked (its leases are no longer renewed): the time
	// without a Ping from it, connected or not. Default 120 s; the parent
	// pings every 20 s.
	DownLock time.Duration
	LogLevel slog.Level
	Now      func() time.Time
	// NitroRoots verify the self-test's own attestation document (release:
	// the pinned AWS Nitro root).
	NitroRoots *x509.CertPool
	// SelftestEgress builds the self-test's egress for a KMS region: the
	// release hosts and roots plus kms.<region>.amazonaws.com
	// (docs/SMOKE.md). Nil: no self-test.
	SelftestEgress func(region string) (*egress.Transport, error)
	// OnReady, if set, is called with the instance once it runs (tests).
	OnReady func(*enclave.Instance)
}

// Supervisor runs one enclave instance.
type Supervisor struct {
	cfg    Config
	link   *link
	log    *slog.Logger
	inst   atomic.Pointer[enclave.Instance]
	status *statusFetcher
	instID string
	bootID string
	now    func() time.Time

	actMu    sync.Mutex
	activity map[string]time.Time

	descMu   sync.Mutex
	lastDesc []byte

	selftestMode  bool          // set once, before selftestReady closes
	selftestReady chan struct{} // closed when the hello asked for a self-test
	selftestOnce  sync.Once
	selftestDone  chan struct{}
	hardenNotes   []string

	// Set by start: what the supervisor brokers for vault processes.
	host      *procHost
	st        *hostStore
	kms       *awskms.Client
	encCfg    enclave.Config
	relayHTTP *http.Client
	relays    map[string]bool
	relayErrs atomic.Uint64 // relay requests that got no answer
	// vaultLimit counts the vault processes that reached their limit of
	// relay requests in flight, each once. A count for the instance
	// only: which vault it was is told to nobody outside the enclave.
	vaultLimit atomic.Uint64

	// droppedTold is the count of dropped log records last logged, and
	// warnedAt the start of the parent's silence last warned about
	// (maintain only).
	droppedTold uint64
	warnedAt    time.Time
	noDeadline  sync.Once

	statsMu    sync.Mutex
	statsAt    time.Time
	statsReply [][]byte
}

// Errors.
var (
	ErrInstanceChanged = errors.New("supervisor: parent named another instance id")
	ErrHello           = errors.New("supervisor: parent hello failed")
)

// New prepares a supervisor.
func New(cfg Config) (*Supervisor, error) {
	if cfg.Enclave == nil || cfg.NSM == nil || cfg.Control == nil || cfg.Egress == nil || len(cfg.Proc.Exec) == 0 {
		return nil, enclave.ErrConfig
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.DownLock == 0 {
		cfg.DownLock = 120 * time.Second
	}
	if cfg.StatusListURL == "" {
		cfg.StatusListURL = StatusListURL
	}
	l := &link{}
	l.hear(cfg.Now())
	boot := make([]byte, 16)
	if _, err := rand.Read(boot); err != nil {
		return nil, err
	}
	s := &Supervisor{cfg: cfg, link: l, now: cfg.Now, activity: map[string]time.Time{}, bootID: hex.EncodeToString(boot), selftestDone: make(chan struct{}), selftestReady: make(chan struct{})}
	s.log = slog.New(&logHandler{l: l, level: cfg.LogLevel})
	s.status = &statusFetcher{url: cfg.StatusListURL, http: cfg.Egress.Client(2 * time.Minute), now: cfg.Now}
	return s, nil
}

// Logger returns the sanitized logger (records go to the parent).
func (s *Supervisor) Logger() *slog.Logger { return s.log }

// Run connects to the parent, starts the instance and serves until ctx
// ends. On return every vault is locked.
func (s *Supervisor) Run(ctx context.Context) error {
	if s.cfg.Harden {
		s.hardenNotes = hardenSelf()
		for _, n := range s.hardenNotes {
			s.log.Warn("hardening: " + n)
		}
	}
	m, err := s.cfg.NSM.Measurements()
	if err != nil {
		return err
	}
	conn, err := s.connect(ctx, m.PCR0)
	if err != nil {
		return err
	}
	if s.selftestMode {
		// The hardware smoke test (docs/SMOKE.md): no instance, no vault;
		// answer the parent's self-test request and stop.
		select {
		case <-s.selftestDone:
			select { // let the report reach the parent
			case <-conn.Done():
			case <-time.After(10 * time.Second):
			}
		case <-conn.Done():
		case <-ctx.Done():
		}
		conn.Close()
		return nil
	}
	if err := s.start(); err != nil {
		conn.Close()
		return err
	}
	defer func() {
		lctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		s.inst.Load().Close(lctx)
		if c := s.link.get(); c != nil {
			c.Close()
		}
	}()
	s.pushDescriptor(true)
	if s.cfg.OnReady != nil {
		s.cfg.OnReady(s.inst.Load())
	}
	go s.status.run(ctx, time.Hour, 5*time.Minute, func(msg string, kv ...any) { s.log.Warn(msg, kv...) })
	go s.maintain(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-conn.Done():
		}
		s.link.set(nil)
		s.log.Warn("parent connection lost")
		if conn, err = s.connect(ctx, m.PCR0); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.pushDescriptor(true)
	}
}

// connect dials the parent (with backoff) and exchanges hello.
func (s *Supervisor) connect(ctx context.Context, release string) (*hostproto.Conn, error) {
	backoff := 200 * time.Millisecond
	for {
		if conn, err := s.dial(ctx, release); err == nil {
			return conn, nil
		} else if errors.Is(err, ErrInstanceChanged) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 5*time.Second)
	}
}

func (s *Supervisor) dial(ctx context.Context, release string) (*hostproto.Conn, error) {
	nc, err := s.cfg.Control(ctx)
	if err != nil {
		return nil, err
	}
	conn := hostproto.NewConnOptions(nc, s.handle, nil, s.connOptions())
	hctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, err := conn.Call(hctx, hostproto.KindHello, []byte(release), []byte(s.bootID))
	if err != nil || status(r) != hostproto.StatusOK || len(r) != 3 || !altchan.ValidInstanceID(string(r[1])) {
		conn.Close()
		return nil, ErrHello
	}
	if string(r[2]) == "selftest" && s.inst.Load() == nil && s.instID == "" {
		s.selftestMode = true
		close(s.selftestReady)
	}
	if string(r[2]) == "fresh" && s.inst.Load() != nil && len(s.inst.Load().Vaults()) > 0 {
		// A restarted parent holds no leases for the vaults running here.
		s.log.Warn("parent restarted: locking every vault")
		s.inst.Load().LockAll(ctx)
	}
	id := string(r[1])
	if s.instID != "" && id != s.instID {
		conn.Close()
		return nil, ErrInstanceChanged
	}
	s.instID = id
	s.link.set(conn)
	return conn, nil
}

// connOptions are the control connection's: a parent that stops reading
// loses it, and the time the reader waits at the request limit is told to
// the link.
func (s *Supervisor) connOptions() hostproto.Options {
	return hostproto.Options{WriteTimeout: writeTimeout, OnWait: func(on bool) { s.link.waiting(s.now(), on) },
		OnNoDeadline: func(err error) {
			s.noDeadline.Do(func() { s.log.Error("control connection takes no write timeout", "error", errText(err)) })
		}}
}

// start creates the enclave instance.
func (s *Supervisor) start() error {
	cfg := s.cfg.Enclave(s.instID)
	creds := &awskms.CachedCredentials{Source: s.link.credentials, Skew: 5 * time.Minute, Now: s.now}
	kms := awskms.NewClient(s.cfg.Egress.Client(60*time.Second), cfg.SealRegion, creds)
	if s.cfg.KMSEndpoint != "" {
		kms.Endpoint = s.cfg.KMSEndpoint
	}
	kms.Now = s.now
	s.st = &hostStore{l: s.link, onWrite: s.touchKey}
	s.kms, s.encCfg = kms, cfg
	s.relayHTTP = s.cfg.Egress.Client(80 * time.Second)
	s.relays = map[string]bool{}
	hosts := s.cfg.RelayHosts
	if len(hosts) == 0 {
		if u, err := url.Parse(cfg.RelayURL); err == nil {
			hosts = []string{u.Hostname()}
		}
	}
	for _, h := range hosts {
		s.relays[h] = true
	}
	s.host = newProcHost(s, s.cfg.Proc)
	// The instance keeps the ETKs and the outer decryption; vaults run in
	// their own processes and their secrets never enter this one (§12.4).
	in, err := enclave.New(enclave.Options{Config: cfg, NSM: s.cfg.NSM, Store: s.st, Host: s.host, Lifecycle: s.lifecycle, Now: s.now})
	if err != nil {
		return err
	}
	s.inst.Store(in)
	return nil
}

// handle answers the parent's requests.
func (s *Supervisor) handle(ctx context.Context, f *hostproto.Frame) [][]byte {
	if f.Kind == hostproto.KindPing {
		// Counted when it is read, whatever the answer will be.
		s.link.ping(s.now(), func(id string) bool { return s.host != nil && s.host.Pid(id) != 0 })
	}
	if f.Kind == hostproto.KindSelftest {
		return s.handleSelftest(ctx, f)
	}
	if s.inst.Load() == nil {
		return hostproto.Strings(hostproto.StatusError) // not started yet
	}
	switch f.Kind {
	case hostproto.KindQueue:
		// [queue message, manifest document] (0.10.0: the parent supplies
		// the served manifest an enroll or unlock names by hash; empty if
		// it has none).
		if len(f.Fields) != 2 {
			return nil
		}
		resp := s.process(ctx, f.Fields[0], f.Fields[1])
		return [][]byte{[]byte(hostproto.StatusOK), resp}
	case hostproto.KindLeaseLost:
		if len(f.Fields) != 1 {
			return nil
		}
		id := string(f.Fields[0])
		s.lockVault(ctx, id, "lease_lost")
		return hostproto.Strings(hostproto.StatusOK)
	case hostproto.KindPing:
		return hostproto.Strings(hostproto.StatusOK, strconv.Itoa(len(s.inst.Load().Vaults())))
	case hostproto.KindStats:
		return s.stats()
	case hostproto.KindShutdown:
		ids := s.inst.Load().Vaults()
		s.log.Info("shutdown requested: locking every vault", "vaults", len(ids))
		for _, id := range ids {
			s.lockVault(ctx, id, "shutdown")
		}
		return hostproto.Strings(hostproto.StatusOK)
	}
	return nil
}

// process runs one queue message and enforces the vault cap afterwards.
func (s *Supervisor) process(ctx context.Context, raw, manifestDoc []byte) (resp []byte) {
	defer func() {
		if r := recover(); r != nil {
			// A panic must not take every vault down; the request gets
			// no answer and its message expires (§11.9).
			s.log.Error("request handler panicked") // the panic value is not logged: it could carry request data
			resp = nil
		}
	}()
	resp = s.inst.Load().ProcessRaw(ctx, raw, manifestDoc)
	s.enforceCap(ctx)
	return resp
}

func (s *Supervisor) lifecycle(ev vault.LifecycleEvent) {
	switch ev.Event {
	case "unlocked", "enrolled":
		s.touch(ev.VaultID)
	case "locked", "deleted":
		s.forget(ev.VaultID)
	}
	s.link.notify(hostproto.KindLifecycle, enclave.LifecycleFields(ev)...)
}

func (s *Supervisor) lockVault(ctx context.Context, id, why string) {
	ran, err := s.inst.Load().Lock(ctx, id)
	if !ran {
		return
	}
	s.forget(id)
	if errors.Is(err, vault.ErrSplitBrain) {
		s.log.Warn("vault locked without final flush: newer state written elsewhere", "vault_id", id, "trigger", why)
		s.link.notify(hostproto.KindStopped, hostproto.Strings(id, hostproto.StopSplitBrain)...)
		return
	}
	if err != nil {
		s.log.Warn("vault locked; final flush failed", "vault_id", id, "trigger", why, "error", errText(err))
		return
	}
	s.log.Info("vault locked", "vault_id", id, "trigger", why)
}

// --- activity and memory pressure (§12.3) ---

func (s *Supervisor) touch(id string) {
	s.actMu.Lock()
	s.activity[id] = s.now()
	s.actMu.Unlock()
}

func (s *Supervisor) touchKey(key string) {
	if id, ok := vaultOfStateKey(key); ok {
		s.touch(id)
	}
}

func (s *Supervisor) forget(id string) {
	s.actMu.Lock()
	delete(s.activity, id)
	s.actMu.Unlock()
}

// lru returns the running vaults, least recently active first.
func (s *Supervisor) lru() []string {
	ids := s.inst.Load().Vaults()
	s.actMu.Lock()
	defer s.actMu.Unlock()
	sort.Slice(ids, func(i, j int) bool {
		a, b := s.activity[ids[i]], s.activity[ids[j]]
		if !a.Equal(b) {
			return a.Before(b)
		}
		return ids[i] < ids[j]
	})
	return ids
}

func (s *Supervisor) enforceCap(ctx context.Context) {
	if s.cfg.MaxVaults <= 0 {
		return
	}
	for {
		ids := s.lru()
		if len(ids) <= s.cfg.MaxVaults {
			return
		}
		s.lockVault(ctx, ids[0], "vault_cap")
	}
}

// memAvailable reads MemAvailable from /proc/meminfo (bytes; 0 if
// unknown).
func memAvailable() uint64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "MemAvailable:"); ok {
			kb, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(rest), " kB"), 10, 64)
			if err == nil {
				return kb * 1024
			}
		}
	}
	return 0
}

// relieve locks least recently active vaults while available memory stays
// below MemoryReserve; each lock ends a process and frees its memory.
func (s *Supervisor) relieve(ctx context.Context) {
	if s.cfg.MemoryReserve == 0 {
		return
	}
	for {
		avail := memAvailable()
		if avail == 0 || avail >= s.cfg.MemoryReserve {
			return
		}
		ids := s.lru()
		if len(ids) == 0 {
			return
		}
		s.lockVault(ctx, ids[0], "memory_pressure")
	}
}

// maintain rotates ETKs, republishes descriptors, locks every vault when
// the parent has been silent for too long and relieves memory pressure.
func (s *Supervisor) maintain(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		// First: every other step may wait for a parent that does not
		// answer (a descriptor or a lock's events on a full queue).
		s.checkParent(ctx, s.host)
		if err := s.inst.Load().Maintain(); err != nil {
			s.log.Error("ETK rotation failed", "error", errText(err))
		}
		s.pushDescriptor(false)
		s.reportDropped()
		s.relieve(ctx)
	}
}

// vaultSet is what checkParent needs of the vault processes (procHost).
type vaultSet interface {
	Vaults() []string
	LockAllWithin(ctx context.Context, d time.Duration) map[string]error
}

// lockAllWithin is the time every vault has to lock once the parent is
// found unreachable; a process that has not locked by then is killed.
const lockAllWithin = 10 * time.Second

// checkParent locks every vault when the parent has not been heard for
// DownLock (§12.3 "Parent unreachable"): no Ping in that time, whether
// there is a connection or not, and a new connection changes nothing.
//
// The time counts only while a vault runs. With none there is nothing to
// lock, and the count starts again: a vault unlocked later has the whole
// of DownLock for the parent's next Ping (after the supervisor's start, or
// a new session, the parent may forward an unlock before its first Ping).
// A parent cannot use that to keep a vault unlocked: the count starts
// again only when no vault runs.
func (s *Supervisor) checkParent(ctx context.Context, in vaultSet) {
	now := s.now()
	ids := in.Vaults()
	if len(ids) == 0 {
		s.link.hear(now)
		return
	}
	silent := s.link.silent(now, s.cfg.DownLock)
	if silent <= s.cfg.DownLock {
		// Half way there, once for each time the count started: nothing
		// else says so before every vault on the host is locked. For the
		// instance: no vault is named.
		if h := s.link.heardAt(); silent > s.cfg.DownLock/2 && !h.Equal(s.warnedAt) {
			s.warnedAt = h
			s.log.Warn("no ping from the parent: every vault is locked if none comes",
				"silent_s", int(silent.Seconds()), "limit_s", int(s.cfg.DownLock.Seconds()), "vaults", len(ids))
		}
		return
	}
	s.log.Warn("parent unreachable: locking every vault", "vaults", len(ids))
	// From here until the parent's next Ping no call to it is made: each
	// vault's final flush fails at once, as it does without a connection,
	// instead of waiting callTimeout for an answer. Ending the connection
	// alone does not do that: Run dials again at once, and a parent whose
	// process lives answers the hello. It is ended all the same, to free
	// the calls that wait on it now.
	//
	// Nor does a Ping read while the vaults are being locked make the
	// parent reachable (a parent that lives pings on the new connection
	// at once): it is reachable again only once it has been told which
	// vaults ended, and those are known when the lock has ended.
	s.link.lost()
	if c := s.link.get(); c != nil {
		c.Close()
	}
	// All at once, and not behind a request that is being processed (it
	// may itself wait for the parent's egress): no vault runs longer than
	// lockAllWithin from here. One that a request opens meanwhile is
	// locked by a later check: the next, unless a Ping was read meanwhile
	// (link.hear).
	ended := in.LockAllWithin(ctx, lockAllWithin)
	killed := 0
	for id, err := range ended {
		// The parent may still count each of them as running and renew
		// its lease: a killed process reports nothing, and a vault's own
		// "locked" found no connection, unless Run had a new one by then
		// (events are sent on whatever connection there is, gone or not).
		// Each is told at the parent's next Ping all the same; a parent
		// that had the "locked" no longer counts the vault as running and
		// does nothing more with the report.
		reason := hostproto.StopLocked
		switch {
		case errors.Is(err, vault.ErrSplitBrain):
			reason = hostproto.StopSplitBrain
		case err != nil:
			reason = hostproto.StopError
			killed++
		}
		s.forget(id)
		s.link.stop(id, reason)
	}
	s.link.locked()
	s.log.Warn("parent unreachable: every vault locked", "vaults", len(ended), "killed", killed)
}

// reportDropped logs how many log records were dropped because the parent
// was not reading (a count from the supervisor's start), when it grew. The
// report is a log record like any other and can be dropped or find no
// connection: the count is then told at a later check.
func (s *Supervisor) reportDropped() {
	n := s.link.logDropped.Load()
	if n == s.droppedTold {
		return
	}
	if s.link.logRecord(hostproto.Strings(slog.LevelWarn.String(), "log records dropped: the parent was not reading",
		"count", strconv.FormatUint(n, 10))...) {
		s.droppedTold = n
	}
}

// pushDescriptor sends the current descriptor when it changed (or always).
func (s *Supervisor) pushDescriptor(always bool) {
	desc, att := s.inst.Load().Descriptor()
	if desc == nil {
		return
	}
	s.descMu.Lock()
	changed := string(desc) != string(s.lastDesc)
	s.lastDesc = desc
	s.descMu.Unlock()
	if changed || always {
		s.link.notify(hostproto.KindDescriptor, []byte(s.inst.Load().Release().PCR0), desc, att)
	}
}

// StatusList returns the cached attestation status list (tests).
func (s *Supervisor) StatusList() *devattest.StatusList { return s.status.get() }

// HTTPClient returns a client over the egress transport (tests).
func (s *Supervisor) HTTPClient() *http.Client { return s.cfg.Egress.Client(60 * time.Second) }

func (s *Supervisor) store() *hostStore { return s.st }

func (s *Supervisor) relayHost(h string) bool { return s.relays[h] }

// stats answers the parent's Stats request (VAULT-RELAY-SCALING §6): the
// shared relay connections, summed over the relay hosts (one, in a
// release), and the relay requests that failed. The parent is not
// trusted and may ask as often as it likes: the answer is at most
// statsEvery old and no fresher, and asking changes nothing.
func (s *Supervisor) stats() [][]byte {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	if now := time.Now(); s.statsReply == nil || now.Sub(s.statsAt) >= statsEvery {
		s.statsAt, s.statsReply = now, s.readStats()
	}
	return s.statsReply
}

// statsEvery is the finest resolution at which the parent can watch the
// relay counts.
const statsEvery = time.Second

func (s *Supervisor) readStats() [][]byte {
	var t egress.Stats
	for h := range s.relays {
		st := s.cfg.Egress.Stats(h)
		t.Conns += st.Conns
		t.Dialed += st.Dialed
		t.InFlight += st.InFlight
		t.Waiting += st.Waiting
		t.RefusedMaxConns += st.RefusedMaxConns
		t.RefusedMinStreams += st.RefusedMinStreams
		t.WaitMax = max(t.WaitMax, st.WaitMax)
		if st.Streams > 0 && (t.Streams == 0 || st.Streams < t.Streams) {
			t.Streams = st.Streams
		}
	}
	out := hostproto.Strings(hostproto.StatusOK)
	add := func(name string, v uint64) { out = append(out, []byte(name), []byte(strconv.FormatUint(v, 10))) }
	add(hostproto.StatRelayConns, uint64(t.Conns))
	add(hostproto.StatRelayDialed, t.Dialed)
	add(hostproto.StatRelayStreams, uint64(t.Streams))
	add(hostproto.StatRelayInFlight, uint64(t.InFlight+t.Waiting))
	add(hostproto.StatRelayWaiting, uint64(t.Waiting))
	add(hostproto.StatRelayWaitMaxMS, uint64(t.WaitMax.Milliseconds()))
	add(hostproto.StatRelayErrors, s.relayErrs.Load())
	add(hostproto.StatRelayRefusedMax, t.RefusedMaxConns)
	add(hostproto.StatRelayRefusedMin, t.RefusedMinStreams)
	add(hostproto.StatRelayVaultLimit, s.vaultLimit.Load())
	return out
}

// VaultPid returns the pid of a vault's process (tests).
func (s *Supervisor) VaultPid(vaultID string) int {
	if s.host == nil {
		return 0
	}
	return s.host.Pid(vaultID)
}

// KillVault kills a vault's process without a flush (tests).
func (s *Supervisor) KillVault(vaultID string) bool {
	if s.host == nil {
		return false
	}
	return s.host.Kill(vaultID)
}
