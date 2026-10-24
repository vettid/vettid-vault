package parent

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/vettid/vettid-vault/internal/hostproto"
)

// Parent runs the host side of one enclave instance.
type Parent struct {
	cfg Config
	log *slog.Logger
	now func() time.Time
	fwd *forwarder

	mu       sync.Mutex
	queueURL string // set by Run; again by recreateQueue and ensureQueue
	// disconnects counts the enclave's disconnections; queueSeenAt is its
	// value when the queue was last known to exist (publish checks once
	// after every disconnection, ensureQueue).
	disconnects, queueSeenAt int
	sess                     *session
	bootID                   string // the connected enclave's boot id
	running                  map[string]*lease
	// taking counts the enroll and unlock requests of each vault between
	// taking the lease and the decision to keep or give it back.
	taking map[string]int
	desc   *descriptor
	stats  stats
	// manifests caches manifest documents by manifest_sha256 (0.10.0).
	manifests map[string][]byte

	events chan func(context.Context)
	// runCtx lives while Run runs (P15's sweeps); sweeping are the vaults
	// being swept.
	runCtx   context.Context
	sweeping map[string]bool
	// keyQ are the app key writes that failed and are tried again until
	// they are written, per vault (appkeyretry.go).
	keyQ map[string][]Lifecycle
	// asserts are the enclave's assertions after a connect, by vault, not
	// yet written; a worker of their own writes them, slowly, so that they
	// never hold up the connection or a confirmation (appkeyassert.go).
	asserts      map[string][]Lifecycle
	assertWorker bool
}

type session struct {
	conn *hostproto.Conn
}

type lease struct {
	expires time.Time
}

type descriptor struct {
	release     string
	descriptor  []byte
	attestation []byte
}

type stats struct {
	lastHeartbeat time.Time
	heartbeatErr  bool
	processed     int
	splitBrain    int
	leasesLost    int
}

// New validates the configuration.
func New(cfg Config) (*Parent, error) {
	if err := cfg.defaults(); err != nil {
		return nil, err
	}
	// Only the enclave is answered on either channel (peer.go).
	cfg.ControlListener = EnclaveOnly(cfg.ControlListener, DefaultEnclaveCID, "control", cfg.Logger)
	cfg.EgressListener = EnclaveOnly(cfg.EgressListener, DefaultEnclaveCID, "egress", cfg.Logger)
	p := &Parent{cfg: cfg, log: cfg.Logger, now: cfg.Now, running: map[string]*lease{}, taking: map[string]int{}, events: make(chan func(context.Context), 1024)}
	p.fwd = newForwarder(&p.cfg)
	return p, nil
}

// queueRecreateWait bounds the wait for SQS to allow recreating the queue
// after its deletion (SQS refuses for 60 s); queueRetryBase is the first
// backoff, doubled up to queueRetryMax.
var (
	queueRecreateWait = 90 * time.Second
	queueRetryBase    = time.Second
	queueRetryMax     = 10 * time.Second
)

// createQueue creates the instance queue. A restart within 60 s of a clean
// stop finds the queue deleted recently: it waits for SQS (with backoff, up
// to queueRecreateWait) instead of exiting into a restart loop. Other
// errors fail at once.
func (p *Parent) createQueue(ctx context.Context) (string, error) {
	deadline := time.Now().Add(queueRecreateWait)
	wait := queueRetryBase
	logged := false
	for {
		url, err := p.cfg.Queues.Create(ctx, p.cfg.QueueName())
		left := time.Until(deadline)
		if err == nil || !errors.Is(err, ErrQueueDeletedRecently) || left <= 0 {
			return url, err
		}
		if !logged {
			p.log.Info("waiting for SQS to allow recreating the queue", "queue", p.cfg.QueueName())
			logged = true
		}
		t := time.NewTimer(min(wait, left))
		select {
		case <-ctx.Done():
			t.Stop()
			return "", ctx.Err()
		case <-t.C:
		}
		wait = min(2*wait, queueRetryMax)
	}
}

// Run creates the queue, serves the enclave and the forwarder, and runs
// until ctx ends; then it locks the enclave's vaults, withdraws the
// instance and deletes the queue.
func (p *Parent) Run(ctx context.Context) error {
	url, err := p.createQueue(ctx)
	if err != nil {
		return err
	}
	p.setQueue(url)
	p.log.Info("queue ready", "queue", p.cfg.QueueName())

	wctx, wcancel := context.WithCancel(context.Background())
	p.mu.Lock()
	p.runCtx = wctx
	p.mu.Unlock()
	var wg sync.WaitGroup
	run := func(f func(context.Context)) {
		wg.Add(1)
		go func() { defer wg.Done(); f(ctx) }()
	}
	go p.eventWorker(wctx)
	go p.resumeSweeps(wctx)
	run(p.fwd.serve)
	run(p.acceptControl)
	run(p.consume)
	run(p.heartbeat)
	run(p.renewLeases)
	if p.cfg.SweepInterval > 0 {
		run(p.sweep)
	}
	if p.cfg.MetricsInterval > 0 {
		run(p.metrics)
	}
	if p.cfg.HealthAddr != "" {
		run(p.serveHealth)
	}
	<-ctx.Done()
	p.cfg.ControlListener.Close()
	p.cfg.EgressListener.Close()

	// Shutdown (§12.3 "Enclave release or restart ... if signalled").
	sctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if s := p.session(); s != nil {
		if _, err := s.conn.Call(sctx, hostproto.KindShutdown); err != nil {
			p.log.Warn("enclave did not confirm shutdown", "error", err.Error())
		}
	}
	p.flushEvents(sctx)
	if err := p.cfg.Tables.DeleteInstance(sctx, p.cfg.InstanceID); err != nil {
		p.log.Warn("instance row not deleted", "error", err.Error())
	}
	if err := p.cfg.Queues.Destroy(sctx, p.queue()); err != nil {
		p.log.Warn("queue not deleted", "error", err.Error())
	}
	if s := p.session(); s != nil {
		s.conn.Close()
	}
	wg.Wait()
	wcancel()
	p.log.Info("parent stopped")
	return nil
}

// queue returns the instance queue's URL.
func (p *Parent) queue() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.queueURL
}

func (p *Parent) setQueue(url string) {
	p.mu.Lock()
	p.queueURL = url
	p.mu.Unlock()
}

// recreateQueue creates the instance queue again after a receive found it
// gone. The queue is otherwise created once, when Run starts; it can go
// while the parent runs when another instance's sweeper takes this
// instance for gone (its registry row is deleted while its enclave is
// disconnected, and a queue without a row that is 15 minutes old is
// swept), or when someone deletes it by hand. Without this the parent
// would publish a row that names a queue which does not exist, and every
// request routed to the instance would fail until the parent restarts.
//
// Create gives the new queue the same name, access policy and redrive
// policy as the first (Queues.Create), so the URL in the registry row
// stays right; SQS refuses the name for 60 s after the deletion, which
// createQueue waits out.
func (p *Parent) recreateQueue(ctx context.Context) error {
	p.log.Warn("instance queue is missing; creating it again", "queue", p.cfg.QueueName())
	url, err := p.createQueue(ctx)
	if err != nil {
		if ctx.Err() == nil {
			p.log.Warn("instance queue not created again", "queue", p.cfg.QueueName(), "error", err.Error())
		}
		return err
	}
	p.setQueue(url)
	p.log.Info("instance queue created again", "queue", p.cfg.QueueName())
	return nil
}

// queueEnsureTimeout bounds ensureQueue's create (a variable for tests).
var queueEnsureTimeout = 10 * time.Second

// ensureQueue makes sure the instance queue exists before the registry
// row of a newly connected enclave is written, and reports whether the
// row may be written now. While the enclave was disconnected the row was
// gone, and another instance's sweeper may have deleted the queue: the
// row must not send requests to a queue that is not there.
//
// It is one Create after each disconnection (creating a queue that exists, with the
// same attributes, returns its URL). If SQS still refuses the name (60 s
// after a deletion) the row waits for a later heartbeat; the Ping has
// been sent all the same. Any other failure does not hold the row back:
// the parent then behaves as it did before this check, and the consumer
// creates the queue if a receive finds it gone.
func (p *Parent) ensureQueue(ctx context.Context) bool {
	p.mu.Lock()
	at := p.disconnects
	seen := p.queueSeenAt == at
	p.mu.Unlock()
	if seen {
		return true
	}
	cctx, cancel := context.WithTimeout(ctx, queueEnsureTimeout)
	url, err := p.cfg.Queues.Create(cctx, p.cfg.QueueName())
	cancel()
	if errors.Is(err, ErrQueueDeletedRecently) {
		p.log.Info("registry row withheld: the instance queue cannot be created yet", "queue", p.cfg.QueueName())
		return false
	}
	if err != nil {
		p.log.Warn("instance queue not checked before the registry row", "queue", p.cfg.QueueName(), "error", err.Error())
	}
	p.mu.Lock()
	if err == nil {
		p.queueURL = url
	}
	p.queueSeenAt = at
	p.mu.Unlock()
	return true
}

func (p *Parent) session() *session {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sess
}

// --- control connection ---

func (p *Parent) acceptControl(ctx context.Context) {
	for {
		c, err := p.cfg.ControlListener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			p.log.Warn("control accept failed", "error", err.Error())
			time.Sleep(100 * time.Millisecond)
			continue
		}
		s := &session{}
		ready := make(chan struct{}) // s.conn is set before any frame is handled
		s.conn = hostproto.NewConn(c, func(ctx context.Context, f *hostproto.Frame) [][]byte {
			<-ready
			return p.handle(ctx, s, f)
		}, func(f *hostproto.Frame) { <-ready; p.notify(s, f) })
		close(ready)
		go func() {
			<-s.conn.Done()
			p.detach(s)
		}()
	}
}

// attach makes s the enclave session (replacing any other).
func (p *Parent) attach(s *session, bootID string) {
	p.mu.Lock()
	old := p.sess
	p.sess = s
	prevBoot := p.bootID
	p.bootID = bootID
	var gone []string
	if prevBoot != "" && prevBoot != bootID {
		// The enclave restarted: its vaults are gone with its memory.
		for id := range p.running {
			gone = append(gone, id)
		}
		p.running = map[string]*lease{}
	}
	p.mu.Unlock()
	if old != nil && old != s {
		old.conn.Close()
	}
	for _, id := range gone {
		p.enqueueRelease(id)
	}
	p.log.Info("enclave connected", "restarted", prevBoot != "" && prevBoot != bootID)
}

func (p *Parent) detach(s *session) {
	p.mu.Lock()
	if p.sess != s {
		p.mu.Unlock()
		return
	}
	p.sess = nil
	p.desc = nil
	p.disconnects++
	p.mu.Unlock()
	p.log.Warn("enclave disconnected")
	// Stop routing to this instance at once.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.cfg.Tables.DeleteInstance(ctx, p.cfg.InstanceID); err != nil {
		p.log.Warn("instance row not deleted", "error", err.Error())
	}
}

func reply(fields ...string) [][]byte { return hostproto.Strings(fields...) }

// storeKeyOK limits the enclave to its own prefixes.
func storeKeyOK(k string) bool {
	if !(strings.HasPrefix(k, "vaults/") || strings.HasPrefix(k, "users/")) || len(k) > 256 {
		return false
	}
	for _, seg := range strings.Split(k, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

func storeErr(err error) [][]byte {
	switch {
	case errors.Is(err, ErrNotFound):
		return reply(hostproto.StatusNotFound)
	case errors.Is(err, ErrConflict):
		return reply(hostproto.StatusConflict)
	}
	return reply(hostproto.StatusError)
}

// storeGetReply is the reply to a StoreGet that found the object. An
// object or a version that no reply frame can carry is answered "error"
// at once: the frame could not be written, and the enclave would wait out
// its 60 s for an answer that never comes.
func storeGetReply(log *slog.Logger, b []byte, version string) [][]byte {
	if len(b) > MaxObject || len(version) > MaxVersion {
		log.Warn("stored object too large for a reply", "bytes", len(b), "version_bytes", len(version), "max_bytes", MaxObject)
		return reply(hostproto.StatusError)
	}
	return [][]byte{[]byte(hostproto.StatusOK), b, []byte(version)}
}

// storePutOK refuses to write an object that could not be read back
// (MaxObject).
func storePutOK(log *slog.Logger, b []byte) bool {
	if len(b) > MaxObject {
		log.Warn("object too large to store", "bytes", len(b), "max_bytes", MaxObject)
		return false
	}
	return true
}

// handle answers the enclave's requests.
func (p *Parent) handle(ctx context.Context, s *session, f *hostproto.Frame) [][]byte {
	switch f.Kind {
	case hostproto.KindHello:
		if len(f.Fields) != 2 || !isHex(string(f.Fields[0]), 96) || len(f.Fields[1]) == 0 || len(f.Fields[1]) > 64 {
			return reply(hostproto.StatusInvalid)
		}
		p.mu.Lock()
		fresh := p.bootID == ""
		p.mu.Unlock()
		p.attach(s, string(f.Fields[1]))
		// A parent that has just started holds no leases: vaults an
		// enclave still runs from before have no renewing lease, so the
		// enclave locks them before serving ("fresh").
		mode := "resume"
		if fresh {
			mode = "fresh"
		}
		return reply(hostproto.StatusOK, p.cfg.InstanceID, mode)
	case hostproto.KindStoreGet:
		if len(f.Fields) != 1 || !storeKeyOK(string(f.Fields[0])) {
			return reply(hostproto.StatusInvalid)
		}
		b, v, err := p.cfg.Objects.Get(ctx, string(f.Fields[0]))
		if err != nil {
			return storeErr(err)
		}
		return storeGetReply(p.log, b, v)
	case hostproto.KindStorePut:
		if len(f.Fields) != 3 || !storeKeyOK(string(f.Fields[0])) {
			return reply(hostproto.StatusInvalid)
		}
		if !storePutOK(p.log, f.Fields[1]) {
			return reply(hostproto.StatusError)
		}
		v, err := p.cfg.Objects.Put(ctx, string(f.Fields[0]), f.Fields[1], string(f.Fields[2]))
		if err != nil {
			return storeErr(err)
		}
		return reply(hostproto.StatusOK, v)
	case hostproto.KindStoreDelete:
		if len(f.Fields) != 2 || !storeKeyOK(string(f.Fields[0])) {
			return reply(hostproto.StatusInvalid)
		}
		if err := p.cfg.Objects.Delete(ctx, string(f.Fields[0]), string(f.Fields[1])); err != nil {
			return storeErr(err)
		}
		return reply(hostproto.StatusOK)
	case hostproto.KindCredentials:
		c, err := p.cfg.Creds.Retrieve(ctx)
		if err != nil {
			p.log.Warn("credentials unavailable", "error", err.Error())
			return reply(hostproto.StatusError)
		}
		exp := ""
		if !c.Expires.IsZero() {
			exp = c.Expires.UTC().Format(time.RFC3339)
		}
		return reply(hostproto.StatusOK, c.AccessKeyID, c.SecretAccessKey, c.SessionToken, exp)
	case hostproto.KindAppKeyNext:
		// The acknowledged app key: ok only once the row names the key
		// (as app_key_next, or as app_key at enrollment) or already has
		// it as app_key; conflict if it names another key at that seq or
		// is gone; error for any other failure, which the enclave retries.
		return p.confirmAppKey(ctx, f.Fields)
	case hostproto.KindMarkDeleting:
		// 0.1.14 §5.6: ok once deleting_at is written or its condition
		// refused (marked already, deleted, or no row: nothing is left to
		// record); error for any other failure, which the enclave retries.
		if len(f.Fields) != 1 || !vaultIDOK(string(f.Fields[0])) {
			return reply(hostproto.StatusInvalid)
		}
		id := string(f.Fields[0])
		// The vault's earlier lifecycle events are written first: an
		// unlocked still queued would remove the mark (§6.1).
		p.flushEvents(ctx)
		err := p.cfg.Tables.MarkDeleting(ctx, id, p.now())
		if err != nil && !errors.Is(err, ErrConflict) {
			p.log.Warn("deletion mark not written", "vault_id", id, "error", err.Error())
			return reply(hostproto.StatusError)
		}
		p.log.Info("deletion marked", "vault_id", id, "already", err != nil)
		return reply(hostproto.StatusOK)
	}
	return nil
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

// notify handles the enclave's notifications, in order.
func (p *Parent) notify(s *session, f *hostproto.Frame) {
	if p.session() != s {
		return
	}
	switch f.Kind {
	case hostproto.KindDescriptor:
		if len(f.Fields) != 3 || !isHex(string(f.Fields[0]), 96) || len(f.Fields[1]) == 0 || len(f.Fields[1]) > 4096 ||
			len(f.Fields[2]) == 0 || len(f.Fields[2]) > 32*1024 {
			return
		}
		d := &descriptor{release: string(f.Fields[0]), descriptor: clone(f.Fields[1]), attestation: clone(f.Fields[2])}
		p.mu.Lock()
		p.desc = d
		p.mu.Unlock()
		p.log.Info("descriptor updated", "release", d.release)
		p.events <- func(ctx context.Context) { p.publish(ctx) }
	case hostproto.KindLifecycle:
		ev, ok := parseLifecycle(f)
		if !ok {
			return
		}
		p.onLifecycle(ev)
	case hostproto.KindStopped:
		if len(f.Fields) != 2 || !vaultIDOK(string(f.Fields[0])) {
			return
		}
		id, reason := string(f.Fields[0]), string(f.Fields[1])
		lvl := slog.LevelWarn
		if hostproto.StopExpected(reason) {
			lvl = slog.LevelInfo // the member's lock, a move: not a crash
		}
		p.log.Log(context.Background(), lvl, "vault stopped", "vault_id", id, "reason", truncate(reason, 64))
		p.mu.Lock()
		_, was := p.running[id]
		delete(p.running, id)
		if reason == hostproto.StopSplitBrain {
			p.stats.splitBrain++
		}
		// The lease stays while an enroll or unlock that took it is under
		// way (as for "locked", Lifecycle.KeepLease): a report of a run
		// that ended earlier (the enclave sends those when the parent is
		// reachable again) must not release the lease of the run that is
		// starting. If that one does not open, it gives the lease back.
		taking := p.taking[id] > 0
		p.mu.Unlock()
		if was && !taking {
			p.enqueueRelease(id)
		}
	case hostproto.KindLog:
		if len(f.Fields) < 2 {
			return
		}
		kv := []any{"source", "enclave"}
		for i := 2; i+1 < len(f.Fields) && i < 2+32; i += 2 {
			kv = append(kv, string(f.Fields[i]), truncate(string(f.Fields[i+1]), 200))
		}
		var lvl slog.Level
		_ = lvl.UnmarshalText(f.Fields[0])
		p.log.Log(context.Background(), lvl, truncate(string(f.Fields[1]), 200), kv...)
	}
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func vaultIDOK(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func parseLifecycle(f *hostproto.Frame) (Lifecycle, bool) {
	// 0.15.0: [event, vault_id, release, vault_version, state_version,
	// app_key (SPKI DER or empty), app_key_seq]; an enclave before it
	// sends the first five.
	if len(f.Fields) != 5 && len(f.Fields) != 7 && len(f.Fields) != 8 && len(f.Fields) != 11 && len(f.Fields) != 14 && len(f.Fields) != 15 {
		return Lifecycle{}, false
	}
	if len(f.Fields) >= 8 {
		// 0.16.0: the backup bit, "1", "0" or "" (not reported).
		switch string(f.Fields[7]) {
		case "1", "0":
		case "":
		default:
			return Lifecycle{}, false
		}
	}
	ev := Lifecycle{Event: string(f.Fields[0]), VaultID: string(f.Fields[1]), Release: string(f.Fields[2]), VaultVersion: string(f.Fields[3])}
	if len(f.Fields) >= 7 && len(f.Fields[5]) > 0 {
		if len(f.Fields[5]) > 256 {
			return Lifecycle{}, false
		}
		seq, err := strconv.ParseUint(string(f.Fields[6]), 10, 53)
		if err != nil || seq == 0 || strconv.FormatUint(seq, 10) != string(f.Fields[6]) {
			return Lifecycle{}, false
		}
		ev.AppKey, ev.AppKeySeq = clone(f.Fields[5]), seq
	}
	if len(f.Fields) >= 8 && len(f.Fields[7]) == 1 {
		b := string(f.Fields[7]) == "1"
		ev.CredentialBackup = &b
	}
	if len(f.Fields) >= 14 {
		// Release R: next ("1", "0", ""), header_seq, next_cleared ("1", "").
		switch string(f.Fields[11]) {
		case "1", "0":
			b := string(f.Fields[11]) == "1"
			ev.Next = &b
		case "":
		default:
			return Lifecycle{}, false
		}
		hs, err := strconv.ParseUint(string(f.Fields[12]), 10, 53)
		if err != nil || strconv.FormatUint(hs, 10) != string(f.Fields[12]) {
			return Lifecycle{}, false
		}
		ev.HeaderSeq = hs
		switch string(f.Fields[13]) {
		case "1":
			ev.NextCleared = true
		case "":
		default:
			return Lifecycle{}, false
		}
	}
	if len(f.Fields) == 15 && len(f.Fields[14]) > 0 {
		// 0.49.0 (VAULT-HOST-PROTOCOL 0.1.13 §7.2): cancelled_recovery_id,
		// a ULID, on unlocked or moved only.
		id := string(f.Fields[14])
		if !ulidRE.MatchString(id) || ev.Event != "unlocked" && ev.Event != "moved" {
			return Lifecycle{}, false
		}
		ev.CancelledRecoveryID = id
	}
	if len(f.Fields) >= 11 {
		// 0.18.0: name_seq, first_name, last_name ("0", "", "" except for
		// account_name).
		n, ok := parseNameFields(f.Fields[8], f.Fields[9], f.Fields[10])
		if !ok {
			return Lifecycle{}, false
		}
		ev.Name = n
	}
	switch ev.Event {
	case EventAppKey, EventAppKeyNext, EventAppKeyAssert, EventAppKeyNextAssert:
		if ev.AppKey == nil || ev.NextCleared && ev.Event != EventAppKey {
			return Lifecycle{}, false
		}
	case EventCredentialBackup:
		if ev.CredentialBackup == nil {
			return Lifecycle{}, false
		}
	case EventAccountName:
		if ev.Name == nil {
			return Lifecycle{}, false
		}
	case "enrolled", "unlocked", "locked", "moved", "deleted", EventAlarmCredentialClone:
	default:
		return Lifecycle{}, false
	}
	if ev.Name != nil && ev.Event != EventAccountName {
		return Lifecycle{}, false
	}
	if !vaultIDOK(ev.VaultID) || !isHex(ev.Release, 96) || !isHex(ev.VaultVersion, 96) {
		return Lifecycle{}, false
	}
	n := 0
	for _, c := range f.Fields[4] {
		if c < '0' || c > '9' || n > 1<<20 {
			return Lifecycle{}, false
		}
		n = n*10 + int(c-'0')
	}
	if len(f.Fields[4]) == 0 {
		return Lifecycle{}, false
	}
	ev.StateVersion = n
	return ev, true
}

// parseNameFields decodes a lifecycle frame's name request (0.18.0):
// nil for "0", "", ""; otherwise a canonical seq ≥ 1 and two names of
// 1–160 bytes of UTF-8 without control characters (§10.8, §11.13).
func parseNameFields(seq, first, last []byte) (*NameChange, bool) {
	if string(seq) == "0" && len(first) == 0 && len(last) == 0 {
		return nil, true
	}
	n, err := strconv.ParseUint(string(seq), 10, 53)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != string(seq) || !accountName(first) || !accountName(last) {
		return nil, false
	}
	return &NameChange{Seq: n, FirstName: string(first), LastName: string(last)}, true
}

func accountName(b []byte) bool {
	if len(b) == 0 || len(b) > 160 || !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if r < 0x20 || r >= 0x80 && r <= 0x9f || r == 0x2028 || r == 0x2029 {
			return false
		}
	}
	return true
}

// onLifecycle updates the running set at once and queues the table write.
func (p *Parent) onLifecycle(ev Lifecycle) {
	p.mu.Lock()
	switch ev.Event {
	case "unlocked":
		if _, ok := p.running[ev.VaultID]; !ok {
			p.running[ev.VaultID] = &lease{expires: p.now().Add(p.cfg.LeaseLength)}
		}
	case "locked", "deleted":
		delete(p.running, ev.VaultID)
		// An unlock of a vault that runs here locks the running process
		// first; that lock must not drop the lease the unlock took
		// (staging S8 canary, 2026-10-10). handleMessage releases it if
		// the vault does not open again.
		ev.KeepLease = ev.Event == "locked" && p.taking[ev.VaultID] > 0
	}
	p.mu.Unlock()
	if ev.Event == EventAppKeyAssert || ev.Event == EventAppKeyNextAssert {
		p.log.Debug("lifecycle", "event", ev.Event, "vault_id", ev.VaultID)
		p.queueAssert(ev)
		return
	}
	p.log.Info("lifecycle", "event", ev.Event, "vault_id", ev.VaultID)
	p.events <- func(ctx context.Context) {
		err := p.cfg.Tables.Lifecycle(ctx, ev, p.cfg.InstanceID, p.now())
		var ke *AppKeyWriteError
		if errors.As(err, &ke) {
			// app_key / app_key_next were not written: tried again until
			// they are; the rest of the event is judged on its own.
			p.retryAppKeys(ev, ke.Err)
			// The line an unwritten event always had.
			p.log.Warn("lifecycle write failed", "event", ev.Event, "vault_id", ev.VaultID, "error", ke.Err.Error())
			err = ke.Rest
		}
		switch {
		case errors.Is(err, ErrAlarmNotWritten):
			// The row is marked deleted: the sweep goes ahead (P15).
			p.log.Warn("lifecycle write failed", "event", ev.Event, "vault_id", ev.VaultID, "error", err.Error())
			p.startSweep(ev.VaultID)
		case errors.Is(err, ErrNotMarked):
			// Not ours to sweep: another instance holds the vault (P15).
			p.log.Info("vault deleted elsewhere; no attachment sweep", "vault_id", ev.VaultID)
		case err != nil:
			p.log.Warn("lifecycle write failed", "event", ev.Event, "vault_id", ev.VaultID, "error", err.Error())
		case ev.Event == "deleted":
			p.startSweep(ev.VaultID)
		}
	}
}

// startSweep starts P15's sweep of a deleted vault's attachment objects
// (VAULT-HOST-PROTOCOL 0.1.9): only after this parent's own conditional
// update marked the row deleted.
func (p *Parent) startSweep(vaultID string) {
	p.mu.Lock()
	ctx := p.runCtx
	p.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	go p.sweepAttachments(ctx, vaultID)
}

// sweepAttachments deletes every object under vaults/<vault_id>/att/,
// listing the prefix (a missing object counting as deleted), and retries
// until the prefix is empty or the parent stops (P15). Before each pass it
// reads the vault's row and stops if the row says the vault is no longer
// deleted (a vault id enrolled again); a row that is gone (the member API
// deletes the rows of a deleted vault) does not stop it. Done, it removes
// the row's record of the pending sweep.
func (p *Parent) sweepAttachments(ctx context.Context, vaultID string) {
	l, ok := p.cfg.Objects.(ObjectLister)
	if !ok || !vaultIDOK(vaultID) {
		return
	}
	p.mu.Lock()
	if p.sweeping == nil {
		p.sweeping = map[string]bool{}
	}
	if p.sweeping[vaultID] {
		p.mu.Unlock()
		return // one sweep per vault at a time
	}
	p.sweeping[vaultID] = true
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.sweeping, vaultID)
		p.mu.Unlock()
	}()
	st, _ := p.cfg.Tables.(SweepTables)
	prefix := "vaults/" + vaultID + "/att/"
	wait := p.cfg.SweepRetry
	if wait <= 0 {
		wait = 5 * time.Second
	}
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(min(wait<<min(attempt-1, 6), 5*time.Minute)):
			}
		}
		if st != nil {
			state, exists, err := st.VaultState(ctx, vaultID)
			if err != nil {
				p.log.Warn("attachment sweep: row not read", "vault_id", vaultID, "error", err.Error())
				continue
			}
			if exists && state != "deleted" {
				p.log.Info("attachment sweep stopped: the vault is no longer deleted", "vault_id", vaultID)
				return
			}
		}
		objs, err := l.ListObjects(ctx, prefix)
		if err == nil && len(objs) == 0 {
			if st != nil {
				if err := st.SweepDone(ctx, vaultID, p.now()); err != nil {
					p.log.Warn("attachment sweep: record not removed", "vault_id", vaultID, "error", err.Error())
					continue
				}
			}
			if attempt > 0 {
				p.log.Info("attachment sweep done", "vault_id", vaultID)
			}
			return
		}
		deleted := 0
		for _, o := range objs {
			if !strings.HasPrefix(o.Key, prefix) {
				continue
			}
			derr := p.cfg.Objects.Delete(ctx, o.Key, o.ETag)
			switch {
			case derr == nil:
				deleted++
			case errors.Is(derr, ErrNotFound), errors.Is(derr, ErrConflict):
				// already gone, or rewritten: the next listing has it
			default:
				err = derr
			}
		}
		if err != nil {
			p.log.Warn("attachment sweep incomplete", "vault_id", vaultID, "error", err.Error())
		} else {
			p.log.Info("attachment sweep", "vault_id", vaultID, "deleted", deleted)
		}
	}
}

// resumeSweeps starts the sweeps an earlier parent left pending (their
// rows record att_sweep_pending), at the parent's start.
func (p *Parent) resumeSweeps(ctx context.Context) {
	st, ok := p.cfg.Tables.(SweepTables)
	if !ok {
		return
	}
	wait := p.cfg.SweepRetry
	if wait <= 0 {
		wait = 5 * time.Second
	}
	for attempt := 0; ; attempt++ {
		ids, err := st.PendingSweeps(ctx)
		for _, id := range ids {
			p.startSweep(id)
		}
		if err == nil {
			return
		}
		p.log.Warn("pending attachment sweeps not read", "error", err.Error())
		select {
		case <-ctx.Done():
			return
		case <-time.After(min(wait<<min(attempt, 6), 5*time.Minute)):
		}
	}
}

func (p *Parent) enqueueRelease(id string) {
	p.events <- func(ctx context.Context) {
		if err := p.cfg.Tables.ReleaseLease(ctx, id, p.cfg.InstanceID, p.now()); err != nil && !errors.Is(err, ErrLeaseHeld) {
			p.log.Warn("lease release failed", "vault_id", id, "error", err.Error())
		}
	}
}

// eventWorker applies table writes in order.
func (p *Parent) eventWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case f := <-p.events:
			wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			f(wctx)
			cancel()
		}
	}
}

// flushEvents waits until every queued table write has run.
func (p *Parent) flushEvents(ctx context.Context) {
	done := make(chan struct{})
	select {
	case p.events <- func(context.Context) { close(done) }:
	case <-ctx.Done():
		return
	}
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// --- instance registry (§11.1) ---

// registryWriteTimeout bounds the write of the registry row (a variable
// for tests).
var registryWriteTimeout = 10 * time.Second

// publish writes the registry row if the enclave answers.
func (p *Parent) publish(ctx context.Context) {
	p.mu.Lock()
	s, d := p.sess, p.desc
	p.mu.Unlock()
	if s == nil || d == nil {
		return
	}
	// Ping and row together, in at most 15 s (25 s for the first publish
	// after a disconnection, which checks for the queue in between, at
	// most 10 s, ensureQueue): the enclave locks every vault after 120 s
	// without a Ping, so one write that hangs (a table that does not
	// answer) must not hold the pings that follow it.
	start := time.Now()
	defer func() {
		if took := time.Since(start); took > p.cfg.Heartbeat {
			p.log.Warn("heartbeat took longer than its interval", "ms", took.Milliseconds(), "interval_ms", p.cfg.Heartbeat.Milliseconds())
		}
	}()
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	r, err := s.conn.Call(pctx, hostproto.KindPing)
	cancel()
	if err != nil || len(r) != 2 || string(r[0]) != hostproto.StatusOK {
		p.log.Warn("enclave did not answer ping")
		return
	}
	load := 0
	for _, c := range r[1] {
		if c >= '0' && c <= '9' && load < 1<<20 {
			load = load*10 + int(c-'0')
		}
	}
	if !p.ensureQueue(ctx) {
		return
	}
	var heavy *bool
	if st := enclaveStats(ctx, s); st != nil {
		if v, ok := st[hostproto.StatHeavyKDFFree]; ok {
			free := v == 1
			heavy = &free
		}
	}
	now := p.now()
	wctx, cancel := context.WithTimeout(ctx, registryWriteTimeout)
	defer cancel()
	err = p.cfg.Tables.PutInstance(wctx, InstanceRow{InstanceID: p.cfg.InstanceID, Release: d.release, QueueURL: p.queue(),
		Descriptor: d.descriptor, Attestation: d.attestation, HeartbeatAt: now.Unix(), ExpiresAt: now.Add(10 * time.Minute).Unix(), Load: load,
		HeavyKDFFree: heavy})
	p.mu.Lock()
	p.stats.heartbeatErr = err != nil
	if err == nil {
		p.stats.lastHeartbeat = now
	}
	p.mu.Unlock()
	if err != nil {
		p.log.Warn("heartbeat failed", "error", err.Error())
	}
}

func (p *Parent) heartbeat(ctx context.Context) {
	t := time.NewTicker(p.cfg.Heartbeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.publish(ctx)
		}
	}
}

// sweep deletes queues of instances that have gone away (§11.1): no
// registry row, or a heartbeat older than an hour, and the queue older
// than 15 minutes (a starting instance creates its queue first).
func (p *Parent) sweep(ctx context.Context) {
	for {
		qs, err := p.cfg.Queues.List(ctx, p.cfg.QueuePrefix)
		if err == nil {
			for url, created := range qs {
				id := url[strings.LastIndex(url, "/")+1:]
				id = strings.TrimPrefix(id, p.cfg.QueuePrefix)
				if id == p.cfg.InstanceID || !instanceIDRE.MatchString(id) || p.now().Sub(created) < 15*time.Minute {
					continue
				}
				hb, err := p.cfg.Tables.InstanceHeartbeat(ctx, id)
				if err == nil && p.now().Unix()-hb < 3600 {
					continue
				}
				if err != nil && !errors.Is(err, ErrNotFound) {
					continue
				}
				if err := p.cfg.Queues.Destroy(ctx, url); err == nil {
					p.log.Info("swept queue of a gone instance", "instance_id", id)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(p.cfg.SweepInterval):
		}
	}
}

// --- leases (§11.1) ---

func (p *Parent) renewLeases(ctx context.Context) {
	t := time.NewTimer(p.cfg.LeaseRenew)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		start := time.Now()
		p.mu.Lock()
		ids := make([]string, 0, len(p.running))
		for id := range p.running {
			ids = append(ids, id)
		}
		p.mu.Unlock()
		// No renewal waits past the moment the first lease is declared
		// lost (15 s before it ends), so that a table that does not
		// answer is found out in time; and once one renewal was given up
		// the rest of the pass makes no call: every vault's lease is
		// judged by its age alone, however many run.
		var first time.Time
		p.mu.Lock()
		for _, l := range p.running {
			if first.IsZero() || l.expires.Before(first) {
				first = l.expires
			}
		}
		p.mu.Unlock()
		wait, failed, down := leaseRenewTimeout, false, false
		if !first.IsZero() {
			wait = max(min(wait, first.Add(-leaseMargin).Sub(p.now())), leaseRenewTimeout/10)
		}
		for _, id := range ids {
			err := p.renew(ctx, id, wait, down)
			failed = failed || err != nil
			down = down || errors.Is(err, context.DeadlineExceeded)
		}
		// While renewals fail, try again soon: the lease-lost rule is only
		// looked at when a renewal has failed.
		next := max(p.cfg.LeaseRenew-time.Since(start), time.Millisecond)
		if failed {
			next = min(p.cfg.LeaseRenew, leaseRetry)
		}
		t.Reset(next)
	}
}

// A lease renewal is given up after leaseRenewTimeout (the SDK's client
// has no response timeout); after a failed pass the next comes after
// leaseRetry; a lease whose renewals fail is lost leaseMargin before it
// ends (§11.1). Variables for tests.
var (
	leaseRenewTimeout = 10 * time.Second
	leaseRetry        = 5 * time.Second
	leaseMargin       = 15 * time.Second
)

// errLeaseTableDown: a renewal was given up (it is a
// context.DeadlineExceeded to errors.Is).
var errLeaseTableDown error = leaseTableDown{}

type leaseTableDown struct{}

func (leaseTableDown) Error() string { return "lease table did not answer in time" }
func (leaseTableDown) Unwrap() error { return context.DeadlineExceeded }

// renew renews one lease, waiting at most wait for the table (skip: not
// at all, the table did not answer earlier in this pass), and tells the
// enclave when the lease is lost. It returns the renewal's error.
func (p *Parent) renew(ctx context.Context, id string, wait time.Duration, skip bool) error {
	exp := p.now().Add(p.cfg.LeaseLength)
	err := errLeaseTableDown
	if !skip {
		rctx, cancel := context.WithTimeout(ctx, wait)
		err = p.cfg.Tables.RenewLease(rctx, id, p.cfg.InstanceID, exp.Unix())
		if err != nil && rctx.Err() != nil && ctx.Err() == nil {
			err = errLeaseTableDown
		}
		cancel()
	}
	now := p.now()
	p.mu.Lock()
	l := p.running[id]
	if l == nil {
		p.mu.Unlock()
		return err
	}
	lost := errors.Is(err, ErrLeaseHeld)
	if err == nil {
		l.expires = exp
	} else if !lost && !now.Before(l.expires.Add(-leaseMargin)) {
		lost = true // renewals kept failing until the lease is about to lapse
	}
	if lost {
		delete(p.running, id)
		p.stats.leasesLost++
	}
	s := p.sess
	p.mu.Unlock()
	if err != nil && !lost && !skip {
		p.log.Warn("lease renewal failed; will retry", "vault_id", id, "error", err.Error())
	}
	if lost {
		// §12.3 "Lease lost": the enclave locks the vault.
		p.log.Warn("lease lost", "vault_id", id)
		if s != nil {
			lctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			_, _ = s.conn.Call(lctx, hostproto.KindLeaseLost, []byte(id))
			cancel()
		}
	}
	return err
}

// beginTake and endTake bracket an enroll or unlock that holds the lease
// it took (see Lifecycle.KeepLease).
func (p *Parent) beginTake(id string) {
	p.mu.Lock()
	p.taking[id]++
	p.mu.Unlock()
}

func (p *Parent) endTake(id string) {
	p.mu.Lock()
	if p.taking[id]--; p.taking[id] <= 0 {
		delete(p.taking, id)
	}
	p.mu.Unlock()
}

// acquire takes the lease before an enroll or unlock is forwarded.
func (p *Parent) acquire(ctx context.Context, id string) error {
	now := p.now()
	exp := now.Add(p.cfg.LeaseLength)
	err := p.cfg.Tables.AcquireLease(ctx, id, p.cfg.InstanceID, now.Unix(), exp.Unix())
	if !errors.Is(err, ErrLeaseHeld) {
		return err
	}
	// Held by another instance: take it over only if that instance is not
	// live (no heartbeat for 90 s), conditional on the exact lease (§11.1).
	holder, hexp, lerr := p.cfg.Tables.Lease(ctx, id)
	if lerr != nil || holder == "" || holder == p.cfg.InstanceID {
		return err
	}
	hb, herr := p.cfg.Tables.InstanceHeartbeat(ctx, holder)
	if herr == nil && now.Unix()-hb <= liveHeartbeat {
		return err // a live holder keeps its lease
	}
	if herr != nil && !errors.Is(herr, ErrNotFound) {
		return herr
	}
	if terr := p.cfg.Tables.TakeoverLease(ctx, id, p.cfg.InstanceID, holder, hexp, exp.Unix()); terr != nil {
		return terr
	}
	p.log.Info("lease taken over from an instance that is not live", "vault_id", id, "from", holder)
	return nil
}

// liveHeartbeat is how old a heartbeat may be for its instance to be
// live (§11.1).
const liveHeartbeat = 90

// isRunning reports whether the enclave runs the vault.
func (p *Parent) isRunning(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.running[id]
	return ok
}
