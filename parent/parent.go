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

	"github.com/vettid/vettid-vault/internal/hostproto"
)

// Parent runs the host side of one enclave instance.
type Parent struct {
	cfg Config
	log *slog.Logger
	now func() time.Time
	fwd *forwarder

	queueURL string

	mu      sync.Mutex
	sess    *session
	bootID  string // the connected enclave's boot id
	running map[string]*lease
	desc    *descriptor
	stats   stats
	// manifests caches manifest documents by manifest_sha256 (0.10.0).
	manifests map[string][]byte

	events chan func(context.Context)
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
	p := &Parent{cfg: cfg, log: cfg.Logger, now: cfg.Now, running: map[string]*lease{}, events: make(chan func(context.Context), 1024)}
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
	p.queueURL = url
	p.log.Info("queue ready", "queue", p.cfg.QueueName())

	wctx, wcancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	run := func(f func(context.Context)) {
		wg.Add(1)
		go func() { defer wg.Done(); f(ctx) }()
	}
	go p.eventWorker(wctx)
	run(p.fwd.serve)
	run(p.acceptControl)
	run(p.consume)
	run(p.heartbeat)
	run(p.renewLeases)
	if p.cfg.SweepInterval > 0 {
		run(p.sweep)
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
	if err := p.cfg.Queues.Destroy(sctx, p.queueURL); err != nil {
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
		return [][]byte{[]byte(hostproto.StatusOK), b, []byte(v)}
	case hostproto.KindStorePut:
		if len(f.Fields) != 3 || !storeKeyOK(string(f.Fields[0])) {
			return reply(hostproto.StatusInvalid)
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
		p.mu.Unlock()
		if was {
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
	if len(f.Fields) != 5 && len(f.Fields) != 7 && len(f.Fields) != 8 {
		return Lifecycle{}, false
	}
	if len(f.Fields) == 8 {
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
	if len(f.Fields) == 8 && len(f.Fields[7]) == 1 {
		b := string(f.Fields[7]) == "1"
		ev.CredentialBackup = &b
	}
	switch ev.Event {
	case EventAppKey:
		if ev.AppKey == nil {
			return Lifecycle{}, false
		}
	case EventCredentialBackup:
		if ev.CredentialBackup == nil {
			return Lifecycle{}, false
		}
	case "enrolled", "unlocked", "locked", "moved", "deleted", EventAlarmCredentialClone:
	default:
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
	}
	p.mu.Unlock()
	p.log.Info("lifecycle", "event", ev.Event, "vault_id", ev.VaultID)
	p.events <- func(ctx context.Context) {
		if err := p.cfg.Tables.Lifecycle(ctx, ev, p.cfg.InstanceID, p.now()); err != nil {
			p.log.Warn("lifecycle write failed", "event", ev.Event, "vault_id", ev.VaultID, "error", err.Error())
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

// publish writes the registry row if the enclave answers.
func (p *Parent) publish(ctx context.Context) {
	p.mu.Lock()
	s, d := p.sess, p.desc
	p.mu.Unlock()
	if s == nil || d == nil {
		return
	}
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
	now := p.now()
	err = p.cfg.Tables.PutInstance(ctx, InstanceRow{InstanceID: p.cfg.InstanceID, Release: d.release, QueueURL: p.queueURL,
		Descriptor: d.descriptor, Attestation: d.attestation, HeartbeatAt: now.Unix(), ExpiresAt: now.Add(10 * time.Minute).Unix(), Load: load})
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
	t := time.NewTicker(p.cfg.LeaseRenew)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		p.mu.Lock()
		ids := make([]string, 0, len(p.running))
		for id := range p.running {
			ids = append(ids, id)
		}
		p.mu.Unlock()
		for _, id := range ids {
			p.renew(ctx, id)
		}
	}
}

func (p *Parent) renew(ctx context.Context, id string) {
	now := p.now()
	exp := now.Add(p.cfg.LeaseLength)
	err := p.cfg.Tables.RenewLease(ctx, id, p.cfg.InstanceID, exp.Unix())
	p.mu.Lock()
	l := p.running[id]
	if l == nil {
		p.mu.Unlock()
		return
	}
	lost := errors.Is(err, ErrLeaseHeld)
	if err == nil {
		l.expires = exp
	} else if !lost && now.After(l.expires.Add(-15*time.Second)) {
		lost = true // renewals kept failing until the lease is about to lapse
	}
	if lost {
		delete(p.running, id)
		p.stats.leasesLost++
	}
	s := p.sess
	p.mu.Unlock()
	if err != nil && !lost {
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
