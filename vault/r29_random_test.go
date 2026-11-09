package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// The release 29 deadlock search on the real code (owner decision a, GC
// 01M6SRQ1B7NM0Q00G0CEGHFES8): two real vaults in process, with real
// crypto and real state writes through the store; only the relay and the
// clock are simulated. A seeded run draws random actions, mirroring the
// trust model's mix (internal/trustmodel genRun and randomAction):
// rotations by each path, sends, collects (partial and full, with
// reordering, leases and redelivery), housekeeping ticks, time jumps,
// locks and unlocks, crashes (a restart from the store, losing what was
// not written) and injected deposit failures (429, 503). The simulated
// relay enforces a token's exp, its revocation and its quota (§6.6: a
// reconnect token's 4 deposits), and drops what it held 14 days (T).
//
// At quiescence (both unlocked, everything delivered, time past every
// bound) the pair must have converged: one current epoch, each side's
// record of the other at the other's current ik, no pending epoch or open
// handshake, nothing held, a valid standing token each way. An honest
// pair must not suspend, nor end stale, except the stated residuals,
// counted apart: rapid rotations (3 or more key changes within 2 hours on
// a side, ending by quota_exceeded) and a lock longer than T.
//
// Run: R29RP_RUNS=n go test -run TestR29RandomPair ./vault/
//   R29RP_SEED   the master seed (default 1)
//   R29RP_STEPS  at most this many random actions per run (default 40)
//   R29RP_BURST  set: each side first rotates 3 to 6 times in quick
//                succession
//   R29RP_TRACE  a run seed: replay that run alone, with its trace
//   R29RP_SHOW   how many seeds to list per failure class (default 5)
//
// A run replays from its seed: crypto randomness is seeded per run
// (testing/cryptotest), the fixtures are made at a start time drawn from
// the seed and run on the run's clock, and the vault iterates its maps in
// sorted order. R29RP_TRACE runs a seed alone with its trace, and
// R29RP_REPEAT=n replays it n more times and tallies the verdicts.

type rpOp int

const (
	rpRotate rpOp = iota
	rpSend
	rpCollect
	rpTick
	rpTime
	rpLock
	rpUnlock
	rpCrash
	rpFault
	rpNumOps
)

var rpOpName = [...]string{"rotate", "send", "collect", "tick", "time", "lock", "unlock", "crash", "fault"}
var rpWeight = [...]int{6, 8, 14, 6, 8, 3, 3, 2, 3}
var rpJumps = [...]time.Duration{61 * time.Second, 10 * time.Minute, time.Hour + time.Second, 24*time.Hour + time.Second,
	7*24*time.Hour + time.Second, 14*24*time.Hour + time.Second, 30*24*time.Hour + time.Second}

type rpAction struct {
	Op      rpOp
	A, B, N int
}

func (a rpAction) String() string {
	s := a.A % 2
	switch a.Op {
	case rpRotate:
		return fmt.Sprintf("rotate %d (%s)", s, [...]string{"credential.rotate", "transfer", "recovery"}[a.B%3])
	case rpCollect:
		return fmt.Sprintf("collect %d (max %d, %s)", s, rpCollectMax(a.B), map[bool]string{true: "redeliver", false: "ack"}[a.N%10 == 0])
	case rpTime:
		return fmt.Sprintf("time +%v", rpJumps[a.N%len(rpJumps)])
	case rpFault:
		return fmt.Sprintf("fault %d (%d × %s)", s, 1+a.N%3, map[bool]string{true: "429", false: "503"}[a.B%2 == 0])
	}
	return fmt.Sprintf("%s %d", rpOpName[a.Op], s)
}

func rpCollectMax(b int) int { return []int{1, 2, 5, 32}[b%4] }

func rpGen(rs uint64, steps int, burst bool) []rpAction {
	rng := rand.New(rand.NewPCG(rs, 3))
	total := 0
	for _, w := range rpWeight {
		total += w
	}
	n := 1 + rng.IntN(steps)
	acts := make([]rpAction, 0, n)
	for range n {
		x := rng.IntN(total)
		op := rpOp(0)
		for x >= rpWeight[op] {
			x -= rpWeight[op]
			op++
		}
		acts = append(acts, rpAction{Op: op, A: rng.IntN(64), B: rng.IntN(64), N: rng.IntN(64)})
	}
	if burst {
		var b []rpAction
		for s := 0; s < 2; s++ {
			for k := 3 + rng.IntN(4); k > 0; k-- {
				b = append(b, rpAction{Op: rpRotate, A: s, B: rng.IntN(64)}, rpAction{Op: rpCollect, A: rng.IntN(64), B: 3},
					rpAction{Op: rpTime, N: rng.IntN(2)}) // 61 s or 10 min
			}
		}
		rng.Shuffle(len(b), func(i, j int) { b[i], b[j] = b[j], b[i] })
		acts = append(b, acts...)
	}
	return acts
}

type rpMsg struct {
	m    Message
	at   time.Time
	from int
	typ  string // what the depositor sealed (decoded at deposit time)
}

// rpWorld is one run.
type rpWorld struct {
	t       *testing.T
	f       *r29Fx
	locked  [2]bool
	lockAt  [2]time.Time
	maxLock time.Duration
	q       [2][]rpMsg // q[s]: what waits in side s's mailbox
	n       int
	quota   map[string]int64 // deposits per jti under a quota
	rot     [2][]time.Time   // when each side rotated
	fail    [2]int           // injected deposit failures left, by depositing side
	fail429 [2]bool
	refused map[string]int // relay refusals by code
	expired int            // messages the relay dropped at T
	drops   []string       // which, for the trace
	locks   [2][][2]time.Time
	hasher  []string // what the run did, for its fingerprint
	trace   []string
	verbose bool
	// the relay keys and mailboxes, which never change (A5), kept here
	// so that a locked side's are known
	pub  [2]ed25519.PublicKey
	mbox [2]string
	// R29-T1 (0.88.2): the jti of each side's held standing and reconnect
	// token when last looked at, and the adoptions of a token its issuer
	// had already revoked.
	heldJTI    [2][2]string
	violations []string
}

// watchAdoption is R29-T1's harness assertion: whenever a side's held
// standing or reconnect token changes (an adoption), the new one must not
// be revoked by its issuer already (§6.3.1 "A handshake's tokens are
// adopted at confirmation", "Revocation by the issuer"). A token revoked
// after it was adopted (a quota refresh) is not judged here.
func (w *rpWorld) watchAdoption(when string) {
	for s := 0; s < 2; s++ {
		if w.locked[s] || w.f.m(s).st == nil {
			continue
		}
		p := w.f.p(s)
		if p == nil {
			continue
		}
		o := 1 - s
		for k, tok := range []string{p.Standing.Token, p.Reconnect.Token} {
			jti := ""
			if c, err := relayauth.ParseToken(tok, w.pub[o]); err == nil {
				jti = c.Jti
			}
			if jti == w.heldJTI[s][k] {
				continue
			}
			w.heldJTI[s][k] = jti
			if jti == "" {
				continue
			}
			r := w.f.d[o].relay
			r.mu.Lock()
			revoked := slices.Contains(r.revoked, "jti:"+jti)
			r.mu.Unlock()
			if revoked {
				v := fmt.Sprintf("%d:%s@%s", s, []string{"standing", "reconnect"}[k], when)
				w.violations = append(w.violations, v)
				w.logf("R29-T1 violation: %s adopted a revoked token", v)
			}
		}
	}
}

func (w *rpWorld) logf(format string, args ...any) {
	if w.verbose {
		w.trace = append(w.trace, fmt.Sprintf("%s ", w.f.clk.Format("01-02 15:04:05"))+fmt.Sprintf(format, args...))
	}
}

// hook sets side s's relay stub to the simulated clock and relay checks.
func (w *rpWorld) hook(s int) {
	r := w.f.d[s].relay
	r.mu.Lock()
	r.now = func() time.Time { return w.f.clk }
	r.check = func(mailbox, token string) error { return w.check(s, mailbox, token) }
	r.mu.Unlock()
}

// check is the relay's judgement of a deposit by side s (RELAY-PROTOCOL
// §5.3): injected failures, then the token (exp, revocation, quota).
func (w *rpWorld) check(s int, mailbox, token string) error {
	if w.fail[s] > 0 {
		w.fail[s]--
		if w.fail429[s] {
			return &relayclient.Error{Status: 429, Code: "rate_limited"}
		}
		return &relayclient.Error{Status: 503, Code: "unavailable"}
	}
	o := 1 - s
	if mailbox != w.mbox[o] {
		return nil
	}
	c, err := relayauth.ParseToken(token, w.pub[o])
	if err != nil {
		return nil // not a token this relay judges (an open token, a placeholder)
	}
	refuse := func(st int, code string) error {
		w.refused[code]++
		w.logf("relay: %d's deposit refused %s", s, code)
		return &relayclient.Error{Status: st, Code: code}
	}
	if !w.f.clk.Before(c.Exp) {
		return refuse(401, CodeTokenExpired)
	}
	or := w.f.d[o].relay
	for _, x := range or.revoked {
		if x == "jti:"+c.Jti || x == "sub:"+c.Sub {
			return refuse(403, CodeTokenRevoked)
		}
	}
	if q := c.Quota; q != nil && q.Msgs != nil {
		if w.quota[c.Jti] >= *q.Msgs {
			return refuse(429, CodeQuotaExceeded)
		}
		w.quota[c.Jti]++
	}
	return nil
}

// typeOf decodes what side s deposited: a sealed-mode handshake message,
// or a session message opened with s's own send keys.
func (w *rpWorld) typeOf(s int, payload []byte) string {
	env, err := envelope.Parse(payload)
	if err != nil {
		return "?"
	}
	if env.Mode() == envelope.ModeSealed {
		return "sealed(hs.init|hs.resp)"
	}
	if w.locked[s] || w.f.m(s).st == nil {
		return "session"
	}
	kr := w.f.m(s).sessions[w.f.id[s]]
	if kr == nil {
		return "session"
	}
	for _, ep := range []*handshake.Epoch{kr.Current(), kr.Pending()} {
		if ep == nil {
			continue
		}
		if in, err := ep.OpenSent(env); err == nil {
			return in.Type
		}
	}
	return "session(hs.fin or older epoch)"
}

// pull moves side s's deposits for the other side into its mailbox.
func (w *rpWorld) pull(s int) {
	o := 1 - s
	if !w.locked[s] {
		m := w.f.m(s)
		m.mu.Lock()
		_ = m.flushThenDrain(context.Background())
		m.mu.Unlock()
	}
	r := w.f.d[s].relay
	r.mu.Lock()
	deps := r.deposits
	r.deposits = nil
	r.mu.Unlock()
	opk := w.pub[o]
	for _, d := range deps {
		if d.mailbox != w.mbox[o] {
			continue
		}
		jti := ""
		if c, err := relayauth.ParseToken(d.token, opk); err == nil {
			jti = c.Jti
		}
		w.n++
		typ := w.typeOf(s, d.payload)
		w.hasher = append(w.hasher, fmt.Sprintf("dep %d m%08d %s %s", s, w.n, typ, w.f.clk.Format(time.RFC3339)))
		w.q[o] = append(w.q[o], rpMsg{m: Message{MsgID: fmt.Sprintf("m%08d", w.n), Sender: relayauth.EncodeKey(w.pub[s]), JTI: jti,
			Payload: d.payload, DepositedAt: w.f.clk.UTC().Format(time.RFC3339Nano)}, at: w.f.clk, from: s, typ: typ})
	}
}

func (w *rpWorld) pullBoth() { w.pull(0); w.pull(1) }

// expire drops what the relay held 14 days (T).
func (w *rpWorld) expire() {
	for s := 0; s < 2; s++ {
		kept := w.q[s][:0]
		for _, x := range w.q[s] {
			if w.f.clk.Sub(x.at) < 14*24*time.Hour {
				kept = append(kept, x)
			} else {
				w.expired++
				d := fmt.Sprintf("%s %s from %d (deposited %s) dropped at T", x.m.MsgID, x.typ, x.from, x.at.Format("01-02 15:04"))
				w.drops = append(w.drops, w.f.clk.Format("01-02 15:04 ")+d)
				w.logf("relay: %s", d)
			}
		}
		w.q[s] = kept
	}
}

// collect hands side s up to max waiting messages in one batch;
// redeliver leaves them leased (delivered again later); reorder swaps
// two of them.
func (w *rpWorld) collect(s, max int, redeliver, reorder bool, rng *rand.Rand) {
	if w.locked[s] {
		return
	}
	w.expire()
	k := min(max, len(w.q[s]))
	batch := make([]Message, 0, k)
	for _, x := range w.q[s][:k] {
		batch = append(batch, x.m)
	}
	if reorder && k > 1 {
		i, j := rng.IntN(k), rng.IntN(k)
		batch[i], batch[j] = batch[j], batch[i]
	}
	if !redeliver {
		w.q[s] = w.q[s][k:]
	}
	if err := w.f.m(s).ProcessBatch(context.Background(), &fakeCollector{}, batch); err != nil {
		w.logf("side %d: batch error %v: restart", s, err)
		w.crash(s)
	}
	w.pullBoth()
}

// advanceLive moves the clock by d. An unlocked vault collects
// continuously (vault/inbound.go Manager.Run: a long-poll of about 25 s,
// retries at most about 15 s apart; GC #6206), so a jump longer than a day
// is made in steps of at most a day, and after each step every unlocked
// side collects what waits for it and ticks. "Not collecting" is modelled
// only as a lock (the lead, GC #6449): before this, a 30-day jump with both
// sides unlocked let messages expire at the relay unread (seed
// 14735564589240170962).
func (w *rpWorld) advanceLive(d time.Duration) {
	const step = 24 * time.Hour
	for d > step {
		w.f.advance(step)
		d -= step
		for s := 0; s < 2; s++ {
			if w.locked[s] {
				continue
			}
			for i := 0; i < 20 && len(w.q[s]) > 0; i++ {
				w.collect(s, 32, false, false, nil)
			}
			w.tick(s)
		}
	}
	w.f.advance(d)
}

func (w *rpWorld) tick(s int) {
	if w.locked[s] {
		return
	}
	if err := w.f.m(s).ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		w.logf("side %d: tick error %v: restart", s, err)
		w.crash(s)
	}
	w.pullBoth()
}

// open unlocks side s from the store, as r29Fx.restart does after a lock.
func (w *rpWorld) open(s int) {
	f := w.f
	d := f.d[s]
	old := d.relay
	m, _, err := d.unlock(testPIN, 0, 0)
	if err != nil {
		w.t.Fatalf("side %d: unlock: %v", s, err)
	}
	d.m = m
	old.mu.Lock()
	d.relay.mu.Lock()
	d.relay.deposits, d.relay.revoked, d.relay.claims, d.relay.blobs = old.deposits, old.revoked, old.claims, old.blobs
	d.relay.mu.Unlock()
	old.mu.Unlock()
	m.now = func() time.Time { return f.clk }
	m.register(TypeSpec{Type: "test.note", From: []string{KindConnection}, Connections: PeersBoth},
		HandlerFunc(func(_ context.Context, _ *Session, in *envelope.Inner) (json.RawMessage, error) {
			f.got[s] = append(f.got[s], string(in.Body))
			return nil, nil
		}))
	m.features = append(m.features, f.sink[s])
	w.hook(s)
	if w.locked[s] {
		w.maxLock = max(w.maxLock, f.clk.Sub(w.lockAt[s]))
		w.locks[s] = append(w.locks[s], [2]time.Time{w.lockAt[s], f.clk})
	}
	w.locked[s] = false
	w.pullBoth()
}

func (w *rpWorld) lock(s int) {
	if w.locked[s] {
		return
	}
	if err := w.f.m(s).Lock(context.Background()); err != nil {
		w.logf("side %d: lock: %v", s, err)
	}
	w.pull(s)
	w.locked[s], w.lockAt[s] = true, w.f.clk
}

// crash ends side s without its last unwritten changes and opens it again
// from the store.
func (w *rpWorld) crash(s int) {
	if !w.locked[s] {
		w.pull(s)
		w.f.m(s).Crash()
	}
	w.open(s) // a locked side's lock ends here (counted in maxLock)
}

func (w *rpWorld) do(s int, fn func(m *Manager, p *Peer)) {
	if w.locked[s] {
		return
	}
	m := w.f.m(s)
	m.mu.Lock()
	fn(m, w.f.p(s))
	_ = m.flushThenDrain(context.Background())
	m.mu.Unlock()
	w.pullBoth()
}

func (w *rpWorld) exec(a rpAction, rng *rand.Rand) {
	s := a.A % 2
	w.logf("== %s", a)
	w.hasher = append(w.hasher, fmt.Sprintf("act %s %s", a, w.f.clk.Format(time.RFC3339)))
	switch a.Op {
	case rpRotate:
		if w.locked[s] {
			return
		}
		w.rot[s] = append(w.rot[s], w.f.clk)
		w.do(s, func(m *Manager, _ *Peer) {
			now := w.f.clk
			switch a.B % 3 {
			case 0: // credential.rotate
				if err := m.session(now).RotateIdentity(); err != nil {
					w.logf("rotate: %v", err)
				}
			case 1: // a transfer's rotation
				m.st.RotationOwed = &RotationOwed{Transfer: "t" + strconv.Itoa(w.n), At: now.Add(-8 * 24 * time.Hour), DEKVersion: m.dekVersion()}
				m.retryOwedRotation(now)
			case 2: // a recovery's
				m.st.RotationOwed = &RotationOwed{Recovery: "r" + strconv.Itoa(w.n)}
				m.retryOwedRotation(now)
			}
		})
	case rpSend:
		w.do(s, func(m *Manager, p *Peer) {
			m.sendTo(p, "test.note", json.RawMessage(`{"n":"x"}`), w.f.clk)
		})
	case rpCollect:
		w.collect(s, rpCollectMax(a.B), a.N%10 == 0, a.N%7 == 0, rng)
	case rpTick:
		w.tick(s)
	case rpTime:
		w.advanceLive(rpJumps[a.N%len(rpJumps)])
	case rpLock:
		w.lock(s)
	case rpUnlock:
		if w.locked[s] {
			w.open(s)
		}
	case rpCrash:
		w.crash(s)
	case rpFault:
		w.fail[s], w.fail429[s] = 1+a.N%3, a.B%2 == 0
	}
}

// quiesce: both unlocked, no injected failure, everything delivered, and
// time past every bound (B, the handshake lifetimes, token refreshes).
func (w *rpWorld) quiesce() {
	w.logf("== quiesce")
	for s := 0; s < 2; s++ {
		w.fail[s] = 0
		if w.locked[s] {
			w.open(s)
		}
	}
	steps := []time.Duration{time.Minute, time.Minute, time.Hour, time.Hour}
	for range 70 {
		steps = append(steps, 24*time.Hour)
	}
	for _, d := range steps {
		for i := 0; i < 20 && (len(w.q[0]) > 0 || len(w.q[1]) > 0); i++ {
			w.collect(0, 32, false, false, nil)
			w.collect(1, 32, false, false, nil)
		}
		w.tick(0)
		w.tick(1)
		w.watchAdoption("quiesce")
		w.f.advance(d)
	}
	for i := 0; i < 20 && (len(w.q[0]) > 0 || len(w.q[1]) > 0); i++ {
		w.collect(0, 32, false, false, nil)
		w.collect(1, 32, false, false, nil)
	}
}

// rapid: 3 or more key changes within 2 hours on a side.
func (w *rpWorld) rapid() bool {
	for s := 0; s < 2; s++ {
		ts := w.rot[s]
		for i := 0; i+2 < len(ts); i++ {
			if ts[i+2].Sub(ts[i]) <= 2*time.Hour {
				return true
			}
		}
	}
	return false
}

// lockShape: whether both sides had locks longer than T that overlapped
// (the hs.confirm re-send worst case, the 0.88.1 residual the owner
// accepted), or a single side's lock longer than T.
func (w *rpWorld) lockShape() (overlapping, single bool) {
	const T = 14 * 24 * time.Hour
	var long [2][][2]time.Time
	for s := 0; s < 2; s++ {
		for _, iv := range w.locks[s] {
			if iv[1].Sub(iv[0]) > T {
				long[s] = append(long[s], iv)
			}
		}
	}
	for s := 0; s < 2; s++ {
		for _, a := range long[s] {
			hit := false
			for _, b := range long[1-s] {
				if a[0].Before(b[1]) && b[0].Before(a[1]) {
					hit = true
				}
			}
			if hit {
				overlapping = true
			} else {
				single = true
			}
		}
	}
	return overlapping, single
}

// lockClass: a failure's class when long locks explain it.
func (w *rpWorld) lockClass() string {
	switch over, single := w.lockShape(); {
	case over && !single:
		return "residual:overlapping-locks"
	case single:
		return "lock>T:single"
	}
	return ""
}

// verdict classifies the end state ("" for converged).
func (w *rpWorld) verdict() string {
	f := w.f
	if len(w.violations) > 0 {
		return "violation:R29-T1 adopted-revoked " + w.violations[0]
	}
	var p [2]*Peer
	for s := 0; s < 2; s++ {
		p[s] = f.p(s)
		if p[s] == nil {
			return fmt.Sprintf("record-gone:%d", s)
		}
	}
	for s := 0; s < 2; s++ {
		if p[s].suspended() {
			return fmt.Sprintf("suspend:%d", s)
		}
	}
	var stale []string
	for s := 0; s < 2; s++ {
		if p[s].State == PeerStale {
			stale = append(stale, strconv.Itoa(s))
		}
	}
	if len(stale) > 0 {
		by := []string{}
		for _, c := range []string{CodeQuotaExceeded, CodeTokenRevoked, CodeTokenExpired} {
			if w.refused[c] > 0 {
				by = append(by, c)
			}
		}
		tag := strings.Join(stale, ",")
		switch {
		case w.refused[CodeQuotaExceeded] > 0 && w.rapid():
			return "residual:rapid-rotation"
		case w.lockClass() != "":
			return w.lockClass()
		case len(by) > 0:
			tag += " after " + strings.Join(by, "+")
		}
		if w.expired > 0 {
			tag += " (relay TTL drops)"
		}
		return "stale:" + tag
	}
	var why []string
	if !bytes.Equal(f.cur(0), f.cur(1)) {
		why = append(why, "epoch")
	}
	for s := 0; s < 2; s++ {
		o := 1 - s
		if !bytes.Equal(p[s].IK, f.m(o).keys.ik.Public().(ed25519.PublicKey)) {
			why = append(why, fmt.Sprintf("ik@%d", s))
		}
		if p[s].Pending != nil {
			why = append(why, fmt.Sprintf("pending@%d", s))
		}
		for _, og := range f.m(s).st.Outgoing {
			if og.PeerID == p[s].ID {
				why = append(why, fmt.Sprintf("outgoing-%s@%d", og.Purpose, s))
			}
		}
		for _, aw := range f.m(s).st.Awaiting {
			if aw.PeerID == p[s].ID {
				why = append(why, fmt.Sprintf("answer-%s@%d", aw.Purpose, s))
			}
		}
		for _, e := range f.m(s).st.Outbox {
			if !e.Done && e.Held != nil && e.PeerID == p[s].ID {
				why = append(why, fmt.Sprintf("held@%d", s))
				break
			}
		}
		if !f.clk.Before(p[s].Standing.Exp) {
			why = append(why, fmt.Sprintf("token@%d", s))
		}
		if f.m(s).currentDemoted(p[s]) {
			why = append(why, fmt.Sprintf("demoted@%d", s))
		}
		if f.m(s).carriedWait(p[s], f.clk) {
			// I1 (0.88.2, R29-T1): no carried tokens awaiting adoption.
			why = append(why, fmt.Sprintf("carried@%d", s))
		}
	}
	if len(why) > 0 {
		if c := w.lockClass(); c != "" {
			return c + " (not converged)"
		}
		return "diverged:" + strings.Join(why, ",")
	}
	return ""
}

func (w *rpWorld) dumpAudit() {
	for s := 0; s < 2; s++ {
		var ev []string
		for _, a := range w.f.m(s).st.Audit {
			ev = append(ev, a.Event)
		}
		w.trace = append(w.trace, fmt.Sprintf("audit %d: %s", s, strings.Join(ev, " ")))
	}
}

// fingerprint hashes what the run did: its actions and deposits, every
// audit entry of both vaults, and the end epochs.
func (w *rpWorld) fingerprint() string {
	h := sha256.New()
	for _, x := range w.hasher {
		h.Write([]byte(x + "\n"))
	}
	for s := 0; s < 2; s++ {
		for _, a := range w.f.m(s).st.Audit {
			fmt.Fprintf(h, "%d %s %s %s\n", s, a.At.Format(time.RFC3339Nano), a.Event, a.PeerID)
		}
		fmt.Fprintf(h, "epoch %d %x\n", s, w.f.cur(s))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// rpRun runs one seed; it returns the verdict and, if verbose, the trace.
func rpRun(t *testing.T, rs uint64, steps int, burst, verbose bool) (string, []string) {
	v, tr, _ := rpRunFP(t, rs, steps, burst, verbose)
	return v, tr
}

// rpRunFP is rpRun with the run's fingerprint.
func rpRunFP(t *testing.T, rs uint64, steps int, burst, verbose bool) (string, []string, string) {
	cryptotest.SetGlobalRandom(t, rs)
	// A fixed start time from the seed: the fixtures are made at it, and
	// from then on everything runs on the run's clock.
	start := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(rs%(365*24*3600)) * time.Second)
	var fx *r29Fx
	fixtureNow = func() time.Time {
		if fx != nil {
			return fx.clk
		}
		return start
	}
	t.Cleanup(func() { fixtureNow = nil })
	f := newR29Fx(t)
	fx = f
	w := &rpWorld{t: t, f: f, quota: map[string]int64{}, refused: map[string]int{}, verbose: verbose}
	for s := 0; s < 2; s++ {
		w.pub[s], w.mbox[s] = f.pk(s), f.m(s).st.Relay.Mailbox
	}
	w.hook(0)
	w.hook(1)
	rng := rand.New(rand.NewPCG(rs, 7))
	w.watchAdoption("start")
	for i, a := range rpGen(rs, steps, burst) {
		w.exec(a, rng)
		w.watchAdoption(strconv.Itoa(i))
	}
	w.quiesce()
	v := w.verdict()
	if verbose {
		for s := 0; s < 2; s++ {
			w.trace = append(w.trace, fmt.Sprintf("locks %d: %v", s, w.locks[s]))
		}
		w.trace = append(w.trace, "relay TTL drops:")
		w.trace = append(w.trace, w.drops...)
		w.dumpAudit()
	}
	return v, w.trace, w.fingerprint()
}

func rpEnv(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

// TestR29RandomPairReplay: R29RP_SEEDS lists run seeds, each "seed" or
// "seed:b" (burst); each is run twice, and the verdicts and fingerprints
// compared.
func TestR29RandomPairReplay(t *testing.T) {
	list := os.Getenv("R29RP_SEEDS")
	if list == "" {
		t.Skip("R29RP_SEEDS not set")
	}
	steps, same := rpEnv("R29RP_STEPS", 40), 0
	var diff []string
	ss := strings.Split(list, ",")
	for _, x := range ss {
		burst := strings.HasSuffix(x, ":b")
		rs, err := strconv.ParseUint(strings.TrimSuffix(x, ":b"), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		var v [2]string
		var fp [2]string
		for i := 0; i < 2; i++ {
			t.Run(fmt.Sprintf("%s-%d", x, i), func(t *testing.T) { v[i], _, fp[i] = rpRunFP(t, rs, steps, burst, false) })
		}
		t.Logf("%-24s %-40q %s %s", x, v[0], fp[0], fp[1])
		if v[0] == v[1] && fp[0] == fp[1] {
			same++
		} else {
			diff = append(diff, x)
		}
	}
	t.Logf("%d of %d seeds replayed identically; differing: %v", same, len(ss), diff)
}

func TestR29RandomPair(t *testing.T) {
	steps, burst := rpEnv("R29RP_STEPS", 40), os.Getenv("R29RP_BURST") != ""
	if s := os.Getenv("R29RP_TRACE"); s != "" {
		rs, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		t.Run("trace", func(t *testing.T) {
			for _, a := range rpGen(rs, steps, burst) {
				t.Logf("action %s", a)
			}
			v, tr := rpRun(t, rs, steps, burst, true)
			t.Log("trace:\n" + strings.Join(tr, "\n"))
			t.Logf("verdict: %q", v)
		})
		// R29RP_REPEAT: replay the seed this many more times and tally the
		// verdicts (map iteration order is not seeded, so a replay can
		// differ).
		tally := map[string]int{}
		for i := 0; i < rpEnv("R29RP_REPEAT", 0); i++ {
			t.Run(fmt.Sprintf("repeat%d", i), func(t *testing.T) {
				v, _ := rpRun(t, rs, steps, burst, false)
				tally[v]++
			})
		}
		if len(tally) > 0 {
			t.Logf("replays: %v", tally)
		}
		return
	}
	runs := rpEnv("R29RP_RUNS", 0)
	if runs == 0 {
		t.Skip("R29RP_RUNS not set")
	}
	master := rand.New(rand.NewPCG(uint64(rpEnv("R29RP_SEED", 1)), 99))
	classes := map[string][]uint64{}
	start := time.Now()
	for i := 0; i < runs; i++ {
		rs := master.Uint64()
		var v string
		t.Run(fmt.Sprintf("run%d", i), func(t *testing.T) { v, _ = rpRun(t, rs, steps, burst, false) })
		if v == "" {
			v = "converged"
		}
		classes[v] = append(classes[v], rs)
	}
	el := time.Since(start)
	var ks []string
	for k := range classes {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	show := rpEnv("R29RP_SHOW", 5)
	for _, k := range ks {
		seeds := classes[k]
		var ss []string
		for _, s := range seeds[:min(show, len(seeds))] {
			ss = append(ss, strconv.FormatUint(s, 10))
		}
		t.Logf("%-50s %5d  e.g. %s", k, len(seeds), strings.Join(ss, " "))
	}
	t.Logf("%d runs (burst %v, steps %d) in %v: %v per 10,000", runs, burst, steps, el.Round(time.Second),
		(el * time.Duration(10000) / time.Duration(runs)).Round(time.Second))
}
