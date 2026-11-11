package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/vettid/vettid-vault/vms/peerwire"
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
// handshake, nothing held, a valid standing token each way, and (GC
// #7160, every mode) every test.note a side queued handled exactly once by
// the other, by inner id (note-lost@s, note-duplicate@s; notesLost). A
// note not handled is excused only if the relay dropped a copy of it at T
// and the run has a lock longer than T. No lock class absorbs a lost or
// duplicate note. An honest pair must not suspend, nor end stale, except
// the stated residuals, counted apart: rapid rotations (3 or more key
// changes within 2 hours on a side, ending by quota_exceeded), a lock
// longer than T, and a note told rather than delivered (rpToldResidual,
// rpCrashToldResidual). The quota-wait and lock-wait residuals are closed
// by card GC #6875's re-stamp at deposit. TestR29RandomPair fails when any
// run ends outside them (rpAccepted).
//
// Run: R29RP_RUNS=n go test -run TestR29RandomPair ./vault/
//   R29RP_SEED   the master seed (default 1)
//   R29RP_STEPS  at most this many random actions per run (default 40)
//   R29RP_BURST  set: each side first rotates 3 to 6 times in quick
//                succession
//   R29RP_TRACE  a run seed: replay that run alone, with its trace
//   R29RP_SHOW   how many seeds to list per failure class (default 5)
//   R29RP_LOSTANS set: an injected "503" fault is instead a deposit the
//                relay stores and whose answer is lost (a transport error):
//                the vault deposits it again, and the peer's inner-id dedupe
//                (§8.2) must absorb the copy (note-duplicate@s otherwise).
//   R29RP_SHUFFLE set: every collect takes its batch from anywhere in the
//                mailbox, in any order (cross-batch reordering, §8.4), and
//                a batch left unacked comes back in any later one
//   R29RP_REFRESH set: a connection's standing token has a quota of
//                rpStandingQuota deposits at the relay, and a low-weight
//                action (and quiescence) has a side refused for it ask for a
//                quota refresh (relay.token.refresh, §7.2; option A of
//                GC #6591: the denial by the collect jti and its spares).
//                Only test.note deposits (known by their bytes) spend it,
//                as an upload spends the byte quota, so the refresh itself
//                still fits; the refresh is asked by the harness, not by
//                the vault's deposit path (it tests the issuer's §7.2, not
//                the holder's trigger). Once quiet, a deposit still queued
//                for the peer or an unanswered refusal is quota-stuck@s.
//                The vault's own deposit path asks too (GC #6783): a note
//                refused for the token's quota waits for a fresh token,
//                letting the handshakes and the refresh pass; the two seeds
//                that ended quota-stuck before it (13894595740220335007,
//                9200229175364500436) are TestQuotaSeeds.
//   R29RP_SPENT  set (with R29RP_REFRESH): the production relay's answer
//                (RELAY-PROTOCOL 0.9.2 §7.1): every deposit under a
//                standing token spends its quota (rpSpentQuota), the
//                refusal carries `quota: token`, and once spent the token
//                refuses every deposit, the refresh included (its msgs
//                spent): the vault's reconnect at once (owner decision a,
//                GC #6840) is what recovers (the lead's review M2, #7027).
//                The quiet phase's housekeeping spends no quota (70 days of
//                re-mints and rekeys would spend a token of rpSpentQuota
//                every few weeks; the real quota is 20,000); a token spent
//                before stays spent. Every test.note must arrive
//                (note-lost@s). The vault often recovers without decision a
//                too (the issuer's re-mint within 16 days), so the search
//                is a weak check of it; the unit tests pin it.
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
	rpRefresh
	rpNumOps
)

var rpOpName = [...]string{"rotate", "send", "collect", "tick", "time", "lock", "unlock", "crash", "fault", "refresh"}

// rpWeight: the refresh action has weight 0 unless R29RP_REFRESH is set
// (rpWeights), so that the other modes draw the runs they always drew.
var rpWeight = [...]int{6, 8, 14, 6, 8, 3, 3, 2, 3, 0}

// rpRefreshWeight is the refresh action's weight under R29RP_REFRESH.
const rpRefreshWeight = 2

// rpStandingQuota is how many bulk messages (test.note) a connection's
// standing token may deposit at the harness relay under R29RP_REFRESH (the
// real quota, PeerQuotaMsgs, is never reached in a run).
const rpStandingQuota = 2

// rpSpentQuota is how many deposits of any kind a connection's standing
// token may make under R29RP_SPENT.
const rpSpentQuota = 24

// rpModes are the optional modes of a run.
type rpModes struct{ shuffle, refresh, spent, lost bool }

func rpEnvModes() rpModes {
	refresh := os.Getenv("R29RP_REFRESH") != ""
	return rpModes{shuffle: os.Getenv("R29RP_SHUFFLE") != "", refresh: refresh, spent: refresh && os.Getenv("R29RP_SPENT") != "",
		lost: os.Getenv("R29RP_LOSTANS") != ""}
}

func (md rpModes) weights() [rpNumOps]int {
	w := rpWeight
	if md.refresh {
		w[rpRefresh] = rpRefreshWeight
	}
	return w
}

// rpTotals sums what the modes did over the runs of a search (the summary).
var rpTotals struct {
	shuffled, shuffleRuns           int // messages delivered ahead of an older one; runs with any
	refreshes, refreshRuns, quotaed int // refreshes asked; runs with any; standing-quota refusals
	granted                         int // refreshes the issuer granted
	refusedRuns, spentRecs, recRuns int // R29RP_SPENT: runs with a refused quota refresh; reconnects after one; runs with any
}
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

func rpGen(rs uint64, steps int, burst bool, md rpModes) []rpAction {
	rng := rand.New(rand.NewPCG(rs, 3))
	rpWeight := md.weights()
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

// rpSeal is what a note deposit carried, judged when the relay saw it (the
// sender running, even in the drain of its own lock): its inner id and ts,
// and whether it was sealed under the sender's epoch current since that ts
// (no key change since it was sealed).
type rpSeal struct {
	id   string
	ts   time.Time
	same bool
}

// rpEpochSeen is a side's current epoch and when the harness first saw it.
type rpEpochSeen struct {
	id    []byte
	since time.Time
}

type rpMsg struct {
	m    Message
	at   time.Time
	from int
	typ  string // what the depositor sealed (decoded at deposit time)
	note string // a test.note's inner id ("" for any other message)
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
	spentJ  map[string]bool  // R29RP_SPENT: the standing tokens whose quota is spent (every deposit refused)
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
	// R29-T1 (0.88.2): the adoptions of a carried token its issuer had
	// already revoked, and the relay.token.issued stores of one
	// (judgeAdoption).
	violations    []string
	issuedRevoked int
	// the optional modes (R29RP_SHUFFLE, R29RP_REFRESH)
	md        rpModes
	srng      *rand.Rand      // the shuffle's, seeded from the run
	shuffled  int             // messages delivered ahead of an older one
	quotaHit  [2]bool         // side s's standing token refused for its quota since its last refresh
	notes     map[string]bool // R29RP_REFRESH: the sealed test.note deposits, by their bytes
	quotaed   int             // standing-quota refusals
	refreshes int             // quota refreshes asked
	qrrSeen   [2]int          // R29RP_SPENT: side s's quota_refresh_refused audits already followed by a reconnect deposit
	spentRecs int             // R29RP_SPENT: reconnect-token deposits that followed a refused quota refresh (decision a's path)
	quiet     bool            // in quiesce: R29RP_SPENT's housekeeping deposits do not spend a quota (the real one is 20,000)
	granted   int             // quota refreshes the issuer granted (its Refreshed stamp moved)
	// The note oracle (GC #7160, every mode): each test.note side s queued
	// (sent[s], by inner id) must be handled exactly once by the other side
	// (r29Fx.gotIDs): note-lost@s, note-duplicate@s.
	sent      [2][]string
	noteBytes map[string]string    // a note's bytes as queued -> its inner id
	epochAt   [2]rpEpochSeen       // side s's current epoch and since when (seen at each pull)
	ttlNote   map[string]bool      // a copy the relay dropped at T
	quotaNote map[string]bool      // a deposit of it refused for the standing quota (R29RP_REFRESH)
	quotaLast map[string]time.Time // when it was last refused for it
	sealed    map[string]rpSeal    // what each note deposit's bytes carried, seen at the relay (the sender live)
	lockNote  map[string]bool      // a copy accepted with no key change since its ts, after a lock of the sender's over 16 days since that ts
	staleNote map[string]bool      // a copy accepted with a ts over 16 days old, under an epoch current since that ts (no key change), after a standing-quota refusal of the sender's since that ts
	noteAhead map[string]string    // the note queued by the same side just before it (the entry ahead in the outbox, of the notes)
	fiveNote  map[string]bool      // a deposit of it answered an injected 5xx (possibly stored, to the vault)
	crashNote map[string]bool      // waiting in its sender's outbox when the sender crashed (#6875: possibly tried)
	lastRef   [2]time.Time
}

// rpIssuedRevokedRuns are the runs in which a side stored a revoked token
// from relay.token.issued (reported in the summary, not a verdict).
var rpIssuedRevokedRuns = map[string]bool{}

// judgeAdoption is R29-T1's oracle (0.88.2 §6.3.1 "A handshake's tokens
// are adopted at confirmation", "Revocation by the issuer"), called by the
// Adopt hook in the write in which side s starts to hold tok: the issuer
// (the other side) must not have revoked it already, judged by the
// issuer's own registry (Issued[].Denied, in memory, or its stored state
// while it is locked) and by the relay's denylist. A token revoked after it
// was adopted (a quota refresh) is not judged here.
//
// R29-T1 is about carried tokens (from "carried"). A relay.token.issued
// whose token the issuer revoked while it was in flight (a quota refresh
// after a near-end re-mint; Fable L1 of the code review, a follow-up) is
// counted in issuedRevoked, not as a violation; §8.6 handles its refusal.
func (w *rpWorld) judgeAdoption(s int, kind, tok, from string) {
	o := 1 - s
	c, err := relayauth.ParseToken(tok, w.pub[o])
	if err != nil {
		return
	}
	denied := false
	if st := w.f.m(o).st; st != nil && !w.locked[o] {
		for _, t := range st.Issued {
			if t.JTI == c.Jti && t.Denied {
				denied = true
			}
		}
	}
	r := w.f.d[o].relay
	r.mu.Lock()
	denied = denied || slices.Contains(r.revoked, "jti:"+c.Jti)
	r.mu.Unlock()
	if denied && from != "carried" {
		w.issuedRevoked++
		rpIssuedRevokedRuns[w.f.t.Name()] = true
		w.logf("side %d stored a revoked %s token from relay.token.issued", s, kind)
		return
	}
	if denied {
		v := fmt.Sprintf("%d:%s@%s", s, kind, w.f.clk.Format("01-02 15:04:05"))
		w.violations = append(w.violations, v)
		w.logf("R29-T1 violation: %s adopted a revoked token", v)
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
	r.checkPayload = func(mailbox, token string, payload []byte) error { return w.check(s, mailbox, token, payload) }
	r.mu.Unlock()
	w.f.m(s).opt.Hooks.Adopt = func(_, kind, tok, from string) { w.judgeAdoption(s, kind, tok, from) }
}

// check is the relay's judgement of a deposit by side s (RELAY-PROTOCOL
// §5.3): injected failures, then the token (exp, revocation, quota).
func (w *rpWorld) check(s int, mailbox, token string, payload []byte) error {
	w.seeNote(s, payload)
	if w.fail[s] > 0 {
		w.fail[s]--
		if w.fail429[s] {
			return &relayclient.Error{Status: 429, Code: "rate_limited"}
		}
		if w.md.lost {
			// R29RP_LOSTANS: stored, and the answer lost (a transport error).
			w.logf("relay: %d's deposit stored, its answer lost", s)
			return storedErr{err: errors.New("transport: connection reset after the relay stored it")}
		}
		if id := w.noteOf(s, payload); id != "" {
			w.fiveNote[id] = true
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
	if w.md.spent && c.Quota != nil && c.Quota.Msgs != nil && *c.Quota.Msgs == handshake.ReconnectTokenQuotaMsgs {
		// A reconnect's deposit after a refused quota refresh: decision a's
		// path reached (counted once per refusal).
		if n := w.f.auditCount(s, "quota_refresh_refused"); n > w.qrrSeen[s] {
			w.qrrSeen[s], w.spentRecs = n, w.spentRecs+1
		}
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
		limit := *q.Msgs
		// Under R29RP_REFRESH a standing token's quota is spent by the bulk
		// messages alone (test.note, as an attachment's upload spends the
		// byte quota): a small message, the refresh among them, still fits.
		standing := w.md.refresh && limit == PeerQuotaMsgs
		note := ""
		if standing {
			note = w.noteOf(s, payload)
			if w.md.spent && w.spentJ[c.Jti] {
				w.quotaed++
				w.quotaHit[s] = true
				if note != "" {
					w.quotaNote[note] = true
					w.quotaLast[note] = w.f.clk
				}
				w.logf("relay: %d's deposit refused %s (standing quota spent) note %q", s, CodeQuotaExceeded, note)
				return &relayclient.Error{Status: 429, Code: CodeQuotaExceeded, Quota: relayclient.QuotaToken}
			}
			if w.md.spent {
				// Every deposit spends it (Fable, #7043): an hs.fin or a
				// rekey's traffic can be the first refusal. Not the quiet
				// phase's housekeeping (70 days of re-mints and rekeys
				// would spend a token of rpSpentQuota every few weeks, the
				// real one 20,000); a token spent before stays spent.
				if w.quiet {
					return nil
				}
				limit = rpSpentQuota
			} else if note == "" && !w.notes[string(payload)] {
				return nil
			} else {
				limit = rpStandingQuota
			}
		}
		if w.quota[c.Jti] >= limit {
			if standing {
				// Counted apart: a reconnect token's quota_exceeded is what the
				// rapid-rotation residual is judged by, never this one.
				w.quotaed++
				w.quotaHit[s] = true
				if note != "" {
					w.quotaNote[note] = true
					w.quotaLast[note] = w.f.clk
				}
				w.logf("relay: %d's deposit refused %s (standing quota) note %q", s, CodeQuotaExceeded, note)
				if w.md.spent {
					w.spentJ[c.Jti] = true
					return &relayclient.Error{Status: 429, Code: CodeQuotaExceeded, Quota: relayclient.QuotaToken}
				}
				return &relayclient.Error{Status: 429, Code: CodeQuotaExceeded}
			}
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

// noteInner opens side s's deposit with its own send keys (current or
// pending epoch): the inner and the epoch's id, or nil.
func (w *rpWorld) noteInner(s int, payload []byte) (*envelope.Inner, []byte) {
	env, err := envelope.Parse(payload)
	if err != nil || env.Mode() != envelope.ModeSession || w.f.m(s).st == nil {
		return nil, nil
	}
	kr := w.f.m(s).sessions[w.f.id[s]]
	if kr == nil {
		return nil, nil
	}
	for _, ep := range []*handshake.Epoch{kr.Current(), kr.Pending()} {
		if ep == nil {
			continue
		}
		if in, err := ep.OpenSent(env); err == nil {
			id := ep.ID()
			return in, id[:]
		}
	}
	return nil, nil
}

// seeNote records a test.note deposit side s is making (the relay's check:
// the vault is running, also in the drain of its own lock): its bytes, so
// that a copy re-sealed since it was queued is still known by them later
// (the lead's re-check Low 1), and what it carried (rpSeal).
func (w *rpWorld) seeNote(s int, payload []byte) {
	in, ep := w.noteInner(s, payload)
	if in == nil || in.Type != "test.note" {
		return
	}
	w.seeEpochLive(s)
	w.noteBytes[string(payload)] = in.ID
	w.sealed[string(payload)] = rpSeal{id: in.ID, ts: in.TS,
		same: bytes.Equal(ep, w.epochAt[s].id) && !w.epochAt[s].since.After(in.TS)}
}

// noteOf is the inner id of side s's test.note deposit: by its bytes (as
// queued, or as seen at the relay) or opened, else "".
func (w *rpWorld) noteOf(s int, payload []byte) string {
	if id, ok := w.noteBytes[string(payload)]; ok {
		return id
	}
	if in, _ := w.noteInner(s, payload); in != nil && in.Type == "test.note" {
		return in.ID
	}
	return ""
}

// noteAccepted is noteOf for a deposit the relay accepted; it records a
// copy sealed under side s's epoch current since its ts (no key change since
// it was sealed: a key change re-seals it with a fresh ts, 0.88.7 §8.3)
// that waited behind the standing quota. Whether the peer refused it for
// its ts is the peer's stale_or_future with its id (notesLost), not judged
// here.
func (w *rpWorld) noteAccepted(s int, payload []byte) string {
	id := w.noteOf(s, payload)
	if id == "" {
		return ""
	}
	sl, ok := w.sealed[string(payload)]
	if !ok {
		w.logf("note %s from %d accepted, sealed under an epoch since replaced", id, s)
		return id
	}
	same := sl.same
	w.logf("note %s from %d accepted: ts %s, no key change since %v", id, s, sl.ts.Format("01-02 15:04"), same)
	// Behind the standing quota: this note refused for it, or the note
	// queued just before it to that mailbox (which held it in the outbox's
	// order; a token-carrying deposit may pass between them, §8.4). The lead's
	// review L-b; this residual goes once #216 (the quota wait) and #6875
	// (the 16-day re-stamp at deposit) land.
	// The note ahead's refusal counts only if it came after this note's ts
	// (the lead's re-check Low 2).
	ahead := w.noteAhead[id]
	waited := w.quotaNote[id] || ahead != "" && w.quotaNote[ahead] && !w.quotaLast[ahead].Before(sl.ts)
	if same && waited {
		w.staleNote[id] = true
	}
	// The sender itself locked for over 16 days since the note's ts, with
	// no key change: deposited at its unlock with that ts (#6875's re-stamp
	// at deposit ends it).
	for _, iv := range w.locks[s] {
		if same && !iv[0].Before(sl.ts) && iv[1].Sub(iv[0]) > envelope.MaxDurableAge {
			w.lockNote[id] = true
		}
	}
	return id
}

// seeEpoch records side s's current epoch, and when it was first seen.
func (w *rpWorld) seeEpoch(s int) {
	if w.locked[s] {
		return
	}
	w.seeEpochLive(s)
}

// seeEpochLive is seeEpoch while side s's vault runs (also in its lock's
// drain).
func (w *rpWorld) seeEpochLive(s int) {
	if w.f.m(s).st == nil {
		return
	}
	kr := w.f.m(s).sessions[w.f.id[s]]
	if kr == nil || kr.Current() == nil {
		return
	}
	id := kr.Current().ID()
	if !bytes.Equal(id[:], w.epochAt[s].id) {
		w.epochAt[s] = rpEpochSeen{id: append([]byte(nil), id[:]...), since: w.f.clk}
	}
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
	w.seeEpoch(s)
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
		note := w.noteAccepted(s, d.payload)
		w.hasher = append(w.hasher, fmt.Sprintf("dep %d m%08d %s %s", s, w.n, typ, w.f.clk.Format(time.RFC3339)))
		w.q[o] = append(w.q[o], rpMsg{m: Message{MsgID: fmt.Sprintf("m%08d", w.n), Sender: relayauth.EncodeKey(w.pub[s]), JTI: jti,
			Payload: d.payload, DepositedAt: w.f.clk.UTC().Format(time.RFC3339Nano)}, at: w.f.clk, from: s, typ: typ, note: note})
	}
}

func (w *rpWorld) pullBoth() {
	w.pull(0)
	w.pull(1)
	if w.md.refresh {
		w.noteGrants()
	}
}

// noteGrants counts the quota refreshes each side granted: its stamp of
// the last one (§7.2, at most one in 24 hours) moved.
func (w *rpWorld) noteGrants() {
	for s := 0; s < 2; s++ {
		if w.locked[s] {
			continue
		}
		m := w.f.m(s)
		if m == nil || m.st == nil {
			continue
		}
		p := w.f.p(s)
		if p == nil {
			continue
		}
		if t, ok := m.st.attach().Refreshed[p.ID]; ok && !t.Equal(w.lastRef[s]) {
			w.granted++
			w.lastRef[s] = t
		}
	}
}

// expire drops what the relay held 14 days (T).
func (w *rpWorld) expire() {
	for s := 0; s < 2; s++ {
		kept := w.q[s][:0]
		for _, x := range w.q[s] {
			if w.f.clk.Sub(x.at) < 14*24*time.Hour {
				kept = append(kept, x)
			} else {
				w.expired++
				if x.note != "" {
					w.ttlNote[x.note] = true
				}
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
	if w.md.shuffle && k > 0 {
		// Cross-batch: k messages from anywhere in the mailbox, in any order.
		pick := w.srng.Perm(len(w.q[s]))[:k]
		taken := map[int]bool{}
		for _, i := range pick {
			taken[i] = true
		}
		for _, i := range pick {
			batch = append(batch, w.q[s][i].m)
			for j := 0; j < i; j++ {
				if !taken[j] {
					w.shuffled++ // delivered ahead of an older one still waiting
					break
				}
			}
		}
		if !redeliver {
			kept := w.q[s][:0]
			for i, x := range w.q[s] {
				if !taken[i] {
					kept = append(kept, x)
				}
			}
			w.q[s] = kept
		}
	} else {
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
			f.handled(s, in)
			return nil, nil
		}))
	m.features = append(m.features, f.sink[s])
	w.hook(s)
	startWrite(m)
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
		// Card GC #6875: what waits at a crash is taken as possibly tried
		// at the restart (no clean end), so it is told, not stamped again.
		m := w.f.m(s)
		m.mu.Lock()
		for _, e := range m.stOutbox() {
			// As State.init marks: a waiting deposit with a payload (a held
			// entry is sealed again, never marked).
			if !e.Done && e.Op == OpDeposit && e.InnerID != "" && len(e.Payload) > 0 && e.Held == nil {
				if w.crashNote == nil {
					w.crashNote = map[string]bool{}
				}
				w.crashNote[e.InnerID] = true
			}
		}
		m.mu.Unlock()
		m.Crash()
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
			n := len(m.st.Outbox)
			if id := m.sendTo(p, "test.note", json.RawMessage(`{"n":"x"}`), w.f.clk); id != "" {
				if n := len(w.sent[s]); n > 0 {
					w.noteAhead[id] = w.sent[s][n-1]
				}
				w.sent[s] = append(w.sent[s], id)
				if len(m.st.Outbox) > n {
					if e := m.st.Outbox[len(m.st.Outbox)-1]; len(e.Payload) > 0 {
						w.noteBytes[string(e.Payload)] = id
					}
				}
			}
			if w.md.refresh && len(m.st.Outbox) > n {
				// Known by its bytes, not by opening it: a note sealed under
				// an epoch since replaced must still spend the quota.
				if w.notes == nil {
					w.notes = map[string]bool{}
				}
				w.notes[string(m.st.Outbox[len(m.st.Outbox)-1].Payload)] = true
			}
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
	case rpRefresh:
		w.refresh(s)
	}
}

// refresh: side s, refused for its standing token's quota, asks the other
// for a fresh one (§7.2), as the vault's own path does (attAskToken).
func (w *rpWorld) refresh(s int) {
	if !w.quotaHit[s] || w.locked[s] {
		return
	}
	w.quotaHit[s] = false
	w.do(s, func(m *Manager, p *Peer) {
		if p == nil || m.requestPending(p.ID, tokenRefreshType) {
			return
		}
		if id := m.sendTo(p, tokenRefreshType, peerwire.TokenRefreshBody(), w.f.clk); id != "" {
			m.requests[id] = p.ID
			m.requestTypes[id] = tokenRefreshType
			w.refreshes++
			w.logf("side %d: quota refresh asked", s)
		}
	})
}

// quiesce: both unlocked, no injected failure, everything delivered, and
// time past every bound (B, the handshake lifetimes, token refreshes).
func (w *rpWorld) quiesce() {
	w.logf("== quiesce")
	w.quiet = true
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
		if w.md.refresh {
			w.refresh(0) // a side still refused for its quota asks again
			w.refresh(1)
		}
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

// rpAccepted reports whether a run's class is one of the stated residuals,
// counted apart and not a failure of the search: the "residual:" classes
// (rapid rotations ending by quota_exceeded, overlapping long locks) and a
// single lock longer than T ("lock>T:single", converged or not).
func rpAccepted(class string) bool {
	return strings.HasPrefix(class, "residual:") || strings.HasPrefix(class, "lock>T:single")
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
	// A note handled twice fails whatever else the run did (a stale end
	// included, which keeps its undelivered notes).
	lost, residual := w.notesLost()
	if slices.ContainsFunc(lost, func(x string) bool { return strings.HasPrefix(x, "note-duplicate") }) {
		return "diverged:" + strings.Join(lost, ",")
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
		// A run that ends stale (the #217 review, Opus L4) still accounts
		// for every note: handled once, still waiting in its sender's
		// outbox, or told (drop.undelivered_* with its id); else lost,
		// whatever the stale class. Case (a), the pending-reconnect
		// abandonment: markStale abandons the vault's pending reconnect
		// epoch, and the notes waiting behind it stay in the outbox (kept,
		// 0.88.7 "Stale is not final"): waiting, not lost.
		if why := w.notesUnaccounted(); len(why) > 0 {
			return "diverged:" + strings.Join(why, ",")
		}
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
		if w.md.refresh {
			// A standing-quota refusal is retried, so its note stays in the
			// outbox: once quiet, every deposit to the peer must have got
			// through and no refusal may be left unanswered by a refresh.
			stuck := w.quotaHit[s]
			for _, e := range f.m(s).st.Outbox {
				if !e.Done && e.Held == nil && e.Op == OpDeposit && e.PeerID == p[s].ID {
					stuck = true
					break
				}
			}
			if stuck {
				why = append(why, fmt.Sprintf("quota-stuck@%d", s))
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
	if len(lost) > 0 {
		// Never absorbed by a lock class (the lead's review M2).
		return "diverged:" + strings.Join(append(why, lost...), ",")
	}
	if len(why) > 0 {
		if c := w.lockClass(); c != "" {
			return c + " (not converged)"
		}
		return "diverged:" + strings.Join(why, ",")
	}
	return residual
}

// rpToldResidual: a run whose only fault is a test.note answered a 5xx
// (which may have been stored, 0.88.7 §8.3), then re-sealed at a key change
// with its kept ts past 16 days, so not deposited and told
// (drop.undelivered_window: "may or may not have been delivered", card GC
// #6875's notice). The harness's 503 stores nothing, so the note is in fact
// lost, as the vault cannot know. Counted apart, accepted.
const rpToldResidual = "residual:told-after-5xx (#6875)"

// rpCrashToldResidual: a run whose only fault is a test.note waiting in its
// sender's outbox at a crash, taken as possibly tried at the restart (card
// GC #6875: a crash leaves no clean end, so a Tried may have been lost),
// and so ended past 16 days as undelivered_window, told ("may not have
// been delivered") rather than stamped again (which could make the peer
// run it twice). Counted apart, accepted.
const rpCrashToldResidual = "residual:told-after-crash (#6875)"

// notesUnaccounted is the note oracle for a run that ends stale: a note
// not handled must still wait in its sender's outbox or have been told
// (drop.undelivered_* with its id), unless excused as notesLost excuses.
func (w *rpWorld) notesUnaccounted() (why []string) {
	lost, _ := w.notesLost()
	if len(lost) == 0 {
		return nil
	}
	over, single := w.lockShape()
	for s := 0; s < 2; s++ {
		o := 1 - s
		got := w.f.handledIDs(o)
		m := w.f.m(s)
		bad := false
		for _, id := range w.sent[s] {
			if got[id] > 0 || w.ttlNote[id] && (over || single) {
				continue
			}
			waiting, told := false, false
			for _, e := range m.st.Outbox {
				if !e.Done && (e.InnerID == id || heldID(e.Held) == id) {
					waiting = true
				}
			}
			for _, a := range m.st.Audit {
				if a.Ref == id && strings.HasPrefix(a.Event, "undelivered_") {
					told = true
				}
			}
			if !waiting && !told {
				bad = true
				w.logf("note %s from %d unaccounted at a stale end", id, s)
			}
		}
		if bad {
			why = append(why, fmt.Sprintf("note-lost@%d", s))
		}
	}
	for _, x := range lost {
		if strings.HasPrefix(x, "note-duplicate") {
			why = append(why, x)
		}
	}
	return why
}

// notesLost is the note oracle (GC #7160, every mode): each test.note side
// s queued is handled exactly once by the other side, by inner id. One not
// handled is excused only if the relay dropped a copy of it at T and the
// run has a lock longer than T (the lock residual); or if it was answered
// a 5xx, or was waiting at a crash, and its sender audited
// undelivered_window, or unconfirmed_late at its deposit (told:
// rpToldResidual, rpCrashToldResidual).
func (w *rpWorld) notesLost() (why []string, residual string) {
	told, crashTold := false, false // quota-wait and lock-wait are no longer excused (#6875)
	over, single := w.lockShape()
	for s := 0; s < 2; s++ {
		o := 1 - s
		lost, dup := false, false
		got := w.f.handledIDs(o)
		for _, id := range w.sent[s] {
			switch n := got[id]; {
			case n > 1:
				dup = true
			case n == 1:
			case w.ttlNote[id] && (over || single):
			// The quota-wait and lock-wait residuals are no longer excused:
			// card GC #6875's re-stamp at deposit closes both (a note that
			// waited past 16 days with no key change and no attempt is
			// sealed again with a fresh ts), so such a loss is a loss.
			case w.fiveNote[id] && w.toldRef(s, id):
				told = true
			case w.crashNote[id] && w.toldRef(s, id):
				crashTold = true
			default:
				lost = true
				w.logf("note %s from %d lost: ttl %v quota %v stale-copy %v", id, s, w.ttlNote[id], w.quotaNote[id], w.staleNote[id])
			}
		}
		if lost {
			why = append(why, fmt.Sprintf("note-lost@%d", s))
		}
		if dup {
			why = append(why, fmt.Sprintf("note-duplicate@%d", s))
		}
	}
	switch {
	case told:
		residual = rpToldResidual
	case crashTold:
		residual = rpCrashToldResidual
	}
	return why, residual
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

// rpRunModes is the mode set every run of this process uses (from the env).
var rpRunModes = rpEnvModes()

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
	f.notesInState = true
	fx = f
	w := &rpWorld{t: t, f: f, quota: map[string]int64{}, spentJ: map[string]bool{}, refused: map[string]int{}, verbose: verbose, md: rpRunModes,
		noteBytes: map[string]string{}, noteAhead: map[string]string{},
		ttlNote: map[string]bool{}, quotaNote: map[string]bool{}, staleNote: map[string]bool{}, fiveNote: map[string]bool{},
		crashNote: map[string]bool{},
		quotaLast: map[string]time.Time{}, sealed: map[string]rpSeal{}, lockNote: map[string]bool{},
		srng: rand.New(rand.NewPCG(rs, 11))}
	for s := 0; s < 2; s++ {
		w.pub[s], w.mbox[s] = f.pk(s), f.m(s).st.Relay.Mailbox
	}
	w.hook(0)
	w.hook(1)
	rng := rand.New(rand.NewPCG(rs, 7))
	for _, a := range rpGen(rs, steps, burst, w.md) {
		w.exec(a, rng)
	}
	w.quiesce()
	v := w.verdict()
	rpTotals.shuffled += w.shuffled
	rpTotals.refreshes += w.refreshes
	rpTotals.quotaed += w.quotaed
	rpTotals.granted += w.granted
	rpTotals.spentRecs += w.spentRecs
	if w.spentRecs > 0 {
		rpTotals.recRuns++
	}
	if w.f.audited(0, "quota_refresh_refused") || w.f.audited(1, "quota_refresh_refused") {
		rpTotals.refusedRuns++
	}
	if w.shuffled > 0 {
		rpTotals.shuffleRuns++
	}
	if w.refreshes > 0 {
		rpTotals.refreshRuns++
	}
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
			for _, a := range rpGen(rs, steps, burst, rpRunModes) {
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
	t.Logf("runs in which relay.token.issued delivered a token already revoked (follow-up, not R29-T1): %d", len(rpIssuedRevokedRuns))
	// The search fails when any run ends outside the accepted residuals (the
	// lead, GC #7066): a PASS then means no such run, not just no crash.
	for _, k := range ks {
		if k != "converged" && !rpAccepted(k) {
			t.Errorf("%d runs ended %s (not an accepted residual), e.g. %d", len(classes[k]), k, classes[k][0])
		}
	}
	md := rpRunModes
	t.Logf("shuffle %v: %d messages delivered ahead of an older one, in %d runs", md.shuffle, rpTotals.shuffled, rpTotals.shuffleRuns)
	t.Logf("refresh %v (spent %v): ~%d quota refreshes asked (by the harness) in %d runs, ~%d granted (approximate), %d standing-quota refusals (quota %d, spent %d)", md.refresh, md.spent,
		rpTotals.refreshes, rpTotals.refreshRuns, rpTotals.granted, rpTotals.quotaed, rpStandingQuota, rpSpentQuota)
	if md.spent {
		t.Logf("spent (quiet-phase housekeeping spends no quota): %d runs with a refused quota refresh; %d reconnect deposits after one (decision a), in %d runs", rpTotals.refusedRuns, rpTotals.spentRecs, rpTotals.recRuns)
	}
	t.Logf("%d runs (burst %v, steps %d) in %v: %v per 10,000", runs, burst, steps, el.Round(time.Second),
		(el * time.Duration(10000) / time.Duration(runs)).Round(time.Second))
}

// stOutbox is the outbox, or none for a zeroized state.
func (m *Manager) stOutbox() []*OutboxEntry {
	if m.st == nil {
		return nil
	}
	return m.st.Outbox
}

// toldRef reports whether side s told the member that note id may not have
// been delivered: ended past 16 days (undelivered_window), or deposited
// late as it is (unconfirmed_late, #7901) and then refused by the peer as
// too old (its stale_or_future for that id), the loss the notice is for.
func (w *rpWorld) toldRef(s int, id string) bool {
	if w.f.auditedRef(s, "undelivered_window", id) {
		return true
	}
	return w.f.auditedRef(s, "unconfirmed_late", id) && w.f.auditedRef(1-s, "stale_or_future", id)
}
