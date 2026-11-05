package vault

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// The relay-key rotation (VAULT-MESSAGING §3.4 "The order of a relay-key
// rotation" and "Resending the new address"; §12.2 "On unlock" step 3).
//
//  1. The rotation's state write stores the new relay key as pending, with
//     the new tokens for every recipient, held (startRelayRotation, in the
//     flush of rotateKeys' caller). The current key stays current.
//  2. After that write the vault calls the relay's rotate, signed by the
//     current key, with the pending key (relayKeyStep); past the grace
//     (mailbox_unknown) it registers the pending key instead.
//  3. On success a second write makes the pending key current
//     (makePendingCurrent): the old key becomes deposit-only, the held
//     tokens near their end (all of them, for a mailbox the relay created
//     afresh) are re-minted, the recipients are taken again, and the
//     relay.address.updates are queued, sent after that write.
//
// A run that ends between the steps leaves the key pending in the stored
// state; the next unlock calls the rotate again with the same key, which
// the relay answers with the same mailbox (RELAY-PROTOCOL 0.10.1 §6.7).

// relayKeyRun is the memory-only runtime of a relay-key rotation.
type relayKeyRun struct {
	// stored: the pending key in memory is in the stored state.
	stored bool
	// fromStorage: the unlock (or recovery open) found a key pending,
	// left by an earlier run; leftMailbox is its mailbox.
	fromStorage bool
	leftMailbox string
	// failAudited: identity.rotation_failed is audited at most once per
	// unlock (each unlock is a new Manager).
	failAudited bool
	// triedRefused: the refused state's one attempt of this unlock.
	triedRefused bool
	// fails counts the attempts in a row that got no definite answer;
	// next is when the next sooner retry is due (full jitter, §3.4).
	fails int
	next  time.Time
	// resent are the recipients sent relay.address.update in this unlock
	// (at most one resend per recipient per unlock).
	resent map[string]bool
	// pending and old are Relays for the pending key and the old keys
	// (keys.oldRelay, by index); built when first used.
	pending Relay
	old     []Relay
	// set is published for the lockless blob transfers (publishRelays).
	set atomic.Pointer[relaySet]
}

// Backoff of the sooner retries while unlocked (§3.4): the wait before
// the n-th retry in a row is random from 0 to min(1 h, 1 min × 2^(n−1)).
const (
	relayRetryBase = time.Minute
	relayRetryMax  = time.Hour
)

func relayRetryWait(n int) time.Duration {
	d := relayRetryMax
	if n < 7 {
		d = min(relayRetryMax, relayRetryBase<<max(n-1, 0))
	}
	return time.Duration(rand.Int64N(int64(d) + 1))
}

// TypeAddressUpdate is the message that carries a new relay address
// (§3.4, §10.2).
const TypeAddressUpdate = "relay.address.update"

func pubOf(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

// ownSub is the current relay key as a token sub.
func (m *Manager) ownSub() string { return relayauth.EncodeKey(pubOf(m.keys.relay)) }

// pendingRelayClient is the Relay for the pending key.
func (m *Manager) pendingRelayClient() Relay {
	if m.relay == nil && m.opt.Relay != nil {
		m.relay = m.opt.Relay(m.st.Relay.URL, m.keys.relay) // a recovery's open rotates before it registers
		m.publishRelays()
	}
	if m.rk.pending == nil && m.keys.pendingRelay != nil {
		m.rk.pending = m.relay.WithKey(m.keys.pendingRelay)
	}
	return m.rk.pending
}

// oldRelayClient is the Relay for the old key i.
func (m *Manager) oldRelayClient(i int) Relay {
	for len(m.rk.old) < len(m.keys.oldRelay) {
		m.rk.old = append(m.rk.old, nil)
	}
	if m.rk.old[i] == nil {
		m.rk.old[i] = m.relay.WithKey(m.keys.oldRelay[i])
	}
	return m.rk.old[i]
}

// tokenClaims reads a deposit token's claims without verifying it: the
// vault's own stored tokens, read to choose the key that signs a deposit
// (the relay checks the token).
func heldTokenClaims(tok string) (sub string, exp time.Time, ok bool) {
	const prefix = "v4.public."
	if !strings.HasPrefix(tok, prefix) {
		return "", time.Time{}, false
	}
	body := strings.TrimPrefix(tok, prefix)
	if i := strings.IndexByte(body, '.'); i >= 0 {
		body = body[:i]
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || len(raw) <= ed25519.SignatureSize {
		return "", time.Time{}, false
	}
	c, err := relayauth.ParseClaims(raw[:len(raw)-ed25519.SignatureSize])
	if err != nil {
		return "", time.Time{}, false
	}
	return c.Sub, c.Exp, true
}

// oldIndex is the index of the old relay key, still used for deposits,
// that tok was issued to; -1 for any other token.
func (m *Manager) oldIndex(tok string) int {
	sub, _, ok := heldTokenClaims(tok)
	if !ok || m.keys == nil || sub == m.ownSub() {
		return -1
	}
	for i, k := range m.keys.oldRelay {
		if i < len(m.st.Relay.Old) && !m.st.Relay.Old[i].Retired && relayauth.EncodeKey(pubOf(k)) == sub {
			return i
		}
	}
	return -1
}

// relayFor is the Relay whose key a deposit on tok must be signed with:
// the token's sub. A token another principal issued to an old relay key
// is deposited with that key (§3.4 "Resending the new address" (a): the
// old key is used only to deposit); anything else with the current key.
func (m *Manager) relayFor(tok string) Relay {
	if i := m.oldIndex(tok); i >= 0 {
		return m.oldRelayClient(i)
	}
	return m.relay
}

// onOldKey reports whether tok was issued to one of the old relay keys
// still used for deposits.
func (m *Manager) onOldKey(tok string) bool { return m.oldIndex(tok) >= 0 }

// keyRank orders the vault's relay keys a token may be issued to: the
// current key highest, then the old ones from the latest; 0 for none.
func (m *Manager) keyRank(tok string) int {
	if i := m.oldIndex(tok); i >= 0 {
		return i + 1
	}
	if sub, _, ok := heldTokenClaims(tok); ok && m.keys != nil && sub == m.ownSub() {
		return len(m.keys.oldRelay) + 1
	}
	return 0
}

// mintRelay is the Relay that mints p's tokens: the key p knows the vault
// by. A first contact begun under an old relay key (an invitation or
// pairing made before the rotation, a handshake in flight) finishes on
// that key, and p is sent the new address when it completes; every
// principal that was sent it gets tokens from the current key.
func (m *Manager) mintRelay(p *Peer) Relay {
	if _, sent := m.st.Relay.Updates[p.ID]; !sent {
		return m.relayFor(p.Standing.Token)
	}
	return m.relay
}

// relayRecipients are the recipients of a relay-key rotation: every active
// device and connection (§3.4 step 2), in id order.
func (m *Manager) relayRecipients() []*Peer {
	var out []*Peer
	for _, p := range m.allPeers() {
		if p.State == PeerActive {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// --- marks ---

func copyMarks(o *RotationOwed) *RotationOwed {
	if o == nil {
		return &RotationOwed{}
	}
	return &RotationOwed{Recovery: o.Recovery, Transfer: o.Transfer, DEKVersion: o.DEKVersion, At: o.At}
}

// unionMarks is the marks of a and b (b's transfer wins: the later one).
func unionMarks(a, b *RotationOwed) *RotationOwed {
	out := copyMarks(a)
	if b == nil {
		return out
	}
	if b.Recovery != "" {
		out.Recovery = b.Recovery
	}
	if b.Transfer != "" {
		out.Transfer, out.DEKVersion, out.At = b.Transfer, b.DEKVersion, b.At
	}
	return out
}

// markRef is the identity.rotated ref of the marks a rotation clears
// (§11.14.10, 0.69.2), less those an earlier audit named.
func markRef(marks, named *RotationOwed) string {
	if marks == nil {
		return ""
	}
	if marks.Transfer != "" && (named == nil || named.Transfer != marks.Transfer) {
		return marks.Transfer
	}
	if marks.Recovery != "" && (named == nil || named.Recovery != marks.Recovery) {
		return "recovery"
	}
	return ""
}

// pendingRef is the ref the pending key's identity.rotated would carry,
// and its identity.rotation_failed carries.
func (m *Manager) pendingRef() string {
	pr := m.st.Relay.Pending
	if pr == nil {
		return ""
	}
	return markRef(pr.Marks, pr.Named)
}

// marksMade reports whether every owed mark's rotation has been made: it
// is the pending key's, or of a rotation made while it was pending. Its
// retry is then the completion of the pending key, not a new rotation of
// ik, kem or the wake key (§3.4 "Owed marks").
func marksMade(o *RotationOwed, pr *PendingRelay) bool {
	made := func(v string, get func(*RotationOwed) string) bool {
		return v == "" || pr.Marks != nil && get(pr.Marks) == v || pr.Next != nil && get(pr.Next) == v
	}
	return made(o.Recovery, func(r *RotationOwed) string { return r.Recovery }) &&
		made(o.Transfer, func(r *RotationOwed) string { return r.Transfer })
}

// clearMarks clears the owed marks named in marks (each only if still the
// same one), and the owed object when nothing is left.
func (m *Manager) clearMarks(marks *RotationOwed) {
	o := m.st.RotationOwed
	if o == nil || marks == nil {
		return
	}
	if marks.Recovery != "" && o.Recovery == marks.Recovery {
		o.Recovery = ""
	}
	if marks.Transfer != "" && o.Transfer == marks.Transfer {
		o.Transfer, o.DEKVersion, o.At = "", 0, time.Time{}
	}
	if o.Recovery == "" && o.Transfer == "" && !o.RelayKey {
		m.st.RotationOwed = nil
	}
}

// --- step 1: the pending key ---

// relaySeedNeeded reports whether a rotation made now generates a relay
// key: none is pending, or the member's credential.rotate finds one in the
// refused state (§3.4 "The way out of the refused state").
func (m *Manager) relaySeedNeeded(byCredential bool) bool {
	pr := m.st.Relay.Pending
	return pr == nil || byCredential && pr.Refused != ""
}

// startRelayRotation is the relay part of a rotation, in memory; the
// rotation's flush stores it (§3.4 step 1). seed is nil when
// relaySeedNeeded was false.
func (m *Manager) startRelayRotation(seed []byte, byCredential bool, now time.Time) {
	marks := copyMarks(m.st.RotationOwed)
	pr := m.st.Relay.Pending
	switch {
	case pr == nil:
		m.newPendingRelay(seed, marks, nil, now)
	case byCredential && pr.Refused != "":
		// The way out: the refused key, its tokens and the refused mark
		// are discarded; the new key meets any relay-key rotation owed,
		// which clears in this flush; the other marks clear at its second
		// write.
		all := unionMarks(unionMarks(pr.Marks, pr.Next), marks)
		named := pr.Named
		m.dropPendingRelay()
		if o := m.st.RotationOwed; o != nil {
			o.RelayKey = false
			m.clearMarks(&RotationOwed{})
		}
		m.newPendingRelay(seed, all, named, now)
	default:
		// A rotation made while a relay key is pending keeps it and owes a
		// relay-key rotation, which its second write meets.
		suite.Wipe(seed)
		pr.Next = unionMarks(pr.Next, marks)
		if m.st.RotationOwed == nil {
			m.st.RotationOwed = &RotationOwed{}
		}
		m.st.RotationOwed.RelayKey = true
		m.dirty = true
	}
}

// newPendingRelay stores seed as the pending relay key with new tokens for
// every recipient, held (§3.4 step 1).
func (m *Manager) newPendingRelay(seed []byte, marks, named *RotationOwed, now time.Time) {
	m.st.Relay.Pending = &PendingRelay{Seed: seed, Tokens: map[string]*HeldUpdate{}, Marks: marks, Named: named}
	m.keys.pendingRelay = ed25519.NewKeyFromSeed(seed)
	m.rk.pending, m.rk.stored, m.rk.fails, m.rk.next = nil, false, 0, time.Time{}
	pr, r := m.st.Relay.Pending, m.pendingRelayClient()
	for _, p := range m.relayRecipients() {
		mintHeld(m, pr, r, p, false, now)
	}
	m.dirty = true
}

// dropPendingRelay discards the pending key (the refused state's way out).
func (m *Manager) dropPendingRelay() {
	if pr := m.st.Relay.Pending; pr != nil {
		suite.Wipe(pr.Seed)
	}
	suite.Wipe(m.keys.pendingRelay)
	m.st.Relay.Pending, m.keys.pendingRelay, m.rk.pending = nil, nil, nil
	m.dirty = true
}

// mintHeld mints p's tokens on pr's key (standing, and reconnect for a
// connection), through r, and holds them in pr. fresh: iat now, not
// backdated (a mailbox the relay created afresh, RELAY-PROTOCOL §6.10).
func mintHeld(m *Manager, pr *PendingRelay, r Relay, p *Peer, fresh bool, now time.Time) {
	if pr.Tokens == nil {
		pr.Tokens = map[string]*HeldUpdate{} // read back without recipients (omitempty)
	}
	h := pr.Tokens[p.ID]
	if h == nil {
		h = &HeldUpdate{}
		pr.Tokens[p.ID] = h
	}
	if tok, it, err := m.mintKind(r, fresh, p, TokStanding, now); err == nil {
		h.Standing = tok
		pr.Issued = replaceIssued(pr.Issued, it)
	}
	if p.Kind == KindConnection {
		if tok, it, err := m.mintKind(r, fresh, p, TokReconnect, now); err == nil {
			h.Reconnect = tok
			pr.Issued = replaceIssued(pr.Issued, it)
		}
	}
}

// replaceIssued puts it in place of the entry of the same peer and kind.
func replaceIssued(list []IssuedToken, it IssuedToken) []IssuedToken {
	out := list[:0]
	for _, t := range list {
		if t.PeerID != it.PeerID || t.Kind != it.Kind {
			out = append(out, t)
		}
	}
	return append(out, it)
}

func heldExp(list []IssuedToken, peer, kind string) (time.Time, bool) {
	for _, t := range list {
		if t.PeerID == peer && t.Kind == kind {
			return t.Exp, true
		}
	}
	return time.Time{}, false
}

// --- step 2: the rotate, or the registration ---

type relayOutcome int

const (
	relayDone     relayOutcome = iota // the relay has the mailbox
	relayNoAnswer                     // retried: no definite answer
	relayRefused                      // a definite refusal
)

// definiteRefusal reports whether err is a definite refusal (§3.4): any
// 4xx other than 429 rate_limited, timestamp_stale and replay_detected
// (which a freshly signed request can pass). The rotate's mailbox_unknown
// is handled before this (it leads to the registration).
func definiteRefusal(err error) bool {
	st, ok := statusOf(err)
	if !ok || st < 400 || st >= 500 {
		return false
	}
	switch RelayCode(err) {
	case "rate_limited", CodeTimestampStale, "replay_detected":
		return false
	}
	return true
}

// retryAfterOf is a 429 rate_limited answer's retry_after.
func retryAfterOf(err error) time.Duration {
	var e *relayclient.Error
	if errors.As(err, &e) && e.Code == "rate_limited" && e.RetryAfter > 0 {
		return time.Duration(e.RetryAfter) * time.Second
	}
	return 0
}

// relayKeyCall makes one attempt: the rotate signed by the current key
// with the pending key; on mailbox_unknown (past the grace) the
// registration of the stored pending key. fresh: the registration was
// answered 201 (a fresh mailbox). registration: the answer is the
// registration's (the current mailbox is gone), not the rotate's.
func (m *Manager) relayKeyCall(ctx context.Context) (out relayOutcome, fresh, registration bool, err error) {
	pr := m.pendingRelayClient()
	_, err = m.relay.Rotate(ctx, m.keys.pendingRelay)
	if err == nil {
		// The relay's limits for the new key: registering an existing key
		// again creates nothing (RELAY-PROTOCOL §6.1); a failure keeps
		// the limits the vault has.
		if lim, _, rerr := pr.RegisterCreated(ctx); rerr == nil {
			m.setLimits(lim)
		}
		return relayDone, false, false, nil
	}
	if RelayCode(err) == CodeMailboxUnknown {
		registration = true
		lim, created, rerr := pr.RegisterCreated(ctx)
		if rerr == nil {
			m.setLimits(lim)
			return relayDone, created, true, nil
		}
		err = rerr
	}
	if ctx.Err() == nil && definiteRefusal(err) {
		return relayRefused, false, registration, err
	}
	return relayNoAnswer, false, registration, err
}

// relayKeyStep completes a pending relay key after a state write: at the
// unlock (§12.2 step 3: one attempt; the steps after it go on when it
// fails or gets no answer), after the flush that stored a new one, and as
// the sooner retries while unlocked come due. A chained next key, stored
// by the second write, is attempted at once.
func (m *Manager) relayKeyStep(ctx context.Context, atUnlock bool) {
	for range 2 {
		if !m.relayKeyAttempt(ctx, atUnlock) {
			return
		}
	}
}

// waitsForRecoveredPhone reports whether pr is a key a recovery stored
// whose phone has not paired yet: its first handshake checks the vault's
// relay key and mailbox as the open's vault_bundle gave them, so the key
// is not made current before it (as retryOwedRotation waits for the
// identity key). A key pending since before the recovery was completed by
// its open (completeStoredRelayKey).
func (m *Manager) waitsForRecoveredPhone(pr *PendingRelay) bool {
	return pr.Recovery != "" && m.recoveredPhoneUnpaired()
}

// recoveredPhoneUnpaired reports whether a completed recovery's phone has
// not paired yet (its recovery invite is still there).
func (m *Manager) recoveredPhoneUnpaired() bool {
	for _, inv := range m.st.Invites {
		if inv.CreatedBy == inviteByRecovery {
			return true
		}
	}
	return false
}

// relayKeyAttempt makes one attempt if one is due; true when the key was
// made current (the second write made; another key may be pending).
func (m *Manager) relayKeyAttempt(ctx context.Context, atUnlock bool) bool {
	if m.locked || m.st == nil {
		return false
	}
	pr := m.st.Relay.Pending
	if pr == nil || m.st.Deleting != nil || !m.rk.stored || m.waitsForRecoveredPhone(pr) {
		return false
	}
	now := m.now()
	switch {
	case pr.Refused != "":
		// One attempt at each unlock, no sooner retries.
		if !atUnlock || m.rk.triedRefused {
			return false
		}
		m.rk.triedRefused = true
	case now.Before(pr.RetryAfter):
		// A running retry_after is honored at an unlock too.
		m.rk.next = pr.RetryAfter
		return false
	case !atUnlock && now.Before(m.rk.next):
		return false
	}
	out, fresh, _, err := m.relayKeyCall(ctx)
	now = m.now() // after the relay's answer: a 201's tokens are minted with iat then
	switch out {
	case relayDone:
		if fresh && !pr.Created {
			// A fresh mailbox: stored first, so that a second write that
			// fails, made again by a later run (whose registration then
			// answers 200), still re-mints every held token.
			pr.Created = true
			m.dirty = true
			if err := m.persist(ctx, false); err != nil {
				return false
			}
		}
		if !m.makePendingCurrent(fresh || pr.Created, now) {
			m.rk.next = now.Add(relayRetryWait(1))
			return false
		}
		m.rk.fails = 0
		perr := m.persist(ctx, false)
		if err := perr; err != nil {
			return false // memory is ahead; the next write that succeeds stores it
		}
		return true
	case relayRefused:
		pr.Refused, pr.RetryAfter = RelayCode(err), time.Time{}
		if pr.Refused == "" {
			pr.Refused = "refused"
		}
		m.dirty = true
		m.relayKeyFailed(now)
		_ = m.persist(ctx, false) // the refused state's own state write
		return false
	default:
		if ctx.Err() != nil {
			return false // interrupted (a lock): not an attempt
		}
		m.rk.fails++
		wait := relayRetryWait(m.rk.fails)
		if ra := retryAfterOf(err); ra > 0 && pr.Refused == "" {
			pr.RetryAfter = now.Add(ra).UTC()
			m.dirty = true
			wait = max(wait, ra)
		}
		m.rk.next = now.Add(wait)
		return false
	}
}

// completeStoredRelayKey settles, in a recovery's open, a relay key
// pending since an earlier run, before the recovered phone is given the
// vault's address (its vault_bundle), in one attempt:
//   - the relay has the new mailbox: the second write, in memory (stored
//     by the open's step-2 write), re-minting every held token (a 201 made
//     here would be lost with an open that fails later);
//   - no definite answer (a timeout, a 5xx, a 429, a retry_after still
//     running): false, the open answers retry;
//   - a refused rotate: the current mailbox lives; the open goes on with
//     it and the key stays pending in the refused state (§3.4), the
//     recovery's rotation owing a relay-key rotation;
//   - a refused registration (past the grace: no live mailbox):
//     recoveryReplacesRefusedKey.
func (m *Manager) completeStoredRelayKey(ctx context.Context, newRelay func(string, ed25519.PrivateKey) Relay) bool {
	pr := m.st.Relay.Pending
	if pr == nil {
		return true
	}
	m.relay = newRelay(m.st.Relay.URL, m.keys.relay)
	m.publishRelays()
	if m.now().Before(pr.RetryAfter) {
		return false
	}
	out, _, registration, err := m.relayKeyCall(ctx)
	now := m.now()
	switch {
	case out == relayDone:
		if !m.makePendingCurrent(true, now) {
			return false
		}
	case out == relayNoAnswer:
		return false
	case !registration:
		pr.Refused, pr.RetryAfter = RelayCode(err), time.Time{}
		if pr.Refused == "" {
			pr.Refused = "refused"
		}
		m.relayKeyFailed(now) // stored with the open's step-2 write
		m.dirty = true
	default:
		if !m.recoveryReplacesRefusedKey(ctx, now) {
			return false
		}
	}
	m.rk.fromStorage, m.rk.leftMailbox = false, ""
	return true
}

// recoveryReplacesRefusedKey is a recovery's answer to a pending key whose
// registration the relay refused past the grace, when the vault has no
// live mailbox to give the phone (OWNER QUESTION open, 2026-11-05; the
// recommended behaviour, kept apart so that it can be switched): as
// credential.rotate's way out of the refused state does (§3.4), the
// refused key, its tokens and its refused mark are discarded and a fresh
// key is generated, stored as pending (meeting any relay-key rotation
// owed) and registered; it is made current in memory by the open's step-2
// write. false: not done now (the open answers retry).
func (m *Manager) recoveryReplacesRefusedKey(ctx context.Context, now time.Time) bool {
	pr := m.st.Relay.Pending
	draw := suite.RandomBytes
	if m.opt.KeyRand != nil {
		draw = m.opt.KeyRand
	}
	seed, err := draw(32)
	if err != nil {
		return false
	}
	marks, named := unionMarks(pr.Marks, pr.Next), pr.Named
	m.dropPendingRelay()
	if o := m.st.RotationOwed; o != nil {
		o.RelayKey = false
		m.clearMarks(&RotationOwed{})
	}
	m.newPendingRelay(seed, marks, named, now)
	lim, _, err := m.pendingRelayClient().RegisterCreated(ctx)
	if err != nil {
		return false
	}
	m.setLimits(lim)
	return m.makePendingCurrent(true, m.now())
}

// relayKeyFailed audits identity.rotation_failed for the pending key, with
// its feed item, at most once per unlock (§3.4 "What is audited").
func (m *Manager) relayKeyFailed(now time.Time) {
	if m.rk.failAudited {
		return
	}
	m.rk.failAudited = true
	m.record(Activity{Kind: "identity.rotation_failed", Ref: m.pendingRef(), Audit: true, Feed: true, Priority: "high"}, now)
}

// relayKeyAtUnlock is §12.2 step 3: a key left pending by an earlier run
// is completed, or audited identity.rotation_failed when this unlock's
// own attempt does not complete it (it fails, gets no answer or is not
// made because a retry_after still runs).
func (m *Manager) relayKeyAtUnlock(ctx context.Context) {
	m.relayKeyStep(ctx, true)
	if m.st == nil || !m.rk.fromStorage {
		return
	}
	if pr := m.st.Relay.Pending; pr != nil && m.keys.pendingRelay != nil && mailboxOf(m.keys.pendingRelay) == m.rk.leftMailbox &&
		!m.waitsForRecoveredPhone(pr) {
		m.relayKeyFailed(m.now())
	}
}

// --- step 3: the second write ---

// makePendingCurrent is the second write, in memory (§3.4 step 3); the
// caller persists it. false: nothing changed (no randomness for a next
// key).
func (m *Manager) makePendingCurrent(fresh bool, now time.Time) bool {
	pr := m.st.Relay.Pending
	o := m.st.RotationOwed
	var nextSeed []byte
	if o != nil && o.RelayKey {
		draw := suite.RandomBytes
		if m.opt.KeyRand != nil {
			draw = m.opt.KeyRand
		}
		s, err := draw(32)
		if err != nil {
			return false
		}
		nextSeed = s
	}
	// The old key becomes deposit-only (Resending the new address (a)).
	m.st.Relay.Old = append(m.st.Relay.Old, OldRelayKey{Seed: m.st.Relay.Seed, Mailbox: m.st.Relay.Mailbox, At: now.UTC()})
	m.keys.oldRelay = append(m.keys.oldRelay, m.keys.relay)
	for len(m.rk.old) < len(m.keys.oldRelay)-1 {
		m.rk.old = append(m.rk.old, nil)
	}
	m.rk.old = append(m.rk.old, m.relay)
	newRelay := m.pendingRelayClient()
	m.st.Relay.Seed, m.st.Relay.Mailbox = pr.Seed, mailboxOf(m.keys.pendingRelay)
	m.keys.relay, m.keys.pendingRelay = m.keys.pendingRelay, nil
	m.relay, m.rk.pending = newRelay, nil
	m.st.Relay.Pending = nil // its retry_after goes with it
	m.resetCollector()
	m.publishRelays()
	// First contacts begun under the old key may finish on it (owner
	// decision 2026-11-05): an invitation or pairing not yet claimed, and
	// the vault's own hs.init in flight, are stamped with the old mailbox.
	oldMB := m.st.Relay.Old[len(m.st.Relay.Old)-1].Mailbox
	for _, inv := range m.st.Invites {
		if inv.Mailbox == "" && !inv.Used && now.Before(inv.Exp) {
			inv.Mailbox = oldMB
		}
	}
	for _, og := range m.st.Outgoing {
		if og.New != nil && og.Mailbox == "" {
			og.Mailbox = oldMB
		}
	}

	// The recipients again; tokens that waited are re-minted near their
	// end (§7.2 "On unlock"), every one for a fresh mailbox (iat now).
	updates := map[string]*AddressUpdate{}
	recips := m.relayRecipients()
	keep := map[string]bool{}
	for _, p := range recips {
		keep[p.ID] = true
		h := pr.Tokens[p.ID]
		if h == nil || fresh {
			mintHeld(m, pr, newRelay, p, fresh, now)
			continue
		}
		if exp, ok := heldExp(pr.Issued, p.ID, TokStanding); !ok || exp.Sub(now) < StandingRemintBelow && m.standingTTL(p.Kind) > StandingRemintBelow {
			if tok, it, err := m.mintKind(newRelay, false, p, TokStanding, now); err == nil {
				h.Standing, pr.Issued = tok, replaceIssued(pr.Issued, it)
			}
		}
		if p.Kind == KindConnection {
			if exp, ok := heldExp(pr.Issued, p.ID, TokReconnect); !ok || handshake.ReconnectRemintDue(exp, now) {
				if tok, it, err := m.mintKind(newRelay, false, p, TokReconnect, now); err == nil {
					h.Reconnect, pr.Issued = tok, replaceIssued(pr.Issued, it)
				}
			}
		}
	}
	for _, t := range pr.Issued {
		if keep[t.PeerID] {
			m.st.Issued = append(m.st.Issued, t)
		}
	}
	for _, p := range recips {
		h := pr.Tokens[p.ID]
		if h == nil || h.Standing == "" {
			continue
		}
		u := &AddressUpdate{Body: m.addressBody(h.Standing, h.Reconnect), Since: now.UTC()}
		for _, t := range pr.Issued {
			if t.PeerID == p.ID {
				u.JTIs = append(u.JTIs, t.JTI)
			}
		}
		updates[p.ID] = u
		m.sendAddressUpdate(p, u, now)
	}
	m.st.Relay.Updates = updates

	// What is audited, and the owed marks (§3.4, §11.14.10).
	m.record(Activity{Kind: "identity.rotated", Ref: markRef(pr.Marks, pr.Named), Audit: true}, now)
	if nextSeed != nil {
		// A relay-key rotation is owed: the next key is stored in this
		// write, which meets (and clears) that mark; the other marks clear
		// at the next key's own second write.
		o.RelayKey = false
		m.newPendingRelay(nextSeed, unionMarks(pr.Marks, pr.Next), unionMarks(pr.Named, pr.Marks), now)
	} else {
		m.clearMarks(pr.Marks)
	}
	m.dirty = true
	return true
}

// addressBody is relay.address.update's body: the current address and
// the recipient's new tokens (§10.2).
func (m *Manager) addressBody(standing, reconnect string) []byte {
	addr := strictjson.NewBuilder().String("url", m.st.Relay.URL).String("mailbox", m.st.Relay.Mailbox).
		Base64("pk", pubOf(m.keys.relay)).Bytes()
	b := strictjson.NewBuilder().Raw("relay", addr).String("token", standing)
	if reconnect != "" {
		b.String("reconnect_token", reconnect)
	}
	return b.Bytes()
}

// sendNewAddress makes p a recipient of the last relay-key rotation when
// its first contact finished on an old key (owner decision 2026-11-05):
// new tokens from the current key and relay.address.update, after the
// messages of its activation; it then counts like every recipient.
func (m *Manager) sendNewAddress(p *Peer, now time.Time) {
	if _, sent := m.st.Relay.Updates[p.ID]; sent || p.State != PeerActive || !m.onOldKey(p.Standing.Token) {
		return
	}
	st, it, err := m.mintKind(m.relay, false, p, TokStanding, now)
	if err != nil {
		return
	}
	u := &AddressUpdate{Since: now.UTC(), JTIs: []string{it.JTI}}
	m.st.Issued = append(m.st.Issued, it)
	rc := ""
	if p.Kind == KindConnection {
		if tok, rit, err := m.mintKind(m.relay, false, p, TokReconnect, now); err == nil {
			rc = tok
			m.st.Issued = append(m.st.Issued, rit)
			u.JTIs = append(u.JTIs, rit.JTI)
		}
	}
	u.Body = m.addressBody(st, rc)
	if m.st.Relay.Updates == nil {
		m.st.Relay.Updates = map[string]*AddressUpdate{}
	}
	m.st.Relay.Updates[p.ID] = u
	m.sendAddressUpdate(p, u, now)
	m.dirty = true
}

// sendAddressUpdate queues relay.address.update to p (deposited, like
// every message to p, on p's standing token: with the old key while that
// token is for it).
func (m *Manager) sendAddressUpdate(p *Peer, u *AddressUpdate, now time.Time) {
	if m.sendTo(p, TypeAddressUpdate, u.Body, now) == "" {
		return
	}
	m.st.Outbox[len(m.st.Outbox)-1].AddressUpdate = true
	u.SentAt = now.UTC()
	if m.rk.resent == nil {
		m.rk.resent = map[string]bool{}
	}
	m.rk.resent[p.ID] = true
}

// resetCollector drops the collect session: the next one collects with the
// keys now current (and the old mailboxes still collected).
func (m *Manager) resetCollector() {
	if m.collector != nil {
		_ = m.collector.Close()
		m.collector = nil
	}
}

// --- Resending the new address (§3.4 (b)) ---

// noteAddressAck records that a recipient followed the new address: it
// issued the vault a token for the current key (relay.token.issued, §3.4
// "The signal"; owner decision 2026-11-05: a deposit to the new mailbox
// alone does not count).
func (m *Manager) noteAddressAck(peerID string) {
	if u := m.st.Relay.Updates[peerID]; u != nil && !u.Acked {
		u.Acked = true
		m.dirty = true
	}
}

// resendAddressUpdates deposits relay.address.update again at an unlock to
// each recipient that has not acknowledged and whose standing token for an
// old sub is still valid: at most one per recipient per unlock and one per
// hour; nothing while a key is pending.
func (m *Manager) resendAddressUpdates(now time.Time) {
	if m.st.Relay.Pending != nil || len(m.st.Relay.Updates) == 0 {
		return
	}
	ids := make([]string, 0, len(m.st.Relay.Updates))
	for id := range m.st.Relay.Updates {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		u := m.st.Relay.Updates[id]
		if u.Acked || u.Ended || m.rk.resent[id] || now.Sub(u.SentAt) < time.Hour {
			continue
		}
		p := m.peer(id)
		if p == nil || p.State != PeerActive || !m.onOldKey(p.Standing.Token) || !now.Before(p.Standing.Exp) {
			continue // a reconnect token cannot carry it (§6.6)
		}
		m.sendAddressUpdate(p, u, now)
	}
}

// endAddressUpdate ends the resends to a recipient after a definite
// refusal of a deposit of its update.
func (m *Manager) endAddressUpdate(peerID string) {
	if u := m.st.Relay.Updates[peerID]; u != nil && !u.Ended {
		u.Ended = true
		m.dirty = true
	}
}

// UnfollowedAfter is how long a recipient may take to issue the vault a
// token for its new key before it is shown as needing reconnecting (owner
// decision 2026-11-05; divided by the release's time scale).
const UnfollowedAfter = 30 * 24 * time.Hour

// pruneOldRelayKeys ends the old relay keys' use (§3.4 "When the old key
// is deleted", owner decision 2026-11-05):
//   - A recipient that has not issued a token for the new key
//     UnfollowedAfter after it was first sent the address is shown as
//     needing reconnecting (the stale connection's state and notices) and
//     no longer holds the key.
//   - A key's use for deposits ends (Retired) when no recipient that has
//     not followed holds a token for it, no notice to a removed device
//     holds a valid token for it (a pending unlink, a recovery's
//     device.unlinked{replaced}, any deposit queued on such a token), and
//     no first contact begun under it lives (an invitation or pairing made
//     before the rotation, a handshake or a request whose peer knows the
//     vault by it).
//   - A retired key is deleted once its mailbox is gone (the relay's grace
//     ended): until then it collects that mailbox.
func (m *Manager) pruneOldRelayKeys(now time.Time) {
	if len(m.st.Relay.Old) == 0 {
		if m.st.Relay.Updates != nil && m.st.Relay.Pending == nil {
			m.st.Relay.Updates = nil
			m.dirty = true
		}
		return
	}
	for id, u := range m.st.Relay.Updates {
		p := m.peer(id)
		if p == nil {
			delete(m.st.Relay.Updates, id) // a recipient removed since
			m.dirty = true
			continue
		}
		if !u.Acked && !u.Ended && !u.Since.IsZero() && !now.Before(u.Since.Add(m.opt.scale(UnfollowedAfter))) {
			u.Ended = true
			m.dirty = true
			if p.State == PeerActive {
				m.markStale(p, now)
				if p.Kind != KindConnection {
					// A device that missed the address: the member is told it
					// needs pairing again (NEW: the device.stale feed item,
					// "<device> can't reach your vault any more. Pair it
					// again.", and sync.event{kind: "device.stale"}, for owner
					// approval with the app PRs).
					m.notifyDevices("sync.event", strictjson.NewBuilder().String("kind", "device.stale").String("device_id", p.ID).
						String("role", p.Kind).Bytes(), p.ID, now)
					m.record(Activity{Kind: "device.stale", DeviceID: p.ID, Audit: true, Feed: true}, now)
				}
			}
		}
	}
	validFor := func(tok string, exp time.Time, sub string) bool {
		s, texp, ok := heldTokenClaims(tok)
		if exp.IsZero() {
			exp = texp
		}
		return ok && s == sub && now.Before(exp)
	}
	// The earliest old key a recipient that has not followed holds a token
	// for: it, and every later old key, which that recipient may still
	// learn from an update sent with it (a chain K0→K1→K2), stay in use.
	minRank := 0
	for id, u := range m.st.Relay.Updates {
		if p := m.peer(id); p != nil && !u.Acked && !u.Ended {
			if r := m.keyRank(p.Standing.Token); r > 0 && r <= len(m.st.Relay.Old) && (minRank == 0 || r < minRank) {
				minRank = r
			}
		}
	}
	keepSeeds := m.st.Relay.Old[:0]
	var keepKeys []ed25519.PrivateKey
	var keepRelays []Relay
	removed, retired := false, false
	for i, o := range m.st.Relay.Old {
		k := m.keys.oldRelay[i]
		if !o.Retired {
			sub := relayauth.EncodeKey(pubOf(k))
			needed := minRank > 0 && i+1 >= minRank
			if pu := m.st.PendingUnlink; pu != nil && validFor(pu.Token, pu.TokenExp, sub) {
				needed = true
			}
			for _, e := range m.st.Outbox {
				if !e.Done && e.Op == OpDeposit && e.Token != "" && validFor(e.Token, time.Time{}, sub) {
					needed = true
				}
			}
			if m.firstContactsUnder(o.Mailbox, sub, now) {
				needed = true
			}
			if !needed {
				o.Retired = true
				m.dirty = true
				retired = true
			}
		}
		if o.Retired && o.Gone {
			suite.Wipe(o.Seed)
			suite.Wipe(k) // the collectors and blob transfers sign with copies of their own
			removed = true
			m.dirty = true
			continue
		}
		keepSeeds = append(keepSeeds, o)
		keepKeys = append(keepKeys, k)
		if i < len(m.rk.old) {
			keepRelays = append(keepRelays, m.rk.old[i])
		} else {
			keepRelays = append(keepRelays, nil)
		}
	}
	m.st.Relay.Old, m.keys.oldRelay, m.rk.old = keepSeeds, keepKeys, keepRelays
	if m.st.Relay.Pending == nil && m.allRetired() {
		m.st.Relay.Updates = nil
	}
	if removed {
		m.resetCollector()
	}
	if removed || retired {
		m.publishRelays()
	}
}

// allRetired reports whether no old key is used for deposits any more.
func (m *Manager) allRetired() bool {
	for _, o := range m.st.Relay.Old {
		if !o.Retired {
			return false
		}
	}
	return true
}

// firstContactsUnder reports whether a first contact begun under the old
// key (mailbox, sub) still lives (owner decision 2026-11-05): it may
// finish on the old address.
func (m *Manager) firstContactsUnder(mailbox, sub string, now time.Time) bool {
	on := func(tok string) bool {
		s, _, ok := heldTokenClaims(tok)
		return ok && s == sub
	}
	for _, inv := range m.st.Invites {
		if inv.Mailbox == mailbox && !inv.Used && now.Before(inv.Exp) {
			return true
		}
	}
	for _, og := range m.st.Outgoing {
		if og.New != nil && og.Mailbox == mailbox {
			return true
		}
	}
	for _, aw := range m.st.Awaiting {
		if aw.New != nil && on(aw.New.Standing.Token) {
			return true
		}
	}
	for _, r := range m.st.Requests {
		if on(r.Peer.Standing.Token) || r.PeerRequest != nil && on(r.PeerRequest.Token) {
			return true
		}
	}
	return false
}

// expireFirstContactsUnder ends the first contacts begun under an old key
// whose mailbox is gone: they cannot finish. Each ends by its own expiry
// path and notice (connection.event{failed}, the request's expired
// sync.event); an invitation or pairing nobody claimed, or one whose
// handshake had not completed, is recorded invite.expired (NEW, a feed
// item: "Your invitation expired. Send a new one.", for owner approval
// with the app PRs).
func (m *Manager) expireFirstContactsUnder(mailbox, sub string, now time.Time) {
	on := func(tok string) bool {
		s, _, ok := heldTokenClaims(tok)
		return ok && s == sub
	}
	for _, inv := range m.st.Invites {
		if inv.Mailbox == mailbox && !inv.Used && now.Before(inv.Exp) {
			inv.Exp = now
			m.record(Activity{Kind: "invite.expired", Ref: inv.ID, Audit: true, Feed: true}, now)
		}
	}
	for _, og := range m.st.Outgoing {
		if og.New != nil && og.Mailbox == mailbox {
			og.Expires = now // connection.event{failed} (expireRequests)
		}
	}
	for _, aw := range m.st.Awaiting {
		if aw.New != nil && on(aw.New.Standing.Token) {
			aw.Expires = now
			m.record(Activity{Kind: "invite.expired", Ref: aw.InviteID, Audit: true, Feed: true}, now)
		}
	}
	for _, r := range m.st.Requests {
		if on(r.Peer.Standing.Token) || r.PeerRequest != nil && on(r.PeerRequest.Token) {
			r.Expires = now // the request's own expiry notice (expireRequests)
		}
	}
	m.expireRequests(now)
	m.dirty = true
}

// expireFirstContactsUnderOldIK ends, at a rotation of ik (its first
// write), every unclaimed invitation and pairing and every first contact
// the vault began, made under the old ik (owner decision (a),
// 2026-11-05): their bundle or hs.init names the old ik, which a first
// contact's hs.resp cannot follow. Each records invite.expired at once
// (the member's notice: NEW feed item, "Your invitation expired. Send a
// new one."); an outgoing one also ends as an aborted one does
// (connection.event{failed}). Direct invitations (the first app's
// enrollment, a recovered phone's, made for the new ik) and a transfer's
// pairing (ended with its transfer) are not touched.
func (m *Manager) expireFirstContactsUnderOldIK(now time.Time) {
	for _, inv := range m.st.Invites {
		if inv.Used || inv.EnrollIK != nil || inv.CreatedBy == inviteByRecovery || inv.Transfer || !now.Before(inv.Exp) {
			continue
		}
		inv.Exp = now
		m.record(Activity{Kind: "invite.expired", Ref: inv.ID, Audit: true, Feed: true}, now)
		m.dirty = true
	}
	for id, og := range m.st.Outgoing {
		if og.New == nil {
			continue
		}
		// As a handshake not restored (restoreLive): its hs.init is not
		// sent, the tokens it minted are revoked, the devices hear it failed.
		p := og.New
		m.abandonOutgoing(id, now)
		m.denyPeerTokens(p, now)
		m.notifyDevices("connection.event", connEvent(p.ID, "failed"), "", now)
		m.record(Activity{Kind: "invite.expired", Ref: id, Audit: true, Feed: true}, now)
	}
}

// oldMailboxGone records that an old mailbox's grace ended (it answered
// mailbox_unknown): it is no longer collected, and what was begun under
// its key and has not finished cannot finish.
func (m *Manager) oldMailboxGone(mailbox string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st == nil {
		return
	}
	now := m.now()
	for i := range m.st.Relay.Old {
		if m.st.Relay.Old[i].Mailbox == mailbox && !m.st.Relay.Old[i].Gone {
			m.st.Relay.Old[i].Gone = true
			m.dirty = true
			m.expireFirstContactsUnder(mailbox, relayauth.EncodeKey(pubOf(m.keys.oldRelay[i])), now)
		}
	}
	m.publishRelays()
}

// relayRefused reports the refused state, for vault.status (§10.2).
func (m *Manager) relayRefused() bool {
	pr := m.st.Relay.Pending
	return pr != nil && pr.Refused != ""
}

// --- collecting from more than one mailbox (§3.4 "Collecting while a key
// is pending", §12.2) ---

// multiCollector collects from the current mailbox and from old mailboxes
// still in the relay's grace: each old one is polled without waiting
// before each long-poll of the current one. Acks go to the collector the
// message came from.
type multiCollector struct {
	main  Collector
	extra []oldCollector
	gone  func(mailbox string)
	from  map[string]Collector
	// keys are the old collectors' own copies of the old keys: the vault
	// may delete a key while a collect is in flight outside its lock; the
	// copies are wiped once the collector is closed and no collect runs.
	mu     sync.Mutex
	keys   []ed25519.PrivateKey
	busy   bool
	closed bool
}

type oldCollector struct {
	c       Collector
	mailbox string
	gone    bool
}

func (c *multiCollector) Next(ctx context.Context) ([]Message, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errStreamClosed
	}
	c.busy = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.busy = false
		if c.closed {
			c.wipe()
		}
		c.mu.Unlock()
	}()
	for i := range c.extra {
		x := &c.extra[i]
		if x.gone {
			continue
		}
		msgs, err := x.c.Next(ctx)
		if RelayCode(err) == CodeMailboxUnknown {
			x.gone = true
			c.gone(x.mailbox)
			continue
		}
		if err != nil || len(msgs) == 0 {
			continue
		}
		for _, m := range msgs {
			c.from[m.MsgID] = x.c
		}
		return msgs, nil
	}
	msgs, err := c.main.Next(ctx)
	for _, m := range msgs {
		c.from[m.MsgID] = c.main
	}
	return msgs, err
}

func (c *multiCollector) Ack(ctx context.Context, id string) error {
	x := c.from[id]
	delete(c.from, id)
	if x == nil {
		x = c.main
	}
	return x.Ack(ctx, id)
}

func (c *multiCollector) Close() error {
	for _, x := range c.extra {
		_ = x.c.Close()
	}
	c.mu.Lock()
	c.closed = true
	if !c.busy {
		c.wipe()
	}
	c.mu.Unlock()
	return c.main.Close()
}

func (c *multiCollector) wipe() {
	for _, k := range c.keys {
		suite.Wipe(k)
	}
	c.keys = nil
}

// withOldCollectors wraps the current mailbox's collector with the old
// mailboxes still collected, each signing with its own copy of its key.
func (m *Manager) withOldCollectors(ctx context.Context, main Collector) Collector {
	mc := &multiCollector{main: main, gone: m.oldMailboxGone, from: map[string]Collector{}}
	for i, o := range m.st.Relay.Old {
		if o.Gone {
			continue
		}
		k := append(ed25519.PrivateKey(nil), m.keys.oldRelay[i]...)
		r := m.relay.WithKey(k)
		var c Collector
		if cr, ok := r.(*ClientRelay); ok {
			c = cr.NewPollCollector(0)
		} else if oc, err := r.Collector(ctx, false); err == nil {
			c = oc
		} else {
			suite.Wipe(k)
			continue
		}
		mc.keys = append(mc.keys, k)
		mc.extra = append(mc.extra, oldCollector{c: c, mailbox: o.Mailbox})
	}
	if len(mc.extra) == 0 {
		return main
	}
	return mc
}

// relaySet is what the blob transfers, which run outside the vault's
// lock, use (§10.5.1): the current key's Relay and the old keys' (each
// with its own copy of its key): to fetch a blob a peer left in an old
// mailbox still in the relay's grace, and to upload on a token a recipient
// issued to an old key still used for deposits. A set is replaced at each
// change of the keys; the copies of a replaced set are wiped once no
// transfer uses it (acquireRelays, release), and at the lock.
type relaySet struct {
	cur  Relay
	old  []setRelay
	keys []ed25519.PrivateKey

	mu    sync.Mutex
	users int
	done  bool
}

type setRelay struct {
	r       Relay
	sub     string
	collect bool // its mailbox is still in the grace
	deposit bool // still used for deposits
}

// publishRelays makes the Relays the lockless transfers use follow the
// keys (after an unlock, a second write, an old key's change).
func (m *Manager) publishRelays() {
	if m.relay == nil || m.keys == nil || m.st == nil {
		return
	}
	set := &relaySet{cur: m.relay}
	for i, o := range m.st.Relay.Old {
		if i >= len(m.keys.oldRelay) || o.Gone && o.Retired {
			continue
		}
		k := append(ed25519.PrivateKey(nil), m.keys.oldRelay[i]...)
		set.keys = append(set.keys, k)
		set.old = append(set.old, setRelay{r: m.relay.WithKey(k), sub: relayauth.EncodeKey(pubOf(k)), collect: !o.Gone, deposit: !o.Retired})
	}
	if prev := m.rk.set.Swap(set); prev != nil {
		prev.retire()
	}
}

// unpublishRelays ends the published set (the lock).
func (m *Manager) unpublishRelays() {
	if prev := m.rk.set.Swap(nil); prev != nil {
		prev.retire()
	}
}

// acquireRelays returns the published set for one transfer, which
// releases it.
func (m *Manager) acquireRelays() *relaySet {
	for {
		s := m.rk.set.Load()
		if s == nil {
			return &relaySet{cur: m.relay}
		}
		s.mu.Lock()
		if !s.done {
			s.users++
			s.mu.Unlock()
			return s
		}
		s.mu.Unlock()
	}
}

func (s *relaySet) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.users > 0 {
		s.users--
	}
	if s.done && s.users == 0 {
		s.wipe()
	}
}

// retire marks a replaced set: its copies go once no transfer uses it.
func (s *relaySet) retire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = true
	if s.users == 0 {
		s.wipe()
	}
}

func (s *relaySet) wipe() {
	for _, k := range s.keys {
		suite.Wipe(k)
	}
	s.keys = nil
}

// forToken is the Relay an upload on tok signs with: the old key the token
// was issued to, while it is used for deposits; else the current key.
func (s *relaySet) forToken(tok string) Relay {
	if sub, _, ok := heldTokenClaims(tok); ok {
		for _, o := range s.old {
			if o.deposit && o.sub == sub {
				return o.r
			}
		}
	}
	return s.cur
}

// getBlob fetches a blob of the vault's mailbox: the current one, else an
// old one still in the grace (a peer that had not followed the new
// address uploaded it there).
func (m *Manager) getBlob(ctx context.Context, id string) ([]byte, error) {
	set := m.acquireRelays()
	defer set.release()
	data, err := set.cur.GetBlob(ctx, id)
	if RelayCode(err) != CodeBlobUnknown {
		return data, err
	}
	for _, o := range set.old {
		if !o.collect {
			continue
		}
		if d, e := o.r.GetBlob(ctx, id); e == nil {
			return d, nil
		}
	}
	return data, err
}

// deleteBlob deletes a blob of the vault's mailbox, wherever it is.
func (m *Manager) deleteBlob(ctx context.Context, id string) error {
	set := m.acquireRelays()
	defer set.release()
	err := set.cur.DeleteBlob(ctx, id)
	for _, o := range set.old {
		if o.collect {
			_ = o.r.DeleteBlob(ctx, id)
		}
	}
	return err
}

// putBlob uploads to a peer's mailbox on tok, signed with the key the
// token was issued to (§3.4 "Resending the new address" (a)).
func (m *Manager) putBlob(ctx context.Context, url, mailbox, tok string, data []byte) (string, time.Time, error) {
	set := m.acquireRelays()
	defer set.release()
	return set.forToken(tok).PutBlob(ctx, url, mailbox, tok, data)
}

// listBlobs lists the current mailbox's blobs.
func (m *Manager) listBlobs(ctx context.Context) (BlobList, error) {
	set := m.acquireRelays()
	defer set.release()
	return set.cur.ListBlobs(ctx)
}

// relayKeyHousekeeping runs before each batch: the old keys no longer
// needed are deleted.
func (m *Manager) relayKeyHousekeeping(now time.Time) {
	m.pruneOldRelayKeys(now)
	m.expirePeerRelayKeys(now)
}

// setLimits takes the relay's limits from a registration, and keeps them
// in the state for the unlocks that do not register (a relay key pending).
func (m *Manager) setLimits(l Limits) {
	m.limits = l
	if m.st == nil {
		return
	}
	if old := m.st.Relay.Limits; old == nil || !sameLimits(*old, l) {
		c := l
		m.st.Relay.Limits = &c
		m.dirty = true
	}
}

// storedLimits are the limits kept in the state (none: the zero limits).
func (m *Manager) storedLimits() {
	if l := m.st.Relay.Limits; l != nil {
		m.limits = *l
	}
}

func sameLimits(a, b Limits) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

// --- a principal's own relay-key rotation, as its receiver (§3.4
// "Device relay key"; a peer vault's rotation) ---

// PeerRelayGrace is how long a principal's earlier relay key is accepted
// after its relay.address.update: the relay's rotation grace
// (RELAY-PROTOCOL §6.7, a relay setting, 7 days by default). The tokens
// issued to it are denylisted then.
const PeerRelayGrace = 7 * 24 * time.Hour

// prevKey reports whether pk is one of p's earlier relay keys, still
// accepted at now.
func (p *Peer) prevKey(pk []byte, now time.Time) bool {
	for _, k := range p.PrevRelay {
		if suite.EqualPublic(k.PK, pk) && now.Before(k.Until) {
			return true
		}
	}
	return false
}

// peerHasKey reports whether pk is p's relay key or an earlier one still
// accepted.
func (m *Manager) peerHasKey(p *Peer, pk []byte) bool {
	return suite.EqualPublic(p.Relay.PK, pk) || p.prevKey(pk, m.now())
}

// awaitingFrom reports whether a handshake of p's (a rekey or reconnect
// the vault answered) waits for p's hs.fin.
func (m *Manager) awaitingFrom(peerID string) bool {
	for _, aw := range m.st.Awaiting {
		if aw.New == nil && aw.PeerID == peerID {
			return true
		}
	}
	return false
}

// endPrevRelay ends p's earlier relay keys: the tokens issued to them are
// denylisted (§3.4 "Device relay key").
func (m *Manager) endPrevRelay(p *Peer, now time.Time) {
	for _, k := range p.PrevRelay {
		m.denySubKey(k.PK, now)
	}
	p.PrevRelay = nil
	m.dirty = true
}

// expirePeerRelayKeys ends the grace of principals' earlier relay keys:
// the tokens issued to them are denylisted (§3.4 "Device relay key": the
// old sub after the grace period).
func (m *Manager) expirePeerRelayKeys(now time.Time) {
	for _, p := range m.allPeers() {
		kept := p.PrevRelay[:0]
		for _, k := range p.PrevRelay {
			if now.Before(k.Until) {
				kept = append(kept, k)
				continue
			}
			m.denySubKey(k.PK, now)
			m.dirty = true
		}
		if len(kept) == 0 {
			kept = nil
		}
		p.PrevRelay = kept
	}
}

// lockedErr is the error of a manager a write zeroized.
func (m *Manager) lockedErr() error {
	if m.splitBrained {
		return ErrSplitBrain
	}
	return ErrLocked
}

// relayMailboxUnknown is the collect loop's mailbox_unknown on the current
// mailbox: while a relay key is pending and not refused, it starts the
// rotate and then the registration of the pending key (§3.4, §12.2).
func (m *Manager) relayMailboxUnknown(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked {
		return ErrLocked
	}
	if pr := m.st.Relay.Pending; pr == nil || pr.Refused != "" {
		return nil
	}
	m.relayKeyStep(ctx, false)
	if m.locked {
		return m.lockedErr()
	}
	m.drainOutbox(ctx)
	return m.flushIfDirty(ctx)
}

// RelayKeyStatus is what a test or a host tool may read of the relay-key
// rotation: no key and no token.
type RelayKeyStatus struct {
	Mailbox string // the current mailbox
	Pending bool   // a key is pending
	Refused string // the pending key's refusal code (the refused state)
	OldKeys int    // old keys still used for deposits
	// Collecting are the old mailboxes still collected (their keys kept
	// until the relay's grace ends).
	Collecting int
	// Unacknowledged are the recipients that have not acknowledged the
	// last new address (nor had their resends ended).
	Unacknowledged []string
}

// RelayKeyStatus returns the relay-key rotation's state (§3.4).
func (m *Manager) RelayKeyStatus() RelayKeyStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st == nil {
		return RelayKeyStatus{}
	}
	s := RelayKeyStatus{Mailbox: m.st.Relay.Mailbox}
	for _, o := range m.st.Relay.Old {
		if !o.Retired {
			s.OldKeys++
		}
		if !o.Gone {
			s.Collecting++
		}
	}
	if pr := m.st.Relay.Pending; pr != nil {
		s.Pending, s.Refused = true, pr.Refused
	}
	for id, u := range m.st.Relay.Updates {
		if !u.Acked && !u.Ended {
			s.Unacknowledged = append(s.Unacknowledged, id)
		}
	}
	sort.Strings(s.Unacknowledged)
	return s
}
