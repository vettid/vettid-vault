package vault

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"math/rand/v2"
	"sort"
	"strings"
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

// relayFor is the Relay whose key a deposit on tok must be signed with:
// the token's sub. A token another principal issued to an old relay key
// is deposited with that key (§3.4 "Resending the new address" (a): the
// old key is used only to deposit); anything else with the current key.
func (m *Manager) relayFor(tok string) Relay {
	sub, _, ok := heldTokenClaims(tok)
	if !ok || m.keys == nil || sub == m.ownSub() {
		return m.relay
	}
	for i, k := range m.keys.oldRelay {
		if relayauth.EncodeKey(pubOf(k)) == sub {
			return m.oldRelayClient(i)
		}
	}
	return m.relay
}

// onOldKey reports whether tok was issued to one of the old relay keys.
func (m *Manager) onOldKey(tok string) bool {
	sub, _, ok := heldTokenClaims(tok)
	if !ok || sub == m.ownSub() {
		return false
	}
	for _, k := range m.keys.oldRelay {
		if relayauth.EncodeKey(pubOf(k)) == sub {
			return true
		}
	}
	return false
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
// answered 201 (a fresh mailbox).
func (m *Manager) relayKeyCall(ctx context.Context) (out relayOutcome, fresh bool, err error) {
	pr := m.pendingRelayClient()
	_, err = m.relay.Rotate(ctx, m.keys.pendingRelay)
	if err == nil {
		// The relay's limits for the new key: registering an existing key
		// again creates nothing (RELAY-PROTOCOL §6.1); a failure keeps
		// the limits the vault has.
		if lim, _, rerr := pr.RegisterCreated(ctx); rerr == nil {
			m.limits = lim
		}
		return relayDone, false, nil
	}
	if RelayCode(err) == CodeMailboxUnknown {
		lim, created, rerr := pr.RegisterCreated(ctx)
		if rerr == nil {
			m.limits = lim
			return relayDone, created, nil
		}
		err = rerr
	}
	if ctx.Err() == nil && definiteRefusal(err) {
		return relayRefused, false, err
	}
	return relayNoAnswer, false, err
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

// recoveredPhoneUnpaired reports whether a completed recovery's phone has
// not paired yet: its first handshake checks the vault's relay key and
// mailbox as the open's vault_bundle gave them, so the relay key is not
// made current before it (as retryOwedRotation waits for the identity key).
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
	if pr == nil || m.st.Deleting != nil || !m.rk.stored || m.recoveredPhoneUnpaired() {
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
	out, fresh, err := m.relayKeyCall(ctx)
	switch out {
	case relayDone:
		if !m.makePendingCurrent(fresh, now) {
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
		!m.recoveredPhoneUnpaired() {
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
	addr := strictjson.NewBuilder().String("url", m.st.Relay.URL).String("mailbox", m.st.Relay.Mailbox).
		Base64("pk", pubOf(m.keys.relay)).Bytes()
	if m.rk.resent == nil {
		m.rk.resent = map[string]bool{}
	}
	for _, p := range recips {
		h := pr.Tokens[p.ID]
		if h == nil || h.Standing == "" {
			continue
		}
		b := strictjson.NewBuilder().Raw("relay", addr).String("token", h.Standing)
		if h.Reconnect != "" {
			b.String("reconnect_token", h.Reconnect)
		}
		u := &AddressUpdate{Body: b.Bytes()}
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

// noteAddressAck records a recipient's acknowledgement (§3.4 "The
// signal"): relay.token.issued for the new sub (byToken), or a message
// deposited with a token the vault issued for the new mailbox (jti).
func (m *Manager) noteAddressAck(peerID, jti string, byToken bool) {
	u := m.st.Relay.Updates[peerID]
	if u == nil || u.Acked {
		return
	}
	if !byToken {
		found := false
		for _, j := range u.JTIs {
			if j == jti {
				found = true
			}
		}
		if !found {
			return
		}
	}
	u.Acked = true
	m.dirty = true
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

// pruneOldRelayKeys deletes the old relay keys no longer needed (§3.4
// "When the old key is deleted"): when every recipient has acknowledged
// or every standing token the recipients issued to it has expired,
// whichever is first, and not while a notice to a removed device holds a
// valid token for it (a pending unlink, a recovery's
// device.unlinked{replaced}, any deposit queued on such a token).
func (m *Manager) pruneOldRelayKeys(now time.Time) {
	if len(m.st.Relay.Old) == 0 {
		if m.st.Relay.Updates != nil && m.st.Relay.Pending == nil {
			m.st.Relay.Updates = nil
			m.dirty = true
		}
		return
	}
	allAcked := true
	for id, u := range m.st.Relay.Updates {
		if m.peer(id) == nil {
			delete(m.st.Relay.Updates, id) // a recipient removed since
			m.dirty = true
			continue
		}
		if !u.Acked && !u.Ended {
			allAcked = false
		}
	}
	validFor := func(tok string, exp time.Time, sub string) bool {
		s, texp, ok := heldTokenClaims(tok)
		if exp.IsZero() {
			exp = texp
		}
		return ok && s == sub && now.Before(exp)
	}
	keepSeeds := m.st.Relay.Old[:0]
	var keepKeys []ed25519.PrivateKey
	var keepRelays []Relay
	for i, o := range m.st.Relay.Old {
		k := m.keys.oldRelay[i]
		sub := relayauth.EncodeKey(pubOf(k))
		needed := false
		if !allAcked {
			for id, u := range m.st.Relay.Updates {
				if p := m.peer(id); !u.Acked && !u.Ended && p != nil && validFor(p.Standing.Token, p.Standing.Exp, sub) {
					needed = true
				}
			}
		}
		if pu := m.st.PendingUnlink; pu != nil && validFor(pu.Token, pu.TokenExp, sub) {
			needed = true
		}
		for _, e := range m.st.Outbox {
			if !e.Done && e.Op == OpDeposit && e.Token != "" && validFor(e.Token, time.Time{}, sub) {
				needed = true
			}
		}
		if needed {
			keepSeeds = append(keepSeeds, o)
			keepKeys = append(keepKeys, k)
			if i < len(m.rk.old) {
				keepRelays = append(keepRelays, m.rk.old[i])
			} else {
				keepRelays = append(keepRelays, nil)
			}
			continue
		}
		suite.Wipe(o.Seed)
		suite.Wipe(k)
		m.dirty = true
	}
	removed := len(keepKeys) != len(m.keys.oldRelay)
	m.st.Relay.Old, m.keys.oldRelay, m.rk.old = keepSeeds, keepKeys, keepRelays
	if len(m.st.Relay.Old) == 0 {
		m.st.Relay.Updates = nil
	}
	if removed {
		m.resetCollector() // the deleted keys' mailboxes are no longer collected
	}
}

// oldMailboxGone records that an old mailbox's grace ended (it answered
// mailbox_unknown): it is no longer collected.
func (m *Manager) oldMailboxGone(mailbox string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st == nil {
		return
	}
	for i := range m.st.Relay.Old {
		if m.st.Relay.Old[i].Mailbox == mailbox && !m.st.Relay.Old[i].Gone {
			m.st.Relay.Old[i].Gone = true
			m.dirty = true
		}
	}
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
}

type oldCollector struct {
	c       Collector
	mailbox string
	gone    bool
}

func (c *multiCollector) Next(ctx context.Context) ([]Message, error) {
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
	return c.main.Close()
}

// withOldCollectors wraps the current mailbox's collector with the old
// mailboxes still collected.
func (m *Manager) withOldCollectors(ctx context.Context, main Collector) Collector {
	var extra []oldCollector
	for i, o := range m.st.Relay.Old {
		if o.Gone {
			continue
		}
		r := m.oldRelayClient(i)
		var c Collector
		if cr, ok := r.(*ClientRelay); ok {
			c = cr.NewPollCollector(0)
		} else if oc, err := r.Collector(ctx, false); err == nil {
			c = oc
		} else {
			continue
		}
		extra = append(extra, oldCollector{c: c, mailbox: o.Mailbox})
	}
	if len(extra) == 0 {
		return main
	}
	return &multiCollector{main: main, extra: extra, gone: m.oldMailboxGone, from: map[string]Collector{}}
}

// relayKeyHousekeeping runs before each batch: the old keys no longer
// needed are deleted.
func (m *Manager) relayKeyHousekeeping(now time.Time) {
	m.pruneOldRelayKeys(now)
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
	OldKeys int    // old keys kept for deposits
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
	s := RelayKeyStatus{Mailbox: m.st.Relay.Mailbox, OldKeys: len(m.st.Relay.Old)}
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
