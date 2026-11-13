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

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// The vault's own relay-key rotation (VAULT-MESSAGING §3.4 "The order of a
// relay-key rotation", owner decision a of 2026-11-05: store first, then
// rotate, and retry with the same key). Only with Options.RelayKeyRotation;
// without it the three paths that rotate the vault's keys rotate ik, kem
// and the wake key only (§3.4.1 A5).
//
//  1. The rotation's state write stores the new relay key as pending, with
//     new tokens for every recipient, held (startRelayRotation, in the flush
//     of the path that rotates). The current key stays current.
//  2. After that write the vault calls the relay's rotate, signed by the
//     current key, with the pending key; past the grace (mailbox_unknown)
//     it registers the pending key instead (relayKeyAttempt). Just before
//     the first attempt away from the current key, a write of its own
//     stores that key's anchor (§3.4.2 RK14 step 1).
//  3. On success a second write makes the pending key current
//     (makePendingCurrent): the old key is kept for deposits, the held
//     tokens are re-minted near their end (every one for a mailbox the
//     relay created afresh), the recipients are taken again, and each
//     recipient's key for the vault and S1's clock are recorded.
//
// A run that ends between two steps leaves the stored state at the earlier
// one, and the next unlock goes on from there with the same key: the
// relay answers a repeated rotate with the same mailbox (RELAY-PROTOCOL
// §6.7, "Repeating a rotation").

// relayKeyRun is the memory-only runtime of the rotation (one per unlock:
// each unlock is a new Manager).
type relayKeyRun struct {
	// stored is the mailbox of the pending key as the last successful
	// state write stored it ("" for none): step 2 is made only for a key
	// already stored (store first).
	stored string
	// left is the mailbox of a key found pending when the state was
	// loaded (left by an earlier run): an unlock that does not complete
	// it audits identity.rotation_failed.
	left string
	// failAudited: identity.rotation_failed was audited in this unlock
	// (at most once per unlock, §3.4 "What is audited").
	failAudited bool
	// triedRefused: the refused state's one attempt of this unlock.
	triedRefused bool
	// fails counts the attempts in a row with no definite answer; next is
	// when the next sooner retry may be made (full jitter).
	fails int
	next  time.Time
	// noOK: an attempt since the last collect of the current mailbox got
	// no 200 (§3.4.2 RK14 step 1 "The order once the anchor is old").
	noOK bool
	// carryNamed are the marks a discarded inherited key's audit already
	// named, for the recovery's own key; relayMet: the open's fresh key is
	// the recovery's relay key (relayrecovery.go).
	carryNamed *RotationOwed
	relayMet   bool
	// openRecovery is the id of the recovery whose open is running: a
	// relay key stored as pending meanwhile is that recovery's own
	// (PendingRelay.Recovery).
	openRecovery string
	// unlockTried: this unlock's attempt was made before the recovered
	// phone's bundle (relayKeyBeforeBundle).
	unlockTried bool
	// pending and old are the Relays of the pending key and the old keys
	// (keys.oldRelay, by index), built when first used.
	pending Relay
	old     []Relay
}

// loaded notes a key pending in the state just read.
func (r *relayKeyRun) loaded(k *keyset) {
	if k.pendingRelay != nil {
		r.stored, r.left = mailboxOf(k.pendingRelay), mailboxOf(k.pendingRelay)
	}
}

// loadRelayRotation derives the pending and old relay keys from the state.
func (k *keyset) loadRelayRotation(rs *RelayState) error {
	if pr := rs.Pending; pr != nil {
		if len(pr.Seed) != ed25519.SeedSize {
			return ErrState
		}
		k.pendingRelay = ed25519.NewKeyFromSeed(pr.Seed)
	}
	for _, o := range rs.Old {
		if len(o.Seed) != ed25519.SeedSize {
			return ErrState
		}
		k.oldRelay = append(k.oldRelay, ed25519.NewKeyFromSeed(o.Seed))
	}
	return nil
}

// Backoff of the sooner retries while unlocked (§3.4 "Retrying with the
// same key"): the wait before the n-th retry in a row is random from 0 to
// min(1 h, 1 min × 2^(n−1)).
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

// relayRotation reports whether the vault rotates its own relay key.
func (m *Manager) relayRotation() bool { return m.opt.RelayKeyRotation }

// relayGateOpen is §3.4.1 "The gate", checked only when a new relay key
// would be generated. Not built here: the gate and its owed mark are a
// later change, and until then the switch alone opens it.
func (m *Manager) relayGateOpen() bool { return true }

// pendingMailbox is the pending key's mailbox, "" for none.
func (m *Manager) pendingMailbox() string {
	if m.keys == nil || m.keys.pendingRelay == nil {
		return ""
	}
	return mailboxOf(m.keys.pendingRelay)
}

func pubOf(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

// relayBase is the vault's relay URL as a token's aud.
func (m *Manager) relayBase() string {
	if m.relay != nil {
		return m.relay.BaseURL()
	}
	return strings.TrimRight(m.st.Relay.URL, "/")
}

// withKey is a Relay for another of the vault's own relay keys; nil when
// the Relay cannot rotate.
func (m *Manager) withKey(k ed25519.PrivateKey) Relay {
	if rot, ok := m.relay.(RelayRotator); ok {
		return rot.WithKey(k)
	}
	return nil
}

// pendingRelayClient is the Relay for the pending key.
func (m *Manager) pendingRelayClient() Relay {
	if m.rk.pending == nil && m.keys.pendingRelay != nil {
		m.rk.pending = m.withKey(m.keys.pendingRelay)
	}
	return m.rk.pending
}

// oldRelayClient is the Relay for the old key i.
func (m *Manager) oldRelayClient(i int) Relay {
	for len(m.rk.old) < len(m.keys.oldRelay) {
		m.rk.old = append(m.rk.old, nil)
	}
	if m.rk.old[i] == nil {
		m.rk.old[i] = m.withKey(m.keys.oldRelay[i])
	}
	return m.rk.old[i]
}

// tokenSub reads a deposit token's sub without verifying it: a token the
// vault holds, read only to choose the key that signs a deposit on it
// (the relay checks the token).
func tokenSub(tok string) (string, bool) {
	const prefix = "v4.public."
	if !strings.HasPrefix(tok, prefix) {
		return "", false
	}
	body := strings.TrimPrefix(tok, prefix)
	if i := strings.IndexByte(body, '.'); i >= 0 {
		body = body[:i]
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || len(raw) <= ed25519.SignatureSize {
		return "", false
	}
	c, err := relayauth.ParseClaims(raw[:len(raw)-ed25519.SignatureSize])
	if err != nil {
		return "", false
	}
	return c.Sub, true
}

// relayFor is the Relay whose key a deposit on tok is signed with: a token
// another principal issued to one of the vault's old relay keys is
// deposited with that key (§3.4 "Resending the new address" (a): the old
// key is kept for deposits); anything else with the current key. Without
// old keys it is the current Relay, as before.
func (m *Manager) relayFor(tok string) Relay {
	if m.keys == nil || len(m.keys.oldRelay) == 0 {
		return m.relay
	}
	sub, ok := tokenSub(tok)
	if !ok {
		return m.relay
	}
	for i, k := range m.keys.oldRelay {
		if relayauth.EncodeKey(pubOf(k)) == sub {
			if r := m.oldRelayClient(i); r != nil {
				return r
			}
		}
	}
	return m.relay
}

// blobMailbox is the own mailbox a blob named by the message being handled
// was put in: the one the message was collected from ("" without
// Options.RelayKeyRotation: the current one).
func (m *Manager) blobMailbox() string {
	if !m.relayRotation() {
		return ""
	}
	return m.collectedFrom()
}

// errBlobGone answers a blob in an own mailbox the vault no longer
// collects (its key's collects ended, §3.4.2 RK14 step 1): as the relay
// answers a blob it does not have.
var errBlobGone = &relayclient.Error{Status: 404, Code: CodeBlobUnknown}

// blobRelay is the Relay that may fetch and delete the blobs of the own
// mailbox mb ("" or the current one: the current Relay; an old one still
// collected: its key's), nil for any other. Takes the lock.
func (m *Manager) blobRelay(mb string) Relay {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st == nil || mb == "" || mb == m.st.Relay.Mailbox {
		return m.relay
	}
	for i := range m.st.Relay.Old {
		if o := &m.st.Relay.Old[i]; o.Mailbox == mb && o.Collect.Stopped.IsZero() {
			return m.oldRelayClient(i)
		}
	}
	return nil
}

// blobRelays are the Relays to look for a blob of the own mailbox mb in:
// that mailbox's first (while it is collected), then the other own
// mailboxes still collected. A blob recorded before the first rotation
// ("", the then-current mailbox) or put by a peer that changed the
// vault's address between its upload and its deposit lies in another of
// them; blob ids are the relay's, so another mailbox cannot hold another
// blob under the same id.
func (m *Manager) blobRelays(mb string) []Relay {
	first := m.blobRelay(mb)
	var out []Relay
	if first != nil {
		out = append(out, first)
	}
	for _, r := range m.ownRelays() {
		if r != first {
			out = append(out, r)
		}
	}
	return out
}

// getBlobAny fetches a blob of the own mailbox mb, looking in the others
// still collected when that one does not have it (blobRelays).
func (m *Manager) getBlobAny(ctx context.Context, mb, id string) ([]byte, error) {
	var err error = errBlobGone
	for _, rel := range m.blobRelays(mb) {
		var data []byte
		if data, err = rel.GetBlob(ctx, id); RelayCode(err) != CodeBlobUnknown {
			return data, err
		}
	}
	return nil, err
}

// deleteBlobIn deletes a blob of the own mailbox mb, best effort, in every
// own mailbox it may lie in (blobRelays).
func (m *Manager) deleteBlobIn(ctx context.Context, mb, id string) {
	for _, rel := range m.blobRelays(mb) {
		_ = rel.DeleteBlob(ctx, id)
	}
}

// ownRelays are the Relays of the vault's own mailboxes whose blobs it
// keeps: the current one first, then each old one still collected. Takes
// the lock: for the attachment workers, which run unlocked, while the
// second write (§3.4 step 3) replaces the current Relay under it. Never
// called with the lock held.
func (m *Manager) ownRelays() []Relay {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Relay{m.relay}
	if m.st == nil || !m.relayRotation() {
		return out
	}
	for i := range m.st.Relay.Old {
		if m.st.Relay.Old[i].Collect.Stopped.IsZero() {
			if r := m.oldRelayClient(i); r != nil {
				out = append(out, r)
			}
		}
	}
	return out
}

// revoke sends a revocation to the mailboxes that issued what it names
// (§3.4.1 S7): a token by its jti to the one that issued it, a sender's
// key to the current mailbox and every old one kept. An old key revokes
// only during its grace (§3.4 (a)): not once RK14 step 1 has ended its
// mailbox's collects or its stop is due (13 days after its anchor, before
// the relay's grace ends). Skipping a stopped old key is safe only
// because nothing deposited there after its stop is ever collected. An
// old mailbox already gone (mailbox_unknown) took its tokens with it.
func (m *Manager) revoke(ctx context.Context, kind, value string) error {
	if !m.relayRotation() || len(m.st.Relay.Old) == 0 {
		return m.relay.Revoke(ctx, kind, value)
	}
	now := m.now()
	inGrace := func(i int) bool {
		o := &m.st.Relay.Old[i]
		return o.Collect.Stopped.IsZero() && !oldStopDue(o, now)
	}
	rels := []Relay{m.relay}
	switch kind {
	case "jti":
		for _, t := range m.st.Issued {
			if t.JTI == value && t.Iss != "" && t.Iss != m.st.Relay.Mailbox {
				rels = nil
				for i := range m.st.Relay.Old {
					if m.st.Relay.Old[i].Mailbox == t.Iss && inGrace(i) {
						rels = append(rels, m.oldRelayClient(i))
					}
				}
			}
		}
	case "sub":
		for i := range m.st.Relay.Old {
			if inGrace(i) {
				rels = append(rels, m.oldRelayClient(i))
			}
		}
	}
	var err error
	for _, r := range rels {
		if r == nil {
			continue
		}
		if e := r.Revoke(ctx, kind, value); e != nil && RelayCode(e) != CodeMailboxUnknown && err == nil {
			err = e
		}
	}
	return err
}

// relayRecipients are the recipients of a relay-key rotation (§3.4 step
// 2): every active device and connection, in id order.
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

// --- the owed marks (§3.4 "Owed marks", §11.14.10) ---

// marksOf are the recovery and transfer marks of o (not the relay-key
// mark), a copy.
func marksOf(o *RotationOwed) *RotationOwed {
	if o == nil {
		return &RotationOwed{}
	}
	return &RotationOwed{Recovery: o.Recovery, Transfer: o.Transfer, DEKVersion: o.DEKVersion, At: o.At}
}

// unionMarks is the marks of a and b (b's transfer wins: the later one).
func unionMarks(a, b *RotationOwed) *RotationOwed {
	out := marksOf(a)
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

// markRef is the identity.rotated ref of a rotation that clears marks
// (§11.14.10, 0.69.2), less those an earlier audit named (§3.4 "What is
// audited"): the transfer_id, else "recovery", else none.
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

// pendingRef is the ref of the pending key's identity.rotated, and of its
// identity.rotation_failed.
func (m *Manager) pendingRef() string {
	if pr := m.st.Relay.Pending; pr != nil {
		return markRef(pr.Marks, pr.Named)
	}
	return ""
}

// marksMade reports whether the rotation every owed mark asks for has been
// made: its relay key is pending, or it was made while that key was
// pending. The retry the mark asks for at each unlock is then the
// completion of the pending key, not a new rotation of ik, kem or the wake
// key (§3.4 "Owed marks", §11.14.10 "The owed mark").
func marksMade(o *RotationOwed, pr *PendingRelay) bool {
	made := func(v string, get func(*RotationOwed) string) bool {
		return v == "" || pr.Marks != nil && get(pr.Marks) == v || pr.Next != nil && get(pr.Next) == v
	}
	return made(o.Recovery, func(r *RotationOwed) string { return r.Recovery }) &&
		made(o.Transfer, func(r *RotationOwed) string { return r.Transfer })
}

// clearMarks clears the owed marks named in marks, each only if it is
// still the same one, and the owed object when nothing is left.
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
	if o.Recovery == "" && o.Transfer == "" && o.RelayKey.IsZero() {
		m.st.RotationOwed = nil
	}
	m.dirty = true
}

// --- step 1: the pending key ---

// relaySeedNeeded reports whether a rotation made now generates a relay
// key: none is pending, or the member's credential.rotate finds one in
// the refused state (§3.4 "The way out of the refused state").
func (m *Manager) relaySeedNeeded(byCredential bool) bool {
	pr := m.st.Relay.Pending
	return m.relayGateOpen() && (pr == nil || byCredential && pr.Refused != "")
}

// startRelayRotation is the relay part of a rotation, in memory; the
// rotation's flush stores it (§3.4 step 1). seed is nil when
// relaySeedNeeded was false. Nothing is audited and no mark clears here:
// the second write does both.
func (m *Manager) startRelayRotation(seed []byte, byCredential bool, now time.Time) {
	pr := m.st.Relay.Pending
	switch {
	case seed == nil && pr == nil:
		// The gate is closed (a later change records the relay-key mark).
	case pr == nil:
		// A new key meets any relay-key rotation owed.
		if o := m.st.RotationOwed; o != nil && !o.RelayKey.IsZero() {
			o.RelayKey = time.Time{}
			m.clearMarks(&RotationOwed{})
		}
		named := m.rk.carryNamed
		m.rk.carryNamed = nil
		m.newPendingRelay(seed, marksOf(m.st.RotationOwed), named, now)
	case byCredential && pr.Refused != "":
		// The way out of the refused state: the refused key, its tokens and
		// the refused mark are discarded; the new key meets any relay-key
		// rotation owed, which clears in this flush; the other marks clear
		// at its second write. The current key's anchor stays with it.
		all := unionMarks(unionMarks(pr.Marks, pr.Next), m.st.RotationOwed)
		named := pr.Named
		m.dropPendingRelay()
		if o := m.st.RotationOwed; o != nil {
			o.RelayKey = time.Time{}
			m.clearMarks(&RotationOwed{})
		}
		m.newPendingRelay(seed, all, named, now)
	default:
		// A rotation made while a relay key is pending keeps that key, its
		// tokens and its held updates, and owes a relay-key rotation, which
		// the pending key's second write meets (a mark already set keeps
		// its time).
		suite.Wipe(seed)
		pr.Next = unionMarks(pr.Next, m.st.RotationOwed)
		if m.st.RotationOwed == nil {
			m.st.RotationOwed = &RotationOwed{}
		}
		if m.st.RotationOwed.RelayKey.IsZero() {
			m.st.RotationOwed.RelayKey = now.UTC()
		}
		m.dirty = true
	}
}

// newPendingRelay stores seed as the pending relay key with new tokens for
// every recipient, held (§3.4 steps 1 and 2).
func (m *Manager) newPendingRelay(seed []byte, marks, named *RotationOwed, now time.Time) {
	pr := &PendingRelay{Seed: seed, Held: map[string]*HeldTokens{}, Marks: marks, Named: named, Recovery: m.rk.openRecovery}
	if m.limits != (Limits{}) {
		lim := m.limits
		pr.Limits = &lim
	}
	m.st.Relay.Pending = pr
	m.keys.pendingRelay = ed25519.NewKeyFromSeed(seed)
	m.rk.pending, m.rk.fails, m.rk.next = nil, 0, time.Time{}
	for _, p := range m.relayRecipients() {
		m.mintHeld(pr, m.keys.pendingRelay, p, now)
	}
	m.dirty = true
}

// dropPendingRelay discards the pending key (the way out of the refused
// state).
func (m *Manager) dropPendingRelay() {
	if pr := m.st.Relay.Pending; pr != nil {
		suite.Wipe(pr.Seed)
	}
	suite.Wipe(m.keys.pendingRelay)
	m.st.Relay.Pending, m.keys.pendingRelay, m.rk.pending = nil, nil, nil
	m.dirty = true
}

// mintHeld mints p's standing token (and reconnect token, for a
// connection) on key, pr's, and holds them in pr.
func (m *Manager) mintHeld(pr *PendingRelay, key ed25519.PrivateKey, p *Peer, now time.Time) {
	h := &HeldTokens{}
	if old := pr.Held[p.ID]; old != nil {
		h = old
	}
	if pr.Held == nil {
		pr.Held = map[string]*HeldTokens{} // read back without recipients (omitempty)
	}
	pr.Held[p.ID] = h
	if tok, it, err := m.mintOnKey(key, p, TokStanding, now); err == nil {
		h.Standing, h.Issued = tok, replaceIssued(h.Issued, it)
	}
	if p.Kind == KindConnection {
		if tok, it, err := m.mintOnKey(key, p, TokReconnect, now); err == nil {
			h.Reconnect, h.Issued = tok, replaceIssued(h.Issued, it)
		}
	}
}

// mintOnKey mints a standing or reconnect token for p on key, with the
// lifetime and quota of its kind (§7.1, §6.6), as mintStanding and
// mintReconnect do on the current key. iat is backdated as relayclient's
// (RELAY-PROTOCOL §5.2), for a mailbox made afresh too: freshMailboxWait
// counts the backdate, and a vault clock ahead of the relay's needs it.
func (m *Manager) mintOnKey(key ed25519.PrivateKey, p *Peer, kind string, now time.Time) (string, IssuedToken, error) {
	ttl := m.standingTTL(p.Kind)
	var quota *relayauth.Quota
	if kind == TokReconnect {
		ttl = handshake.ReconnectTokenLifetime(time.Duration(m.limits.MaxTokenLifetimeSeconds) * time.Second)
		quota = &relayauth.Quota{Msgs: i64(handshake.ReconnectTokenQuotaMsgs), Bytes: i64(handshake.ReconnectTokenQuotaBytes)}
	} else if p.Kind == KindConnection {
		quota = &relayauth.Quota{Msgs: i64(PeerQuotaMsgs), Bytes: i64(PeerQuotaBytes)}
	}
	iat := now.UTC().Truncate(time.Second).Add(-tokenBackdate) // as relayclient (RELAY-PROTOCOL §5.2)
	jti := m.newID(now)
	sub := relayauth.EncodeKey(p.Relay.PK)
	tok, err := relayauth.MintToken(key, relayauth.Claims{Iss: relayauth.MailboxID(pubOf(key)), Sub: sub, Aud: m.relayBase(),
		Iat: iat, Exp: iat.Add(ttl), Jti: jti, Scope: relayauth.ScopeDeposit, Quota: quota,
		OwnerDevice: kind == TokStanding && p.Kind == KindApp})
	if err != nil {
		return "", IssuedToken{}, err
	}
	return tok, IssuedToken{JTI: jti, Kind: kind, Sub: sub, PeerID: p.ID, Exp: iat.Add(ttl), Iss: relayauth.MailboxID(pubOf(key))}, nil
}

// replaceIssued puts it in place of the entry of the same kind.
func replaceIssued(list []IssuedToken, it IssuedToken) []IssuedToken {
	out := list[:0]
	for _, t := range list {
		if t.Kind != it.Kind {
			out = append(out, t)
		}
	}
	return append(out, it)
}

func issuedOf(list []IssuedToken, kind string) (IssuedToken, bool) {
	for _, t := range list {
		if t.Kind == kind {
			return t, true
		}
	}
	return IssuedToken{}, false
}

// keepRelayLimits stores the limits of a registration just answered with a
// pending key, which an unlock that registers no key uses.
func (m *Manager) keepRelayLimits() {
	if pr := m.st.Relay.Pending; pr != nil && m.limits != (Limits{}) {
		lim := m.limits
		pr.Limits = &lim
		m.dirty = true
	}
}

// --- step 2: the rotate, or the registration ---

type relayOutcome int

const (
	relayDone     relayOutcome = iota // the relay has the new mailbox
	relayNoAnswer                     // no definite answer: retried
	relayRefused                      // a definite refusal: the refused state
)

// definiteRefusal reports whether err is a definite refusal (§3.4): any
// 4xx other than 429 rate_limited, timestamp_stale and replay_detected
// (which a freshly signed request can pass). The rotate's mailbox_unknown
// is handled before (it leads to the registration).
func definiteRefusal(err error) bool {
	st, ok := statusOf(err)
	if !ok || st < 400 || st >= 500 {
		return false
	}
	switch RelayCode(err) {
	case "rate_limited", CodeTimestampStale, CodeReplayDetected:
		return false
	}
	return true
}

// relaysOwnRefusal reports the relay's own 400 bad_request or 401
// signature_invalid, with the error body of RELAY-PROTOCOL §7.1: the
// relay did not carry out that request (§3.4.2 RK14 step 1 "When it is
// cleared"). A 4xx without that body (a proxy, a firewall) is not one.
func relaysOwnRefusal(err error) bool {
	var e *relayclient.Error
	if !errors.As(err, &e) {
		return false
	}
	return e.Status == 400 && e.Code == "bad_request" || e.Status == 401 && e.Code == "signature_invalid"
}

// retryAfterOf is a 429 rate_limited answer's retry_after.
func retryAfterOf(err error) time.Duration {
	var e *relayclient.Error
	if errors.As(err, &e) && e.Status == 429 && e.RetryAfter > 0 {
		return time.Duration(e.RetryAfter) * time.Second
	}
	return 0
}

// relayKeyCall makes one attempt: the rotate signed by the current key
// with the pending key; on mailbox_unknown (past the grace) the
// registration of the stored pending key. created: the mailbox may have
// been created afresh, at an id that may carry a tombstone (RELAY-PROTOCOL
// §6.10): every registration past the grace that succeeds (a 201, or a 200
// that may follow this vault's own 201 whose answer or record was lost),
// and a 201 to the registration after a rotate. byRotate: the answer was
// the rotate's (a refusal of it, or its success, after which a created
// mailbox is told by a 201 itself).
func (m *Manager) relayKeyCall(ctx context.Context) (out relayOutcome, created, byRotate bool, err error) {
	rot, ok := m.relay.(RelayRotator)
	pending, ok2 := m.pendingRelayClient().(RelayRotator)
	if !ok || !ok2 {
		return relayNoAnswer, false, false, errors.New("vault: the relay cannot rotate")
	}
	if _, err = rot.Rotate(ctx, m.keys.pendingRelay); err == nil {
		// The new mailbox's limits: registering a key the relay already
		// has creates nothing (RELAY-PROTOCOL §6.1); a failure keeps the
		// limits the vault has. A 201 here means the relay created the
		// mailbox afresh after all (the successor gone again): every held
		// token is minted again after freshMailboxWait (RELAY-PROTOCOL
		// §6.10).
		if lim, c, rerr := pending.RegisterCreated(ctx); rerr == nil {
			m.limits, created = lim, c
		}
		return relayDone, created, true, nil
	}
	if RelayCode(err) != CodeMailboxUnknown {
		if ctx.Err() == nil && definiteRefusal(err) {
			return relayRefused, false, true, err
		}
		return relayNoAnswer, false, false, err
	}
	// §3.4.2 RK14 step 1: the current mailbox's collects end, for good.
	m.mailboxGone(m.st.Relay.Mailbox, m.now())
	lim, _, err := pending.RegisterCreated(ctx)
	if err == nil {
		m.limits = lim
		return relayDone, true, false, nil
	}
	if ctx.Err() == nil && definiteRefusal(err) {
		return relayRefused, false, false, err
	}
	return relayNoAnswer, false, false, err
}

// freshMailboxWait is how long after the answer that created the pending
// key's mailbox afresh the vault waits before it mints that mailbox's
// tokens (the second write, every held token minted again with iat at
// that time). RELAY-PROTOCOL §6.10: a mailbox made again at an id that
// had a tombstone refuses every token with iat before the deletion plus
// 90 seconds, by the relay's clock; the deletion came before the answer.
// The wait is that 90 seconds, plus the 90 seconds of skew RELAY-PROTOCOL
// §4.1's freshness window allows between the vault's clock and the
// relay's (a vault clock behind the relay's by up to that much still
// mints after the tombstone's bound), plus the 60 seconds every token's
// iat is backdated (RELAY-PROTOCOL §5.2: the held tokens, mintStanding
// and the unlock tokens of the answer that completes the key alike, so
// that a vault clock ahead of the relay's by up to that much is not
// refused), plus a second for iat's truncation to whole seconds: 241
// seconds. Minting at once with a later iat would not do: the relay
// checks iat <= now strictly (RELAY-PROTOCOL §5.3 step 5). A reading of
// this release (the spec should confirm).
const freshMailboxWait = freshMailboxTombstone + collectedToWindow + tokenBackdate + time.Second

// freshMailboxTombstone is RELAY-PROTOCOL §6.10's 90 seconds after a
// deletion before which a mailbox made again refuses a token's iat.
const freshMailboxTombstone = 90 * time.Second

// freshWaitRuns reports whether pr waits for its mailbox made afresh.
func (m *Manager) freshWaitRuns(pr *PendingRelay) bool {
	return pr != nil && !pr.Created.IsZero() && m.now().Before(pr.Created.Add(freshMailboxWait))
}

// relayKeyStep completes a pending relay key after a state write: at the
// unlock (one attempt; the unlock goes on whatever its answer), after the
// flush that stored a new key, and as the sooner retries come due while
// unlocked. A next key, stored by the second write, is attempted at once.
func (m *Manager) relayKeyStep(ctx context.Context, atUnlock bool) {
	for range 2 {
		if !m.relayKeyAttempt(ctx, atUnlock) {
			return
		}
	}
}

// recoveryWaits reports whether the attempts of pr wait for a recovered
// phone: pr is the key a recovery's open stored as pending (never a key
// it inherited), that recovery's phone has not paired yet (its invite is
// pending and has not expired: each of the phone's own unlocks renews it,
// so the wait ends a RecoveredInviteWindow after the phone was last
// seen), and the current mailbox, whose address the open's vault_bundle
// gave the phone, still lives. A reading of this release (the spec should
// confirm): the phone's first handshake checks the vault's relay key and
// mailbox as the open's vault_bundle gave them, as retryOwedRotation waits
// for the ik. Once that mailbox answered mailbox_unknown the phone cannot
// reach it, and the key is completed as any other (§3.4 "Retrying with the
// same key"); the phone's own unlock before its first handshake makes
// that attempt before its bundle (relayKeyBeforeBundle), which then
// carries the new address (resumeLostOK).
func (m *Manager) recoveryWaits(pr *PendingRelay) bool {
	if pr == nil || pr.Recovery == "" || !m.st.Relay.Collect.Stopped.IsZero() {
		return false
	}
	inv := m.st.Invites[pr.Recovery]
	return inv != nil && inv.CreatedBy == inviteByRecovery && m.now().Before(inv.Exp)
}

// relayKeyAttempt makes one attempt if one is due; true when the key was
// made current and the second write stored (another key may be pending).
func (m *Manager) relayKeyAttempt(ctx context.Context, atUnlock bool) bool {
	if !m.relayRotation() || m.locked || m.st == nil {
		return false
	}
	pr := m.st.Relay.Pending
	if pr == nil || m.st.Deleting != nil || m.rk.stored == "" || m.rk.stored != m.pendingMailbox() || m.recoveryWaits(pr) {
		return false
	}
	now := m.now()
	switch {
	case pr.Refused != "":
		// One attempt at each unlock, no sooner retries.
		if !atUnlock || m.rk.triedRefused {
			return false
		}
	case now.Before(pr.RetryAfter):
		return false // a running retry_after is honored at an unlock too
	case !atUnlock && now.Before(m.rk.next):
		// The sooner retries' wait (full jitter) runs: no attempt may be
		// made, before a collect either (beforeCollect).
		return false
	case m.freshWaitRuns(pr):
		return false // the wait after a mailbox created afresh, at an unlock too
	}
	if !pr.Created.IsZero() && m.stateBehind {
		// It fails closed: the answer's time of a mailbox made afresh is
		// stored before the key is completed. Unstored, a lock or a restart
		// would forget the wait, and an attempt then (a repeated rotate
		// within the grace, answered 200) would complete it with tokens the
		// relay refuses.
		if m.persist(ctx, false) != nil {
			return false
		}
	}
	// §3.4.2 RK14 step 1: the anchor, in a write of its own just before
	// the first attempt away from the current key. Nothing is sent until
	// it is stored.
	anchored := false
	if m.st.Relay.Anchor.IsZero() {
		m.st.Relay.Anchor = now.UTC()
		m.dirty = true
		if err := m.persist(ctx, false); err != nil {
			if m.st != nil {
				m.st.Relay.Anchor = time.Time{}
			}
			return false
		}
		anchored = true
	}
	if pr.Refused != "" {
		m.rk.triedRefused = true
	}
	out, created, byRotate, err := m.relayKeyCall(ctx)
	switch out {
	case relayDone:
		if created && (pr.Created.IsZero() || byRotate) {
			// (A 201 after a rotate, the wait already stored: the mailbox
			// was made afresh again, and the wait starts again. Past the
			// grace a registration cannot tell a 200 from a 201, so a
			// stored wait stands there.)
			// A mailbox created afresh: its tokens wait (freshMailboxWait),
			// the time of the answer stored with the key, in a write of its
			// own, so that a lock or a restart waits too. The key stays
			// pending, nothing announced; the attempt after the wait
			// completes it.
			// A write that fails leaves the state behind (stateBehind): the
			// key is not completed until a write stores the wait.
			pr.Created, pr.Refused, pr.RetryAfter = now.UTC(), "", time.Time{}
			m.dirty = true
			m.rk.fails, m.rk.next = 0, now.Add(freshMailboxWait)
			_ = m.persist(ctx, false)
			return false
		}
		if !m.makePendingCurrent(created || !pr.Created.IsZero(), now) {
			m.rk.next = now.Add(relayRetryWait(1))
			return false
		}
		m.rk.fails = 0
		return m.persist(ctx, false) == nil // memory is ahead on failure: the next write that succeeds stores it
	case relayRefused:
		m.rk.noOK = true
		// It fails secure: the refused state, in a write of its own.
		pr.Refused, pr.RetryAfter = RelayCode(err), time.Time{}
		if pr.Refused == "" {
			pr.Refused = "refused"
		}
		if anchored && byRotate && relaysOwnRefusal(err) {
			m.st.Relay.Anchor = time.Time{} // the relay did not carry it out
		}
		m.dirty = true
		m.rk.failAudited = false // a definite refusal is audited at once
		m.relayKeyFailed(now)
		_ = m.persist(ctx, false)
		return false
	default:
		if ctx.Err() != nil {
			return false // interrupted (a lock): not counted
		}
		m.rk.noOK = true
		if m.dirty {
			_ = m.persist(ctx, false) // a stop on mailbox_unknown, at once
		}
		if pr.Refused != "" {
			return false
		}
		m.rk.fails++
		wait := relayRetryWait(m.rk.fails)
		if ra := retryAfterOf(err); ra > 0 {
			pr.RetryAfter = now.Add(ra).UTC()
			m.dirty = true
			wait = max(wait, ra)
			_ = m.persist(ctx, false) // stored with the key, so a lock and an unlock do not reset it
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

// relayKeyAtUnlock completes a key left pending by an earlier run (the
// unlock's attempt), and audits identity.rotation_failed when this
// unlock's own attempt does not complete it: it fails, gets no answer, or
// is not made because a retry_after still runs. A key that waits for the
// recovered phone (recoveryWaits), or for its mailbox made afresh
// (freshMailboxWait), is not audited: the relay has not failed it.
func (m *Manager) relayKeyAtUnlock(ctx context.Context) {
	if !m.relayRotation() {
		return
	}
	if !m.rk.unlockTried { // made before the recovered phone's bundle
		m.relayKeyStep(ctx, true)
	}
	if m.st == nil || m.rk.left == "" || m.st.Relay.Pending == nil || m.pendingMailbox() != m.rk.left || m.recoveryWaits(m.st.Relay.Pending) ||
		m.freshWaitRuns(m.st.Relay.Pending) {
		return
	}
	m.relayKeyFailed(m.now())
}

// errRelayKeyUnanswered answers a recovered phone's unlock whose relay-key
// attempt got no definite answer (relayKeyBeforeBundle).
var errRelayKeyUnanswered = errors.New("vault: the relay key's attempt got no definite answer")

// relayKeyBeforeBundle is the unlock's one relay-key attempt, made before
// the recovered phone's bundle is built when the current mailbox is gone
// (its collects ended on mailbox_unknown) and a key is pending: the
// bundle (§11.14.6 "A lost ok") then names the mailbox the attempt made
// current, not the gone one. relayKeyAtUnlock makes no second attempt.
// A key that stays pending, not refused, after it (no definite answer, a
// retry_after or freshMailboxWait still running) answers the unlock
// "retry" (code), with the time after which another attempt may be made
// (wait): an ok would hand the phone the gone mailbox again and spend one
// of its tries; a retry spends nothing. A refused key goes on as before
// (the refused state).
//
// The attempt may have written the state (the anchor's own write, a stop,
// a retry_after, the answer of a mailbox made afresh) through persist,
// under the DEK the unlock opened. The unlocks that would store what
// only their ok completes make no attempt here (resume); what is left
// (the unlocked report, the app key and name reports) recurs at every
// unlock, and the retry locks the vault again.
func (m *Manager) relayKeyBeforeBundle(ctx context.Context) (code string, wait time.Duration, err error) {
	pr := m.st.Relay.Pending
	if !m.relayRotation() || pr == nil || m.st.Relay.Collect.Stopped.IsZero() {
		return "", 0, nil
	}
	m.relayKeyStep(ctx, true)
	m.rk.unlockTried = true
	if m.st == nil || m.locked {
		return CodeRetry, 0, ErrSplitBrain
	}
	pr = m.st.Relay.Pending
	if pr == nil || pr.Refused != "" || m.st.Relay.Collect.Stopped.IsZero() {
		return "", 0, nil
	}
	now := m.now()
	switch {
	case now.Before(pr.RetryAfter):
		wait = pr.RetryAfter.Sub(now)
	case m.freshWaitRuns(pr):
		wait = pr.Created.Add(freshMailboxWait).Sub(now)
	case now.Before(m.rk.next):
		wait = m.rk.next.Sub(now)
	default:
		wait = relayRetryWait(max(m.rk.fails, 1))
	}
	// At least a second: the full jitter starts at 0, and retry_after is
	// whole seconds rounded up.
	return CodeRetry, max(wait, time.Second), errRelayKeyUnanswered
}

// relayMailboxUnknown is the collect loop's mailbox_unknown on the current
// mailbox: while a key is pending and not refused it starts the same path,
// the rotate and then the registration (§3.4 "Retrying with the same
// key").
func (m *Manager) relayMailboxUnknown(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked {
		return ErrLocked
	}
	pr := m.st.Relay.Pending
	if !m.relayRotation() || pr == nil {
		return nil
	}
	// §3.4.2 RK14 step 1: the current mailbox's collects end, for good, in
	// a write at once; in the refused state nothing more is tried.
	if m.mailboxGone(m.st.Relay.Mailbox, m.now()) {
		if err := m.persist(ctx, false); err != nil {
			return err
		}
	}
	if pr.Refused != "" {
		return nil
	}
	m.relayKeyStep(ctx, false)
	if m.locked {
		return ErrLocked
	}
	m.drainOutbox(ctx)
	return m.flushIfDirty(ctx)
}

// --- step 3: the second write ---

// makePendingCurrent is the second write, in memory (§3.4 step 3); the
// caller stores it. false: nothing changed (no randomness for a next key).
// created: the mailbox was created afresh (a 201 past the grace).
func (m *Manager) makePendingCurrent(created bool, now time.Time) bool {
	pr := m.st.Relay.Pending
	o := m.st.RotationOwed
	var nextSeed []byte
	if o != nil && !o.RelayKey.IsZero() && m.relayGateOpen() {
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
	// The old key is kept, with its anchor (§3.4 (a); §3.4.2 RK14 step
	// 1: the key made current has none until a rotation away from it is
	// attempted).
	// Old keys are not deleted yet: §3.4 "When the old key is deleted"
	// (every recipient acknowledged or stale, the notices to removed
	// devices settled, RK14 step 1 done) is a later change.
	oldKey, oldSub := m.keys.relay, relayauth.EncodeKey(pubOf(m.keys.relay))
	// §3.4.2 RK14 step 1: what was collected from it goes with it; a stop
	// recorded before this write (mailbox_unknown) has its telling queued
	// here, and a timed stop already due is made in this write.
	kept := m.st.Relay.Collect
	kept.TellingDue = !kept.Stopped.IsZero()
	m.st.Relay.Old = append(m.st.Relay.Old, OldRelayKey{Seed: m.st.Relay.Seed, Mailbox: m.st.Relay.Mailbox, MadeOld: now.UTC(),
		Anchor: m.st.Relay.Anchor, Collect: kept})
	m.st.Relay.Collect = MailboxCollect{}
	m.keys.oldRelay = append(m.keys.oldRelay, oldKey)
	for len(m.rk.old) < len(m.keys.oldRelay)-1 {
		m.rk.old = append(m.rk.old, nil)
	}
	m.rk.old = append(m.rk.old, m.relay)
	newRelay := m.pendingRelayClient()
	m.st.Relay.Seed, m.st.Relay.Mailbox, m.st.Relay.Anchor = pr.Seed, mailboxOf(m.keys.pendingRelay), time.Time{}
	m.keys.relay, m.keys.pendingRelay = m.keys.pendingRelay, nil
	m.relay, m.rk.pending = newRelay, nil
	if m.limits == (Limits{}) && pr.Limits != nil {
		m.limits = *pr.Limits
	}
	m.st.Relay.Pending = nil // its retry_after and refused mark go with it
	m.resetCollector()
	m.stopOldCollects(now)

	// The recipients again: a device or peer added since gets new tokens,
	// those of one removed since are dropped; held tokens re-minted near
	// their end (§7.2 "On unlock"), or minted for a key of the recipient's
	// that changed since (§3.4.1 S3), and every one for a fresh mailbox.
	if m.st.Relay.Recipients == nil {
		m.st.Relay.Recipients = map[string]*RelayRecipient{}
	}
	keep := map[string]bool{}
	for _, p := range m.relayRecipients() {
		keep[p.ID] = true
		h := pr.Held[p.ID]
		sub := relayauth.EncodeKey(p.Relay.PK)
		if h == nil || created {
			m.mintHeld(pr, m.keys.relay, p, now)
			h = pr.Held[p.ID]
		} else {
			if t, ok := issuedOf(h.Issued, TokStanding); !ok || t.Sub != sub ||
				t.Exp.Sub(now) < StandingRemintBelow && m.standingTTL(p.Kind) > StandingRemintBelow {
				if tok, it, err := m.mintOnKey(m.keys.relay, p, TokStanding, now); err == nil {
					h.Standing, h.Issued = tok, replaceIssued(h.Issued, it)
				}
			}
			if p.Kind == KindConnection {
				if t, ok := issuedOf(h.Issued, TokReconnect); !ok || t.Sub != sub || handshake.ReconnectRemintDue(t.Exp, now) {
					if tok, it, err := m.mintOnKey(m.keys.relay, p, TokReconnect, now); err == nil {
						h.Reconnect, h.Issued = tok, replaceIssued(h.Issued, it)
					}
				}
			}
		}
		m.st.Issued = append(m.st.Issued, h.Issued...)
		// §3.4.1 S1, §3.4.2 RK13: the recipient's key for the vault (the
		// old key) and the start of S1's clock. A recipient still in S1
		// from an earlier rotation keeps its key for the vault and its
		// clock: a reading of this release (the spec should confirm).
		rec := m.st.Relay.Recipients[p.ID]
		if rec == nil {
			rec = &RelayRecipient{KeyFor: oldSub, S1Since: now.UTC()}
			m.st.Relay.Recipients[p.ID] = rec
		}
		rec.Standing, rec.Reconnect, rec.UpdateDue = h.Standing, h.Reconnect, true
	}
	for id := range m.st.Relay.Recipients {
		if !keep[id] {
			delete(m.st.Relay.Recipients, id)
		}
	}

	// What is audited, and the owed marks (§3.4, §11.14.10).
	m.record(Activity{Kind: "identity.rotated", Ref: markRef(pr.Marks, pr.Named), Audit: true}, now)
	if nextSeed != nil {
		// A relay-key rotation is owed: the next key is stored in this
		// write, which meets (and clears) that mark; the other marks clear
		// at the next key's own second write.
		o.RelayKey = time.Time{}
		m.newPendingRelay(nextSeed, unionMarks(pr.Marks, pr.Next), unionMarks(pr.Named, pr.Marks), now)
	} else {
		m.clearMarks(pr.Marks)
	}
	m.dirty = true
	return true
}

// resetCollector drops the collect session: the next one collects with
// the key now current.
func (m *Manager) resetCollector() {
	if m.collector != nil {
		_ = m.collector.Close()
		m.collector = nil
	}
}

// relayRefusedState reports the refused state, for vault.status (§10.2,
// §3.4 "What the member sees").
func (m *Manager) relayRefusedState() bool {
	pr := m.st.Relay.Pending
	return m.relayRotation() && pr != nil && pr.Refused != ""
}

// RelayKeyStatus is what a test or a host tool may read of the vault's own
// relay-key rotation: no key and no token.
type RelayKeyStatus struct {
	Mailbox        string // the current mailbox
	PendingMailbox string // the pending key's mailbox, "" for none
	Refused        string // the pending key's refusal code (the refused state)
	OldMailboxes   []string
	Anchor         time.Time
}

// RelayKeyStatus returns the relay-key rotation's state (§3.4).
func (m *Manager) RelayKeyStatus() RelayKeyStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st == nil {
		return RelayKeyStatus{}
	}
	s := RelayKeyStatus{Mailbox: m.st.Relay.Mailbox, PendingMailbox: m.pendingMailbox(), Anchor: m.st.Relay.Anchor}
	if pr := m.st.Relay.Pending; pr != nil {
		s.Refused = pr.Refused
	}
	for _, o := range m.st.Relay.Old {
		s.OldMailboxes = append(s.OldMailboxes, o.Mailbox)
	}
	return s
}
