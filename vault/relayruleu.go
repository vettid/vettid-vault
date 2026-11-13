package vault

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Rule U, a relay.address.update (VAULT-MESSAGING 0.90.4 §3.4.1), with
// §3.4.2 RK5 (the update's identity links, applied first, and the ik
// requirement) and RK6 (the vault's own reconnects at a follow). Only with
// Options.RelayKeyRotation; without it hAddressUpdate refuses every update
// (relay_unlinked), as before.
//
// The order, for a message from p deposited with sender:
//  1. Parse (updateParseRefuses, before acceptFrom step 1): a fault in a
//     link's form or the chain's count is refused relay_unlinked, and no
//     link of the message, identity or relay, is checked or kept by rule C.
//     A malformed body (malformed wins) is refused as a whole by the
//     handler (dropped, no link read).
//  2. acceptFrom steps 1-3 (dispatch): rule C on the relay links (RK12
//     while suspended) and on the identity links (evidenceFirst).
//  3. Table A: rule U in every row but Record suspended and Foreign.
//  4. The handler (ruleU), first the checks that do not depend on the ik,
//     each refusing with no link followed, identity links included
//     (RK10): the chain and its ends (relay_unlinked), the followed
//     prefix; for a duplicate, straight to step 5; then relay_rollback,
//     the per-peer cap, rule T on the update's token (token_unusable).
//  5. From an earlier key after its cut-off, the update's identity links
//     are judged as Table A's identity.rotate column judges that row: all
//     already followed, they change nothing and only R29-K9 is judged;
//     any other is refused superseded_relay (earlierAfterRotations). This
//     exception is a reading of this release (rule U and RK5 say nothing
//     of the sender's row for the update's identity links); the spec
//     should confirm it.
//  6. RK5: the identity links (Table B, H5, the demotion rules, R29-K9)
//     and the ik requirement; a duplicate is then answered; otherwise the
//     follow, in one state write: the links and cut-offs, relay.pk
//     current, the tokens kept; then the answer, the revocations and RK6.

// MaxEarlierRelays caps a peer's earlier relay keys (Peer.EarlierRelays).
// The spec sets no cap: earlier keys leave only when no token the vault
// issued to them can still deposit. This takes the spec's one bound on
// relay links, a chain's 32 (handshake.MaxRelayLinks), and fails closed: a
// follow that would keep more is refused (unexpected) and changes nothing,
// so that no key the vault followed away from is forgotten while it could
// still be announced again (I3). A reading of this release; the spec should
// confirm the cap and the refusal.
const MaxEarlierRelays = handshake.MaxRelayLinks

// RelayRestartWait is how long §3.4.2 RK6 waits for a reconnect token for
// the peer's current mailbox before an owed restart is given up (60 days
// after the follow, the vault not being in S1 itself: it rotates no relay
// key of its own).
// It is scaled with the vault's time scale (STAGING-TIME-SCALE), as RK13's
// clocks are.
const RelayRestartWait = 60 * 24 * time.Hour

// RelayRestart is an own reconnect RK6 abandoned and owes again.
type RelayRestart struct {
	Named []byte    `json:"named"`
	Since time.Time `json:"since"`
}

// updateParseRefuses is rule U's parse-time refusal ("When it is refused",
// "Precedence"): a fault in a link's form or the chain's count, in an
// otherwise well-formed body, is refused relay_unlinked before acceptFrom
// step 1, and no link is checked or kept. A resend with the same inner id
// is not audited again (§8.2). It reports whether the update was refused.
func (m *Manager) updateParseRefuses(p *Peer, in *envelope.Inner, now time.Time) bool {
	_, err := peerwire.ParseAddressUpdate(in.Body)
	if err == nil || !errors.Is(err, handshake.ErrRelayLink) {
		return false
	}
	key := p.ID + "|" + in.ID
	if _, dup := m.st.SeenInner[key]; dup {
		return true
	}
	m.st.SeenInner[key] = now
	m.refusePeerKey(p, "relay_unlinked", now)
	return true
}

// ruleU handles a relay.address.update from s.peer that acceptFrom passed
// (see the order above).
func (m *Manager) ruleU(s *Session, in *envelope.Inner) error {
	p, now, sender := s.peer, s.now, m.msgSender
	u, err := peerwire.ParseAddressUpdate(in.Body)
	if err != nil {
		// A malformed body (relay_links missing included) is refused as a
		// whole, as any malformed body of a message that is not a request
		// (identity.rotate's too): acked, no link read, no drop.peer_key.
		return errBadRequest
	}
	if p.suspended() {
		return nil // acceptFrom step 1
	}
	// Rule U's checks that do not depend on the ik run first and change
	// nothing: the chain and its ends, the followed prefix, rollback, the
	// cap and rule T on the update's token. If any fails the update is
	// refused with none of its links followed, identity links included
	// (§3.4.2 RK10: "An update Q refuses has none of its links followed
	// ... whatever the reason for the refusal"): otherwise an old copy
	// holding an earlier key could move P's ik through an update it knows
	// will be refused. Only then are the identity links applied (RK5 "Links
	// first", with R29-K9), the ik requirement checked, and the relay links
	// followed (RK8's order: identity links, relay links, tokens).
	if _, ok := relayLinksKept(sender, u.Relay.PK, u.Links); !ok {
		// v, suite, old equal to new, a repeated key, a bad signature, a
		// break, or an end mismatch (the first old is not the sender, the
		// last new is not relay.pk).
		m.refusePeerKey(p, "relay_unlinked", now)
		return nil
	}
	k := m.followedRelayPrefix(p, u.Links)
	if k == len(u.Links) {
		// The duplicate: nothing is followed; its identity links are
		// applied first (RK5; R29-K9 runs on a duplicate too). Rule T on
		// its token is not checked: no token is kept (the spec does not
		// say; a reading of this release).
		if m.earlierAfterRotations(p, sender, u.Rotations, now) {
			return nil
		}
		if m.rk5(s, u.Rotations) {
			m.ruleUDuplicate(p, now)
		}
		return nil
	}
	links := u.Links[k:]
	if !suite.EqualPublic(links[0].Old, p.Relay.PK) {
		m.refusePeerKey(p, "relay_rollback", now)
		return nil
	}
	for _, l := range links {
		if p.keepsRelayKey(l.New) {
			m.refusePeerKey(p, "relay_rollback", now)
			return nil
		}
	}
	if len(p.EarlierRelays)+len(links) > MaxEarlierRelays {
		m.refusePeerKey(p, "unexpected", now)
		return nil
	}
	addr := relayOf(u.Relay)
	st, err := m.heldTokenFrom(u.Token, p, addr, TokStanding)
	if err != nil {
		m.refusePeerKey(p, "token_unusable", now)
		return nil
	}
	// rule T: a reconnect_token that does not pass (§7.1's holder's checks
	// included) is ignored, no reason to refuse (rule U names the update's
	// `token` only; a reading of this release, the spec should confirm);
	// only a connection holds one.
	var rt HeldToken
	if u.ReconnectToken != "" && p.Kind == KindConnection {
		if t, err := m.heldTokenFrom(u.ReconnectToken, p, addr, TokReconnect); err == nil {
			rt = t
		}
	}
	if m.earlierAfterRotations(p, sender, u.Rotations, now) {
		return nil
	}
	if !m.rk5(s, u.Rotations) {
		return nil
	}
	passed := make([]ed25519.PublicKey, 0, len(links))
	for _, l := range links {
		passed = append(passed, l.Old)
	}
	old := p.Relay
	if m.followRelayLinks(p, links, u.Relay) != nil {
		m.refusePeerKey(p, "relay_unlinked", now) // cannot happen after the checks above
		return nil
	}
	p.Standing = st
	if h := m.opt.Hooks.Adopt; h != nil {
		h(p.ID, TokStanding, st.Token, "update")
	}
	if p.Kind == KindConnection {
		// The reconnect token held for the passed mailbox cannot deposit at
		// the new one: it counts as not held. The update's replaces it, as
		// a held token is replaced (§6.3.1, 0.90.4 §7.1: only by a later
		// exp; none for the new mailbox is held, so any passes). Without
		// one, a reconnect wanted until one arrives waits (RK6's owed
		// wait, relayAwaitsRC), not stale.
		p.Reconnect = HeldToken{}
		p.RelayAwaitRC = time.Time{}
		if rt.Token != "" {
			p.Reconnect = rt
			if h := m.opt.Hooks.Adopt; h != nil {
				h(p.ID, TokReconnect, rt.Token, "update")
			}
		} else {
			p.RelayAwaitRC = now.UTC()
		}
	}
	m.readdressQueued(p, old, now)
	m.revokePassedReconnect(p, passed, now)
	m.rk6(p, passed, now)
	m.answerUpdate(p, now)
	m.retryPeer(p.ID)
	return nil
}

// followedRelayPrefix is how many leading links of links the vault has
// already followed for p (rule U: "Leading links Q has already followed
// are skipped").
func (m *Manager) followedRelayPrefix(p *Peer, links []*handshake.RelayLink) int {
	n := 0
	for _, l := range links {
		if !p.followedRelayLink(l) {
			break
		}
		n++
	}
	return n
}

// ruleUDuplicate is rule U's duplicate: every link already followed. The
// update is ignored, and answered with relay.token.issued for p's current
// key (fresh tokens, S3), at most one per update received (a resend with
// the same inner id is a duplicate at §8.2 and never reaches here) and,
// for a connection, at most one an hour (§7.2's bound on refreshes near a
// token's end), so that a lost answer is replaced at p's next resend.
// RK5's identity links were applied first (R29-K9 runs on a duplicate
// too); if Table B refused one, or the ik requirement failed, nothing is
// answered (conservative: the spec says only that no link is followed and
// no token taken). The hourly bound is §7.2's for a refresh near a token's
// end, on the same clock as relay.token.refresh (a reading of this release; the
// spec should confirm which of §7.2's limits applies).
func (m *Manager) ruleUDuplicate(p *Peer, now time.Time) {
	// A device too: §7.2 bounds only a connection's refreshes, but a
	// duplicate update costs a fresh token each (a reading of this release).
	if t, ok := m.st.attach().Renewed[p.ID]; ok && now.Sub(t) < RenewEvery {
		return
	}
	m.st.attach().Renewed[p.ID] = now
	m.dirty = true
	m.answerUpdate(p, now)
}

// answerUpdate sends relay.token.issued for p's current relay key:
// standing, and reconnect for a connection (rule U).
func (m *Manager) answerUpdate(p *Peer, now time.Time) {
	m.issueTo(p, TokStanding, now)
	if p.Kind == KindConnection {
		m.issueTo(p, TokReconnect, now)
	}
}

// rk5 is §3.4.2 RK5 for an update from s.peer carrying identity links
// rots: they are applied first, as an identity.rotate's (rule C, Table B,
// H5, the demotion rules and R29-K9), and the update's relay links are
// followed, and its tokens kept, only if, after that, the chain from the
// update's ik (the P-side signer of the epoch it travels under) ends at
// the vault's current ik for p, or the update's ik is that ik. It reports
// whether the update may go on. A device rotates no ik (§6.7): its update
// carrying identity links cannot occur and is refused (unexpected).
//
// Links all already followed are judged by R29-K9 first (evidence first).
// Otherwise the ik requirement is judged before any link is applied, against the ik
// the links would lead to (rotsOutcome, which makes Table B's decisions
// without acting on them): an update refused for it has none of its
// identity links followed (§3.4.2 RK10: "An update Q refuses has none of
// its links followed ... whatever the reason for the refusal"). Its
// R29-K9 is not judged either: K9 runs with the links, which are applied
// only to an update that goes on (a reading of this release; the spec
// should confirm that a refused update's already-followed links are not
// judged by K9).
func (m *Manager) rk5(s *Session, rots []*handshake.Rotation) bool {
	p, now := s.peer, s.now
	if p.Kind != KindConnection {
		if len(rots) > 0 {
			m.refusePeerKey(p, "unexpected", now)
			return false
		}
		return true
	}
	var ep []byte
	if s.epoch != nil {
		id := s.epoch.ID()
		ep = id[:]
	}
	post, tableBOK := p.rotsOutcome(rots)
	if !tableBOK {
		// Table B refuses a link: applyIDLinks refuses it with its reason
		// before following any (rule C ran at step 3).
		m.applyIDLinks(p, rots, ep, now)
		return false
	}
	// Links all already followed change nothing and are evidence only:
	// R29-K9 is judged on them first, before the ik requirement (evidence
	// first, as for an identity.rotate Table A ignores), whatever the
	// update's fate.
	known := len(rots) > 0 && handshake.KnownPrefix(parseRotations(p.Chain), rots) == len(rots)
	if known {
		if !m.applyIDLinks(p, rots, ep, now) || m.rk5Stops(p, ep) {
			return false
		}
	}
	var signer []byte
	if e := p.epochMeta(ep); e != nil {
		signer = e.Signer
	}
	if !updateIKOK(post, signer, rots) {
		// The ik requirement failed: no link is followed and no token
		// taken. The spec names no reason; Table B's for the update's ik,
		// as it would stand once the links were applied, is used (a reading
		// of this release; the spec should confirm).
		switch {
		case p.ancestor(signer) || len(signer) > 0 && bytes.Equal(signer, p.IK) && !bytes.Equal(post, p.IK):
			m.refusePeerKey(p, "ancestor_ik", now)
		case p.rejected(signer):
			m.refusePeerKey(p, "rejected_ik", now)
		default:
			m.refusePeerKey(p, "unknown_ik", now)
		}
		return false
	}
	if len(rots) > 0 && !known && !m.applyIDLinks(p, rots, ep, now) {
		return false // a conflict, or the record suspended
	}
	return !m.rk5Stops(p, ep)
}

// rk5Stops is the guard after an update's identity links are applied: if
// they made the vault suspend p (R29-K9, a received flag, a conflict), or
// ended the epoch the update travels under, the vault follows no relay
// link, keeps no token and sends no answer; the suspension stands. (A
// seam for a later rule: an update refused only for its identity links
// could still be answered as a duplicate here; not built.)
func (m *Manager) rk5Stops(p *Peer, ep []byte) bool {
	if p.suspended() {
		return true
	}
	e := p.epochMeta(ep)
	return e != nil && e.Ended
}

// rotsOutcome is the ik p's identity links rots lead to, worked out as
// applyIDLinks would apply them but without acting: the leading links
// already followed are skipped, and the rest must start at p's current ik,
// resolve, and move to no ancestor or rejected ik. ok is false where Table
// B would refuse a link. No links: p's current ik.
func (p *Peer) rotsOutcome(rots []*handshake.Rotation) (ik []byte, ok bool) {
	if len(rots) == 0 || p.suspended() {
		return p.IK, len(rots) == 0
	}
	i := handshake.KnownPrefix(parseRotations(p.Chain), rots)
	if i == len(rots) {
		return p.IK, true
	}
	app := rots[i:]
	if !bytes.Equal(app[0].OldIK, p.IK) {
		return nil, false
	}
	end, _, err := handshake.ResolveChain(p.IK, app)
	if err != nil {
		return nil, false
	}
	for _, r := range app {
		if p.ancestor(r.NewIK) || p.rejected(r.NewIK) {
			return nil, false
		}
	}
	return end, true
}

// updateIKOK is RK5's ik requirement against ik, the vault's current ik for
// p once the update's links are applied: the update's ik (signer) is ik,
// or the update's chain rots starts at it and ends at ik. An unknown
// signer fails.
func updateIKOK(ik, signer []byte, rots []*handshake.Rotation) bool {
	if len(signer) != ed25519.PublicKeySize || len(ik) != ed25519.PublicKeySize {
		return false
	}
	if bytes.Equal(signer, ik) {
		return true
	}
	if len(rots) == 0 {
		return false
	}
	end, _, err := handshake.ResolveChain(signer, rots)
	return err == nil && bytes.Equal(end, ik)
}

// readdressQueued moves p's queued deposits that go on the held standing
// token (no token of their own) from p's previous mailbox old to its
// current one: the held token is now the new mailbox's. A queued
// relay.token.issued to p is dropped instead: the tokens it carries name
// the passed key, and §3.4.2 RK2 wants the key on record when it is
// deposited; answerUpdate sends fresh ones. Deposits on a token of their
// own (a handshake's carried or answer token) keep their mailbox, and a
// handshake message already sealed keeps the tokens it carries, minted
// for the passed key. Rule U says only that relay.pk becomes current; the
// re-addressing and the sealed messages' tokens are this release's reading
// and the spec should confirm them.
func (m *Manager) readdressQueued(p *Peer, old PeerRelay, now time.Time) {
	for _, e := range m.st.Outbox {
		if e.Done || e.Op != OpDeposit || e.PeerID != p.ID || e.Token != "" || e.Mailbox != old.Mailbox {
			continue
		}
		if e.Type == tokenIssuedType {
			e.Done = true
		} else {
			e.RelayURL, e.Mailbox = p.Relay.URL, p.Relay.Mailbox
		}
		m.markUnstored(e)
	}
	m.dirty = true
}

// revokePassedReconnect revokes the reconnect tokens the vault issued to
// p's passed relay keys (rule U; at the vault's own mailbox, which issued
// them, S7): the registry's, and those of handshakes not activated yet (a
// pending epoch's, an answer's). The standing tokens are left to expire.
// The own open reconnects' tokens are revoked by RK6's abandonment. That
// the in-flight ones are revoked too (the peer meets that as §3.4.2 RK9
// says) is a reading of this release; the spec should confirm it.
func (m *Manager) revokePassedReconnect(p *Peer, passed []ed25519.PublicKey, now time.Time) {
	subs := map[string]bool{}
	for _, k := range passed {
		subs[relayauth.EncodeKey(k)] = true
	}
	for i := range m.st.Issued {
		t := &m.st.Issued[i]
		if t.PeerID == p.ID && t.Kind == TokReconnect && subs[t.Sub] && !t.Denied {
			t.Denied = true
			m.queueRevoke("jti", t.JTI, now)
		}
	}
	inflight := func(ts []IssuedToken) {
		for _, t := range ts {
			if t.Kind == TokReconnect && subs[t.Sub] {
				m.revokeIssued(t, p.ID, now)
			}
		}
	}
	if p.Pending != nil {
		inflight(p.Pending.Issued)
	}
	for _, id := range sortedKeys(m.st.Awaiting) {
		if aw := m.st.Awaiting[id]; aw != nil && aw.New == nil && aw.PeerID == p.ID {
			inflight(aw.Issued)
		}
	}
	m.dirty = true
}

// rk6 is §3.4.2 RK6, Q's mirror of S2, at a follow of p's relay link from
// the passed keys: each own open reconnect with p whose hs.init carried
// tokens naming a passed key and that has sent no hs.fin (one still
// awaiting hs.resp) is abandoned, its tokens revoked, and started again
// with tokens naming the new key, on a held reconnect token for p's
// current mailbox only; without one it is owed (rk6Tick). The rule's
// "not restarted" case (the reconnect whose own message made the follow)
// and its order after an establishment are RK8's, not built yet.
func (m *Manager) rk6(p *Peer, passed []ed25519.PublicKey, now time.Time) {
	if p.Kind != KindConnection {
		return
	}
	subs := map[string]bool{}
	for _, k := range passed {
		subs[relayauth.EncodeKey(k)] = true
	}
	for _, id := range sortedKeys(m.st.Outgoing) {
		og, ok := m.st.Outgoing[id]
		if !ok || og.New != nil || og.PeerID != p.ID || og.Purpose != handshake.PurposeReconnect {
			continue
		}
		named := false
		for _, t := range og.Issued {
			named = named || subs[t.Sub]
		}
		if !named {
			continue
		}
		ctx := append([]byte(nil), og.Named...)
		if len(ctx) == 0 {
			ctx = append(ctx, p.LastEpochID...)
		}
		m.abandonOutgoing(id, now)
		p.RelayRestart = &RelayRestart{Named: ctx, Since: now.UTC()}
		m.dirty = true
	}
	m.rk6Tick(p, now)
}

// rk6Tick starts an owed RK6 restart once the vault holds a reconnect token
// for p's current mailbox (one kept under rule T: an update's, a
// relay.token.issued, or one adopted at a confirmation; never a carried
// one not yet adopted). Past RelayRestartWait it is given up: the vault
// holds no reconnect token for p, and "The reconnect bound" makes the
// connection stale (not while carried tokens wait).
func (m *Manager) rk6Tick(p *Peer, now time.Time) {
	r := p.RelayRestart
	if r == nil {
		return
	}
	if p.suspended() || p.State != PeerActive || p.Kind != KindConnection {
		p.RelayRestart = nil
		m.dirty = true
		return
	}
	if !bytes.Equal(r.Named, p.LastEpochID) && !m.currentDemoted(p) {
		// The epoch it would reconnect from is no longer the current one
		// (another epoch was established since, §3.4.2 RK6 "dropped once
		// P's reconnect is established"), and the current one is not
		// demoted: nothing is owed.
		p.RelayRestart = nil
		m.dirty = true
		return
	}
	if m.heldReconnectForCurrent(p, now) {
		p.RelayRestart = nil
		m.dirty = true
		if m.currentDemoted(p) {
			m.startReconnect(p, now) // never naming a demoted epoch
			return
		}
		m.startReconnectCtx(p, r.Named, now)
		return
	}
	if now.Sub(r.Since) >= m.opt.scale(RelayRestartWait) {
		p.RelayRestart = nil
		m.dirty = true
		if !m.carriedWait(p, now) {
			m.markStale(p, now)
		}
	}
}

// heldReconnectForCurrent reports whether the vault holds an unexpired
// reconnect token minted by p's current mailbox.
func (m *Manager) heldReconnectForCurrent(p *Peer, now time.Time) bool {
	if noReconnectToken(p, now) {
		return false
	}
	_, err := m.heldTokenFrom(p.Reconnect.Token, p, p.Relay, TokReconnect)
	return err == nil
}

// rk6Ticks runs rk6Tick for every peer with an owed restart (housekeeping).
func (m *Manager) rk6Ticks(now time.Time) {
	if !m.opt.RelayKeyRotation {
		return
	}
	for _, p := range m.allPeers() {
		if p.RelayRestart != nil {
			m.rk6Tick(p, now)
		}
	}
}

// unpinnedSender is the collect sender handed to the handshake library for
// an hs.resp or hs.fin of a handshake with an existing peer (existing)
// whose library state pins the peer's relay key at its start (pinned).
// Rule U: "A handshake does not pin P's relay key ... acceptFrom decides
// each later message", and S2 re-deposits an hs.resp or hs.fin with the
// new key once the vault's token for it arrives. So, with relay-key
// rotation, when acceptFrom has judged sender to be the peer's current key
// or an earlier one before its cut-off (an earlier one after it was
// refused by Table A first), and pinned is a key the vault keeps for the
// peer, the library is given pinned: the sender check is acceptFrom's.
// Otherwise sender is passed as is, and a foreign one is refused there.
func (m *Manager) unpinnedSender(existing bool, peerID string, pinned, sender ed25519.PublicKey) ed25519.PublicKey {
	if !m.opt.RelayKeyRotation || !existing || suite.EqualPublic(pinned, sender) {
		return sender
	}
	p := m.peer(peerID)
	if p == nil || !p.keepsRelayKey(pinned) {
		return sender
	}
	switch m.relayStateOf(p, sender) {
	case relayCurrent, relayEarlierBefore:
		return pinned
	}
	return sender
}

// issuedRecorded reports whether a token with jti is in the issued
// registry.
func (m *Manager) issuedRecorded(jti string) bool {
	for i := range m.st.Issued {
		if m.st.Issued[i].JTI == jti {
			return true
		}
	}
	return false
}

// relayAwaitsRC is §3.4.2 RK6's owed wait for any reconnect the vault
// wants with p after following its relay link, while it holds no
// reconnect token for p's new mailbox (the one it held was for the passed
// mailbox: not held): instead of "no reconnect token" (stale), the
// reconnect naming ctx is owed and started by rk6Tick once a token for the
// current mailbox arrives, within RelayRestartWait of the follow. It
// reports whether the reconnect waits.
func (m *Manager) relayAwaitsRC(p *Peer, ctx []byte, now time.Time) bool {
	if !m.opt.RelayKeyRotation || p.RelayAwaitRC.IsZero() {
		return false
	}
	if !noReconnectToken(p, now) {
		p.RelayAwaitRC = time.Time{}
		m.dirty = true
		return false
	}
	if now.Sub(p.RelayAwaitRC) >= m.opt.scale(RelayRestartWait) {
		p.RelayAwaitRC = time.Time{}
		m.dirty = true
		return false
	}
	if p.RelayRestart == nil {
		p.RelayRestart = &RelayRestart{Named: append([]byte(nil), ctx...), Since: p.RelayAwaitRC}
		m.dirty = true
	}
	return true
}

// earlierAfterRotations judges the identity links of an update from an
// earlier relay key of p's after its cut-off as Table A judges an
// identity.rotate in that row: if every one is already followed they
// change nothing (rk5 then only judges R29-K9 and the ik requirement);
// otherwise the update is refused superseded_relay with none of them
// applied. A relay link from that key can be replayed by anyone who saw
// it (it is the same for every recipient), so it must not carry an ik
// link that an identity.rotate from the same key could not. A reading of
// this release; the spec should confirm it. It reports whether the update
// was refused.
func (m *Manager) earlierAfterRotations(p *Peer, sender ed25519.PublicKey, rots []*handshake.Rotation, now time.Time) bool {
	if len(rots) == 0 || m.relayStateOf(p, sender) != relayEarlierAfter {
		return false
	}
	if handshake.KnownPrefix(parseRotations(p.Chain), rots) == len(rots) {
		return false
	}
	m.refusePeerKey(p, "superseded_relay", now)
	return true
}
