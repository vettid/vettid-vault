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

// Rule U, a relay.address.update (VAULT-MESSAGING 0.90.3 §3.4.1), with
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
//  4. The handler (ruleU): first RK5, the identity links (Table B, H5,
//     the demotion rules, R29-K9) and the ik requirement; then rule U's
//     chain checks (relay_unlinked), the duplicate path, relay_rollback,
//     the per-peer cap, rule T on the update's token (token_unusable);
//     then the follow, in the same state write: the links and cut-offs,
//     relay.pk current, the tokens kept; then the answer, the
//     revocations and RK6.

// MaxEarlierRelays caps a peer's earlier relay keys (Peer.EarlierRelays).
// The spec sets no cap: earlier keys leave only when no token the vault
// issued to them can still deposit. This takes the spec's one bound on
// relay links, a chain's 32 (handshake.MaxRelayLinks), and fails closed: a
// follow that would keep more is refused (unexpected) and changes nothing,
// so that no key the vault followed away from is forgotten while it could
// still be announced again (I3). Decided 2026-11-12; the spec should
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
	// §3.4.2 RK5 "Links first", and RK8's order (the identity links first,
	// then the relay links, then the tokens): the identity links are
	// applied, and R29-K9 judged, before any of rule U's checks, so an
	// update then refused for its relay links or its token still has its
	// identity links followed. RK10's "An update Q refuses has none of its
	// links followed" is read as its relay links and tokens (decided
	// 2026-11-12; the spec should confirm). The ik requirement is checked
	// right after the identity links.
	if !m.rk5(s, u.Rotations) {
		return nil
	}
	if _, ok := relayLinksKept(sender, u.Relay.PK, u.Links); !ok {
		// v, suite, old equal to new, a repeated key, a bad signature, a
		// break, or an end mismatch (the first old is not the sender, the
		// last new is not relay.pk).
		m.refusePeerKey(p, "relay_unlinked", now)
		return nil
	}
	k := m.followedRelayPrefix(p, u.Links)
	if k == len(u.Links) {
		m.ruleUDuplicate(p, now)
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
	st, err := m.heldTokenFrom(u.Token, p, addr)
	if err != nil {
		m.refusePeerKey(p, "token_unusable", now)
		return nil
	}
	// rule T: a reconnect_token that does not pass is ignored, no reason to
	// refuse (rule U names the update's `token` only; decided 2026-11-12,
	// the spec should confirm); only a connection holds one.
	var rt HeldToken
	if u.ReconnectToken != "" && p.Kind == KindConnection {
		if t, err := m.heldTokenFrom(u.ReconnectToken, p, addr); err == nil {
			rt = t
		}
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
	if rt.Token != "" {
		p.Reconnect = rt
		if h := m.opt.Hooks.Adopt; h != nil {
			h(p.ID, TokReconnect, rt.Token, "update")
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
// end, on the same clock as relay.token.refresh (decided 2026-11-12; the
// spec should confirm which of §7.2's limits applies).
func (m *Manager) ruleUDuplicate(p *Peer, now time.Time) {
	if p.Kind == KindConnection {
		if t, ok := m.st.attach().Renewed[p.ID]; ok && now.Sub(t) < RenewEvery {
			return
		}
		m.st.attach().Renewed[p.ID] = now
		m.dirty = true
	}
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
	if len(rots) > 0 && !m.applyIDLinks(p, rots, ep, now) {
		return false // Table B refused a link (audited with its reason), or a conflict
	}
	if p.suspended() {
		return false // the links made it suspend (K9, a flag set)
	}
	var signer []byte
	if e := p.epochMeta(ep); e != nil {
		signer = e.Signer
	}
	if updateIKOK(p, signer, rots) {
		return true
	}
	// The ik requirement failed: no relay link is followed and no token
	// taken. The spec names no reason; Table B's for the update's ik is
	// used (decided 2026-11-12; the spec should confirm).
	switch {
	case p.ancestor(signer):
		m.refusePeerKey(p, "ancestor_ik", now)
	case p.rejected(signer):
		m.refusePeerKey(p, "rejected_ik", now)
	default:
		m.refusePeerKey(p, "unknown_ik", now)
	}
	return false
}

// updateIKOK is RK5's ik requirement after the links are applied: the
// update's ik (signer) is p's current ik, or the update's chain rots
// starts at it and ends at p's current ik. An unknown signer fails.
func updateIKOK(p *Peer, signer []byte, rots []*handshake.Rotation) bool {
	if len(signer) != ed25519.PublicKeySize {
		return false
	}
	if bytes.Equal(signer, p.IK) {
		return true
	}
	if len(rots) == 0 {
		return false
	}
	end, _, err := handshake.ResolveChain(signer, rots)
	return err == nil && bytes.Equal(end, p.IK)
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
// re-addressing and the sealed messages' tokens are decided 2026-11-12
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
// says) is decided 2026-11-12; the spec should confirm it.
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
	_, err := m.heldTokenFrom(p.Reconnect.Token, p, p.Relay)
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
