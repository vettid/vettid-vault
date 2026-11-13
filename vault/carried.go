package vault

import (
	"bytes"
	"time"
)

// A handshake's tokens are adopted at confirmation (VAULT-MESSAGING 0.88.2
// §6.3.1, owner decision a, GC 01M6SWPHVH6WFYJ8096KX0D5GC, with the
// clarifications of GC 01M70MBJ82KFZ0C7GX0M6VCR3S; R29-T1).
//
// The standing and reconnect tokens a reconnect carried are kept apart, per
// handshake, as carried tokens: the initiator's on its pending epoch
// (PendingEpoch.Carried), the responder's per epoch it activated
// (Peer.Carried), and before hs.fin in the answer (AwaitingHS.Reconnect).
// They are adopted, in place of the held tokens, only in the write in which
// that epoch is confirmed at this side. Until then they are used only for
// the handshake's own hs.resp, hs.fin and hs.confirm; everything else uses
// the held tokens, and a reconnect hs.init only the held reconnect token.

// adoptHeld replaces the held token of a kind with a carried one only if the
// carried one's exp is later.
//
// With relay-key rotation a carried token is adopted only if it passes
// rule T (§3.4.1) as a held token now: minted by the peer's current mailbox
// and unexpired. A reconnect hs.init's tokens from an earlier relay key
// were kept only to deposit its answer, and are never held.
func (m *Manager) adoptHeld(p *Peer, kind string, held *HeldToken, c HeldToken) {
	if m.opt.RelayKeyRotation && c.Token != "" {
		if _, err := m.heldToken(c.Token, p); err != nil {
			return
		}
	}
	if c.Token != "" && c.Exp.After(held.Exp) {
		*held = c
		if h := m.opt.Hooks.Adopt; h != nil {
			h(p.ID, kind, c.Token, "carried")
		}
	}
}

// adoptCarried adopts c's tokens for p, and lets entries waiting for a
// valid standing token go.
func (m *Manager) adoptCarried(p *Peer, c *CarriedTokens) {
	if c == nil {
		return
	}
	m.adoptHeld(p, TokStanding, &p.Standing, c.Standing)
	if p.Kind == KindConnection {
		m.adoptHeld(p, TokReconnect, &p.Reconnect, c.Reconnect)
		if m.opt.RelayKeyRotation {
			m.rk6Tick(p, m.now()) // §3.4.2 RK6: a token adopted at a confirmation
		}
	}
	m.retryPeer(p.ID)
	m.dirty = true
}

// confirmStopped reports whether "hs.confirm again" has stopped for p's
// current epoch: its carried tokens were discarded (0.88.2 §6.3.1).
func (p *Peer) confirmStopped() bool {
	c := p.carriedFor(p.LastEpochID)
	return c != nil && c.Discarded
}

// carriedFor is p's carried-token record for the epoch id, or nil.
func (p *Peer) carriedFor(id []byte) *CarriedTokens {
	for i := range p.Carried {
		if bytes.Equal(p.Carried[i].Epoch, id) {
			return &p.Carried[i]
		}
	}
	return nil
}

// carriedUsable reports whether the responder's record c still waits for
// adoption: its epoch neither destroyed, demoted nor ended, and within the
// bound (the carried standing token's exp, capped at B from activation).
func (p *Peer) carriedUsable(c *CarriedTokens, now time.Time) bool {
	if c.Discarded {
		return false
	}
	e := p.epochMeta(c.Epoch)
	if e == nil || e.Destroyed || e.Demoted || e.Ended || e.Pending || e.Abandoned {
		return false
	}
	if c.Standing.Token != "" && !now.Before(c.Standing.Exp) {
		return false
	}
	return now.Before(c.Since.Add(PendingLife))
}

// adoptReached is called when p's confirmed epoch moves to id (setConfirmed,
// before the handler of the message that moved it): the responder adopts
// the carried tokens of id, or of an earlier epoch that is still usable,
// and discards the rest of what it no longer waits for.
func (m *Manager) adoptReached(p *Peer, id []byte, now time.Time) {
	if len(p.Carried) == 0 {
		return
	}
	keep := p.Carried[:0]
	discarded := false
	for i := range p.Carried {
		c := p.Carried[i]
		switch {
		case !p.carriedUsable(&c, now):
			discarded = discarded || !c.Discarded
			if bytes.Equal(c.Epoch, p.LastEpochID) && !bytes.Equal(c.Epoch, id) {
				c.Discarded, c.Standing, c.Reconnect = true, HeldToken{}, HeldToken{}
				keep = append(keep, c)
			}
		case bytes.Equal(c.Epoch, id) || p.newer(id, c.Epoch):
			// The confirmed epoch reached c's epoch, or a later one reached
			// from it by rekeys only: a later token-carrying handshake
			// supersedes c (supersedeCarried), so no record of an earlier
			// reconnect is still here (review F1: never adopt the tokens of
			// an epoch the peer may have abandoned and revoked). "Rekeys
			// only" relies on every token-carrying activation passing
			// through a supersede: the own reconnect at makePending, the
			// peer's at finishReconnect.
			m.adoptCarried(p, &c)
			m.note(now, "carried_adopted", p.ID)
		default:
			keep = append(keep, c)
		}
	}
	p.Carried = keep
	m.dirty = true
	if discarded {
		// A discard here leads to a reconnect when no valid token is held;
		// only then (at the initiator the hs.resp's tokens are adopted
		// right after this, in confirmPending).
		m.afterCarriedDiscard(p, now)
	}
}

// supersedeCarried drops p's carried records of every epoch: a newer
// token-carrying handshake (this vault's own reconnect becoming pending, or
// the peer's reconnect established at its hs.fin) supersedes them, and an
// earlier epoch's carried tokens are never adopted at a later confirmation
// (0.88.2 §6.3.1 "When they are adopted"). No reconnect follows: the new
// handshake is the way on.
//
// The current epoch's record is kept as a Discarded marker, as sweepCarried
// keeps it, so that "hs.confirm again" stays stopped for that epoch if the
// superseding handshake is abandoned (review 3ce94c6, item 1). If the
// superseding handshake fails, the way on is §6.6's reconnect.
func (m *Manager) supersedeCarried(p *Peer) {
	if len(p.Carried) == 0 {
		return
	}
	keep := p.Carried[:0]
	for i := range p.Carried {
		c := p.Carried[i]
		if bytes.Equal(c.Epoch, p.LastEpochID) {
			c.Discarded, c.Standing, c.Reconnect = true, HeldToken{}, HeldToken{}
			keep = append(keep, c)
		}
	}
	for i := len(keep); i < len(p.Carried); i++ {
		p.Carried[i] = CarriedTokens{}
	}
	p.Carried = keep
	m.dirty = true
}

// carriedWait is §6.3.1 "No reconnect while carried tokens wait": p's
// current epoch is one the vault activated as responder, its confirmed
// epoch has not reached it, and its carried tokens are undiscarded and
// within their bound. While it holds, the vault starts no reconnect for
// want of a valid standing token and does not judge "no reconnect token".
func (m *Manager) carriedWait(p *Peer, now time.Time) bool {
	if p == nil || p.Kind != KindConnection || len(p.LastEpochID) == 0 {
		return false
	}
	c := p.carriedFor(p.LastEpochID)
	if c == nil || !p.carriedUsable(c, now) {
		return false
	}
	cur := p.epochMeta(p.LastEpochID)
	return cur != nil && !cur.Mine && !bytes.Equal(p.confirmedID(), p.LastEpochID)
}

// sweepCarried discards the carried tokens p no longer waits for (their
// epoch destroyed, demoted or ended, or the bound passed). In that write,
// with no valid standing token held, the vault is in the "no valid standing
// token" case and reconnects (§6.3.1 "Discarded, never adopted"; §6.6).
func (m *Manager) sweepCarried(p *Peer, now time.Time) {
	if len(p.Carried) == 0 {
		return
	}
	keep := p.Carried[:0]
	dropped := false
	for i := range p.Carried {
		c := p.Carried[i]
		if p.carriedUsable(&c, now) {
			keep = append(keep, c)
			continue
		}
		if !c.Discarded {
			dropped = true
		}
		if bytes.Equal(c.Epoch, p.LastEpochID) {
			c.Discarded, c.Standing, c.Reconnect = true, HeldToken{}, HeldToken{}
			keep = append(keep, c) // "hs.confirm again" stops for it
		}
	}
	if !dropped && len(keep) == len(p.Carried) {
		return
	}
	for i := len(keep); i < len(p.Carried); i++ {
		p.Carried[i] = CarriedTokens{}
	}
	p.Carried = keep
	m.dirty = true
	if dropped {
		m.note(now, "carried_discarded", p.ID)
		m.afterCarriedDiscard(p, now)
	}
}

// dropCarried removes p's carried record of epoch id without a discard: the
// epoch was never established (finishReconnect, when following the links
// suspended the connection), so nothing was waiting for its tokens.
func (m *Manager) dropCarried(p *Peer, id []byte) {
	keep := p.Carried[:0]
	for i := range p.Carried {
		if !bytes.Equal(p.Carried[i].Epoch, id) {
			keep = append(keep, p.Carried[i])
		}
	}
	if len(keep) == len(p.Carried) {
		return
	}
	for i := len(keep); i < len(p.Carried); i++ {
		p.Carried[i] = CarriedTokens{}
	}
	p.Carried = keep
	m.dirty = true
}

// afterCarriedDiscard: a discard with no valid held standing token puts the
// vault in §8.6's "no valid standing token" case.
func (m *Manager) afterCarriedDiscard(p *Peer, now time.Time) {
	if p.Kind != KindConnection || p.State != PeerActive || p.suspended() || m.carriedWait(p, now) {
		return
	}
	if p.Standing.Token == "" || !now.Before(p.Standing.Exp) {
		m.noStandingToken(p, now)
	}
}

// carriedRevoked handles token_revoked on a deposit made with a carried
// token (0.88.2 §6.3.1 "A carried token refused", §8.6): the issuer revokes
// a carried token only before it confirms or activates, so the handshake
// was abandoned or dropped there. The entry is dropped and that handshake's
// carried tokens are discarded. It reports whether tok was a carried token.
func (m *Manager) carriedRevoked(p *Peer, e *OutboxEntry, tok string, now time.Time) bool {
	if !e.CarriedTok || p == nil || p.Kind != KindConnection || tok == "" {
		return false
	}
	e.Done = true
	m.dropHeldToken(p, tok, now) // never offered again (heldToken refuses it)
	m.audit(now, "carried_token_revoked", p.ID)
	// The responder's records, after hs.fin and before it.
	for i := range p.Carried {
		if c := &p.Carried[i]; c.Standing.Token == tok {
			c.Discarded, c.Standing, c.Reconnect = true, HeldToken{}, HeldToken{}
		}
	}
	for _, id := range sortedKeys(m.st.Awaiting) {
		aw := m.st.Awaiting[id]
		if aw == nil || aw.PeerID != p.ID {
			continue
		}
		if aw.RespOutbox == e.ID {
			// (owner decision a, GC 01M713PZNT77VVDSCY6DC00NWH, item 2) Its hs.resp refused: I dropped this
			// reconnect, so R's answer ends now, not after L (it would hold R's own reconnect back). Not a try of the
			// reconnect bound: R's own reconnects are counted by their own handshakes.
			m.abandonAwaiting(id, now)
			m.note(now, "answer_ended_carried_revoked", p.ID)
			continue
		}
		if aw.Reconnect != nil && aw.Reconnect.Standing.Token == tok {
			aw.Reconnect.Standing, aw.Reconnect.Reconnect = HeldToken{}, HeldToken{}
		}
	}
	// The initiator's, on its pending epoch.
	if pe := p.Pending; pe != nil && (bytes.Equal(e.FinEpoch, pe.ID) || pe.Carried != nil && pe.Carried.Standing.Token == tok) {
		// (owner decision a, item 2) Its hs.fin refused: R dropped its answer, so the pending epoch ends now, not at B,
		// and the reconnect starts again (not a failed try of the reconnect bound: the try did not expire).
		pe.Carried = nil
		m.abandonPending(p, "carried_revoked", true, now)
	}
	m.dirty = true
	m.afterCarriedDiscard(p, now)
	return true
}
