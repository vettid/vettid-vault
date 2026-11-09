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
func adoptHeld(held *HeldToken, c HeldToken) {
	if c.Token != "" && c.Exp.After(held.Exp) {
		*held = c
	}
}

// adoptCarried adopts c's tokens for p, and lets entries waiting for a
// valid standing token go.
func (m *Manager) adoptCarried(p *Peer, c *CarriedTokens) {
	if c == nil {
		return
	}
	adoptHeld(&p.Standing, c.Standing)
	if p.Kind == KindConnection {
		adoptHeld(&p.Reconnect, c.Reconnect)
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
	for i := range p.Carried {
		c := p.Carried[i]
		switch {
		case !p.carriedUsable(&c, now):
			if bytes.Equal(c.Epoch, p.LastEpochID) && !bytes.Equal(c.Epoch, id) {
				c.Discarded, c.Standing, c.Reconnect = true, HeldToken{}, HeldToken{}
				keep = append(keep, c)
			}
		case bytes.Equal(c.Epoch, id) || p.newer(id, c.Epoch):
			m.adoptCarried(p, &c)
			m.note(now, "carried_adopted", p.ID)
		default:
			keep = append(keep, c)
		}
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

// afterCarriedDiscard: a discard with no valid held standing token puts the
// vault in §8.6's "no valid standing token" case.
func (m *Manager) afterCarriedDiscard(p *Peer, now time.Time) {
	if p.Kind != KindConnection || p.State != PeerActive || m.carriedWait(p, now) {
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
		if aw := m.st.Awaiting[id]; aw.PeerID == p.ID && aw.Reconnect != nil && aw.Reconnect.Standing.Token == tok {
			aw.Reconnect.Standing, aw.Reconnect.Reconnect = HeldToken{}, HeldToken{}
		}
	}
	// The initiator's, on its pending epoch.
	if pe := p.Pending; pe != nil && pe.Carried != nil && pe.Carried.Standing.Token == tok {
		pe.Carried = nil
	}
	m.dirty = true
	m.afterCarriedDiscard(p, now)
	return true
}
