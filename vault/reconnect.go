package vault

import (
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// ReconnectTries is §3.4.1 "The reconnect bound": the connection becomes
// stale at the third try that fails for the same named epoch.
const ReconnectTries = 3

// noReconnectToken reports whether the vault holds no valid reconnect
// token for p.
func noReconnectToken(p *Peer, now time.Time) bool {
	return p.Reconnect.Token == "" || !now.Before(p.Reconnect.Exp)
}

// reconnectNaming starts a reconnect to connection p naming epoch ctx
// (after a demotion, or by strict F1, §3.4.1): the vault's own rekey and
// its unfinished rekey answers to p are dropped (the peer did not finish
// them, and they would block it), and its pending epoch is abandoned.
func (m *Manager) reconnectNaming(p *Peer, ctx []byte, why string, now time.Time) bool {
	if p.Kind != KindConnection || p.State != PeerActive || p.suspended() || m.hasOutgoing(p.ID, handshake.PurposeReconnect) ||
		p.Pending != nil && p.Pending.Purpose == handshake.PurposeReconnect {
		// One reconnect at a time (§3.4.1 "After a demotion"): none starts
		// while the vault's own is open or pending, and none is tried.
		return false
	}
	if noReconnectToken(p, now) {
		if !m.carriedWait(p, now) { // 0.88.2 §6.3.1: not judged while carried tokens wait
			m.markStale(p, now) // §3.4.1 "The reconnect bound": no reconnect token
		}
		return false
	}
	if !m.canReconnect(p, now) {
		return false // nothing is abandoned for a reconnect that cannot start
	}
	for _, id := range sortedKeys(m.st.Outgoing) {
		og, sortedOK := m.st.Outgoing[id]
		if !sortedOK {
			continue // removed earlier in this loop
		}
		if og.New == nil && og.PeerID == p.ID && og.Purpose == handshake.PurposeRekey {
			m.abandonOutgoing(id, now)
		}
	}
	for _, id := range sortedKeys(m.st.Awaiting) {
		aw, sortedOK := m.st.Awaiting[id]
		if !sortedOK {
			continue // removed earlier in this loop
		}
		if aw.New == nil && aw.PeerID == p.ID && aw.Purpose == handshake.PurposeRekey {
			m.abandonAwaiting(id, now)
		}
	}
	if p.Pending != nil {
		m.abandonPending(p, why, false, now)
	}
	og := m.startReconnectCtx(p, ctx, now)
	if og == nil {
		m.note(now, "reconnect_not_started", p.ID)
		return false
	}
	m.note(now, "reconnect_"+why, p.ID)
	return true
}

// StaleReach is how long after the last exp of a token this vault issued
// to a stale connection's peer a deposit of the peer's under it can still
// arrive (0.88.7 §8.3 "Not delivered", case 6): the relay holds a message
// up to T (14 days) after a deposit made just before the exp, plus the
// clock skew the ts window allows.
const StaleReach = 14*24*time.Hour + envelope.MaxClockSkewFuture

// staleReachUntil is when connection p can no longer come back: the latest
// exp of any token this vault issued to the peer (adopted, or in a
// handshake still in flight: an hs.resp or hs.init not yet activated,
// revoked or not, since one deposited before the revocation still
// arrives), plus StaleReach. Zero: none was ever issued.
func (m *Manager) staleReachUntil(p *Peer) time.Time {
	var last time.Time
	see := func(ts []IssuedToken, all bool) {
		for _, t := range ts {
			if (all || t.PeerID == p.ID) && t.Exp.After(last) {
				last = t.Exp
			}
		}
	}
	see(m.st.Issued, false)
	for _, aw := range m.st.Awaiting {
		if aw.PeerID == p.ID {
			see(aw.Issued, true)
		}
	}
	for _, og := range m.st.Outgoing {
		if og.PeerID == p.ID {
			see(og.Issued, true)
		}
	}
	if p.Pending != nil {
		see(p.Pending.Issued, true)
	}
	if last.IsZero() {
		return last
	}
	return last.Add(StaleReach)
}

// tickStale ends the waiting messages of a stale connection that can no
// longer come back (0.88.7 §3.4.1 "Stale is not final", proposed bound,
// §8.3 "Not delivered" case 6): the peer reaches this vault only with a
// token this vault issued to it (a standing token for its rekey, a
// reconnect token for its reconnect), so once the last of them has expired
// and anything deposited under it has left the relay (staleReachUntil), no
// rekey or reconnect of its can make the connection active again. Each
// waiting durable member deposit (held or sealed) is then not delivered
// (undelivered_stale). A new invitation replaces the record (§7.4).
func (m *Manager) tickStale(p *Peer, now time.Time) {
	if p.Kind != KindConnection || p.State != PeerStale {
		return
	}
	if now.Before(m.staleReachUntil(p)) {
		return // it can still come back
	}
	for _, e := range m.st.Outbox {
		if !e.Done && e.PeerID == p.ID && memberDeposit(e) {
			m.notDelivered(e, "undelivered_stale", now)
		}
	}
}

// markStale makes connection p stale (§3.4.1 "The reconnect bound"):
// audited connection.stale with its feed item ("Your connection with
// <name> stopped working. Send them a new invitation.", app text), so a
// new invitation from that peer is accepted (§6.4). (0.88.7) Stale is not
// final: the peer's rekey or reconnect can make it active again
// (activate, connection.active_again), so the outbox keeps its entries,
// held ones included; a removal or a replacement ends them (notDelivered).
func (m *Manager) markStale(p *Peer, now time.Time) {
	if p.State == PeerStale {
		return
	}
	p.State = PeerStale
	// Held entries are kept (0.88.7, GC #7160 cause 1; until then they
	// were dropped here, unaudited, and lost when the connection came back).
	m.abandonHandshakes(p, true, true, now)
	if p.Pending != nil {
		m.abandonPending(p, "stale", false, now)
	}
	m.notifyDevices("connection.event", connEvent(p.ID, "stale"), "", now)
	m.record(Activity{Kind: "connection.stale", ConnectionID: p.ID, Ref: p.ID, Audit: true, Feed: true}, now)
	m.dirty = true
}
