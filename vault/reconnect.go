package vault

import (
	"time"

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
