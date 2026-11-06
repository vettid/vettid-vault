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
	if p.Kind == KindConnection && p.State == PeerActive && !p.suspended() && noReconnectToken(p, now) {
		m.markStale(p, now) // §3.4.1 "The reconnect bound": no reconnect token
		return false
	}
	if p.Kind != KindConnection || p.State != PeerActive || p.suspended() || m.hasOutgoing(p.ID, handshake.PurposeReconnect) ||
		!m.canReconnect(p, now) {
		return false // nothing is abandoned for a reconnect that cannot start
	}
	for id, og := range m.st.Outgoing {
		if og.New == nil && og.PeerID == p.ID && og.Purpose == handshake.PurposeRekey {
			m.abandonOutgoing(id, now)
		}
	}
	for id, aw := range m.st.Awaiting {
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
// new invitation from that peer is accepted (§6.4).
func (m *Manager) markStale(p *Peer, now time.Time) {
	if p.State == PeerStale {
		return
	}
	p.State = PeerStale
	for _, e := range m.st.Outbox {
		if !e.Done && e.PeerID == p.ID && e.Held != nil {
			e.Done, e.Held = true, nil // held for an epoch that will not come (review 2)
		}
	}
	m.abandonHandshakes(p, true, true, now)
	if p.Pending != nil {
		m.abandonPending(p, "stale", false, now)
	}
	m.notifyDevices("connection.event", connEvent(p.ID, "stale"), "", now)
	m.record(Activity{Kind: "connection.stale", ConnectionID: p.ID, Ref: p.ID, Audit: true, Feed: true}, now)
	m.dirty = true
}
