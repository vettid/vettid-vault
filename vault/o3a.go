package vault

import (
	"crypto/ed25519"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// O3a (VAULT-MESSAGING §3.4.1 "An older peer's hs.fin", 0.85.4 with the
// lead's consistency check): an hs.fin for an answer Q dropped under H5
// that verifies under an ancestor ik shows that the peer activated an
// epoch Q never established. From a peer that advertised no features
// (release 28 or earlier) the connection is made stale (connection.stale
// with its feed item, once per connection); from a peer with features it
// is acked and dropped (S5). Q keeps, for each answer H5 drops and until
// its lifetime ends, only what recognises and checks that hs.fin.

// keepDroppedAnswer records an answer H5 is about to drop.
func (m *Manager) keepDroppedAnswer(p *Peer, aw *AwaitingHS, now time.Time) {
	r := m.awaiting[aw.ID]
	if r == nil {
		return
	}
	c, err := r.FinCheck()
	if err != nil {
		return
	}
	m.st.DroppedAnswers = append(m.st.DroppedAnswers, DroppedAnswer{PeerID: p.ID, Check: c, Until: aw.Created.Add(HandshakeTTL)})
	m.dirty = true
}

// droppedAnswerFin handles a message that matches a dropped answer's
// hs.fin kids. It reports whether one matched (the message is then acked).
func (m *Manager) droppedAnswerFin(env *envelope.Envelope, raw []byte, sender ed25519.PublicKey, now time.Time) bool {
	for i, d := range m.st.DroppedAnswers {
		if !d.Check.Matches(env.RecipientKid(), env.SenderKid()) {
			continue
		}
		if d.Check.CheckFin(raw, sender, now) != nil {
			// Not the initiator's (sender, opening or sig_I): dropped; the
			// record stays, so a forged match cannot erase it (review 6).
			m.note(now, "hs_fin_dropped", d.PeerID)
			return true
		}
		// Verified: the record (k_i2r with it) is erased now, or at its end.
		m.st.DroppedAnswers = append(m.st.DroppedAnswers[:i:i], m.st.DroppedAnswers[i+1:]...)
		m.dirty = true
		p := m.peer(d.PeerID)
		if p == nil {
			return true
		}
		if p.ancestor(d.Check.VerifyIK) && !p.advertisedFeatures() && p.Kind == KindConnection {
			m.markStale(p, now) // O3a: the peer activated an epoch this vault never established
			return true
		}
		m.audit(now, "hs_fin_dropped", p.ID) // a peer with features: acked and dropped (S5)
		return true
	}
	return false
}

// pruneDroppedAnswers forgets the records whose lifetime ended.
func (m *Manager) pruneDroppedAnswers(now time.Time) {
	kept := m.st.DroppedAnswers[:0]
	for _, d := range m.st.DroppedAnswers {
		if now.Before(d.Until) {
			kept = append(kept, d)
		}
	}
	if len(kept) != len(m.st.DroppedAnswers) {
		m.dirty = true
	}
	m.st.DroppedAnswers = kept
}
