package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// One successor per key (VAULT-MESSAGING 0.33.0 §3.4): a valid statement
// whose old_ik a connection already followed to another new_ik means two
// copies of that vault are rotating; the receiver keeps neither, suspends
// the connection, audits identity.rotate_conflict and tells its member
// with both candidates' fingerprints, until connection.rotation.resolve.

// TypeRotationResolve is the holder's resolution (§10.4).
const TypeRotationResolve = "connection.rotation.resolve"

func fingerprint(ik []byte) string {
	h := sha256.Sum256(ik)
	return hex.EncodeToString(h[:16])
}

// rotationConflict reports (and records) whether r conflicts with a
// successor p already accepted.
func (m *Manager) rotationConflict(p *Peer, r *handshake.Rotation, now time.Time) bool {
	return m.rotationConflictRec(p, r, true, now)
}

// MaxSeen bounds Peer.Seen (review 5): a link past it is not recorded.
const MaxSeen = handshake.MaxRotations

// rotationConflictRec is rotationConflict; record says whether a link not
// yet followed or seen is recorded as seen (not for a rekey hs.init until
// it has passed rekeyPrecheck).
func (m *Manager) rotationConflictRec(p *Peer, r *handshake.Rotation, record bool, now time.Time) bool {
	if p.Kind != KindConnection || r.Verify() != nil {
		return false
	}
	for _, x := range p.Rejected {
		if suite.EqualPublic(x.OldIK, r.OldIK) && suite.EqualPublic(x.NewIK, r.NewIK) {
			// The copy the holder dropped at a resolution: refused, no
			// new suspension.
			m.audit(now, "rotation_rejected", p.ID)
			return true
		}
	}
	followed := false
	prior := append([]json.RawMessage(nil), p.Chain...)
	prior = append(prior, p.Seen...) // 0ee0078 rotateconflict.go:32: followed links only
	for _, raw := range prior {
		prev, err := handshake.ParseRotation(raw)
		if err != nil || !suite.EqualPublic(prev.OldIK, r.OldIK) || rejectedLink(p, prev) {
			continue // a link dropped at a resolution is no successor
		}
		if suite.EqualPublic(prev.NewIK, r.NewIK) {
			followed = true // the same statement again (followed or seen)
			continue
		}
		if p.Conflict == nil {
			p.Conflict = &RotationConflict{OldIK: append([]byte(nil), r.OldIK...), Statements: []json.RawMessage{raw, r.Marshal()}, At: now.UTC()}
			m.record(Activity{Kind: "identity.rotate_conflict", ConnectionID: p.ID, Audit: true, Feed: true, Priority: "high",
				Ref: fingerprint(prev.NewIK) + "/" + fingerprint(r.NewIK)}, now)
			// H5: a conflict suspension abandons every open handshake with
			// the peer and revokes its tokens (review RR2-4).
			m.abandonHandshakes(p, true, true, now)
			if p.Pending != nil {
				m.abandonPending(p, "conflict", false, now)
			}
			m.dirty = true
		}
		return true
	}
	if record && !followed && seenRelevant(p, r.OldIK) && len(p.Seen) < MaxSeen {
		// 0.86.0 rule C: kept as seen, followed or not, at most one per old
		// key (another would be the conflict above); only links from the
		// current ik, an ancestor, or a key a seen link reaches, and at
		// most MaxSeen of them.
		p.Seen = append(p.Seen, r.Marshal())
		m.dirty = true
	}
	return false
}

// seenRelevant reports whether a link from old is kept as seen: old is p's
// current ik, an ancestor, or reached through seen links.
func seenRelevant(p *Peer, old []byte) bool {
	if suite.EqualPublic(old, p.IK) || p.ancestor(old) {
		return true
	}
	for _, raw := range p.Seen {
		if s, err := handshake.ParseRotation(raw); err == nil && suite.EqualPublic(s.NewIK, old) {
			return true
		}
	}
	return false
}

// pruneSeen keeps the seen links that are still relevant.
func pruneSeen(p *Peer) {
	kept := p.Seen[:0]
	for _, raw := range p.Seen {
		if s, err := handshake.ParseRotation(raw); err == nil && handshake.KnownPrefix(parseRotations(p.Chain), []*handshake.Rotation{s}) == 0 &&
			seenRelevant(p, s.OldIK) {
			kept = append(kept, raw)
		}
	}
	p.Seen = kept
}

func rejectedLink(p *Peer, r *handshake.Rotation) bool {
	for _, x := range p.Rejected {
		if suite.EqualPublic(x.OldIK, r.OldIK) && suite.EqualPublic(x.NewIK, r.NewIK) {
			return true
		}
	}
	return false
}

// hRotationResolve keeps one successor of a connection's identity key
// after out-of-band verification (the holder only).
func (m *Manager) hRotationResolve(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	if s.from.Kind != KindApp {
		return nil, errForbiddenH
	}
	o, err := strictjson.ParseObject(in.Body)
	if err != nil {
		return nil, errBadRequest
	}
	id, err := o.String("connection_id")
	if err != nil {
		return nil, errBadRequest
	}
	want, err := o.Base64("new_ik", 32)
	if err != nil {
		return nil, errBadRequest
	}
	p := m.st.Connections[id]
	if p == nil || p.Conflict == nil {
		return nil, errNotFound
	}
	for _, raw := range p.Conflict.Statements {
		r, err := handshake.ParseRotation(raw)
		if err != nil || !suite.EqualPublic(r.NewIK, want) {
			continue
		}
		for _, c := range p.Conflict.Statements {
			if o, err := handshake.ParseRotation(c); err == nil && !suite.EqualPublic(o.NewIK, want) {
				p.Rejected = append(p.Rejected, RejectedSuccessor{OldIK: o.OldIK, NewIK: o.NewIK})
			}
		}
		// Keep this successor: the chain's link for old_ik becomes it.
		kept := p.Chain[:0]
		for _, c := range p.Chain {
			if prev, err := handshake.ParseRotation(c); err == nil && suite.EqualPublic(prev.OldIK, p.Conflict.OldIK) {
				break
			}
			kept = append(kept, c)
		}
		p.Chain = append(kept, raw)
		p.IK, p.KEM = append([]byte(nil), r.NewIK...), r.NewKEM.Bytes()
		p.Conflict = nil
		m.dirty = true
		m.record(Activity{Kind: "identity.rotate_resolved", ConnectionID: p.ID, Ref: fingerprint(r.NewIK), Audit: true}, s.now)
		return json.RawMessage(`{}`), nil
	}
	return nil, errNotFound
}
