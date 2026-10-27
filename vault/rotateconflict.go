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
	for _, raw := range p.Chain {
		prev, err := handshake.ParseRotation(raw)
		if err != nil || !suite.EqualPublic(prev.OldIK, r.OldIK) {
			continue
		}
		if suite.EqualPublic(prev.NewIK, r.NewIK) {
			return false // the same statement again
		}
		if p.Conflict == nil {
			p.Conflict = &RotationConflict{OldIK: append([]byte(nil), r.OldIK...), Statements: []json.RawMessage{raw, r.Marshal()}, At: now.UTC()}
			m.record(Activity{Kind: "identity.rotate_conflict", ConnectionID: p.ID, Audit: true, Feed: true, Priority: "high",
				Ref: fingerprint(prev.NewIK) + "/" + fingerprint(r.NewIK)}, now)
			m.dirty = true
		}
		return true
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
