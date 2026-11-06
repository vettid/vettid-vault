package vault

import (
	"context"
	"encoding/json"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// Stand-ins for what the next stages add, so that each stage builds: the
// ungated path (stage c, ungated.go) and the §3.4.1 ik rules (stage d,
// iklinks.go). Each stage removes its part of this file.

// --- stage c ---

func (m *Manager) startRevertKeep(*Peer, []byte, []byte, int, time.Time) {}
func (m *Manager) keepCopy(*Peer, *envelope.Inner, string)               {}
func (m *Manager) endRevertKeep(p *Peer, _ time.Time)                    { p.Revert = nil }
func (m *Manager) revert(*Peer, bool, time.Time)                         {}
func (m *Manager) tickRevert(*Peer, time.Time)                           {}
func (m *Manager) reconnectNaming(*Peer, []byte, string, time.Time) bool { return false }
func (m *Manager) ruleRCExpired(*Peer, *OutgoingHS, time.Time)           {}
func (m *Manager) markStale(*Peer, time.Time)                            {}

// --- stage d ---

func (p *Peer) ancestor([]byte) bool                                           { return false }
func (m *Manager) followLinks(*Peer, []*handshake.Rotation, []byte, time.Time) {}
func (p *Peer) forkEpoch([]byte) (bool, bool)                                  { return false, false }
func (m *Manager) acceptOwnCopy(*Peer, []byte, time.Time)                      {}
func (m *Manager) rekeyOtherEpoch(*Peer, *envelope.Inner, *handshake.Epoch, time.Time) bool {
	return false
}
func (m *Manager) identityRotateBody(*Peer) []byte                              { return nil }
func (m *Manager) s5(*Peer, time.Time) bool                                     { return false }
func (m *Manager) idResend(*Peer, *handshake.Epoch, *envelope.Inner, time.Time) {}
func (m *Manager) ruleL(*Peer, time.Time) bool                                  { return false }

// hIdentityRotate follows one link of a connection's rotation chain.
func (m *Manager) hIdentityRotate(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	raw, ok := o["rotation"]
	if !ok {
		return nil, errBadRequest
	}
	r, err := handshake.ParseRotation(raw)
	if err != nil {
		return nil, errBadRequest
	}
	if c := m.rotationConflict(s.peer, r, s.now); c {
		return nil, nil
	}
	if s.peer.suspended() {
		return nil, nil
	}
	final, kem, err := handshake.ResolveChain(s.peer.IK, []*handshake.Rotation{r})
	if err != nil {
		m.audit(s.now, "bad_rotation", s.peer.ID)
		return nil, nil
	}
	s.peer.IK, s.peer.KEM = final, kem.Bytes()
	s.peer.Chain = append(s.peer.Chain, r.Marshal())
	return nil, nil
}

var _ = context.Background
var _ json.RawMessage
