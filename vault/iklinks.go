package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// The identity-key parts of VAULT-MESSAGING §3.4.1 that 0.86.0 changed
// (and that apply without relay-key rotation, which this release does not
// build): Table B for identity.rotate with the whole chain (S8), "Epochs
// after an ik link" (strict F1 demotion, F2 fork evidence by the confirmed
// epoch, the own_copy exception), H5 with pending epochs, S5 at the
// vault's own rotation, the identity.rotate resend, and rule L.

// ancestor reports whether ik is an ancestor of p's current ik: the old_ik
// of a followed link (§3.4.1 "Terms").
func (p *Peer) ancestor(ik []byte) bool {
	if len(ik) == 0 || bytes.Equal(ik, p.IK) {
		return false
	}
	for _, r := range parseRotations(p.Chain) {
		if bytes.Equal(r.OldIK, ik) {
			return true
		}
	}
	return false
}

// rejected reports whether ik was dropped at connection.rotation.resolve.
func (p *Peer) rejected(ik []byte) bool {
	for _, x := range p.Rejected {
		if bytes.Equal(x.NewIK, ik) {
			return true
		}
	}
	return false
}

// rotateLinks reads an identity.rotate body: `rotations` (S8, 0.86.0: the
// whole chain since the epoch's signer) when present, else `rotation`
// alone (a release-28 sender).
func rotateLinks(body []byte) ([]*handshake.Rotation, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBadRequest
	}
	raw, ok := o["rotation"]
	if !ok {
		return nil, errBadRequest
	}
	last, err := handshake.ParseRotation(raw)
	if err != nil {
		return nil, errBadRequest
	}
	arr, present, err := o.OptArray("rotations")
	if err != nil || len(arr) > handshake.MaxRotations {
		return nil, errBadRequest
	}
	if !present || len(arr) == 0 {
		return []*handshake.Rotation{last}, nil
	}
	var links []*handshake.Rotation
	for _, x := range arr {
		r, err := handshake.ParseRotation(x)
		if err != nil {
			return nil, errBadRequest
		}
		links = append(links, r)
	}
	if !bytes.Equal(links[len(links)-1].Marshal(), last.Marshal()) {
		return nil, errBadRequest // `rotation` is the chain's last link
	}
	return links, nil
}

// hIdentityRotate is Table B's identity.rotate column (§3.4.1): the links
// already followed are skipped (all followed: ignore); the first one not
// followed must start at the current ik (an ancestor or rejected ik:
// rejected_ik; any other: unknown_ik); the chain must verify and no new
// ik may be an ancestor or rejected (ik_rollback). Following applies
// "Epochs after an ik link" and H5.
func (m *Manager) hIdentityRotate(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	links, err := rotateLinks(in.Body)
	if err != nil {
		return nil, err
	}
	if m.emu28() {
		links = links[len(links)-1:] // release 28 reads `rotation` only
	}
	p := s.peer
	for _, r := range links {
		if m.rotationConflict(p, r, s.now) {
			return nil, nil
		}
	}
	if p.suspended() {
		return nil, nil
	}
	known := parseRotations(p.Chain)
	i := handshake.KnownPrefix(known, links)
	if i == len(links) {
		return nil, nil // every link already followed: ignore
	}
	switch first := links[i].OldIK; {
	case bytes.Equal(first, p.IK):
	case p.ancestor(first), p.rejected(first):
		m.refusePeerKey(p, "rejected_ik", false, s.now)
		return nil, nil
	default:
		m.refusePeerKey(p, "unknown_ik", false, s.now)
		return nil, nil
	}
	app := links[i:]
	if _, _, err := handshake.ResolveChain(p.IK, app); err != nil {
		m.audit(s.now, "bad_rotation", p.ID)
		return nil, nil
	}
	for _, r := range app {
		if p.ancestor(r.NewIK) || p.rejected(r.NewIK) {
			m.refusePeerKey(p, "ik_rollback", false, s.now)
			return nil, nil
		}
	}
	var ep []byte
	if s.epoch != nil {
		id := s.epoch.ID()
		ep = id[:]
	}
	m.followLinks(p, app, ep, s.now)
	return nil, nil
}

// followLinks follows identity links at the position of the message being
// handled, which traveled under epoch msgEpoch (nil: a handshake), with
// "Epochs after an ik link" and H5.
func (m *Manager) followLinks(p *Peer, app []*handshake.Rotation, msgEpoch []byte, now time.Time) {
	if len(app) == 0 {
		return
	}
	p.upgradeEpochs()
	for _, r := range app {
		p.IK, p.KEM = append([]byte(nil), r.NewIK...), r.NewKEM.Bytes()
		p.Chain = append(p.Chain, r.Marshal())
	}
	m.dirty = true
	// Following a link abandons the pending epoch whose sig_R the link's
	// old_ik made (the peer dropped that answer at its rotation, S5),
	// unless the message traveled under it (it has just confirmed it).
	if pe := p.Pending; pe != nil && !bytes.Equal(pe.ID, msgEpoch) {
		if e := p.epochMeta(pe.ID); e != nil && p.ancestor(e.Signer) {
			m.abandonPending(p, "link", false, now)
		}
	}
	demotedCurrent := false
	for i := range p.Epochs {
		e := &p.Epochs[i]
		if e.Demoted || e.Pending || !p.ancestor(e.Signer) {
			continue
		}
		// An epoch signed by an old ik, established by a message deposited
		// after the link: an old copy's. It stops being current.
		if posAfter(e.EstAt, e.EstMsg, m.relayAt, m.msgID) && !e.EstAt.IsZero() {
			e.Demoted, e.DemotedAt, e.DemotedMsg = true, m.relayAt, m.msgID
			demotedCurrent = demotedCurrent || bytes.Equal(e.ID, p.LastEpochID)
			m.note(now, "epoch_demoted", p.ID)
		}
	}
	m.f1Demote(p, app, msgEpoch, now)
	if demotedCurrent {
		m.restartAfterDemotion(p, now)
	}
	m.h5(p, now)
}

// f1Demote (§3.4.1, F1, strict): a link carried under an epoch E of P
// while Q's current epoch is later than E and signed by the link's old_ik
// shows that P never activated that later epoch: Q demotes it and
// reconnects naming E (a device: rekeys), which P accepts as its last.
// No exception for an epoch Q activated at hs.fin without confirmation.
func (m *Manager) f1Demote(p *Peer, app []*handshake.Rotation, msgEpoch []byte, now time.Time) {
	if msgEpoch == nil || bytes.Equal(msgEpoch, p.LastEpochID) || !p.newer(p.LastEpochID, msgEpoch) {
		return
	}
	cur := p.epochMeta(p.LastEpochID)
	if cur == nil {
		return
	}
	for _, r := range app {
		if !bytes.Equal(cur.Signer, r.OldIK) {
			continue
		}
		cur.Demoted, cur.DemotedAt, cur.DemotedMsg = true, time.Time{}, ""
		m.note(now, "epoch_demoted_f1", p.ID)
		kr := m.sessions[p.ID]
		if p.Revert != nil && bytes.Equal(p.Revert.Old, msgEpoch) && kr != nil && kr.Reinstate(epochIDOf(msgEpoch)) {
			// The epoch it traveled under is current again (it was kept
			// whole, §6.3.1 "Deployment").
			p.LastEpochID, p.OwnChainAtEpoch = append([]byte(nil), msgEpoch...), p.Revert.OldOwnChain
			p.Revert = nil
			if e := p.epochMeta(msgEpoch); e != nil {
				e.Superseded = time.Time{}
			}
		}
		for id, og := range m.st.Outgoing {
			if og.New == nil && og.PeerID == p.ID && og.Purpose == handshake.PurposeRekey {
				m.abandonOutgoing(id, now)
			}
		}
		if p.Kind == KindConnection {
			m.reconnectNaming(p, msgEpoch, "f1", now)
		} else {
			m.startRekey(p, now)
		}
		return
	}
}

// restartAfterDemotion: the current epoch was demoted (an old copy's):
// nothing more is sent in it, and a new epoch is made (a reconnect naming
// the newest epoch not demoted; a device: none can be made from it, so the
// device pairs again, as §6.7).
func (m *Manager) restartAfterDemotion(p *Peer, now time.Time) {
	for i := len(p.Epochs) - 1; i >= 0; i-- {
		e := p.Epochs[i]
		if !e.Demoted && !e.Pending && !e.Destroyed && p.Kind == KindConnection {
			m.reconnectNaming(p, e.ID, "demoted", now)
			return
		}
	}
}

// h5 (§3.4.1 H5, 0.86.0): whenever the current ik for p changes, the
// vault's open handshakes with p pinned to an ik no longer current are
// abandoned and started again (a pending epoch included), and its
// answers awaiting hs.fin whose pinned ik is no longer current are
// dropped.
func (m *Manager) h5(p *Peer, now time.Time) {
	rekey, reconnect := false, false
	for id, og := range m.st.Outgoing {
		if og.New != nil || og.PeerID != p.ID || og.Replaced || bytes.Equal(og.Init.ResponderIK, p.IK) {
			continue
		}
		rekey = rekey || og.Purpose == handshake.PurposeRekey
		reconnect = reconnect || og.Purpose == handshake.PurposeReconnect
		m.abandonOutgoing(id, now)
	}
	if pe := p.Pending; pe != nil {
		if e := p.epochMeta(pe.ID); e != nil && !bytes.Equal(e.Signer, p.IK) {
			m.abandonPending(p, "h5", false, now)
			rekey = true
		}
	}
	for id, aw := range m.st.Awaiting {
		if aw.New == nil && aw.PeerID == p.ID && aw.Signer != nil && !bytes.Equal(aw.Signer, p.IK) &&
			(aw.Reconnect == nil || !aw.Reconnect.Fork) {
			m.abandonAwaiting(id, now)
		}
	}
	switch {
	case reconnect:
		m.startReconnect(p, now)
	case rekey:
		m.startRekey(p, now)
	}
}

// forkEpoch is "Epochs after an ik link" for a rekey or reconnect from P
// whose ctx names epoch ctx (0.86.0, F2): the current or confirmed epoch
// is ordinary; one older than the confirmed epoch, where an epoch after
// it up to the confirmed one has an ancestor of P's ik as its signer, is
// fork evidence; except when every such epoch is one the vault began
// (own_copy).
func (p *Peer) forkEpoch(ctx []byte) (fork, ownCopy bool) {
	if bytes.Equal(ctx, p.LastEpochID) || bytes.Equal(ctx, p.confirmedID()) {
		return false, false
	}
	ic, ik := p.epochIndex(ctx), p.epochIndex(p.confirmedID())
	if ic < 0 || ik <= ic {
		return false, false
	}
	found, ownOnly := false, true
	for _, e := range p.Epochs[ic+1 : ik+1] {
		if p.ancestor(e.Signer) {
			found = true
			ownOnly = ownOnly && e.Mine
		}
	}
	return found && !ownOnly, found && ownOnly
}

// acceptOwnCopy is the own_copy exception: the epochs after ctx are
// demoted (every message under them is refused, ancestor_ik, without a
// History line), ctx is accepted as the last epoch, and
// connection.fork_suspected (ref own_copy) is audited with a History line
// ("<connection name> restarted its secure session with you.", app text)
// and no feed item.
func (m *Manager) acceptOwnCopy(p *Peer, ctx []byte, now time.Time) {
	after := false
	for i := range p.Epochs {
		e := &p.Epochs[i]
		if after && !e.Demoted {
			e.Demoted, e.DemotedAt, e.DemotedMsg, e.OwnCopy = true, time.Time{}, "", true
		}
		after = after || bytes.Equal(e.ID, ctx)
	}
	if p.Pending != nil {
		m.abandonPending(p, "own_copy", false, now)
	}
	m.record(Activity{Kind: "connection.fork_suspected", ConnectionID: connID(p), DeviceID: devID(p), Ref: "own_copy", Audit: true}, now)
	m.dirty = true
}

// rekeyOtherEpoch decides a rekey hs.init under an epoch that is neither
// current nor the confirmed one: fork evidence suspends; the own_copy
// exception accepts it when that epoch still has its rk (the epoch Q kept
// whole as a reverting initiator), making it current again. It reports
// whether the rekey is to be answered.
func (m *Manager) rekeyOtherEpoch(p *Peer, in *envelope.Inner, ep *handshake.Epoch, now time.Time) bool {
	if p.Kind != KindConnection {
		return false
	}
	id := ep.ID()
	fork, own := p.forkEpoch(id[:])
	if fork {
		m.suspendForkRef(p, "epoch", now)
		return false
	}
	if !own || !ep.HasRK() || !ep.CanSend() {
		return false
	}
	m.acceptOwnCopy(p, id[:], now)
	if kr := m.sessions[p.ID]; kr != nil && kr.Reinstate(id) {
		p.LastEpochID = append([]byte(nil), id[:]...)
		if p.Revert != nil {
			p.OwnChainAtEpoch = p.Revert.OldOwnChain
			p.Revert = nil
		}
		if e := p.epochMeta(id[:]); e != nil {
			e.Superseded = time.Time{}
		}
		return true
	}
	return false
}

// --- the rotating side ---

// identityRotateBody is identity.rotate to p (S8, 0.86.0): `rotation`, the
// newest link, and `rotations`, the whole chain since the signer of the
// epoch it travels in.
func (m *Manager) identityRotateBody(p *Peer) []byte {
	links := m.ownRotationsSince(p.OwnChainAtEpoch)
	if len(links) == 0 {
		return nil
	}
	last := links[len(links)-1]
	arr := []byte{'['}
	for i, r := range links {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, r.Marshal()...)
	}
	return strictjson.NewBuilder().Raw("rotation", last.Marshal()).Raw("rotations", append(arr, ']')).Bytes()
}

// s5 is the vault's own rotation's step for p (S5, 0.86.0): its own open
// rekeys and reconnects and its pending epoch are abandoned (started again
// after identity.rotate); its answers awaiting hs.fin are dropped toward
// a peer that advertised hs_confirm (their epochs would be signed by the
// superseded ik), and kept toward any other, which activates at hs.fin:
// established there, then rekeyed at once under the new ik
// (responderEstablish).
func (m *Manager) s5(p *Peer, now time.Time) (reconnect bool) {
	for id, og := range m.st.Outgoing {
		if og.New != nil || og.PeerID != p.ID || og.Replaced {
			continue
		}
		reconnect = reconnect || og.Purpose == handshake.PurposeReconnect
		m.abandonOutgoing(id, now)
	}
	if p.Pending != nil {
		m.abandonPending(p, "s5", false, now)
	}
	if p.hasConfirm() {
		for id, aw := range m.st.Awaiting {
			if aw.New == nil && aw.PeerID == p.ID {
				m.abandonAwaiting(id, now)
			}
		}
	}
	return reconnect
}

// idResend is S5's resend (0.86.0): a session message from p under an
// epoch whose own-side signer is an ancestor of the vault's ik, with an
// inner ts more than 1 hour after the vault's rotation, means p missed
// it: identity.rotate goes again with the whole chain, at most 3 times
// per peer per rotation and once an hour.
func (m *Manager) idResend(p *Peer, ep *handshake.Epoch, in *envelope.Inner, now time.Time) {
	if p.Kind != KindConnection || ep == nil || len(m.st.Rotations) == 0 || m.st.RotatedAt.IsZero() {
		return
	}
	id := ep.ID()
	e := p.epochMeta(id[:])
	if e == nil || e.OwnChain >= len(m.st.Rotations) || !in.TS.After(m.st.RotatedAt.Add(time.Hour)) {
		return
	}
	r := p.IDResend
	if r == nil || r.Rotation != len(m.st.Rotations) {
		r = &IDResend{Rotation: len(m.st.Rotations)}
		p.IDResend = r
	}
	if r.N >= 3 || now.Sub(r.At) < time.Hour {
		return
	}
	links := m.ownRotationsSince(e.OwnChain)
	if len(links) == 0 {
		return
	}
	arr := []byte{'['}
	for i, l := range links {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, l.Marshal()...)
	}
	body := strictjson.NewBuilder().Raw("rotation", links[len(links)-1].Marshal()).Raw("rotations", append(arr, ']')).Bytes()
	if m.sendTo(p, "identity.rotate", body, now) != "" {
		r.N++
		r.At = now
		m.dirty = true
	}
}

// ruleL (§3.4.1 rule L, 0.86.0): toward a peer that has advertised no
// features (release 28 or earlier), when its rekey was evidently refused
// and the vault's ik is newer than the one that signed the current epoch
// (the peer may have missed a link), the vault drops its unfinished
// answers to it and reconnects (carrying the whole chain), once per
// current epoch; tried again up to 3 times if unanswered; refused, or
// the last failing, the connection goes stale. It reports whether a
// reconnect started.
func (m *Manager) ruleL(p *Peer, now time.Time) bool {
	if p.Kind != KindConnection || p.advertisedFeatures() || p.State != PeerActive || p.suspended() || m.emu28() {
		return false
	}
	if p.OwnChainAtEpoch >= len(m.st.Rotations) {
		return false // not after a rotation of the vault's own
	}
	if l := p.RuleL; l != nil && bytes.Equal(l.Epoch, p.LastEpochID) {
		return false // once per current epoch
	}
	p.RuleL = &RuleLState{Epoch: append([]byte(nil), p.LastEpochID...), Tries: 1}
	m.dirty = true
	return m.reconnectNaming(p, p.LastEpochID, ruleRCL, now)
}

var _ = ed25519.PublicKeySize
var _ = suite.EpochIDSize
var _ json.RawMessage
