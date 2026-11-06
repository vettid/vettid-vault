package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
// epoch), H5 with pending epochs, S5 at the vault's own rotation and the
// identity.rotate resend.

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

// signedAtOrBefore reports whether signer is the link's oldIK or an
// ancestor of it: the old_ik of a followed link before the one from oldIK
// (§3.4.1 "that link's old_ik or an ancestor").
func (p *Peer) signedAtOrBefore(signer, oldIK []byte) bool {
	if len(signer) == 0 {
		return false
	}
	if bytes.Equal(signer, oldIK) {
		return true
	}
	for _, r := range parseRotations(p.Chain) {
		if bytes.Equal(r.OldIK, oldIK) {
			return false
		}
		if bytes.Equal(r.OldIK, signer) {
			return true
		}
	}
	return false
}

// signedByLinks reports whether signer is the old_ik of one of links, or
// an ancestor of one.
func (p *Peer) signedByLinks(signer []byte, links []*handshake.Rotation) bool {
	for _, r := range links {
		if p.signedAtOrBefore(signer, r.OldIK) {
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
// alone (rotateIdentity's fallback when identityRotateBody has no chain).
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
// followed must start at the current ik (an ancestor ik: unexpected; a
// rejected ik: rejected_ik; any other: unknown_ik); the chain must verify and no new
// ik may be an ancestor or rejected (ik_rollback). Following applies
// "Epochs after an ik link" and H5.
func (m *Manager) hIdentityRotate(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	links, err := rotateLinks(in.Body)
	if err != nil {
		return nil, err
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
	var ep []byte
	if s.epoch != nil {
		id := s.epoch.ID()
		ep = id[:]
	}
	known := parseRotations(p.Chain)
	i := handshake.KnownPrefix(known, links)
	if i == len(links) {
		m.k9(p, links, ep, s.now) // every link already followed: ignore, R29-K9 still judged
		return nil, nil
	}
	switch first := links[i].OldIK; {
	case bytes.Equal(first, p.IK):
	case p.rejected(first):
		m.refusePeerKey(p, "rejected_ik", s.now)
		return nil, nil
	case p.ancestor(first):
		// Table B: an ancestor ik in identity.rotate is only "every link
		// already followed: ignore"; any other case cannot occur ("—"),
		// so refuse (unexpected).
		m.refusePeerKey(p, "unexpected", s.now)
		return nil, nil
	default:
		m.refusePeerKey(p, "unknown_ik", s.now)
		return nil, nil
	}
	app := links[i:]
	if _, _, err := handshake.ResolveChain(p.IK, app); err != nil {
		m.audit(s.now, "bad_rotation", p.ID)
		return nil, nil
	}
	for _, r := range app {
		if p.ancestor(r.NewIK) || p.rejected(r.NewIK) {
			m.refusePeerKey(p, "ik_rollback", s.now)
			return nil, nil
		}
	}
	m.followLinks(p, app, ep, s.now)
	m.k9(p, links, ep, s.now)
	return nil, nil
}

// k9 is §3.4.1 "Epochs abandoned while pending, at P's identity.rotate"
// (R29-K9), in the write that follows or ignores an identity.rotate from
// P under epoch msgEpoch (E): for each of its links, every epoch of P that
// the vault began and abandoned while pending (never confirmed), later
// than E in establishing order, whose sig_R was made by the link's old_ik
// or an ancestor, was never activated by P. With its received flag set a
// copy used it: suspended (ref epoch, the neutral feed item). Otherwise it
// is ended (connection.fork_suspected, ref epoch, no feed item): a later
// message under it is fork evidence, and a reconnect ctx naming it is
// refused. One this message's link just abandoned is ended, not demoted.
// It is not judged at an hs.resp or hs.fin.
func (m *Manager) k9(p *Peer, links []*handshake.Rotation, msgEpoch []byte, now time.Time) {
	ie := p.epochIndex(msgEpoch)
	if p.Kind != KindConnection || ie < 0 || p.suspended() {
		return
	}
	var judged []*EpochMeta
	for i := ie + 1; i < len(p.Epochs); i++ {
		e := &p.Epochs[i]
		if !e.Mine || !e.Abandoned || e.Ended {
			continue
		}
		for _, r := range links {
			if p.signedAtOrBefore(e.Signer, r.OldIK) {
				judged = append(judged, e)
				break
			}
		}
	}
	for _, e := range judged {
		if e.GotFromPeer {
			m.suspendForkRef(p, "epoch", now)
			return
		}
	}
	for _, e := range judged {
		e.Ended = true
		e.Demoted, e.DemotedAt, e.DemotedMsg = false, time.Time{}, ""
		m.record(Activity{Kind: "connection.fork_suspected", ConnectionID: connID(p), DeviceID: devID(p), Ref: "epoch", Audit: true}, now)
		m.dirty = true
	}
}

// evidenceFirst is acceptFrom step 3 (§3.4.1): every identity link a
// message carries is checked by rule C before anything refuses it (a
// demoted or destroyed epoch, Table B), so that a second successor is
// recorded whatever epoch it travels under. It reports whether the
// connection is (now) suspended by a conflict.
func (m *Manager) evidenceFirst(p *Peer, in *envelope.Inner, now time.Time) bool {
	if p.Kind != KindConnection {
		return false
	}
	var links []*handshake.Rotation
	switch in.Type {
	case "identity.rotate":
		links, _ = rotateLinks(in.Body)
	case handshake.TypeInit:
		// A rekey's links are checked here and recorded as seen only once
		// it has passed rekeyPrecheck (handleRekeyInit, review 5).
		if b, err := handshake.ParseInit(in.Body); err == nil {
			for _, r := range b.Rotations {
				if m.rotationConflictRec(p, r, false, now) {
					return p.Conflict != nil
				}
			}
		}
		return false
	}
	for _, r := range links {
		if m.rotationConflict(p, r, now) {
			return p.Conflict != nil
		}
	}
	return false
}

// followLinks follows identity links at the position of the message being
// handled, which traveled under epoch msgEpoch (nil: a handshake), with
// "Epochs after an ik link" and H5.
func (m *Manager) followLinks(p *Peer, app []*handshake.Rotation, msgEpoch []byte, now time.Time) {
	if len(app) == 0 {
		return
	}
	for _, r := range app {
		p.IK, p.KEM = append([]byte(nil), r.NewIK...), r.NewKEM.Bytes()
		p.Chain = append(p.Chain, r.Marshal())
	}
	pruneSeen(p) // a followed link is no longer only seen; irrelevant ones go
	m.dirty = true
	// Following a link abandons the pending epoch whose sig_R the link's
	// old_ik made (the peer dropped that answer at its rotation, S5),
	// unless the message traveled under it (it has just confirmed it).
	restart := ""
	if pe := p.Pending; pe != nil && !bytes.Equal(pe.ID, msgEpoch) {
		if e := p.epochMeta(pe.ID); e != nil && p.signedByLinks(e.Signer, app) {
			m.abandonPending(p, "link", false, now)
			restart = string(pe.Purpose) // started again under the current ik, as H5 says
		}
	}
	if m.noLinkRestart {
		restart = ""
	}
	defer func() {
		switch handshake.Purpose(restart) {
		case handshake.PurposeReconnect:
			m.startReconnect(p, now)
		case handshake.PurposeRekey:
			m.startRekey(p, now)
		}
	}()
	byPosition := func(e *EpochMeta) bool {
		return !e.Demoted && !e.Pending && p.signedByLinks(e.Signer, app) && !e.EstAt.IsZero() && posAfter(e.EstAt, e.EstMsg, m.relayAt, m.msgID)
	}
	for i := range p.Epochs {
		if e := &p.Epochs[i]; byPosition(e) && e.GotFromPeer {
			// §3.4.1 "Epochs after an ik link" (R29-K4): its received flag
			// is set, so P's side used it after the rotation: a copy did.
			m.suspendForkRef(p, "epoch", now)
			return
		}
	}
	demotedCurrent := false
	for i := range p.Epochs {
		e := &p.Epochs[i]
		// An epoch signed by an old ik, established by a message deposited
		// after the link: an old copy's. It stops being current.
		if byPosition(e) {
			e.Demoted, e.DemotedAt, e.DemotedMsg = true, m.relayAt, m.msgID
			// S8 (0.86.6): a demotion by position is audited as a fork
			// sign (ref epoch), without a feed item or a suspension.
			m.record(Activity{Kind: "connection.fork_suspected", ConnectionID: connID(p), DeviceID: devID(p), Ref: "epoch", Audit: true}, now)
			if bytes.Equal(e.ID, p.LastEpochID) {
				demotedCurrent = true
				if kr := m.sessions[p.ID]; kr != nil {
					m.rehold(p, kr.Current())
				}
			}
			m.note(now, "epoch_demoted", p.ID)
		}
	}
	m.f1Demote(p, app, msgEpoch, now)
	if demotedCurrent && !m.noLinkRestart {
		m.restartAfterDemotion(p, now) // not beside the caller's own handshake
	}
	m.h5(p, now)
}

// f1Demote is §3.4.1 "Strict F1, a link under an earlier epoch": a link
// carried under an epoch E of P, while Q's current epoch is later than E
// and signed by the link's old_ik, shows that P never activated the epochs
// after E signed by that key, or that a copy did. Q takes together every
// epoch of P after E whose P-side signer is the link's old_ik or an
// ancestor: if any has its received flag set, Q suspends (ref epoch);
// otherwise it demotes them all and reconnects naming E (a device:
// rekeys), which P accepts as its last.
func (m *Manager) f1Demote(p *Peer, app []*handshake.Rotation, msgEpoch []byte, now time.Time) {
	if msgEpoch == nil || bytes.Equal(msgEpoch, p.LastEpochID) || !p.newer(p.LastEpochID, msgEpoch) {
		return
	}
	cur := p.epochMeta(p.LastEpochID)
	ie := p.epochIndex(msgEpoch)
	if cur == nil || ie < 0 {
		return
	}
	for _, r := range app {
		if !bytes.Equal(cur.Signer, r.OldIK) {
			continue
		}
		var later []*EpochMeta
		for i := ie + 1; i < len(p.Epochs); i++ {
			e := &p.Epochs[i]
			if e.Pending || e.Abandoned || e.Destroyed {
				continue // pending and abandoned ones: "Pending epochs at a link", K9
			}
			if p.signedAtOrBefore(e.Signer, r.OldIK) {
				later = append(later, e)
			}
		}
		for _, e := range later {
			if e.GotFromPeer {
				// P's side used it after the rotation: a copy did.
				m.suspendForkRef(p, "epoch", now)
				return
			}
		}
		for _, e := range later {
			if !e.Demoted {
				e.Demoted, e.DemotedAt, e.DemotedMsg = true, time.Time{}, ""
			}
		}
		// Audited as a fork sign (ref epoch), without a feed item or a
		// suspension, as a demotion by position is.
		m.record(Activity{Kind: "connection.fork_suspected", ConnectionID: connID(p), DeviceID: devID(p), Ref: "epoch", Audit: true}, now)
		m.note(now, "epoch_demoted_f1", p.ID)
		kr := m.sessions[p.ID]
		if kr != nil {
			m.rehold(p, kr.Current())
		}
		for id, og := range m.st.Outgoing {
			if og.New == nil && og.PeerID == p.ID && og.Purpose == handshake.PurposeRekey {
				m.abandonOutgoing(id, now)
			}
		}
		switch {
		case m.noLinkRestart:
			// Not beside the caller's own handshake, which establishes
			// the next epoch.
		case p.Kind == KindConnection:
			m.reconnectNaming(p, msgEpoch, "f1", now)
		default:
			m.startRekey(p, now)
		}
		return
	}
}

// Held messages (§3.4.1 "Epochs after an ik link", 0.86.2/0.86.3 draft):
// while p's current epoch is demoted, a durable message to p waits
// unsealed in its place in the outbox and is sealed, with a new ts and the
// same inner id (receivers dedupe by it), under the next current epoch;
// one whose exp passes first is discarded; an ephemeral one is not sent.

// holdDemoted queues a message made while p's current epoch is demoted.
func (m *Manager) holdDemoted(p *Peer, in *envelope.Inner, wake string) {
	if te := m.registry[in.Type]; te != nil && te.spec.Ephemeral {
		return // ephemeral: not sent
	}
	m.holdInner(p, in, wake)
}

// holdInner queues in, unsealed, as a held entry for p.
func (m *Manager) holdInner(p *Peer, in *envelope.Inner, wake string) {
	c := *in
	c.Seq, c.Features = 0, nil
	j, err := c.Marshal(envelope.ModeSealed)
	if err != nil {
		return
	}
	m.queueDeposit(&OutboxEntry{PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Held: j, HeldExp: in.Exp, Wake: wake}, m.now())
}

// rehold turns p's outbox entries sealed under the epoch ep (the current
// epoch, just demoted) and not yet deposited back into held ones: the
// vault reads each back with ep's send key. Handshake messages and
// entries already deposited are left as they are.
func (m *Manager) rehold(p *Peer, ep *handshake.Epoch) {
	if ep == nil {
		return
	}
	for _, e := range m.st.Outbox {
		if e.Done || e.PeerID != p.ID || e.Op != OpDeposit || e.Held != nil || e.Handshake || len(e.Payload) == 0 {
			continue
		}
		env, err := envelope.Parse(e.Payload)
		if err != nil {
			continue
		}
		in, err := ep.OpenSent(env)
		if err != nil {
			continue // sealed under another epoch: as it is
		}
		if te := m.registry[in.Type]; te != nil && te.spec.Ephemeral {
			e.Done = true // ephemeral: not sent
			continue
		}
		in.Seq, in.Features = 0, nil
		j, err := in.Marshal(envelope.ModeSealed)
		if err != nil {
			continue
		}
		e.Payload, e.Held, e.HeldExp = nil, j, in.Exp
		m.dirty = true
	}
}

// sealHeld seals p's held messages under its current epoch, once that is
// not demoted, each in its place in the outbox: the same inner id, a new
// ts (the durable ts window is 16 days; a hold can last up to B); one
// whose exp has passed is discarded.
func (m *Manager) sealHeld(p *Peer) {
	kr := m.sessions[p.ID]
	if kr == nil || kr.Current() == nil {
		return
	}
	now := m.now()
	for _, e := range m.st.Outbox {
		if e.Done || e.PeerID != p.ID || e.Held == nil {
			continue
		}
		if !e.HeldExp.IsZero() && !now.Before(e.HeldExp) {
			e.Done, e.Held = true, nil
			m.audit(now, "held_expired", p.ID) // S12
			m.dirty = true
			continue
		}
		in, err := envelope.ParseInner(e.Held, envelope.ModeSealed)
		if err != nil {
			// Unreadable: dropped and audited (§3.4.1 "After a demotion":
			// no held message goes silently).
			e.Done, e.Held = true, nil
			m.audit(now, "held_unsealable", p.ID)
			m.dirty = true
			continue
		}
		in.TS = now
		raw, err := m.sealFor(p, kr.Current(), in)
		if errors.Is(err, errDemoted) {
			return // still demoted: the rest wait too, in order
		}
		if err != nil {
			// It cannot be sealed at all (review M1): dropped, audited, so
			// that it does not hold the mailbox's queue for good.
			e.Done, e.Held = true, nil
			m.audit(now, "held_unsealable", p.ID) // drop.held_unsealable
			m.dirty = true
			continue
		}
		e.Payload, e.Held, e.HeldExp = raw, nil, time.Time{}
		e.RelayURL, e.Mailbox = p.Relay.URL, p.Relay.Mailbox
		m.dirty = true
	}
}

// reconnectFailed counts a failed try of a reconnect to p naming epoch
// named (§3.4.1 "The reconnect bound": a try fails only when its handshake
// expires unanswered; a refusal is silent and not counted): at the third
// for the same named epoch the connection goes stale (with
// connection.stale and its feed item). Every reconnect counts, whatever
// started it. Each expired one's tokens were revoked already.
func (m *Manager) reconnectFailed(p *Peer, named []byte, now time.Time) {
	if p.Kind != KindConnection {
		return
	}
	if p.RC == nil || !bytes.Equal(p.RC.Epoch, named) {
		p.RC = &ReconnectCount{Epoch: append([]byte(nil), named...)}
	}
	p.RC.Tries++
	m.dirty = true
	if p.RC.Tries >= ReconnectTries {
		m.markStale(p, now)
	}
}

// tickDemoted: while the current epoch is demoted and no handshake that
// would replace it is open (the last one expired, its tokens revoked), a
// new one is started (§3.4.1: Q sends nothing until a new epoch is
// established, so it keeps trying to establish one; one at a time, each
// bounded by the handshake lifetime).
func (m *Manager) tickDemoted(p *Peer, now time.Time) {
	if p.Kind != KindConnection || p.State != PeerActive || p.suspended() || p.Pending != nil ||
		m.hasOutgoing(p.ID, handshake.PurposeReconnect) || !m.currentDemoted(p) {
		return
	}
	if !m.canReconnect(p, now) {
		if noReconnectToken(p, now) {
			m.markStale(p, now) // no reconnect token left: no way back (review RR2-3)
		}
		return // until something changes (an answer settles): no-op
	}
	m.restartAfterDemotion(p, now)
}

// restartAfterDemotion: the current epoch was demoted (an old copy's):
// nothing more is sent in it, and a new epoch is made (a reconnect naming
// the newest epoch not demoted; a device: none can be made from it, so the
// device pairs again, as §6.7).
//
// 0.86.5 (vettid.org #548): the epoch named is the newest of P's that has
// been current here and is neither demoted nor destroyed (an abandoned
// pending epoch never was current); with none, the connection goes stale.
func (m *Manager) restartAfterDemotion(p *Peer, now time.Time) {
	if p.Kind != KindConnection {
		return
	}
	for i := len(p.Epochs) - 1; i >= 0; i-- {
		e := p.Epochs[i]
		if !e.Demoted && !e.Pending && !e.Abandoned && !e.Destroyed {
			m.reconnectNaming(p, e.ID, "demoted", now)
			return
		}
	}
	m.markStale(p, now)
}

// demotedMeta is the record of the epoch current in p's keyring if it is
// demoted, or nil (the keyring's current epoch, review RR2-1).
func (m *Manager) demotedMeta(p *Peer) *EpochMeta {
	kr := m.sessions[p.ID]
	if kr == nil || kr.Current() == nil {
		return nil
	}
	id := kr.Current().ID()
	if e := p.epochMeta(id[:]); e != nil && e.Demoted {
		return e
	}
	return nil
}

func (m *Manager) currentDemoted(p *Peer) bool { return m.demotedMeta(p) != nil }

// canReconnect reports whether a reconnect to p could start now: a valid
// reconnect token, no answer of ours to its reconnect awaiting hs.fin
// (between persons), its kem readable.
func (m *Manager) canReconnect(p *Peer, now time.Time) bool {
	if p.Kind != KindConnection || noReconnectToken(p, now) {
		return false
	}
	if !p.isService() && len(m.answeredReconnects(p)) > 0 {
		return false
	}
	_, err := suite.ParsePublicKey(p.KEM)
	return err == nil
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
			if pe.Purpose == handshake.PurposeReconnect {
				reconnect = true // its tokens were revoked: a reconnect brings fresh ones
			} else {
				rekey = true
			}
		}
	}
	for id, aw := range m.st.Awaiting {
		if aw.New == nil && aw.PeerID == p.ID && aw.Signer != nil && !bytes.Equal(aw.Signer, p.IK) &&
			(aw.Reconnect == nil || !aw.Reconnect.Fork) {
			m.abandonAwaiting(id, now)
		}
	}
	if m.noLinkRestart {
		return // the caller's own handshake establishes the next epoch
	}
	switch {
	case reconnect:
		m.startReconnect(p, now)
	case rekey:
		m.startRekey(p, now)
	}
}

// forkEpoch is §3.4.1 "Fork by ctx" for a rekey or reconnect from P whose
// ctx names epoch ctx: the current or confirmed epoch is ordinary; one
// older than the confirmed epoch, where an epoch after it up to the
// confirmed one has an ancestor of P's ik as its signer, is fork
// evidence. There is no exception for an epoch the vault began.
//
// The ancestors are those of the ik the message reaches (Table B,
// reached included): the stored chain's and the old_ik of every link the
// message carries that Q has not yet followed (reached, from reachedLinks).
func (p *Peer) forkEpoch(ctx []byte, reached []*handshake.Rotation) bool {
	if bytes.Equal(ctx, p.LastEpochID) || bytes.Equal(ctx, p.confirmedID()) {
		return false
	}
	ic, ik := p.epochIndex(ctx), p.epochIndex(p.confirmedID())
	if ic < 0 || ik <= ic {
		return false
	}
	for _, e := range p.Epochs[ic+1 : ik+1] {
		if p.ancestor(e.Signer) {
			return true
		}
		for _, r := range reached {
			if bytes.Equal(r.OldIK, e.Signer) {
				return true
			}
		}
	}
	return false
}

// reachedLinks returns the links of rots (a handshake's rotations) that
// the vault has not yet followed, when the chain resolves from p's stored
// ik (Table B "reached"); nil otherwise.
func (p *Peer) reachedLinks(rots []*handshake.Rotation) []*handshake.Rotation {
	if len(rots) == 0 {
		return nil
	}
	_, _, n, err := handshake.ResolveChainKnown(p.IK, parseRotations(p.Chain), rots)
	if err != nil {
		return nil
	}
	return rots[n:]
}

// rekeyOtherEpoch judges a rekey hs.init under an epoch that is neither
// current nor the confirmed one, once the hs.init has passed
// rekeyPrecheck: fork evidence (§3.4.1 "Fork by ctx") suspends. The
// hs.init is not answered either way.
func (m *Manager) rekeyOtherEpoch(p *Peer, ep *handshake.Epoch, rots []*handshake.Rotation, now time.Time) {
	if p.Kind != KindConnection {
		return
	}
	id := ep.ID()
	if p.forkEpoch(id[:], p.reachedLinks(rots)) {
		m.suspendForkRef(p, "epoch", now)
	}
}

// rekeyPrecheck applies, before anything is changed, every check of a
// rekey hs.init that does not depend on the outcome (what AcceptRekey and
// the responder's initiator check would refuse): it parses, is a rekey,
// names the epoch it travels under, is within the durable ts window,
// comes from the relay key on record (= from.relay.pk), and its from.ik
// is the stored ik or reached through the links it carries.
func (m *Manager) rekeyPrecheck(p *Peer, in *envelope.Inner, ep *handshake.Epoch, sender []byte, now time.Time) error {
	body, err := handshake.ParseInit(in.Body)
	if err != nil {
		return err
	}
	if body.Purpose != handshake.PurposeRekey || body.Ctx != handshake.EpochCtx(ep.ID()) {
		return handshake.ErrCtx
	}
	if err := in.CheckTime(now, true); err != nil {
		return err
	}
	if !bytes.Equal(sender, p.Relay.PK) || !bytes.Equal(sender, body.From.Relay.PK) {
		return handshake.ErrSender
	}
	if len(body.Rotations) == 0 {
		if !bytes.Equal(body.From.IK, p.IK) {
			return handshake.ErrIdentity
		}
		return nil
	}
	final, _, _, err := handshake.ResolveChainKnown(p.IK, parseRotations(p.Chain), body.Rotations)
	if err != nil || !bytes.Equal(final, body.From.IK) {
		return handshake.ErrIdentity
	}
	return nil
}

// --- the rotating side ---

// identityRotateBody is identity.rotate to p (S8, 0.86.0): `rotation`, the
// newest link, and `rotations`, the whole chain since the signer of the
// epoch it travels in.
func (m *Manager) identityRotateBody(p *Peer) []byte {
	links := m.ownRotationsSince(p.OwnChainAtEpoch)
	if len(links) == 0 { // 0ee0078 core.go:744: `rotation` only
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
// after identity.rotate); its answers awaiting hs.fin are dropped (their
// epochs would be signed by the superseded ik).
func (m *Manager) s5(p *Peer, now time.Time) (reconnect bool) {
	for id, og := range m.st.Outgoing {
		if og.New != nil || og.PeerID != p.ID || og.Replaced {
			continue
		}
		reconnect = reconnect || og.Purpose == handshake.PurposeReconnect
		m.abandonOutgoing(id, now)
	}
	if pe := p.Pending; pe != nil {
		reconnect = reconnect || pe.Purpose == handshake.PurposeReconnect
		m.abandonPending(p, "s5", false, now)
	}
	for id, aw := range m.st.Awaiting {
		if aw.New == nil && aw.PeerID == p.ID {
			m.abandonAwaiting(id, now)
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
