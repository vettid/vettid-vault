package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
		// 0ee0078 core.go:573-599: `rotation` only, rule C against followed
		// links, followed only from the stored ik, else bad_rotation.
		r := links[len(links)-1]
		if m.rotationConflict(s.peer, r, s.now) || s.peer.suspended() {
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

// evidenceFirst is acceptFrom step 3 (§3.4.1): every identity link a
// message carries is checked by rule C before anything refuses it (a
// demoted or destroyed epoch, Table B), so that a second successor is
// recorded whatever epoch it travels under. It reports whether the
// connection is (now) suspended by a conflict.
func (m *Manager) evidenceFirst(p *Peer, in *envelope.Inner, now time.Time) bool {
	if p.Kind != KindConnection || m.emu28() {
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
	p.upgradeEpochs()
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
		if e := p.epochMeta(pe.ID); e != nil && p.ancestor(e.Signer) {
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
			// S8 (0.86.6): a demotion by position is audited as a fork
			// sign (ref epoch), without a feed item or a suspension.
			m.record(Activity{Kind: "connection.fork_suspected", ConnectionID: connID(p), DeviceID: devID(p), Ref: "epoch", Audit: true}, now)
			if p.Revert != nil && bytes.Equal(p.Revert.New, e.ID) {
				m.keepToHeld(p, false, now) // S1
			}
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
		if kr != nil {
			m.rehold(p, kr.Current())
		}
		if r := p.Revert; r != nil && bytes.Equal(r.Old, msgEpoch) && kr != nil && kr.Reinstate(epochIDOf(msgEpoch), now) {
			// The epoch it traveled under is current again (it was kept
			// whole, §6.3.1 "Deployment"); the copies of what was sent
			// under the demoted one are sealed in it (S1).
			oldChain := r.OldOwnChain
			m.keepToHeld(p, true, now)
			p.LastEpochID, p.OwnChainAtEpoch = append([]byte(nil), msgEpoch...), oldChain
			if e := p.epochMeta(msgEpoch); e != nil {
				e.Superseded = time.Time{}
			}
			m.sealHeld(p)
		} else if r != nil && bytes.Equal(r.New, cur.ID) {
			m.keepToHeld(p, false, now) // S1: held for the next epoch
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
	if h := p.HoldFor; h != nil {
		if id := kr.Current().ID(); bytes.Equal(h.Epoch, id[:]) {
			return // S4: until something arrives under it
		}
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
			e.Done, e.Held = true, nil
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
			m.note(now, "held_unsealable", p.ID)
			m.dirty = true
			continue
		}
		m.keepCopy(p, in, e.Wake)
		e.Payload, e.Held, e.HeldExp = raw, nil, time.Time{}
		e.RelayURL, e.Mailbox = p.Relay.URL, p.Relay.Mailbox
		m.dirty = true
	}
}

// demotedReconnectExpired counts an expired reconnect while p's current
// epoch is demoted: at the third the connection goes stale (with
// connection.stale and its feed item), as for rules E and L (the lead's
// call). Each expired one's tokens were revoked already.
//
// 0.86.5: a try fails when its handshake expires or its pending epoch is
// abandoned (B, H5, S5, crossing, link); both count. A refusal ends it
// stale at once (handleResp). Three tries stay within the reconnect
// token's quota (4 deposits).
func (m *Manager) demotedReconnectExpired(p *Peer, now time.Time) {
	e := m.demotedMeta(p)
	if e == nil {
		return
	}
	e.RCTries++
	m.dirty = true
	if e.RCTries >= RuleRCTries {
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
		if p.Reconnect.Token == "" || !now.Before(p.Reconnect.Exp) {
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
// demoted, or nil. The keyring's current epoch, not LastEpochID: the
// own_copy branch without rk takes the named epoch as the last by id
// while the demoted one stays current in the keyring (review RR2-1).
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
	if p.Kind != KindConnection || p.Reconnect.Token == "" || !now.Before(p.Reconnect.Exp) {
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
			m.keepDroppedAnswer(p, aw, now)
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
	after, got := false, false
	for i := range p.Epochs {
		e := &p.Epochs[i]
		if after {
			got = got || e.GotFromPeer // demoted already (F1) or not
		}
		if after && !e.Demoted {
			e.Demoted, e.DemotedAt, e.DemotedMsg, e.OwnCopy = true, time.Time{}, "", true
		}
		after = after || bytes.Equal(e.ID, ctx)
	}
	if got && OwnCopyGotFromPeerSuspends {
		// S13 option (a): P sent a message under an epoch the exception
		// would demote, so "P never activated it" does not hold: this is
		// the fork rule's outcome (§3.4.1 "Epochs after an ik link", ref
		// epoch): suspended, with its paused-connection feed item.
		m.suspendForkRef(p, "epoch", now)
		return
	}
	if p.Pending != nil {
		m.abandonPending(p, "own_copy", false, now)
	}
	if r := p.Revert; r != nil {
		if e := p.epochMeta(r.New); e != nil && e.Demoted {
			m.keepToHeld(p, false, now) // S1
		}
	}
	if kr := m.sessions[p.ID]; kr != nil && m.currentDemoted(p) {
		m.rehold(p, kr.Current()) // its undeposited entries wait for the next epoch (review RR2 L4)
	}
	m.record(Activity{Kind: "connection.fork_suspected", ConnectionID: connID(p), DeviceID: devID(p), Ref: "own_copy", Audit: true}, now)
	m.dirty = true
}

// rekeyOtherEpoch decides a rekey hs.init under an epoch that is neither
// current nor the confirmed one, once the hs.init has passed
// rekeyPrecheck: fork evidence suspends; the own_copy exception (0.86.3
// "When the exception applies") answers it only if that epoch still has
// its rk (then the later epochs are demoted, the audit made, and the
// epoch current again); otherwise the later epochs are demoted, the epoch
// is taken as the last by id, the audit made, and the vault reconnects
// naming it; the hs.init is then acked and dropped unanswered. answer
// says whether to answer it; handled whether this rule dealt with it
// (rule L then does not apply).
func (m *Manager) rekeyOtherEpoch(p *Peer, in *envelope.Inner, ep *handshake.Epoch, now time.Time) (answer, handled bool) {
	if p.Kind != KindConnection {
		return false, false
	}
	id := ep.ID()
	fork, own := p.forkEpoch(id[:])
	if fork {
		m.suspendForkRef(p, "epoch", now)
		return false, true
	}
	if !own {
		return false, false
	}
	// 0.86.6 S2: the vault always takes the named epoch as its last, by id,
	// and reconnects naming it; the rekey is acked and dropped unanswered.
	// (A branch answering it when the epoch still had its rk was removed:
	// unreachable, since anything received under a later epoch both
	// confirms it and ends the revert keep that held that rk.)
	m.acceptOwnCopy(p, id[:], now)
	if p.suspended() {
		return false, true // S13 (a)
	}
	p.LastEpochID = append([]byte(nil), id[:]...)
	m.reconnectNaming(p, id[:], "own_copy", now)
	return false, true
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

// OwnCopyGotFromPeerSuspends switches S13 option (a), for the owner's
// decision: when an epoch the own_copy exception would demote had a
// message from P under it (EpochMeta.GotFromPeer), the connection is
// suspended with fork_suspected (ref epoch) and its feed item instead.
// false: the exception as before (audit and History line only).
const OwnCopyGotFromPeerSuspends = true

// --- the rotating side ---

// identityRotateBody is identity.rotate to p (S8, 0.86.0): `rotation`, the
// newest link, and `rotations`, the whole chain since the signer of the
// epoch it travels in.
func (m *Manager) identityRotateBody(p *Peer) []byte {
	links := m.ownRotationsSince(p.OwnChainAtEpoch)
	if len(links) == 0 || m.emu28() { // 0ee0078 core.go:744: `rotation` only
		return nil
	}
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
	if m.emu28() {
		return false // release 28: only its rekeys are replaced (rotateIdentity's dropRekey)
	}
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
		// Toward a peer that advertised hs_confirm when its hs.init was
		// answered (0.86.6 S11), the answer is dropped.
		if aw.New == nil && aw.PeerID == p.ID && aw.Gated {
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
