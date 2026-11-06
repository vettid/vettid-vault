package vault

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// Activation on confirmation (VAULT-MESSAGING 0.86.0, §6.3.1, owner
// decision R1 of 2026-11-05), for purposes rekey and reconnect.
//
// The responder half applies toward every peer: R activates at a verified
// hs.fin and queues hs.confirm in the same write; its confirmed epoch (the
// newest in which the peer sent anything but hs.fin) keeps its rk and
// receive keys while not current, a rekey or reconnect naming it is
// accepted as if current, and at such a handshake's hs.fin rule E destroys
// the epochs after it. The initiator half (a pending epoch that becomes
// current only when a message from the peer opens under it, and the bound
// B) applies only toward a peer that advertised hs_confirm when the
// hs.init was sent. Toward the others the initiator activates at hs.fin
// as before but keeps the old epoch and copies of what it sends, and
// reverts if the peer shows it never activated (the "Deployment" text).
//
// Every change below is made in memory within one batch; the batch's one
// state write stores it with the outbox entries it queued (queue: nothing
// leaves before that write), so each step and its effects land together.

// Lifetimes (§6.3.1 "Lifetimes"; T is the relay TTL, 14 days).
const (
	// PendingLife is B: an initiator's pending epoch awaiting
	// confirmation, from hs.fin (L + T + 2 days), judged only after the
	// first collect after an unlock that returned fewer than max messages.
	PendingLife = 32 * 24 * time.Hour
	// ConfirmedKeysFor is how long a responder's confirmed epoch keeps its
	// keys while not current, from the first activation that superseded
	// it.
	ConfirmedKeysFor = 48 * 24 * time.Hour
	// RevertAfter is T + 2 days: an old-epoch message whose inner ts is
	// later than hs.fin by more than this shows the peer never activated.
	RevertAfter = 16 * 24 * time.Hour
)

// --- positions and epoch records ---

// posAfter reports whether position (at, id) is after (at2, id2): later
// deposited_at, or the same with a later msg_id (§3.4.1 "Cut-off"; the
// vault has one mailbox, so msg_id order is the relay's order). A shorter
// msg_id sorts first, so that counters compare as numbers.
func posAfter(at time.Time, id string, at2 time.Time, id2 string) bool {
	if !at.Equal(at2) {
		return at.After(at2)
	}
	if len(id) != len(id2) {
		return len(id) > len(id2)
	}
	return id > id2
}

func (p *Peer) epochMeta(id []byte) *EpochMeta {
	for i := range p.Epochs {
		if bytes.Equal(p.Epochs[i].ID, id) {
			return &p.Epochs[i]
		}
	}
	return nil
}

func (p *Peer) epochIndex(id []byte) int {
	for i := range p.Epochs {
		if bytes.Equal(p.Epochs[i].ID, id) {
			return i
		}
	}
	return -1
}

// confirmedID is the confirmed epoch: before 0.86.0 recorded one, the
// current epoch.
func (p *Peer) confirmedID() []byte {
	if p.Confirmed != nil {
		return p.Confirmed
	}
	return p.LastEpochID
}

// upgradeEpochs gives a record from before 0.86.0 its epoch record: the
// current epoch, signed by the ik current for the peer at the upgrade
// (§3.4.1), and confirmed.
func (p *Peer) upgradeEpochs() {
	if len(p.Epochs) > 0 || len(p.LastEpochID) == 0 {
		return
	}
	p.Epochs = []EpochMeta{{ID: append([]byte(nil), p.LastEpochID...), Signer: append([]byte(nil), p.IK...)}}
	if p.Confirmed == nil {
		p.Confirmed = append([]byte(nil), p.LastEpochID...)
	}
}

// newer reports whether epoch a was recorded after epoch b (b unknown or
// nil: whether a is recorded at all). Pending and destroyed epochs are not
// newer than anything.
func (p *Peer) newer(a, b []byte) bool {
	ia, ib := p.epochIndex(a), p.epochIndex(b)
	if ia < 0 || p.Epochs[ia].Pending || p.Epochs[ia].Abandoned || p.Epochs[ia].Destroyed {
		return false
	}
	return ia > ib
}

// actOpts says how activate installs an epoch and what it records.
type actOpts struct {
	how         int // actNormal, actKeepRK, actInstalled
	until       time.Time
	signer      []byte // the peer's ik that signed it; nil: the stored ik
	mine        bool   // the vault began it
	unconfirmed bool   // activated at hs.fin without confirmation
	ownChain    int    // set by activate
}

const (
	actNormal    = iota
	actKeepRK    // the previous epoch is the confirmed one: it keeps its rk (§6.3.1)
	actInstalled // already current (a confirmed pending epoch)
)

// recordActivated records the epoch id as current: the previous current
// epoch is superseded now.
func (m *Manager) recordActivated(p *Peer, id []byte, o actOpts, now time.Time) {
	for i := range p.Epochs {
		e := &p.Epochs[i]
		if e.Superseded.IsZero() && !e.Pending && !bytes.Equal(e.ID, id) {
			e.Superseded = now
		}
	}
	if e := p.epochMeta(id); e != nil {
		e.Pending, e.Superseded = false, time.Time{}
		return
	}
	signer := o.signer
	if signer == nil {
		signer = p.IK
	}
	p.Epochs = append(p.Epochs, EpochMeta{ID: append([]byte(nil), id...), Signer: append([]byte(nil), signer...),
		Mine: o.mine, Unconfirmed: o.unconfirmed, EstAt: m.relayAt, EstMsg: m.msgID, OwnChain: o.ownChain})
	if p.Confirmed == nil {
		p.Confirmed = append([]byte(nil), id...) // a new peer's first epoch
	}
}

// setConfirmed moves the confirmed epoch to id if id is newer (it never
// moves back). The epoch it leaves, if not current, keeps its keys 16
// days from now, as any previous epoch's (§6.3.1 table).
func (m *Manager) setConfirmed(p *Peer, id []byte, now time.Time) {
	old := p.confirmedID()
	if len(p.LastEpochID) == 0 || bytes.Equal(old, id) || (old != nil && !p.newer(id, old)) {
		return // a record without its epoch's id (built by hand) has nothing to confirm
	}
	p.Confirmed = append([]byte(nil), id...)
	p.Abandoned = nil // a newer epoch is confirmed (§6.3.1 "Initiator")
	m.dirty = true
	if old != nil && !bytes.Equal(old, p.LastEpochID) {
		if kr := m.sessions[p.ID]; kr != nil {
			kr.Release(epochIDOf(old), now.Add(handshake.ReceiveKeyRetention))
		}
	}
}

// pruneEpochs drops the records nothing needs any more: superseded more
// than ConfirmedKeysFor + 16 days ago and neither current, confirmed,
// pending nor abandoned-but-accepted. Time only, no count cap.
func (m *Manager) pruneEpochs(p *Peer, now time.Time) {
	keep := p.Epochs[:0]
	for _, e := range p.Epochs {
		needed := e.Superseded.IsZero() || e.Pending || bytes.Equal(e.ID, p.Confirmed) || bytes.Equal(e.ID, p.LastEpochID) ||
			now.Sub(e.Superseded) < ConfirmedKeysFor+handshake.ReceiveKeyRetention
		for _, a := range p.Abandoned {
			needed = needed || bytes.Equal(a, e.ID)
		}
		if needed {
			keep = append(keep, e)
		}
	}
	for i := len(keep); i < len(p.Epochs); i++ {
		p.Epochs[i] = EpochMeta{}
	}
	p.Epochs = keep
}

// --- the initiator half ---

// gateFor reports whether the initiator half applies to a handshake begun
// now with p: p advertised hs_confirm (§6.3.1 "Deployment"; fixed when the
// hs.init is sent).
func gateFor(p *Peer) bool { return p.hasConfirm() }

// makePending records the vault's own verified rekey or reconnect epoch as
// pending (§6.3.1 "Initiator"): established, its signer recorded, not
// current. The caller has queued hs.fin.
func (m *Manager) makePending(p *Peer, og *OutgoingHS, res *handshake.Result, now time.Time) {
	kr := m.sessions[p.ID]
	if kr == nil {
		kr = &handshake.Keyring{}
		m.sessions[p.ID] = kr
	}
	if p.Pending != nil {
		m.abandonPending(p, "replaced", false, now)
	}
	kr.SetPending(res.Epoch, now)
	id := res.Epoch.ID()
	p.Pending = &PendingEpoch{ID: id[:], Purpose: og.Purpose, FinAt: now, RespTS: res.Inner.TS, Issued: og.Issued,
		OwnChain: chainOr(og.OwnChain, len(m.st.Rotations)), SigIK: append([]byte(nil), m.keys.ik.Public().(ed25519.PublicKey)...)}
	p.Epochs = append(p.Epochs, EpochMeta{ID: id[:], Signer: append([]byte(nil), res.ResponderIK...), Mine: true, Pending: true,
		EstAt: m.relayAt, EstMsg: m.msgID, OwnChain: p.Pending.OwnChain})
	m.dirty = true
}

// confirmPending makes p's pending epoch current: a message from the peer
// opened under it and passed acceptFrom steps 1-4. It takes effect before
// anything else is done with the message.
func (m *Manager) confirmPending(p *Peer, now time.Time) {
	pe := p.Pending
	kr := m.sessions[p.ID]
	if pe == nil || kr == nil {
		return
	}
	ep := kr.ConfirmPending(now)
	p.Pending = nil
	if ep == nil {
		return
	}
	m.activate(p, ep, pe.Purpose, pe.Issued, "", pe.OwnChain, actOpts{how: actInstalled, mine: true}, now)
	m.setConfirmed(p, pe.ID, now)
	m.dirty = true
}

// abandonPending abandons p's pending epoch (B passed, H5, S5, a crossing
// rekey, token_expired, the peer's own handshake activating): its receive
// keys are kept 16 days as a previous epoch's, and nothing under it
// confirms any more. Its id stays acceptable as a reconnect ctx until a
// newer epoch is confirmed. With restart, the vault reconnects naming its
// current epoch (a device: rekeys).
func (m *Manager) abandonPending(p *Peer, why string, restart bool, now time.Time) {
	pe := p.Pending
	if pe == nil {
		return
	}
	if kr := m.sessions[p.ID]; kr != nil {
		kr.AbandonPending(now)
	}
	if e := p.epochMeta(pe.ID); e != nil {
		e.Pending, e.Abandoned, e.Superseded = false, true, now
		if why == "link" {
			// 0.86.6 S3: abandoned by a link (old-copy suspicion): messages
			// under it are refused (ancestor_ik). Every other abandon keeps
			// its receive keys and processes authenticated messages under
			// it without confirming it.
			e.Demoted, e.DemotedAt, e.DemotedMsg = true, time.Time{}, ""
		}
	}
	for _, t := range pe.Issued {
		// The tokens its hs.init carried (a reconnect's standing and
		// reconnect tokens) are revoked in this write, as an abandoned
		// handshake's are (§6.6): otherwise the peer, or an old copy of it
		// holding its relay key and kem, could still deposit with them. A
		// peer that did activate the epoch gets fresh ones in the
		// reconnect that follows (B, token_expired, H5 and S5 restart a
		// reconnect for an abandoned reconnect).
		m.revokeIssued(t, p.ID, now)
	}
	p.Abandoned = append(p.Abandoned, append([]byte(nil), pe.ID...))
	p.Pending = nil
	m.note(now, "pending_abandoned_"+why, p.ID)
	m.dirty = true
	if pe.Purpose == handshake.PurposeReconnect && why == "b_passed" && m.currentDemoted(p) {
		// 0.86.6 S5: a try of the reconnect after a demotion fails at its
		// handshake's expiry or at B only (at the third: stale).
		m.demotedReconnectExpired(p, now)
	}
	if !restart || p.State != PeerActive || p.suspended() {
		return
	}
	switch {
	case p.Kind != KindConnection:
		m.startRekey(p, now)
	case m.currentDemoted(p):
		m.restartAfterDemotion(p, now) // never naming the demoted epoch
	default:
		m.startReconnect(p, now)
	}
}

// tickPending applies B (§6.3.1): judged only once a collect since this
// unlock returned fewer than max messages.
func (m *Manager) tickPending(p *Peer, now time.Time) {
	if pe := p.Pending; pe != nil && m.drainedOnce && now.Sub(pe.FinAt) > PendingLife {
		m.abandonPending(p, "b_passed", true, now)
	}
}

// --- the responder half ---

// queueConfirm queues hs.confirm to p under its current epoch (body {},
// durable, not a request).
func (m *Manager) queueConfirm(p *Peer, now time.Time) {
	kr := m.sessions[p.ID]
	if kr == nil || kr.Current() == nil || p.suspended() {
		return
	}
	in := &envelope.Inner{ID: m.newID(now), Type: handshake.TypeConfirm, TS: now, Body: []byte(`{}`)}
	raw, err := m.sealFor(p, kr.Current(), in)
	if err != nil {
		return
	}
	m.queueDeposit(&OutboxEntry{PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Payload: raw, Confirm: true}, now)
}

// confirmQueued reports whether an hs.confirm to p is still in the outbox.
func (m *Manager) confirmQueued(p *Peer) bool {
	for _, e := range m.st.Outbox {
		if e.PeerID == p.ID && e.Confirm && !e.Done {
			return true
		}
	}
	return false
}

// reconfirmAll queues hs.confirm again for each peer the batch marked.
func (m *Manager) reconfirmAll(now time.Time) {
	for id := range m.reconfirm {
		if p := m.peer(id); p != nil && p.State == PeerActive && !m.confirmQueued(p) {
			m.queueConfirm(p, now)
		}
	}
	m.reconfirm = nil
}

// ruleE destroys every epoch with p later than the confirmed one (§6.3.1
// rule E), in the write that establishes an epoch at the verified hs.fin
// of a handshake that named the confirmed epoch, recording the accepted
// hs.init's inner ts. An hs.fin of the vault's own for a destroyed epoch
// not yet sent is dropped with its outbox entry. Their receive keys are
// kept as a previous epoch's, so that a later message under one is still
// authenticated (fork evidence or a refusal).
func (m *Manager) ruleE(p *Peer, initTS time.Time, gated bool, now time.Time) {
	ci := p.epochIndex(p.confirmedID())
	if ci < 0 {
		return
	}
	kr := m.sessions[p.ID]
	for i := ci + 1; i < len(p.Epochs); i++ {
		e := &p.Epochs[i]
		if e.Destroyed || e.Pending {
			continue
		}
		e.Destroyed, e.DestroyTS, e.GatedAtE = true, initTS, gated
		if e.Superseded.IsZero() {
			e.Superseded = now
		}
		if kr != nil && !bytes.Equal(e.ID, p.LastEpochID) {
			kr.Release(epochIDOf(e.ID), now.Add(handshake.ReceiveKeyRetention))
		}
		for _, o := range m.st.Outbox {
			if !o.Done && o.PeerID == p.ID && bytes.Equal(o.FinEpoch, e.ID) {
				o.Done = true // its hs.fin, not yet sent, is dropped (rule E)
			}
		}
		m.note(now, "epoch_destroyed", p.ID)
	}
	m.dirty = true
}

// responderActivation is how a responder installs an epoch established at
// a verified hs.fin: the confirmed epoch, if it is the current one, keeps
// its rk and receive keys while not current, up to 48 days from now (the
// first activation that superseded it).
func (m *Manager) responderActivation(p *Peer, signer []byte, now time.Time) actOpts {
	o := actOpts{how: actNormal, signer: signer}
	if len(p.LastEpochID) > 0 && bytes.Equal(p.confirmedID(), p.LastEpochID) {
		o.how, o.until = actKeepRK, now.Add(ConfirmedKeysFor)
	}
	return o
}

// --- receiving: before a session message is accepted ---

// beforeAccept applies §6.3.1 to a session-mode message from p that opened
// under ep, before anything else is done with it: a destroyed or demoted
// epoch's refusals (and rule E's evidence), the confirmation of a pending epoch and the confirmed epoch's
// bookkeeping. It reports whether the message was dealt with (acked and
// dropped) here.
func (m *Manager) beforeAccept(p *Peer, ep *handshake.Epoch, in *envelope.Inner, now time.Time) bool {
	if p.suspended() || ep == nil {
		return false
	}
	p.upgradeEpochs()
	id := ep.ID()
	meta := p.epochMeta(id[:])
	if meta != nil && meta.Destroyed {
		m.destroyedEpochMessage(p, meta, in, now)
		return true
	}
	if meta != nil && meta.Demoted && posAfter(m.relayAt, m.msgID, meta.DemotedAt, meta.DemotedMsg) {
		// §3.4.1 "Epochs after an ik link": deposited after the link.
		m.refusePeerKey(p, "ancestor_ik", meta.OwnCopy, now)
		return true
	}
	fin := in.Type == handshake.TypeFin
	if meta != nil && !meta.GotFromPeer && !strings.HasPrefix(in.Type, "hs.") {
		meta.GotFromPeer = true // S13 (a): written with this batch
		m.dirty = true
	}
	if h := p.HoldFor; h != nil && !fin {
		switch {
		case bytes.Equal(h.Epoch, id[:]):
			p.HoldFor = nil // the peer activated it: the held messages go
			m.sealHeld(p)
		case bytes.Equal(h.Named, id[:]) && in.TS.Sub(h.FinAt) > RevertAfter:
			// It never activated it: the new epoch is destroyed (as a
			// revert's), and the vault is demoted again (a new try).
			if e := p.epochMeta(h.Epoch); e != nil {
				e.Destroyed, e.DestroyTS, e.Demoted = true, in.TS, true
			}
			p.HoldFor = nil
		}
	}
	if pe := p.Pending; pe != nil && !fin && bytes.Equal(pe.ID, id[:]) {
		m.confirmPending(p, now)
	}
	if !fin {
		m.setConfirmed(p, id[:], now)
		if c := p.confirmedID(); len(p.LastEpochID) > 0 && !bytes.Equal(c, p.LastEpochID) && bytes.Equal(c, id[:]) {
			if m.reconfirm == nil {
				m.reconfirm = map[string]bool{}
			}
			m.reconfirm[p.ID] = true
		}
	}
	return false
}

// destroyedEpochMessage is an authenticated message under an epoch rule E
// destroyed: with a later inner ts it is fork evidence (ref epoch); toward
// a peer that has not advertised hs_confirm it is refused; an earlier ts
// is refused (superseded_epoch).
func (m *Manager) destroyedEpochMessage(p *Peer, meta *EpochMeta, in *envelope.Inner, now time.Time) {
	if !in.TS.After(meta.DestroyTS) {
		m.refusePeerKey(p, "superseded_epoch", false, now)
		return
	}
	if p.Kind != KindConnection {
		m.refusePeerKey(p, "superseded_epoch", false, now)
		return
	}
	if meta.GatedAtE {
		// The gate as judged at the hs.init of the handshake whose rule E
		// destroyed it (0.86.6 S11).
		m.suspendForkRef(p, "epoch", now)
		return
	}
	m.refusePeerKey(p, "superseded_epoch", false, now)
}

// refusePeerKey refuses a message under §3.4.1 (acked, dropped, audited
// drop.peer_key with the reason). noHistory: an ancestor_ik refusal under
// an epoch demoted with an own_copy audit, which shows no History line
// (O7a, 0.85.4): it is kept in the vault's own audit log only.
func (m *Manager) refusePeerKey(p *Peer, reason string, noHistory bool, now time.Time) {
	if noHistory {
		m.note(now, "peer_key_"+reason, p.ID)
		return
	}
	m.record(Activity{Kind: "drop.peer_key", ConnectionID: connID(p), DeviceID: devID(p), Ref: reason, Audit: true}, now)
}

func connID(p *Peer) string {
	if p.Kind == KindConnection {
		return p.ID
	}
	return ""
}

func devID(p *Peer) string {
	if p.Kind != KindConnection {
		return p.ID
	}
	return ""
}

// --- crossing and the rekey block (§6.5) ---

// answerAwaitingFin reports whether one of the vault's answers to p awaits
// hs.fin.
func (m *Manager) answerAwaitingFin(p *Peer) bool {
	for _, aw := range m.st.Awaiting {
		if aw.New == nil && aw.PeerID == p.ID {
			return true
		}
	}
	return false
}

// rekeyBlocked: a side starts no rekey with a peer while one of its
// answers to that peer awaits hs.fin or while its own new epoch awaits
// confirmation (§6.5, §6.3.1, S5).
func (m *Manager) rekeyBlocked(p *Peer) bool {
	return p.Pending != nil || m.answerAwaitingFin(p)
}

// crossingRekeyLoses applies the lower-th1 rule to a peer's rekey hs.init
// crossing the vault's own open handshakes with p (§6.5; 0.86.0: any two
// crossing handshakes, whatever their purposes). Against an own rekey with
// the lower th1 the peer's rekey loses (it is not answered, as before);
// an own handshake with the higher th1 is abandoned; an own reconnect with
// the lower th1 is kept and the rekey answered too (the answer is dropped
// when the reconnect completes, as between two reconnects of persons).
func (m *Manager) crossingRekeyLoses(p *Peer, theirs [32]byte, now time.Time) bool {
	for id, og := range m.st.Outgoing {
		if og.New != nil || og.PeerID != p.ID || og.Replaced || len(og.Th1) != 32 {
			continue
		}
		var ours [32]byte
		copy(ours[:], og.Th1)
		if handshake.SimultaneousRekeyWinner(ours, theirs) {
			if og.Purpose == handshake.PurposeRekey {
				return true
			}
			continue
		}
		m.note(now, "crossing_abandoned", p.ID)
		m.abandonOutgoing(id, now)
	}
	return false
}

// classifyCtx086 is what 0.86.0 adds to "Accepting ctx" (§6.6, §6.3.1):
// with the vault's own reconnect pending, only its pending epoch is
// accepted ("a side which has sent hs.fin for its own reconnect refuses
// its earlier epoch"); otherwise also its pending epoch, its confirmed
// epoch while not current (namedConf: rule E at hs.fin), and an abandoned
// pending epoch until a newer one is confirmed. An older epoch of the
// connection is judged by §3.4.1 F2: fork evidence (forkEp, judged at
// hs.fin) or the own_copy exception. named is nil when the classic rules
// (classifyCtx) decide.
func (m *Manager) classifyCtx086(p *Peer, ctx string) (named []byte, namedConf, ownCopy, forkEp, refuse bool) {
	p.upgradeEpochs()
	is := func(id []byte) bool { return len(id) == 16 && ctx == handshake.EpochCtx(epochIDOf(id)) }
	if pe := p.Pending; pe != nil && pe.Purpose == handshake.PurposeReconnect {
		if is(pe.ID) {
			return pe.ID, false, false, false, false
		}
		return nil, false, false, false, true
	}
	if is(p.LastEpochID) {
		return nil, false, false, false, false
	}
	if pe := p.Pending; pe != nil && is(pe.ID) {
		return pe.ID, false, false, false, false
	}
	if c := p.confirmedID(); is(c) {
		return c, true, false, false, false
	}
	for _, a := range p.Abandoned {
		if is(a) {
			return a, false, false, false, false
		}
	}
	for _, e := range p.Epochs {
		if !is(e.ID) || e.Destroyed || e.Pending {
			continue
		}
		fork, own := p.forkEpoch(e.ID)
		if fork || own {
			return e.ID, false, own, fork, false
		}
	}
	return nil, false, false, false, false
}

// pendingReconnectHold reports whether deposits to peer wait because the
// vault's own reconnect epoch with it is pending (§6.3.1).
func (m *Manager) pendingReconnectHold(peer string) bool {
	p := m.peer(peer)
	return p != nil && p.Pending != nil && p.Pending.Purpose == handshake.PurposeReconnect
}
