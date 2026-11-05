package trustmodel

import (
	"fmt"
	"slices"
)

// VAULT-MESSAGING 0.86.0 (draft) §6.3.1 at vettid.org 2da316e: lifetimes,
// activation on confirmation, the confirmed epoch, rule E, and the
// Deployment gate (responder half toward every peer, initiator half only
// toward peers that advertise hs_confirm, a reverting initiator toward
// the others). Config.OldRules turns all of it off (f4a4d97).

const (
	aHSLife   = 16 * day       // an initiator's handshake awaiting hs.resp
	aAnsLife  = 16 * day       // a responder's answer awaiting hs.fin (L)
	aPendLife = 32 * day       // an initiator's pending epoch awaiting confirmation (B)
	aConfKeys = 48 * day       // a confirmed epoch's keys while not current; the revert's keep
	aRevert   = msgTTL + 2*day // Deployment: an old-epoch message this long after hs.fin reverts (lead item 5)
)

// Release-29 options (§15 item 50); optFull is the whole draft (A).
const (
	optFull = iota
	optR1   // everything, gated
	optR2   // the responder half only
	optR3   // the responder half and the revert, no confirmation
)

var optName = [...]string{"A", "R1", "R2", "R3"}

func (w *World) hsLifeFor(reconnect bool) int64 {
	switch {
	case w.optA:
		return aHSLife // §6.6 "After a restore" (7 days) is not modelled
	case reconnect:
		return reconnectFail
	}
	return hsLife
}

func (w *World) answerLife() int64 {
	if w.optA {
		return aAnsLife
	}
	return ansLife
}

// newSpec: this party implements 0.86.0 (not release <= 28).
func (q *Party) newSpec() bool { return q.w.optA && !q.Rel28 }

// respHalf: the responder half applies toward every peer.
func (q *Party) respHalf() bool { return q.newSpec() }

// advertises hs_confirm (every implementation of the subsection).
func (p *Party) advertises() bool { return p.w.optA && !p.Rel28 }

// initHalf: the pending epoch and B, only toward a peer that advertises
// hs_confirm (and whose features this side has seen).
func (q *Party) initHalf(r *PeerRec) bool {
	if !q.newSpec() {
		return false
	}
	switch q.Opt {
	case optR2, optR3:
		return false
	case optR1:
		return r.PeerA
	}
	return !q.w.gate || r.PeerA
}

// revertRule: toward an ungated peer the initiator activates at hs.fin,
// keeps the old epoch and reverts (Deployment). R2 has no revert.
func (q *Party) revertRule(r *PeerRec) bool {
	if !q.newSpec() || q.initHalf(r) {
		return false
	}
	return q.Opt == optR1 || q.Opt == optR3 || (q.Opt == optFull && q.w.gate)
}

// makePending: the initiator, having verified sig_R, records the new epoch
// as pending (established, signer recorded, not current).
func (q *Party) makePending(r *PeerRec, id int, signer, own Key, pos Pos, respTs int64, reconnect bool) {
	if signer != r.IK {
		q.w.violate("I3", "%s establishes E%d signed by %d, not its current ik %d for %s", q.Name, id, signer, r.IK, q.w.party(r.ID).Name)
	}
	r.Epochs = append(r.Epochs, Epoch{ID: id, Signer: signer, Own: own, Est: pos, EstAt: q.w.Now, Pending: true, MineInit: true})
	r.Pend = &PendEp{ID: id, Signer: signer, Own: own, FinAt: q.w.Now, RespTs: respTs, Reconnect: reconnect}
	q.w.hasEpoch[[2]int{int(q.ID), id}] = true
	q.w.stat("A:pending")
	q.w.logf("%s: epoch E%d with %s PENDING (signer %d)", q.Name, id, q.w.party(r.ID).Name, signer)
}

// confirm: a message from the peer under the pending epoch.
func (q *Party) confirm(r *PeerRec) {
	pe := r.Pend
	for j := range r.Epochs {
		ep := &r.Epochs[j]
		if ep.ID == pe.ID {
			ep.Pending = false
		} else if ep.Superseded == 0 {
			ep.Superseded = q.w.Now
		}
	}
	r.Cur, r.Pend = pe.ID, nil
	r.setConf(pe.ID, q.w.Now) // activated at confirmation
	r.AbanIDs = nil
	q.w.stat("A:confirmed")
	q.w.logf("%s: epoch E%d with %s CONFIRMED (current)", q.Name, pe.ID, q.w.party(r.ID).Name)
}

// setConf: the confirmed epoch moves forward (never back); the one it
// leaves keeps its keys 16 days from now (F6).
func (r *PeerRec) setConf(id int, now int64) {
	if old := r.epoch(r.ConfID); old != nil && old.ID != id && old.ID != r.Cur {
		old.Superseded = now
	}
	r.ConfID, r.ConfUntil = id, 0
}

// abandonPending: H5, S5, crossing, token_expired, or B passed.
func (q *Party) abandonPending(r *PeerRec, why string, restart bool) {
	pe := r.Pend
	if pe == nil {
		return
	}
	for j := range r.Epochs {
		if ep := &r.Epochs[j]; ep.ID == pe.ID {
			ep.Pending, ep.Abandoned, ep.Superseded = false, true, q.w.Now
		}
	}
	r.Pend = nil
	r.AbanIDs = append(r.AbanIDs, pe.ID)
	q.w.stat("A:abandoned:" + why)
	q.w.logf("%s: pending E%d with %s ABANDONED (%s)", q.Name, pe.ID, q.w.party(r.ID).Name, why)
	if !restart || r.Status != stActive {
		return
	}
	valid := r.standing(r.KeyFor, r.Relay, q.w.Now).JTI != 0
	switch {
	case why == "B passed" && !r.Device:
		q.startHS(r, true) // §6.3.1: I reconnects naming its current epoch
	case why == "B passed" && !valid:
		q.markStale(r, "pair again (B passed)")
	default:
		q.startHS(r, !r.Device && !valid)
	}
}

// steps14: acceptFrom would not refuse the message at steps 1-4 (a pure check).
func (q *Party) steps14(r *PeerRec, m *RMsg, pos Pos) bool {
	M := m.P
	if r.Status != stActive || (M.Kind == KInit && m.Sender != M.FromRelay) {
		return false
	}
	rs := r.relayState(m.Sender, pos)
	if rs == rkForeign || q.conflictPure(r, M) {
		return false
	}
	if rs == rkAfter {
		switch M.Kind {
		case KUpdate, KTokIssued:
		case KIdRot:
			if !q.allFollowed(r, M.Rot) {
				return false
			}
		default:
			return false
		}
	}
	if ep := r.epoch(M.Epoch); ep != nil && (ep.Destroyed || (ep.Demoted && ep.DemotedAt.after(pos))) {
		return false
	}
	return true
}

// conflictPure: rule C would find a second successor (no side effects).
func (q *Party) conflictPure(r *PeerRec, M *Msg) bool {
	prior := append(slices.Clone(r.Chain), r.Seen...)
	for _, l := range M.Rot {
		if slices.Contains(r.Dropped, l) {
			continue
		}
		for _, f := range prior {
			if f.Old == l.Old && f.New != l.New && !slices.Contains(r.Dropped, f) {
				return true
			}
		}
	}
	_, bad := r.relayConflict(M.RLinks)
	return M.Kind == KUpdate && bad
}

// beforeAccept: confirmation bookkeeping when a message opens; it takes
// effect before anything else is done with the message.
func (q *Party) beforeAccept(r *PeerRec, m *RMsg, pos Pos) {
	M := m.P
	if !q.newSpec() || M.Epoch == 0 || !q.steps14(r, m, pos) {
		return
	}
	// Deployment: the reverting initiator toward an ungated peer
	if r.RevOld != 0 {
		switch {
		case M.Epoch == r.Cur:
			r.RevOld, r.RevSent = 0, nil // the peer activated: the old epoch goes as usual
		case M.Epoch == r.RevOld && M.Kind != KFin && M.Ts > r.RevFinAt+aRevert:
			q.revert(r, M.Kind == KInit) // a92a6eb: a rekey hs.init triggers it too; it is then answered
			return
		}
	}
	if r.Pend != nil && M.Epoch == r.Pend.ID && M.Kind != KFin && !q.w.noF5 { // noF5: see handle
		q.confirm(r)
	}
	if !q.respHalf() {
		return
	}
	// the confirmed epoch: the newest (activation order) the peer used, not hs.fin
	if M.Kind != KFin && M.Epoch != r.ConfID && r.newer(M.Epoch, r.ConfID) {
		r.setConf(M.Epoch, q.w.Now)
	}
	if r.ConfID != 0 && r.ConfID != r.Cur && M.Epoch == r.ConfID {
		r.Reconfirm = true
	}
}

// revert: the peer never activated the new epoch; it is destroyed, the old
// one is current again, and I rekeys from it. What I sent under it is lost.
func (q *Party) revert(r *PeerRec, rekeyIn bool) {
	gone := r.Cur
	if pr := q.w.party(r.ID).st.peer(q.ID); pr != nil && pr.epoch(gone) != nil && !pr.epoch(gone).Destroyed && !pr.epoch(gone).Demoted {
		q.w.violate("I1-false-revert", "%s reverted E%d although %s had activated it", q.Name, gone, q.w.party(r.ID).Name)
	}
	for j := range r.Epochs {
		if ep := &r.Epochs[j]; ep.ID == gone {
			ep.Destroyed, ep.DestroyTs = true, 1<<62
		}
	}
	q.w.reverted[gone] = true
	r.Cur, r.RevOld = r.RevOld, 0
	if ep := r.epoch(r.Cur); ep != nil {
		ep.Superseded = 0
	}
	q.w.stat("A:reverted")
	q.w.logf("%s: E%d with %s REVERTED to E%d (the peer never activated it); connection.epoch_reverted", q.Name, gone, q.w.party(r.ID).Name, r.Cur)
	for _, m := range r.RevSent { // lead item 5: re-sealed in the restored epoch, same inner id
		if q.w.noLead5 {
			break // switch: what was sent under the destroyed epoch is lost
		}
		q.w.stat("A:revert-resealed")
		c := cloneMsg(m)
		c.Ts = q.now() // same inner id, a new ts
		q.enqueueRaw(r.ID, c)
	}
	r.RevSent = nil
	q.abandonOwn(r)
	if !rekeyIn {
		q.startHS(r, false) // else the peer's rekey is answered
	}
}

// ruleE: at the verified hs.fin of a handshake that named the confirmed
// epoch: destroy every other epoch later than it, recording the hs.init's ts.
func (q *Party) ruleE(r *PeerRec, ts int64) {
	after := false
	for j := range r.Epochs {
		ep := &r.Epochs[j]
		if after && !ep.Destroyed && !ep.Pending {
			ep.Destroyed, ep.DestroyTs = true, ts
			q.w.stat("A:destroyed-later-epoch")
			if !q.w.ruleEKeepFin {
				// lead's fix (r7): an hs.fin for a destroyed epoch not yet
				// deposited is dropped with its outbox entry
				for i := range q.st.Out {
					if e := &q.st.Out[i]; e.To == r.ID && e.M.Kind == KFin && e.M.NewEpoch == ep.ID && !e.Done && !e.Ended {
						e.Ended = true
						q.w.stat("A:ruleE-unsent-fin-dropped")
					}
				}
			}
			q.w.logf("%s: E%d with %s DESTROYED by rule E (ts %d)", q.Name, ep.ID, q.w.party(r.ID).Name, ts)
		}
		after = after || ep.ID == r.ConfID
	}
}

// reconfirm: once per batch holding a message under the confirmed epoch,
// unless an hs.confirm to the peer is still in the outbox.
func (q *Party) reconfirm() {
	for i := range q.st.Peers {
		r := &q.st.Peers[i]
		r.IdResendBatch = false
		if !r.Reconfirm {
			continue
		}
		r.Reconfirm = false
		queued := slices.ContainsFunc(q.st.Out, func(e Entry) bool {
			return e.To == r.ID && e.M.Kind == KConfirm && !e.Done && !e.Ended
		})
		if r.Cur != 0 && !q.OldConfirm && (!queued || q.w.noF10) { // noF10: no cap
			q.w.stat("A:hs.confirm-again")
			q.enqueue(r.ID, Msg{Kind: KConfirm, Epoch: r.Cur}, nil)
		}
	}
}

// tickA: §6.3.1 timers.
func (p *Party) tickA(r *PeerRec) {
	w := p.w
	if pe := r.Pend; pe != nil && w.Now-pe.FinAt > aPendLife && (p.collectedSinceUnlock || w.noF13B) {
		p.abandonPending(r, "B passed", true)
	}
	if r.RevOld != 0 && w.Now > r.RevUntil {
		r.RevOld = 0
	}
	// keys end; ids stay (G): the confirmed epoch's and abandoned ones'
	for j := range r.Epochs {
		ep := &r.Epochs[j]
		keep := ep.ID == r.ConfID || slices.Contains(r.AbanIDs, ep.ID)
		if !keep || ep.ID == r.Cur || ep.KeysGone {
			continue
		}
		if ep.ID == r.ConfID {
			if r.ConfUntil == 0 && ep.Superseded != 0 {
				r.ConfUntil = ep.Superseded + aConfKeys // from the first activation that superseded it
			}
			if r.ConfUntil != 0 && w.Now > r.ConfUntil {
				ep.KeysGone = true
			}
		} else if ep.Superseded != 0 && w.Now-ep.Superseded > 16*day {
			ep.KeysGone = true
		}
	}
}

// newer: epoch a was recorded after epoch b (b == 0: any).
func (r *PeerRec) newer(a, b int) bool {
	ia, ib := -1, -1
	for i, e := range r.Epochs {
		if e.ID == a && !e.Pending && !e.Abandoned && !e.Destroyed {
			ia = i
		}
		if e.ID == b {
			ib = i
		}
	}
	return ia >= 0 && ia > ib
}

// idResend: S5 resend. A session message from Q under an epoch whose
// P-side signer is an ancestor of P's ik, inner ts more than 1 h after
// P's rotation; at most 3 per peer per rotation, once an hour.
func (p *Party) idResend(r *PeerRec, m *RMsg) {
	ep := r.epoch(m.P.Epoch)
	if ep == nil || ep.Own == p.st.IK || p.ownLinks(ep.Own) == nil || m.P.Ts <= p.st.LastRot+hour {
		return
	}
	if r.IdResendRot != p.st.LastRot {
		r.IdResendRot, r.IdResendN = p.st.LastRot, 0
	}
	if r.IdResendBatch || p.w.Now-r.IdResend < hour || r.IdResendN >= 3 {
		return
	}
	r.IdResend, r.IdResendBatch = p.w.Now, true
	r.IdResendN++
	p.w.stat("A:identity.rotate-resent")
	p.enqueue(r.ID, Msg{Kind: KIdRot, Rot: p.ownLinks(ep.Own)}, nil)
}

// markStale: the record goes stale. Ground truth for I1-stale-split: at the
// moment a pair first goes stale, did the two sides' current epochs differ
// (or did one side hold an epoch the other never held)?
func (q *Party) markStale(r *PeerRec, ref string) {
	r.Status, r.Ref = stStale, ref
	w := q.w
	if q.Copy {
		return
	}
	key := [2]PID{min(q.ID, r.ID), max(q.ID, r.ID)}
	if _, seen := w.staleAt[key]; seen {
		return
	}
	pr := w.party(r.ID).st.peer(q.ID)
	cause := ""
	if pr != nil {
		if !consistent(r, pr, q.respHalf(), w.party(r.ID).respHalf()) {
			cause = fmt.Sprintf("%s, epochs differ (%s on E%d, %s on E%d)", ref, q.Name, r.Cur, w.party(r.ID).Name, pr.Cur)
			if c := w.lostLabel(q.ID, r.ID); c != "" {
				cause += "; lost handshake message: " + c
			}
		}
	}
	w.staleAt[key] = cause
}

// consistent: the two records can still talk: the same current epoch, or
// one side's current is the other's pending epoch, its confirmed epoch,
// or the old epoch it keeps for a revert.
func consistent(a, b *PeerRec, aNew, bNew bool) bool {
	ok := func(x, y *PeerRec, yNew bool) bool { // y can take x's current epoch
		return x.Cur == y.Cur || (y.Pend != nil && y.Pend.ID == x.Cur) || (yNew && y.ConfID == x.Cur && x.Cur != 0) ||
			(y.RevOld != 0 && y.RevOld == x.Cur)
	}
	return ok(a, b, bNew) || ok(b, a, aNew)
}
