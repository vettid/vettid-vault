package trustmodel

import (
	"fmt"
	"slices"
)

// VAULT-MESSAGING 0.87.1 §6.3.1 at vettid.org 4734dfd8: lifetimes,
// activation on confirmation, the confirmed epoch, rule E. Release 29 has
// no gate: both halves always run, between release-29 vaults and toward
// their devices. Config.OldRules turns all of it off (f4a4d97).

const (
	aHSLife   = 16 * day // an initiator's handshake awaiting hs.resp
	aAnsLife  = 16 * day // a responder's answer awaiting hs.fin (L)
	aPendLife = 32 * day // an initiator's pending epoch awaiting confirmation (B)
	aConfKeys = 48 * day // a confirmed epoch's keys while not current
)

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

// newSpec: this party implements §6.3.1 (Config.OldRules: none does).
func (q *Party) newSpec() bool { return q.w.optA }

// respHalf: the responder half applies toward every peer (an app from
// before release 29 has none).
func (q *Party) respHalf() bool { return q.newSpec() && !q.OldApp }

// initHalf: the pending epoch and B, toward every peer (R29-I1: no gate).
func (q *Party) initHalf() bool { return q.newSpec() && !q.OldApp }

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
	q.w.hit("I1:pending")
	q.w.logf("%s: epoch E%d with %s PENDING (signer %d)", q.Name, id, q.w.party(r.ID).Name, signer)
}

// confirm: a message from the peer under the pending epoch.
func (q *Party) confirm(r *PeerRec) {
	pe := r.Pend
	for j := range r.Epochs {
		ep := &r.Epochs[j]
		if ep.ID == pe.ID {
			ep.Pending, ep.EverCur = false, true
		} else if ep.Superseded == 0 {
			ep.Superseded = q.w.Now
		}
	}
	r.Cur, r.Pend = pe.ID, nil
	q.w.noteCurrent(q, pe.ID)
	if r.Device && !q.Copy {
		// a newer epoch confirmed: F's gap is closed for this pair
		delete(q.w.fDue, pairKey(q.ID, r.ID))
	}
	r.setConf(pe.ID, q.w.Now) // activated at confirmation
	r.AbanIDs = nil
	if pe.Reconnect {
		r.RCNamed, r.RCFails = 0, 0 // R29-K6: the reconnect succeeded
	}
	q.releaseHeld(r) // R29-K5: sealed under the new epoch at confirmation
	q.w.stat("A:confirmed")
	q.w.hit("I2:confirmed")
	q.w.logf("%s: epoch E%d with %s CONFIRMED (current)", q.Name, pe.ID, q.w.party(r.ID).Name)
}

// markF: ground truth for finding F (§3.4.1 Invariants, "With it, finding
// F"; 0.88.1, owner decision a, GC 01M6S2ECFHHGFXC7H8HPZ2FB2V): the vault
// abandoned a pending rekey toward its device or agent, for any reason
// (B, want of a token, token_expired, its own rotation S5, ...). The device
// may already have activated that epoch and stay on it, while the vault's
// rekey from its current epoch may never be deposited or opened. Until a
// newer epoch is confirmed, the pair's I1, I1-loss and I7 failures are the
// device exception.
func (q *Party) markF(r *PeerRec, why string) {
	k := pairKey(q.ID, r.ID)
	if q.Copy || q.w.fDue[k] {
		return
	}
	q.w.fDue[k] = true
	q.w.hit("D1:F-abandoned-toward-device")
	q.w.stat("F: abandoned toward a device: " + why)
	q.w.logf("%s: finding F for %s: a pending rekey abandoned (%s)", q.Name, q.w.party(r.ID).Name, why)
}

// setConf: the confirmed epoch moves forward (never back); the one it
// leaves keeps its keys 16 days from now (F6).
func (r *PeerRec) setConf(id int, now int64) {
	if old := r.epoch(r.ConfID); old != nil && old.ID != id && old.ID != r.Cur {
		old.Superseded = now
	}
	r.ConfID, r.ConfUntil = id, 0
}

// abandonPending: R29-I7, every abandon of a pending epoch (B, I6, H5/S5,
// a link, a crossing, the peer's handshake activated, a reconnect starts).
// The tokens its hs.init carried were revoked when that handshake ended
// (abandonOwn at hs.resp's write keeps them in r.Issued; the abandon here
// revokes them).
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
	if r.Device && !q.Device && !pe.Reconnect {
		q.markF(r, why) // finding F: until a newer epoch is confirmed
	}
	q.w.stat("A:abandoned:" + why)
	q.w.hit("I7:abandon")
	q.w.logf("%s: pending E%d with %s ABANDONED (%s)", q.Name, pe.ID, q.w.party(r.ID).Name, why)
	if !restart || r.Status != stActive {
		return
	}
	valid := r.standing(r.KeyFor, r.Relay, q.now()).JTI != 0
	switch {
	case why == "B passed" && r.Device:
		q.w.hit("D1:B-rekey")
		q.deviceNotice(r, "B passed")
		q.startHS(r, false) // R29-D1: toward a device, rekey from the current epoch, token or not
	case why == "B passed" && pe.Reconnect:
		q.w.hit("I5:B-reconnect-stale")
		q.markStale(r, "K6: a pending reconnect reached B") // R29-I5, K6
		q.h5(r, -1)
	case why == "B passed":
		q.w.hit("I5:B-reconnect")
		q.w.nextOrigin = "B reconnect"
		q.startHS(r, true) // R29-I5: I reconnects naming its current epoch
	case pe.Reconnect:
		q.w.hit("I7:fresh-reconnect")
		q.startHS(r, true) // R29-I7: a fresh reconnect, not a rekey
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
	// R29-F3: the received flag of that epoch, by every message but hs.fin
	if ep := r.epoch(M.Epoch); ep != nil && M.Kind != KFin && !ep.Flag {
		ep.Flag = true
		q.w.hit("F3:flag-set")
		if tr, ok := q.w.epTruth[ep.ID]; ok && !q.Copy && (q.w.party(tr[0]).Copy || q.w.party(tr[1]).Copy) {
			q.pendFlag = append(q.pendFlag, ep.ID) // ground truth once the write stores it
		}
		if ep.Demoted && !r.Device && r.Status == stActive && !q.w.noFlagJudged {
			// (0.88.2, owner decision a, GC 01M6SQNDPRKRMEXQFA7XFMGACH) the
			// flag is judged whenever it is set: a flag-setting message
			// accepted under an epoch demoted with its flag clear (K4 or K7;
			// deposited before x, processed after the demotion) is P's side
			// using it, which an honest P never does: a copy did
			q.w.hit("F3:flag-on-demoted-suspends")
			q.w.logf("%s: a flag-setting message under demoted E%d of %s: a copy used it", q.Name, ep.ID, q.w.party(r.ID).Name)
			q.suspend(r, "connection.fork_suspected/epoch")
		}
		if M.Kind == KConfirm {
			q.w.hit("F3:flag-set-by-hs.confirm")
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
		q.w.hit("R2:confirmed-moves")
	}
	if r.ConfID != 0 && r.ConfID != r.Cur && M.Epoch == r.ConfID {
		r.Reconfirm = true
	}
}

// ruleE: at the verified hs.fin of a handshake that named the confirmed
// epoch: destroy every other epoch later than it, recording the hs.init's ts.
func (q *Party) ruleE(r *PeerRec, ts int64) {
	after := false
	for j := range r.Epochs {
		ep := &r.Epochs[j]
		if after && ep.Abandoned && !ep.Destroyed {
			q.w.hit("R5:own-abandoned-not-destroyed") // R29-R5: I7 applies to it
		}
		if after && !ep.Destroyed && !ep.Pending && !ep.Abandoned {
			ep.Destroyed, ep.DestroyTs = true, ts
			q.w.stat("A:destroyed-later-epoch")
			q.w.hit("R5:destroyed")
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
		if q.Device && q.w.Now-r.LastConfirm < minute {
			q.w.hit("D2:confirm-rate-limited") // R29-D2: at most once a minute
			continue
		}
		if r.Cur != 0 && (!queued || q.w.noF10) { // noF10: no cap
			q.w.stat("A:hs.confirm-again")
			q.w.hit("R3:hs.confirm-again")
			r.LastConfirm = q.w.Now
			q.enqueue(r.ID, Msg{Kind: KConfirm, Epoch: r.Cur}, nil)
		} else if queued {
			q.w.hit("R3:one-still-queued")
		}
	}
}

// confirmAgainAfter: (0.88.1, vettid.org #554) R queues hs.confirm again
// 12 days after the last one it queued (T less 2 days; not scaled).
const confirmAgainAfter = 12 * day

// confirmAgain: (0.88.1) §6.3.1 Responder, "hs.confirm again". While R's
// current epoch with I is one R activated as responder and R's confirmed
// epoch is neither it nor a later one (activation order), R queues
// hs.confirm under it again 12 days after the last one it queued, unless
// one to I is still in its outbox; none while the epoch is demoted or the
// connection suspended. A device does the same toward its vault.
func (p *Party) confirmAgain(r *PeerRec) {
	w := p.w
	if !p.respHalf() || w.noConfirmAgain || r.Status != stActive || r.Cur == 0 {
		return
	}
	ep := r.epoch(r.Cur)
	if ep == nil || ep.MineInit || ep.Demoted || ep.Pending || ep.Abandoned {
		return
	}
	ic := slices.IndexFunc(r.Epochs, func(e Epoch) bool { return e.ID == r.Cur })
	if ik := slices.IndexFunc(r.Epochs, func(e Epoch) bool { return e.ID == r.ConfID }); ik >= ic {
		return // the confirmed epoch is the current one or a later one
	}
	if w.Now-r.LastConfirm < confirmAgainAfter {
		return
	}
	if slices.ContainsFunc(p.st.Out, func(e Entry) bool {
		return e.To == r.ID && e.M.Kind == KConfirm && !e.Done && !e.Ended
	}) {
		return
	}
	w.hit("R3:hs.confirm-again-12d")
	w.logf("%s: hs.confirm again under E%d for %s (12 days, not yet confirmed)", p.Name, r.Cur, w.party(r.ID).Name)
	r.LastConfirm = w.Now
	p.enqueue(r.ID, Msg{Kind: KConfirm, Epoch: r.Cur}, nil)
}

// tickA: §6.3.1 timers.
func (p *Party) tickA(r *PeerRec) {
	w := p.w
	p.confirmAgain(r)
	if pe := r.Pend; pe != nil && w.Now-pe.FinAt > aPendLife && (p.collectedSinceUnlock || w.noF13B) {
		p.abandonPending(r, "B passed", true)
	}
	// R29-I6: a pending rekey with no valid standing token (own clock) is
	// abandoned; a pending reconnect is not (it ends at B)
	if pe := r.Pend; pe != nil && r.standing(r.KeyFor, r.Relay, p.now()).JTI == 0 {
		if pe.Reconnect {
			w.hit("I6:reconnect-kept-without-token")
		} else {
			w.hit("I6:rekey-abandoned-no-token")
			p.abandonPending(r, "no valid standing token", true)
		}
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
				w.hit("L1:confirmed-epoch-keys-end")
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
	p.w.hit("K3:identity.rotate-resent")
	p.enqueue(r.ID, Msg{Kind: KIdRot, Rot: p.ownLinks(ep.Own)}, nil)
}

// markStale: the record goes stale. Ground truth for I1-stale-split: at the
// moment a pair first goes stale, did the two sides' current epochs differ
// (or did one side hold an epoch the other never held)?
func (q *Party) markStale(r *PeerRec, ref string) {
	r.Status, r.Ref = stStale, ref
	w := q.w
	q.endHeld(r)
	w.logf("%s: %s STALE (%s)", q.Name, w.party(r.ID).Name, ref)
	w.feedItem(q.ID, r.ID, "connection.stale")
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
// one side's current is the other's pending epoch or its confirmed epoch.
func consistent(a, b *PeerRec, aNew, bNew bool) bool {
	ok := func(x, y *PeerRec, yNew bool) bool { // y can take x's current epoch
		return x.Cur == y.Cur || (y.Pend != nil && y.Pend.ID == x.Cur) || (yNew && y.ConfID == x.Cur && x.Cur != 0)
	}
	return ok(a, b, bNew) || ok(b, a, aNew)
}
