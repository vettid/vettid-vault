package trustmodel

import "slices"

// VAULT-MESSAGING 0.86.0 (draft) §6.3.1, option A: lifetimes, and
// activation on confirmation for rekeys and reconnects. Selected by
// World.optA (Config.OldRules turns it off: the f4a4d97 behaviour).

const (
	aHSLife   = 16 * day // an initiator's handshake awaiting hs.resp
	aAnsLife  = 16 * day // a responder's answer awaiting hs.fin (L)
	aPendLife = 32 * day // an initiator's pending epoch awaiting confirmation (B)
	aConfKeys = 46 * day // a responder's confirmed epoch's keys, from the activation
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

// makePending: the initiator, having verified sig_R, records the new epoch
// as pending (established, signer recorded, not current).
func (q *Party) makePending(r *PeerRec, id int, signer, own Key, pos Pos, respTs int64, reconnect bool) {
	if signer != r.IK {
		q.w.violate("I3", "%s establishes E%d signed by %d, not its current ik %d for %s", q.Name, id, signer, r.IK, q.w.party(r.ID).Name)
	}
	r.Epochs = append(r.Epochs, Epoch{ID: id, Signer: signer, Own: own, Est: pos, EstAt: q.w.Now, Pending: true})
	r.Pend = &PendEp{ID: id, Signer: signer, Own: own, FinAt: q.w.Now, RespTs: respTs, Reconnect: reconnect}
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
	r.ConfID, r.ConfUntil, r.AbanIDs = pe.ID, 0, nil // activated at confirmation; abandoned ids end
	q.w.stat("A:confirmed")
	q.w.logf("%s: epoch E%d with %s CONFIRMED (current)", q.Name, pe.ID, q.w.party(r.ID).Name)
}

// abandonPending: H5, S5, crossing, or B passed. restart: start a rekey
// from the current epoch, or a reconnect when the standing token expired.
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
	if restart && r.Status == stActive {
		rc := !r.Device && r.standing(r.KeyFor, r.Relay, q.w.Now).JTI == 0
		q.startHS(r, rc)
	}
}

// beforeAccept: confirmation bookkeeping when a message opens (§6.3.1).
func (q *Party) beforeAccept(r *PeerRec, m *RMsg, pos Pos) {
	M := m.P
	if !q.w.optA || r.Status != stActive || M.Epoch == 0 || r.relayState(m.Sender, pos) == rkForeign {
		return
	}
	if r.Pend != nil && M.Epoch == r.Pend.ID && M.Kind != KFin {
		q.confirm(r)
	}
	// the confirmed epoch: the last epoch the peer used (not hs.fin)
	if M.Kind != KFin && M.Epoch != r.ConfID && r.newer(M.Epoch, r.ConfID) {
		if r.ConfID != r.Cur && r.ConfID != 0 {
			q.w.logf("%s: %s now uses E%d (confirmed epoch E%d ends)", q.Name, q.w.party(r.ID).Name, M.Epoch, r.ConfID)
		}
		r.ConfID, r.ConfUntil = M.Epoch, 0
	}
	if r.ConfID != 0 && r.ConfID != r.Cur && M.Epoch == r.ConfID {
		r.Reconfirm = true
	}
}

// reconfirm: once per batch holding a message under the confirmed epoch.
func (q *Party) reconfirm() {
	for i := range q.st.Peers {
		r := &q.st.Peers[i]
		r.IdResendBatch = false
		if r.Reconfirm {
			r.Reconfirm = false
			if r.Cur != 0 && !q.OldConfirm {
				q.w.stat("A:hs.confirm-again")
				q.enqueue(r.ID, Msg{Kind: KConfirm, Epoch: r.Cur}, nil)
			}
		}
	}
}

// tickA: §6.3.1 timers.
func (p *Party) tickA(r *PeerRec) {
	w := p.w
	if pe := r.Pend; pe != nil && w.Now-pe.FinAt > aPendLife {
		p.abandonPending(r, "B passed", true)
	}
	// keys end; ids stay (G): the confirmed epoch's and abandoned ones'
	for j := range r.Epochs {
		ep := &r.Epochs[j]
		keep := ep.ID == r.ConfID || slices.Contains(r.AbanIDs, ep.ID)
		if !keep || ep.ID == r.Cur || ep.KeysGone {
			continue
		}
		if ep.ID == r.ConfID && r.ConfUntil != 0 && w.Now > r.ConfUntil {
			ep.KeysGone = true
		}
		if ep.ID != r.ConfID && ep.Superseded != 0 && w.Now-ep.Superseded > 16*day {
			ep.KeysGone = true
		}
	}
}

// newer: epoch a was recorded after epoch b (b == 0: any).
func (r *PeerRec) newer(a, b int) bool {
	ia, ib := -1, -1
	for i, e := range r.Epochs {
		if e.ID == a && !e.Pending && !e.Abandoned {
			ia = i
		}
		if e.ID == b {
			ib = i
		}
	}
	return ia >= 0 && ia > ib
}

// confFork: §6.3.1 precedence. An epoch that superseded the confirmed one
// is signed by an ancestor ik and was established after the link that
// made it one (a demoted epoch). literalFork reads §3.4.1's sentence
// without the deposited-after condition.
func (q *Party) confFork(r *PeerRec) bool {
	if q.w.literalFork {
		return q.forkEpoch(r, r.ConfID)
	}
	after := false
	for _, e := range r.Epochs {
		if after && e.Demoted {
			return true
		}
		if e.ID == r.ConfID {
			after = true
		}
	}
	return false
}

// destroyLater: §6.3.1 (rev. 3): Q accepts a rekey or reconnect naming its
// confirmed epoch; every later epoch the peer never confirmed is destroyed
// and messages under them are refused (superseded_epoch).
func (q *Party) destroyLater(r *PeerRec) {
	after := false
	for j := range r.Epochs {
		ep := &r.Epochs[j]
		if after && !ep.Destroyed && !ep.Pending {
			ep.Destroyed = true
			q.w.stat("A:destroyed-later-epoch")
			q.w.logf("%s: E%d with %s DESTROYED (never confirmed)", q.Name, ep.ID, q.w.party(r.ID).Name)
			if r.Cur == ep.ID {
				r.Cur = r.ConfID
			}
		}
		after = after || ep.ID == r.ConfID
	}
}

// idResend: S5 resend. A session message from Q under an epoch whose
// P-side signer is an ancestor of P's ik, deposited after P's rotation.
func (p *Party) idResend(r *PeerRec, m *RMsg) {
	ep := r.epoch(m.P.Epoch)
	if ep == nil || ep.Own == p.st.IK || p.ownLinks(ep.Own) == nil || m.DepAt < p.st.LastRot {
		return
	}
	if r.IdResendBatch || p.w.Now-r.IdResend < hour {
		return
	}
	r.IdResend, r.IdResendBatch = p.w.Now, true
	links := p.ownLinks(ep.Own)
	p.w.stat("A:identity.rotate-resent")
	p.enqueue(r.ID, Msg{Kind: KIdRot, Rot: links}, nil)
}
