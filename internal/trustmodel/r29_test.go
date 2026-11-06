package trustmodel

// VAULT-MESSAGING 0.87.0 release-29 rules (§6.3.1, §3.4.1) that span the
// receiving and the rotating side: the epoch a reconnect names (R29-X5,
// K5, K7), the held queue after a demotion of the current epoch (K5), and
// the count of each rule's branches by its §6.3.2 ID (w.hit).

// hit counts one use of a release-29 rule's branch ("K4:demote").
func (w *World) hit(id string) { w.stats["R29 "+id]++ }

// rcName is the epoch a reconnect names (R29-X5): the current epoch; after
// a demotion of the current epoch, strict F1's E (K7), else the newest
// epoch that has been current here and is neither demoted nor destroyed
// (K5). 0: none.
func (r *PeerRec) rcName() int {
	if r.Cur != 0 {
		return r.Cur
	}
	if r.DemName != 0 && r.epoch(r.DemName) != nil {
		return r.DemName
	}
	for i := len(r.Epochs) - 1; i >= 0; i-- {
		if e := r.Epochs[i]; e.EverCur && !e.Demoted && !e.Destroyed {
			return e.ID
		}
	}
	return 0
}

// holdFor: R29-K5, after a demotion of the current epoch Q sends P only
// handshake messages. Durable entries not yet deposited go back to held,
// unsealed; an hs.confirm is not sent (neither held nor counted).
func (q *Party) holdFor(r *PeerRec) {
	for i := range q.st.Out {
		e := &q.st.Out[i]
		if e.To != r.ID || e.Done || e.Ended || e.Denylist {
			continue
		}
		q.holdEntry(r, e)
	}
}

// holdEntry holds one outbox entry for r (handshake messages stay out).
func (q *Party) holdEntry(r *PeerRec, e *Entry) bool {
	switch e.M.Kind {
	case KInit, KResp, KFin:
		return false
	case KConfirm:
		e.Ended = true
		q.w.hit("K5:hs.confirm-not-sent")
		return true
	}
	h := *e
	h.M = cloneMsg(e.M)
	h.Tried, h.Indef = false, false
	r.Held = append(r.Held, h)
	e.Ended = true // it lives on in r.Held with the same id
	q.w.hit("K5:held")
	return true
}

// releaseHeld: a new epoch is current: held messages are sealed with a new
// ts under it (at deposit).
func (q *Party) releaseHeld(r *PeerRec) {
	r.DemName = 0
	if len(r.Held) == 0 {
		return
	}
	for _, e := range r.Held {
		e.M.Ts, e.M.Epoch = q.now(), 0
		q.st.Out = append(q.st.Out, e)
		q.w.hit("K5:released")
	}
	r.Held = nil
}

// endHeld: the connection went stale (or was removed or replaced): held
// messages end with it, without an audit entry each.
func (q *Party) endHeld(r *PeerRec) {
	for _, e := range r.Held {
		q.w.ended[e.ID] = true
		if e.M.Kind == KSession && e.M.Probe > 0 && !q.Copy && q.w.probeFate[e.M.Probe] == "" {
			q.w.probeFate[e.M.Probe] = "held: ended with the connection"
		}
		q.w.hit("K5:held-ended")
	}
	r.Held = nil
}

// afterDemotion: R29-K5. The current epoch was demoted (by position, K4,
// or by strict F1, K7): hold, and start the reconnect after a demotion,
// one at a time per peer (X4). why names the trigger.
func (q *Party) afterDemotion(r *PeerRec, why string) {
	q.holdFor(r)
	if o := r.Own; o != nil && !o.Reconnect {
		q.abandonOwn(r) // its epoch was never P's
	}
	q.w.nextOrigin = why
	q.startHS(r, true)
}

// needsReconnect: a demoted record with no handshake of its own (tick
// retries the reconnect after a demotion, which an answer awaiting hs.fin
// may have held back).
func (q *Party) needsReconnect(r *PeerRec) bool {
	return q.newSpec() && !r.Device && r.Status == stActive && r.Cur == 0 && r.Own == nil && r.Pend == nil
}

// ---------- R29-U1, the upgrade migration ----------

// migrate: R29-U1 (§6.3.1 "Capability and upgrade"). The run so far was
// release 28 (Config.PreUpgrade: the f4a4d97 rules, activation at
// hs.resp, no hs.confirm); every party migrates at once (the test vaults
// upgrade together; a device's app too, except an old app), stored and
// memory state alike. Each connection's and device's stored epoch becomes
// its epoch record: confirmed = current, signer = the stored ik, received
// flag clear. Earlier epochs keep only their receive keys (an epoch
// established before release 29 counts as signed by the ik current for P
// at the upgrade, §3.4.1 "The neutral feed item"). An outgoing handshake
// in flight is cleaned up as an aborted one (handshake_not_restored, its
// hs.init not sent, its tokens denied: the model restores none); answers
// awaiting hs.fin run the responder half.
func (w *World) migrate() {
	if w.migrated || !w.preUpgrade {
		return
	}
	w.migrated, w.optA, w.migratedAt = true, true, w.Now
	w.hit("U1:migrated")
	w.logf("UPGRADE: every party migrates to release 29 (R29-U1)")
	// ground truth for §3.4.1 Residuals, "two splits at the upgrade": an
	// initiator activated at hs.resp, its hs.fin not yet processed
	for _, p := range w.real() {
		for _, r := range p.st.Peers {
			if o := w.party(r.ID).st.peer(p.ID); o != nil && r.Cur != 0 {
				for _, a := range o.Ans {
					if a.NewEpoch == r.Cur {
						w.u1Risk[pairKey(p.ID, r.ID)] = [2]int{int(r.ID), r.Cur}
						w.hit("U1:hs.fin-in-flight")
					}
				}
			}
		}
	}
	for _, p := range w.P {
		for _, st := range []*State{&p.st, &p.stored} {
			for i := range st.Peers {
				p.migratePeer(st, &st.Peers[i])
			}
		}
		if !p.Copy {
			p.storedOut = map[int]bool{}
			for _, e := range p.stored.Out {
				p.storedOut[e.ID] = true
			}
		}
	}
}

func (p *Party) migratePeer(st *State, r *PeerRec) {
	if r.Cur == 0 {
		if e := r.lastEpoch(); e != nil {
			r.Cur = e.ID
		}
	}
	var eps []Epoch
	for _, e := range r.Epochs {
		if e.Demoted || e.Destroyed {
			continue
		}
		e.Signer, e.Flag, e.Pending, e.Abandoned = r.IK, false, false, false
		e.EverCur = e.ID == r.Cur || e.Superseded != 0
		if e.ID == r.Cur {
			e.Superseded, e.EverCur = 0, true
		}
		eps = append(eps, e)
	}
	r.Epochs = eps
	r.ConfID, r.ConfUntil, r.Pend = r.Cur, 0, nil
	r.AbanIDs, r.DemName, r.RCNamed, r.RCFails, r.DropAns = nil, 0, 0, 0, nil
	if o := r.Own; o != nil {
		if st == &p.st {
			p.w.hit("U1:handshake-not-restored")
		}
		for i := range st.Out {
			if e := &st.Out[i]; e.M.Kind == KInit && e.M.HS == o.ID && !e.Done {
				e.Ended = true
			}
		}
		by := map[Key][]int{}
		for _, t := range o.Toks {
			by[t.Iss] = append(by[t.Iss], t.JTI)
		}
		for b, j := range by {
			st.Out = append(st.Out, Entry{ID: p.w.id(), Denylist: true, Box: b, With: b, Revoke: j})
		}
		r.Own = nil
	}
	if len(r.Ans) > 0 && st == &p.st {
		p.w.hit("U1:answer-runs-responder-half")
	}
}

// ---------- R29-D4, an app from before release 29 ----------

// deviceNotice: the vault tells the member that device r needs an update
// (feed item device.update_needed, high), once per device until it
// advertises hs_confirm.
func (q *Party) deviceNotice(r *PeerRec, why string) {
	if q.Device || !r.Device || r.SawHSC || r.Notice || !q.newSpec() {
		return
	}
	r.Notice = true
	q.w.hit("D4:notice " + why)
	q.w.feedItem(q.ID, r.ID, "device.update_needed")
	q.w.logf("%s: device.update_needed for %s (%s)", q.Name, q.w.party(r.ID).Name, why)
}

// seeFeatures: R29-G2, a message from the peer that passed steps 1-4;
// hs_confirm is sticky once seen. Toward a device without it: D4.
func (q *Party) seeFeatures(r *PeerRec, M *Msg) {
	if !q.newSpec() {
		return
	}
	if M.Feat {
		if !r.SawHSC {
			q.w.hit("G2:hs_confirm-seen")
		}
		r.SawHSC = true
		return
	}
	if r.SawHSC {
		q.w.hit("G2:sticky")
		return
	}
	q.deviceNotice(r, "message without hs_confirm")
}

// feedItem records a feed item to the member about the pair (R29 I7).
func (w *World) feedItem(q, r PID, kind string) {
	if w.party(q).Copy {
		return
	}
	k := pairKey(q, w.party(r).Origin)
	w.feed[k] = append(w.feed[k], kind)
}

// ---------- residuals (§3.4.1 Residuals, 0.87.0) ----------

// Residual reasons: each exempts a pair from I1, I6 and I7, and is counted.
const (
	resOldApp   = "an app from before release 29 (earlier releases are unsupported; R29-D4 notice)"
	resU1Fin    = "an hs.fin lost at the upgrade (two splits at the upgrade, U1)"
	resCopyInit = "a copy acting as initiator sent nothing but hs.fin"
)

// residualOf: the residual that exempts the pair (a, b), or "".
func (w *World) residualOf(a, b PID) string {
	if w.party(a).OldApp || w.party(b).OldApp {
		return resOldApp
	}
	if x, ok := w.u1Risk[pairKey(a, b)]; ok {
		resp, other := w.party(PID(x[0])), a
		if other == resp.ID {
			other = b
		}
		if r := resp.st.peer(other); r == nil || r.epoch(x[1]) == nil {
			return resU1Fin // the responder does not hold the epoch the migration made current
		}
	}
	return ""
}

// exempt counts a residual exemption for a pair, once per invariant.
func (w *World) exempt(inv, reason string) { w.stat("residual exemption (" + inv + "): " + reason) }
