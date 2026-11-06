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

// R29-U1 (0.87.1): there is no upgrade migration. A release-29 vault
// refuses state from an earlier release (state_unsupported) and is
// re-enrolled; that is a unit test in the vault, not a two-sided run, so
// every run starts on release 29.

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
	resOldApp         = "an app from before release 29 (earlier releases are unsupported; R29-D4 notice)"
	resCopyInit       = "a copy acting as initiator sent nothing but hs.fin"
	resBeforeRotation = "an old copy acting before the original's rotation is seen (an old copy can make any handshake as P)"
	resLiveMailbox    = "an old copy collects, acks or deletes the original's live mailbox"
)

// residualOf: the residual that exempts the pair (a, b), or "".
func (w *World) residualOf(a, b PID) string {
	if w.party(a).OldApp || w.party(b).OldApp {
		return resOldApp // I7 still requires the R29-D4 notice when the pair split
	}
	return ""
}

// exempt counts a residual exemption for a pair, once per invariant.
func (w *World) exempt(inv, reason string) { w.stat("residual exemption (" + inv + "): " + reason) }
