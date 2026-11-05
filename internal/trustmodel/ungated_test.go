package trustmodel

import (
	"fmt"
	"slices"
)

// r8, the lead's (b) on two points; switches turn each off.
//
// 1. F3 toward a peer that has not advertised hs_confirm (a release-28
//    responder activates a late hs.fin, vault/handshakes.go:571): a later-ts
//    message under an epoch rule E destroyed starts one reconnect naming
//    the confirmed epoch (per destroyed epoch), not a suspension
//    (TRUSTMODEL_F3UNGATED=suspend: the earlier rule).
// 2. Toward a peer that has not advertised features: when its rekey is
//    refused, a release-29 vault reconnects (the reconnect carries the
//    whole chain). Release 28 refuses silently (rekey_refused,
//    rekey_not_current_epoch: audits only), so the release-29 side sees it
//    as its rekey never answered within its lifetime, or as an hs.resp it
//    must abort for an ik it cannot reach, or as the peer's rekey on an
//    epoch that is not its current one. Only when this side's ik is newer
//    than the one that signed the current epoch (the peer may have missed
//    a link). At most one per current epoch;
//    a reconnect that fails is not restarted by this rule
//    (TRUSTMODEL_REKEYRC=off: the earlier behaviour).

// reconnectNaming starts a reconnect naming epoch ctx (0: the last).
func (q *Party) reconnectNaming(r *PeerRec, ctx int, why string) {
	if r.Device || r.Status != stActive || (r.Own != nil && r.Own.Reconnect) {
		return
	}
	q.abandonOwn(r)
	for _, a := range slices.Clone(r.Ans) {
		if !a.Reconnect {
			q.dropAnswer(r, a.ID) // S5 / §6.6 would block the reconnect; the peer did not finish it
		}
	}
	if r.Pend != nil {
		q.abandonPending(r, why, false)
	}
	r.RCCtx = ctx
	q.w.logf("%s: reconnect to %s naming E%d (%s)", q.Name, q.w.party(r.ID).Name, ctx, why)
	q.startHS(r, true)
	if r.Own == nil || !r.Own.Reconnect {
		q.w.stat("A:ungated-reconnect-not-started")
		return
	}
	r.Own.RuleRC = true
	r.RCTries = 1
}

// ruleRCExpired (r9, the lead's recheck): a rule-E or rule-L reconnect
// that expired unanswered is tried again with the same ctx, up to 3 tries
// per epoch (each within the reconnect token's quota, which the relay
// enforces); it reports whether a try started. Otherwise the caller marks
// the connection stale.
func (p *Party) ruleRCExpired(r *PeerRec, o *HS) bool {
	if !o.RuleRC || p.w.noRCRetry || r.RCTries >= 3 {
		return false
	}
	p.abandonOwn(r)
	r.RCCtx = o.Ctx
	p.startHS(r, true)
	if r.Own == nil || !r.Own.Reconnect {
		p.w.stat("A:ruleRC-retry-not-started")
		return false
	}
	r.Own.RuleRC = true
	r.RCTries++
	p.w.stat("A:ruleRC-retry")
	p.w.logf("%s: reconnect to %s tried again (%d of 3)", p.Name, p.w.party(r.ID).Name, r.RCTries)
	return true
}

// rekeyRefusedRC applies point 2; it reports whether a reconnect started.
func (q *Party) rekeyRefusedRC(r *PeerRec, o *HS, why string) bool {
	if q.w.noRekeyRC || !q.newSpec() || r.PeerA || r.Device || r.Status != stActive {
		return false
	}
	if o != nil && o.Reconnect {
		return false // a refused reconnect does not restart one
	}
	if ep := r.epoch(r.Cur); ep == nil || ep.Own == q.st.IK {
		return false // only after my own rotation: the peer may not have followed my link
	}
	if r.RCEpoch == r.Cur && r.Cur != 0 {
		return false // once per current epoch
	}
	r.RCEpoch = r.Cur
	q.w.stat("A:rekey-refused-reconnect (" + why + ")")
	q.reconnectNaming(r, 0, why)
	return r.Own != nil && r.Own.Reconnect
}

// rcStats: the most reconnects started toward one peer in the run.
func (w *World) rcStats() {
	most := 0
	for _, p := range w.real() {
		for _, r := range p.st.Peers {
			most = max(most, r.RCs)
		}
	}
	w.stat(fmt.Sprintf("X:max reconnects per pair %03d", most))
}
