package trustmodel

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Wait classes (instrumentation only; nothing here changes what a party
// does). With relay-key rotation on, a pair that ends stale, or fails I1 at
// quiescence, is labelled by the wait it was stuck in, as the relay-key
// rotation design note (vettid.org RELAY-KEY-ROTATION.md, draft 4,
// sections 1 and 5) names them. P is the side whose relay key for the
// other is not (or was not) current; Q the recipient.
//
//   - G1: S1 at P holds a rekey's hs.fin for Q while Q, demoted (no
//     current epoch) or with its own reconnect pending, holds a
//     relay.token.issued for P (seen at P's flush; ground truth reads Q's
//     state).
//   - G2: P's hs.resp to Q's reconnect, deposited with P's earlier key, is
//     refused: by the relay (the token's sub is P's newer key,
//     signature_invalid) or by Q (superseded_relay).
//   - G3: P's other handshake messages or hs.confirm, deposited with P's
//     earlier key, are refused by Q superseded_relay (after Q's cut-off).
//   - G6: token_revoked on a token Q issued to P's earlier key: on P's
//     reconnect token (a failed try) or on a standing token still P's key
//     for Q (S9).
//   - G7: a deposit into a mailbox of the other side that no longer exists
//     (mailbox_unknown, its rotation grace over; the model has a grace,
//     graceLen).
//
// How it decides: each such event is noted per ordered pair with its time
// (w.waitEv). A pair's class is the set of labels noted, in either
// direction, since the pair last made progress (an epoch confirmed or
// established at either side, w.progressAt), taken at the moment the pair
// first goes stale (markStale, before its held messages end) or, for I1, at
// quiescence. With no label it is OTHER, described by the stale reason,
// each side's handshake state and the other refusals noted in the window.

// waitLabels are the design note's labels; anything else noted is context
// for OTHER.
var waitLabels = []string{"G1", "G2", "G3", "G6", "G7"}

// noteWait records event label for the ordered pair (from, to).
func (w *World) noteWait(from, to PID, label string) {
	if w.party(from).Copy || w.party(to).Copy {
		return
	}
	k := [2]PID{from, to}
	if w.waitEv[k] == nil {
		w.waitEv[k] = map[string]int64{}
	}
	w.waitEv[k][label] = w.Now
}

// noteProgress: an epoch became current at q for r.
func (w *World) noteProgress(q *Party, r *PeerRec) {
	if !q.Copy {
		w.progressAt[pairKey(q.ID, r.ID)] = w.Now
	}
}

// waitDeposit: called from Party.deposit for a refusal.
func (p *Party) waitDeposit(to PID, m *Msg, with, box Key, tok Token, err relayErr) {
	w := p.w
	if p.Copy || !w.relayRot {
		return
	}
	y := w.party(to)
	switch {
	case err == sigInvalid && m.Kind == KResp && m.Reconnect && with != tok.Sub:
		w.noteWait(p.ID, to, "G2")
	case err == tokenRevoked && with != p.st.Relay:
		w.noteWait(p.ID, to, "G6")
	case err == mailboxUnknown && box != y.st.Relay:
		w.noteWait(p.ID, to, "G7")
	default:
		w.noteWait(p.ID, to, "relay "+string(err)+" on "+kindName[m.Kind])
	}
}

// waitRefused: q refused or dropped a message from r with reason.
func (q *Party) waitRefused(r *PeerRec, m *RMsg, d dec) {
	w := q.w
	if q.Copy || !w.relayRot || w.party(m.Actor).Copy || (d.Out != "refuse" && d.Out != "drop" && d.Out != "abort") {
		return
	}
	M := m.P
	switch {
	case d.Reason == "superseded_relay" && M.Kind == KResp && M.Reconnect:
		w.noteWait(r.ID, q.ID, "G2")
	case d.Reason == "superseded_relay" && (M.Kind == KInit || M.Kind == KResp || M.Kind == KFin || M.Kind == KConfirm):
		w.noteWait(r.ID, q.ID, "G3")
	case M.Kind == KInit || M.Kind == KResp || M.Kind == KFin || M.Kind == KConfirm:
		w.noteWait(r.ID, q.ID, d.Reason+" on "+kindName[M.Kind])
	}
}

// waitS1Fin: S1 at p holds entry e (for r). A rekey hs.fin held while the
// recipient is demoted or reconnect-pending and holds relay.token.issued
// for p is G1.
func (p *Party) waitS1Fin(r *PeerRec, e *Entry) {
	w := p.w
	if p.Copy || !w.relayRot || e.M.Kind != KFin || e.M.Reconnect {
		return
	}
	y := w.party(r.ID)
	rq := y.st.peer(p.ID)
	if rq == nil || rq.Status != stActive || !(rq.Cur == 0 || (rq.Pend != nil && rq.Pend.Reconnect)) {
		return
	}
	holds := slices.ContainsFunc(rq.Held, func(h Entry) bool { return h.M.Kind == KTokIssued })
	holds = holds || slices.ContainsFunc(y.st.Out, func(h Entry) bool {
		return h.To == p.ID && h.M.Kind == KTokIssued && !h.Done && !h.Ended
	})
	if holds {
		w.noteWait(p.ID, r.ID, "G1")
	}
}

// waitClass: the class of pair (a, b) now (see above).
func (w *World) waitClass(a, b PID, ref string) string {
	since := w.progressAt[pairKey(a, b)]
	got := map[string]bool{}
	var other []string
	for _, k := range [][2]PID{{a, b}, {b, a}} {
		for l, at := range w.waitEv[k] {
			if at < since {
				continue
			}
			if slices.Contains(waitLabels, l) {
				got[l] = true
			} else {
				other = append(other, w.party(k[0]).Name+"->"+w.party(k[1]).Name+" "+l)
			}
		}
	}
	var ls []string
	for _, l := range waitLabels {
		if got[l] {
			ls = append(ls, l)
		}
	}
	if len(ls) > 0 {
		return strings.Join(ls, "+")
	}
	sort.Strings(other)
	desc := []string{classify(ref), w.sideState(a, b), w.sideState(b, a)}
	if len(other) > 0 {
		desc = append(desc, "refused: "+strings.Join(other, ", "))
	}
	return "OTHER: " + strings.Join(desc, " | ")
}

// sideState: x's handshake state toward y, in a few words.
func (w *World) sideState(a, b PID) string {
	x := w.party(a)
	r := x.st.peer(b)
	if r == nil {
		return x.Name + ": no record"
	}
	var s []string
	if r.Cur == 0 {
		s = append(s, "demoted")
	}
	if r.Own != nil {
		s = append(s, "own "+map[bool]string{false: "rekey", true: "reconnect"}[r.Own.Reconnect])
	}
	if r.Pend != nil {
		s = append(s, "pending "+map[bool]string{false: "rekey", true: "reconnect"}[r.Pend.Reconnect])
	}
	for _, an := range r.Ans {
		s = append(s, "answer "+map[bool]string{false: "rekey", true: "reconnect"}[an.Reconnect])
	}
	if r.KeyFor != x.st.Relay {
		s = append(s, "S1")
	}
	if len(r.Held) > 0 {
		s = append(s, fmt.Sprintf("held %d", len(r.Held)))
	}
	if len(s) == 0 {
		s = append(s, "idle")
	}
	return x.Name + ": " + strings.Join(s, ", ")
}

// statWait counts a liveness failure of pair (a, b) by wait class: the
// class noted when the pair went stale, or the class now.
func (w *World) statWait(inv string, a, b PID, ref string) {
	if !w.relayRot {
		return
	}
	c, ok := w.staleClass[pairKey(a, b)]
	if !ok || !strings.HasPrefix(inv, "M2") {
		c = w.waitClass(a, b, ref)
	}
	w.stat("wait class " + inv + ": " + c)
}
