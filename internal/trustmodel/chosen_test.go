package trustmodel

import (
	"fmt"
	"os"
	"slices"
	"strings"
)

// The relay-key rotation design the owner chose on 2026-11-12
// (vettid.org RELAY-KEY-ROTATION.md, draft 7 at 610585f, §2, §3.3, §7),
// each rule behind its own switch (the note's §6 step 1). The switches act
// only between release-29 parties (newSpec). TRUSTMODEL_CHOSEN=1 turns on
// the whole chosen set; TRUSTMODEL_CH=<a,b,...> turns on single rules (and
// TRUSTMODEL_CH=-x with CHOSEN turns rule x off). G2BX is not part of the
// chosen set: it is the candidate fix of 7.16 (1).
//
//   - N1: Q, following a relay link, restarts its own open reconnect whose
//     hs.init carried tokens naming the passed key and that has sent no
//     hs.fin (not the one whose message made the follow).
//   - N2: between vaults, while Q has accepted no message from P's newer
//     key, an hs.confirm under an epoch signed by Q's current ik for P, and
//     an hs.fin to an answer Q has open pinned to that ik, pass the cut-off.
//   - G2B: rule 1 (a message P sends on a carried token is deposited with
//     the key the token's sub names, if P holds it: hs.resp, hs.fin,
//     hs.confirm), the signal unchanged (S2 advances only on
//     relay.token.issued, not on carried or update tokens), and §6.3.1's
//     prompt to adopt (the initiator, confirming a reconnect, queues
//     relay.token.issued under the new epoch). Rule 0 (Q's tokens name P's
//     key on Q's record) is what the model always did (issue mints for
//     r.Relay).
//   - L24: 2.4, links in reconnects: during S1, P's reconnect hs.init
//     (from.relay K', deposited with K) and its hs.resp to Q's reconnect
//     carry the relay links K->K' and tokens minted by K”s mailbox (rule
//     4); Q accepts them from K before or after the cut-off when the links
//     connect the sender to the announced key and pass rule C, and follows
//     at the verified hs.fin (hs.init) or at sig_R (hs.resp). At the second
//     write, P restarts its open reconnects that announced K and sent no
//     hs.fin.
//   - BINDL: binding L, the update carries P's ik links (sealed afresh at
//     each deposit, as the model always did), which Q applies first by
//     Table B (with K4, strict F1, H5 and R29-K9, on a duplicate too); if
//     Table B refuses a link, no relay link is followed.
//   - GRACE14: the relay's rotation grace is 14 days (was 7).
//   - HOLD: Q's deposits refused mailbox_unknown are held (the model never
//     ended them) for at most 60 days, then told (message.not_delivered).
//   - TELL: relay.mailbox.closed. Approximation: when an old mailbox ends,
//     each message in it that its owner never collected is queued again by
//     its sender (same inner id, deduped by the receiver) at once, if the
//     owner then has a current epoch with the sender; otherwise it is lost
//     (conservative: the real telling would wait under the epoch to come,
//     and the hop it takes is not modelled).
//   - S1PAUSE: S1's 30 days do not run while P has accepted an
//     authenticated message from Q in the last 16 days, capped at 60 days
//     after the second write. The pause intervals are kept as ground truth
//     (a failed write does not roll them back).
//   - R25: 2.5, during S1 a token_revoked on a reconnect token for P's
//     earlier key is not a failed try, starts no S9 clock, and the "no
//     reconnect token" judgement is suspended while P holds none only
//     because of it.
//   - R27: 2.7, a definite refusal (not 429, not quota_exceeded, which
//     stays K6's stale) of a reconnect hs.init is a failed try at once; the
//     next try starts once a newer mailbox (or another reconnect token) is
//     known; mailbox_unknown for P's earlier mailbox while Q knows no newer
//     one is not counted, and Q waits for the links at most 60 days (the
//     hold's limit). An update refused only because its epoch is demoted or
//     destroyed has its links applied (ik links first, then relay links),
//     its tokens not taken.
//   - S9END: S9 at S1's end: no 24-hour clock; when S1 ends a pair stale
//     and a token for an earlier key was revoked, the member gets S9's text
//     (counted; the stale is visible either way).
//   - G2BXA (measurement variant of G2BX): the same for a record that is
//     not demoted.
//   - G2BX (candidate, not chosen): a demoted Q's reconnect may use a held
//     reconnect token naming a newer key of Q's (deposited with that key);
//     Q keeps the reconnect tokens of an update or relay.token.issued it
//     refuses under a demoted epoch (held, no S2).
var chosenRules = []string{"N1", "N2", "G2B", "L24", "BINDL", "GRACE14", "HOLD", "TELL", "S1PAUSE", "R25", "R27", "S9END"}

const (
	holdLimit  = 60 * day // 3.3: the Q-side hold
	s1PauseFor = 16 * day // 7.10 b
	s1Cap      = 60 * day // 7.10 b
)

// loadChosen sets the switches from the environment.
func (w *World) loadChosen() {
	w.chosen = map[string]bool{}
	if os.Getenv("TRUSTMODEL_CHOSEN") != "" {
		for _, r := range chosenRules {
			w.chosen[r] = true
		}
	}
	for _, x := range strings.Split(os.Getenv("TRUSTMODEL_CH"), ",") {
		x = strings.TrimSpace(x)
		switch {
		case x == "":
		case strings.HasPrefix(x, "-"):
			delete(w.chosen, x[1:])
		default:
			w.chosen[x] = true
		}
	}
}

// ch: rule x of the chosen set is on (release-29 parties only).
func (w *World) ch(x string) bool { return w.optA && w.chosen[x] }

// grace: the relay's rotation grace.
func (w *World) grace() int64 {
	if w.ch("GRACE14") {
		return 14 * day
	}
	return graceLen
}

// ---------- S1's pause (7.10 b) ----------

// noteAuth: q accepted an authenticated message from r.
func (w *World) noteAuth(q *Party, r *PeerRec) {
	if q.Copy {
		return
	}
	k := [2]PID{q.ID, r.ID}
	iv := w.s1Pause[k]
	a := w.Now
	if n := len(iv); n > 0 && iv[n-1][1] >= a {
		iv[n-1][1] = max(iv[n-1][1], a+s1PauseFor)
	} else {
		iv = append(iv, [2]int64{a, a + s1PauseFor})
	}
	w.s1Pause[k] = iv
}

// s1Expired: S1 toward r, counted from since (P's second write), is over.
func (w *World) s1Expired(p *Party, r *PeerRec, since int64) bool {
	el := w.Now - since
	if !w.ch("S1PAUSE") {
		return el > staleAfter
	}
	if el > s1Cap {
		return true
	}
	paused := int64(0)
	for _, x := range w.s1Pause[[2]PID{p.ID, r.ID}] {
		a, b := max(x[0], since), min(x[1], w.Now)
		if b > a {
			paused += b - a
		}
	}
	return el-paused > staleAfter
}

// ---------- 2.4 and rule U: following relay links ----------

// links24: m announces a newer relay key of r's by links from its sender
// (2.4): they verify, connect the sender to the announced key, pass rule
// C, and the announced key is Q's current one or is reached through them.
func (q *Party) links24(r *PeerRec, m *RMsg) bool {
	M := m.P
	if !q.w.ch("L24") || q.Device || r.Device || M.RelayPK == 0 {
		return false
	}
	L := M.RLinks
	ok := len(L) >= 1 && len(L) <= 32 && L[0].Old == m.Sender && L[len(L)-1].New == M.RelayPK
	for i := 1; ok && i < len(L); i++ {
		ok = L[i].Old == L[i-1].New
	}
	for _, l := range L {
		if _, made := q.w.rlinkBy[l]; !made {
			ok = false
		}
	}
	if !ok {
		return false
	}
	if _, bad := r.relayConflict(L); bad {
		return false
	}
	if M.RelayPK == r.Relay {
		return true
	}
	skip := 0
	for skip < len(L) && slices.Contains(r.RChain, L[skip]) {
		skip++
	}
	return skip < len(L) && L[skip].Old == r.Relay
}

// followRelay: Q follows P's relay links L (rule U's state write without
// the update's tokens): the passed keys get this cut-off, the new key is
// current, relay.token.issued is queued, the reconnect tokens issued to the
// passed keys are revoked, and N1 restarts Q's own reconnect. It reports
// whether anything was followed.
func (q *Party) followRelay(r *PeerRec, L []RLink, pos Pos, by int) bool {
	return q.followRelayThen(r, L, pos, nil)
}

// followRelayThen is followRelay; then runs after the new key is current and
// before relay.token.issued is queued (rule U keeps the update's tokens there).
func (q *Party) followRelayThen(r *PeerRec, L []RLink, pos Pos, then func()) bool {
	q.lastPassed = nil
	skip := 0
	for skip < len(L) && slices.Contains(r.RChain, L[skip]) {
		skip++
	}
	if skip == len(L) || L[skip].Old != r.Relay {
		return false
	}
	for _, l := range L[skip:] {
		if r.keeps(l.New) {
			return false
		}
	}
	for _, l := range r.RChain {
		if l.Old == L[len(L)-1].New {
			q.w.violate("I3", "%s makes current relay key %d it followed away from", q.Name, l.Old)
		}
	}
	var revoke = map[Key][]int{}
	var passed []Key
	for _, l := range L[skip:] {
		until := q.w.Now
		for _, t := range r.Issued {
			if t.Sub == l.Old && !t.Reconnect && t.Exp > until {
				until = t.Exp
			}
			if t.Sub == l.Old && t.Reconnect {
				revoke[t.Iss] = append(revoke[t.Iss], t.JTI)
			}
		}
		r.Earlier = append(r.Earlier, Earlier{Key: l.Old, Cut: pos, Until: until})
		r.RChain = append(r.RChain, l)
		passed = append(passed, l.Old)
	}
	r.Relay = L[len(L)-1].New
	r.Toks = slices.DeleteFunc(r.Toks, func(t Token) bool { return t.Iss != r.Relay })
	if then != nil {
		then()
	}
	q.enqueue(r.ID, Msg{Kind: KTokIssued, Toks: []Token{{}, {Reconnect: !r.Device}}}, nil)
	for box, jtis := range revoke {
		q.revokeAt(box, jtis)
	}
	if len(revoke) > 0 && !q.Copy {
		q.w.revokedRC[[2]PID{q.ID, r.ID}] = true // ground truth for G4F
	}
	q.lastPassed = passed
	return true
}

// n1: N1, after a follow (and after the tokens of its message are kept):
// Q restarts its own open reconnect whose hs.init carried tokens naming a
// passed key and that has sent no hs.fin, unless its message made the
// follow (by).
func (q *Party) n1(r *PeerRec, by int) {
	passed := q.lastPassed
	q.lastPassed = nil
	if !q.w.ch("N1") || len(passed) == 0 {
		return
	}
	if o := r.Own; o != nil && o.Reconnect && !o.FinSent && o.ID != by &&
		slices.ContainsFunc(o.Toks, func(t Token) bool { return slices.Contains(passed, t.Sub) }) {
		q.w.stat("N1: own reconnect restarted at a follow")
		q.abandonOwn(r)
		q.w.nextOrigin = "N1 restart"
		q.startHS(r, true)
	}
}

// updateIK: binding L, the update's ik links first (Table B, with K4,
// strict F1, H5 and R29-K9, on a duplicate too). stop: refuse or suspend.
func (q *Party) updateIK(r *PeerRec, M *Msg, pos Pos) (dec, bool) {
	if !q.w.ch("BINDL") || len(M.Rot) == 0 {
		return dec{}, false
	}
	d := q.tableBRotate(r, M, pos)
	switch d.Out {
	case "suspend":
		return d, true
	case "refuse":
		q.w.stat("BINDL: update refused by Table B")
		return refuse(d.Reason, "BINDL:"+d.Cell), true
	}
	return dec{}, false
}

// refusedUpdateLinks: 2.7, an update refused only because its epoch is
// demoted or destroyed still has its links applied (ik links first, then
// the relay links); its tokens are not taken (G2BX: its reconnect tokens
// are held).
func (q *Party) refusedUpdateLinks(r *PeerRec, m *RMsg, pos Pos, no dec) dec {
	M := m.P
	if !q.w.ch("R27") || q.Device || r.Device {
		return no
	}
	if d, stop := q.updateIK(r, M, pos); stop {
		if d.Out == "suspend" {
			return d
		}
		return no
	}
	if r.Status != stActive {
		return no
	}
	L := M.RLinks
	ok := len(L) >= 1 && L[0].Old == m.Sender && L[len(L)-1].New == M.RelayPK
	for i := 1; ok && i < len(L); i++ {
		ok = L[i].Old == L[i-1].New
	}
	for _, l := range L {
		if _, made := q.w.rlinkBy[l]; !made {
			ok = false
		}
	}
	if ok && q.followRelay(r, L, pos, 0) {
		q.w.stat("R27: links of a refused update followed")
		no.Cell += ":links-followed"
	}
	q.holdRCTokens(r, M.Toks)
	q.n1(r, 0)
	return no
}

// holdRCTokens: G2BX, Q keeps the reconnect tokens of a message it refuses
// under a demoted epoch (held; they move no S2).
func (q *Party) holdRCTokens(r *PeerRec, toks []Token) {
	if !q.w.ch("G2BX") {
		return
	}
	kept, _ := q.ruleT(r, toks, r.Relay)
	for _, t := range kept {
		if t.Reconnect && !slices.ContainsFunc(r.Toks, func(x Token) bool { return x.JTI == t.JTI }) && !slices.Contains(r.RevokedJTI, t.JTI) {
			r.Toks = append(r.Toks, t)
			q.w.stat("G2BX: reconnect token held from a refused message")
		}
	}
}

// ---------- rule 1 (G2-B) ----------

// carried: rule 1, an entry sent on a carried token goes with the key its
// sub names, to the token's mailbox, if p still holds that key.
func (p *Party) carried(r *PeerRec, toks []Token) func(*Entry) {
	if !p.w.ch("G2B") {
		return nil
	}
	for _, t := range toks {
		if !t.Reconnect && t.Sub != r.KeyFor && p.holds(t.Sub) && t.Iss == r.Relay {
			p.w.stat("G2B: rule 1 deposit key from a carried token")
			return func(e *Entry) { e.Tok, e.With, e.Box = t, t.Sub, t.Iss }
		}
	}
	return nil
}

// g2bxToken: G2BX, a demoted p's reconnect may go on a held reconnect token
// naming a newer key of p's, deposited with that key.
func (p *Party) g2bxToken(r *PeerRec) Token {
	if !(p.w.ch("G2BX") && r.Cur == 0) && !p.w.ch("G2BXA") {
		return Token{}
	}
	for _, t := range r.Toks {
		if t.Reconnect && t.Iss == r.Relay && t.Sub != r.KeyFor && p.holds(t.Sub) && t.valid(p.w.Now) &&
			!slices.Contains(r.RevokedJTI, t.JTI) {
			return t
		}
	}
	return Token{}
}

// ---------- 7.16 measurements ----------

// g4f: G4 "after P followed Q" at Q (demoted, in its own S1 toward P,
// holding no usable reconnect token) while P followed Q's update and its
// rule U revoked Q's old-key reconnect token.
func (w *World) g4f(q *Party, r *PeerRec) bool {
	p := w.party(r.ID)
	rp := p.st.peer(q.ID)
	return r.Cur == 0 && r.KeyFor != q.st.Relay && rp != nil && rp.Relay == q.st.Relay && w.revokedRC[[2]PID{p.ID, q.ID}]
}

// waiting: q holds deposits for r refused mailbox_unknown (7.16.2).
func (q *Party) waiting(to PID) bool {
	r := q.st.peer(to)
	if r == nil || r.Status != stActive {
		return false
	}
	return slices.ContainsFunc(q.st.Out, func(e Entry) bool {
		return e.To == to && e.HoldSince != 0 && !e.Done && !e.Ended
	})
}

// s1StaleGap: P ended the pair stale by S1; 7.16.2 and 7.16.3.
func (w *World) s1StaleGap(p *Party, r *PeerRec) {
	if p.Copy || !w.relayRot {
		return
	}
	q := w.party(r.ID)
	k := [2]PID{p.ID, q.ID}
	if q.waiting(p.ID) {
		w.gapOpen[k] = w.Now
		w.stat("7.16.2: S1 stale while the other side waits")
	} else {
		w.stat("7.16.2: S1 stale, the other side not waiting")
	}
	if _, held := w.k5Since[[2]PID{q.ID, p.ID}]; held {
		w.stat("7.16.3: S1 stale while the other side's S-a guard waits")
	}
}

// gapCheck closes the 7.16.2 gaps that ended (end: the run is over).
func (w *World) gapCheck(end bool) {
	for k, t0 := range w.gapOpen {
		q := w.party(k[1])
		if q.waiting(k[0]) && !end {
			continue
		}
		why := "the other side stopped waiting"
		if r := q.st.peer(k[0]); r != nil && r.Status != stActive {
			why = "the other side ended the pair too"
		} else if end {
			why = "still waiting at the end"
		}
		w.stat(fmt.Sprintf("7.16.2 gap %s: %s", gapBucket(w.Now-t0), why))
		delete(w.gapOpen, k)
	}
}

func gapBucket(d int64) string {
	switch {
	case d < day:
		return "a <1d"
	case d < 7*day:
		return "b 1-7d"
	case d < 14*day:
		return "c 7-14d"
	case d < 30*day:
		return "d 14-30d"
	case d < 60*day:
		return "e 30-60d"
	}
	return "f >=60d"
}

// tell: TELL, mailbox k of its owner ended with msgs uncollected: each
// sender queues them again, same inner id (see the switch's comment).
func (w *World) tell(k Key, msgs []*RMsg) {
	if !w.ch("TELL") {
		return
	}
	o := w.keyOwner(k)
	if o < 0 || w.party(o).Copy {
		return
	}
	owner := w.party(o)
	for _, m := range msgs {
		x := w.party(m.Actor)
		if x.Copy || x.ID == owner.ID || m.P.Kind == KUpdate {
			continue // an update is never re-deposited as the same bytes (2.6): (b)'s resends carry it
		}
		ro, rx := owner.st.peer(x.ID), x.st.peer(owner.ID)
		if ro == nil || rx == nil || ro.Status != stActive || rx.Status != stActive {
			continue
		}
		if ro.Cur == 0 {
			w.stat("TELL: lost (no epoch at the owner to tell under)")
			continue
		}
		w.stat("TELL: re-deposited after the telling")
		// the re-deposit is queued in the sender's stored state (the telling
		// is handled in a write; ground truth, not a party's own step here)
		e := Entry{ID: w.id(), To: owner.ID, M: cloneMsg(*m.P)}
		x.st.Out = append(x.st.Out, e)
		e.M = cloneMsg(e.M)
		x.stored.Out = append(x.stored.Out, e)
		x.storedOut[e.ID] = true
		if w.ever[x.ID] == nil {
			w.ever[x.ID] = map[int]bool{}
		}
		w.ever[x.ID][e.ID] = true
	}
}

// n2: N2, an hs.confirm or an hs.fin to an answer Q has open passes the
// cut-off of P's earlier key m came from.
func (q *Party) n2(r *PeerRec, m *RMsg) bool {
	M := m.P
	if !q.w.ch("N2") || q.Device || r.Device {
		return false
	}
	for _, e := range r.Earlier {
		if e.Key == m.Sender && e.NewerSeen {
			return false
		}
	}
	ok := false
	switch M.Kind {
	case KConfirm:
		ep := r.epoch(M.Epoch)
		ok = ep != nil && ep.Signer == r.IK
	case KFin:
		for _, a := range r.Ans {
			ok = ok || (a.ID == M.HS && a.PeerIK == r.IK && M.Sig == a.PeerIK)
		}
	}
	if ok {
		q.w.stat("N2: " + kindName[M.Kind] + " passes the cut-off")
	}
	return ok
}

// refusedReconnect: 2.7, a definite refusal of my reconnect hs.init ends
// that try at once. mailbox_unknown for P's earlier mailbox while I know no
// newer one is not counted (I wait for the links, at most the hold's
// limit); otherwise it is a failed try of the reconnect bound, and the
// next try starts once a newer mailbox or another reconnect token is known.
func (p *Party) refusedReconnect(r *PeerRec, e *Entry, box Key, tok Token, err relayErr) {
	w := p.w
	o := r.Own
	if o == nil || !o.Reconnect || o.ID != e.M.HS {
		return
	}
	p.abandonOwn(r)
	wait := func(jti int) {
		if r.WaitBox == 0 {
			r.WaitSince = w.Now
		}
		r.WaitBox, r.WaitTok = box, jti
	}
	if err == mailboxUnknown && box == r.Relay {
		w.stat("R27: refused at an earlier mailbox, no newer known: waits for the links")
		w.noteWait(p.ID, r.ID, "G9W")
		wait(0)
		return
	}
	if o.Ctx != r.RCNamed {
		r.RCNamed, r.RCFails = o.Ctx, 0
	}
	r.RCFails++
	w.stat("R27: refused reconnect hs.init is a failed try (" + string(err) + ")")
	w.hit("K6:try-failed")
	if r.RCFails >= 3 {
		w.hit("K6:third-failure-stale")
		p.markStale(r, "K6: third failed try")
		p.h5(r, -1)
		return
	}
	if r.Relay != box {
		p.wantReconnect(r) // a newer mailbox is known: the next try now
		return
	}
	w.noteWait(p.ID, r.ID, "G9W")
	wait(tok.JTI)
}
