package trustmodel

import (
	"fmt"
	"os"
	"slices"
	"strings"
)

// VAULT-MESSAGING 0.90.0 §3.4.2 (vettid.org 6b1b4f5), "Relay-key rotation
// between vaults: the rules that close its wait cycles", RK1 to RK15, each
// rule behind its own switch. The switches act only between release-29
// parties (newSpec). TRUSTMODEL_CHOSEN=1 turns on the final set, every
// switch below; TRUSTMODEL_CH=<a,b,...> turns on single rules (and
// TRUSTMODEL_CH=-x with CHOSEN turns rule x off, for attribution). RK0
// (who advertises relay_follow) is an assumption, not a switch (doc.go).
// RK1 is release 29 as built and is always on. RK15 is not a rule: the
// randomized runs check it.
//
//   - G2B: RK2 (Q's tokens name P's key on Q's record: what the model
//     always did, issue mints for r.Relay), RK3 (a message on a carried
//     token is deposited with the key its sub names, if P holds it: hs.resp,
//     hs.fin, hs.confirm; S2 advances only at relay.token.issued, not on
//     carried or update tokens) and RK4 (S2's re-deposit only for entries
//     on held tokens), with §6.3.1's prompt to adopt.
//   - BINDL: RK5's binding L: the update carries P's identity links, sealed
//     afresh at each deposit, which Q applies first by Table B (with K4,
//     strict F1, H5 and R29-K9, on a duplicate too); if Table B refuses a
//     link, no relay link is followed.
//   - RK5: RK5's ik requirement: Q follows an update's relay links only if
//     the chain from the update's ik (the P-side signer of its epoch) ends
//     at Q's current ik for P, or that ik is current. With BINDL on and RK5
//     off, an I3 probe reports a follow that fails it.
//   - N1: RK6: Q, following a relay link, restarts its own open reconnect
//     whose hs.init carried tokens naming a passed key and that has sent no
//     hs.fin (not the one whose message made the follow); with no reconnect
//     token in the message followed, the restart waits for one for the new
//     mailbox, up to RK13's cap or 60 days after the follow.
//   - N2: RK7: between vaults, an hs.confirm under an epoch signed by Q's
//     current ik for P, and an hs.fin to an answer Q has open pinned to that
//     ik, pass the cut-off; the pass closes per epoch, once Q has accepted,
//     under that epoch or a later one, a message from a later relay key of
//     P's than the message's sender.
//   - L24: RK8, links in reconnects: during S1, P's reconnect hs.init
//     (from.relay K', deposited with K) and its hs.resp to Q's reconnect
//     carry the relay links K->K' and tokens minted by the mailbox of K'; Q
//     accepts them from K before or after the cut-off when the links
//     connect the sender to the announced key and pass rule C, and follows
//     at the verified hs.fin (hs.init) or after sig_R (hs.resp), identity
//     links first; it refuses the message superseded_relay if it has
//     followed P away from the announced key, or with rule U's reason. At
//     the second write, P restarts its open reconnects that announced K and
//     sent no hs.fin.
//   - R25: RK9: during S1 a token_revoked on a reconnect token for P's
//     earlier key is not a failed try and starts no S9 wait; "no reconnect
//     token" is not judged while P holds none only because of it, up to
//     RK13's cap.
//   - S9END: RK9's S9 at S1's end: a reconnect-token revocation is judged
//     only when S1 ends the pair stale (S9's feed item instead of the
//     stale's); S9's 24 hours still apply to a revoked standing token.
//   - R27: RK10: a definite refusal of a reconnect hs.init tied to rotation
//     (any in the side's own S1, or mailbox_unknown) ends the try at once
//     and counts as a failed try; the next try starts at a newer mailbox,
//     a new reconnect token or the refused try's expiry.
//     mailbox_unknown with no newer mailbox known is not counted: the side
//     waits for the links up to RK13's cap (in its own S1) or 60 days after
//     the first refusal, then becomes stale. Other refusals stay silent
//     (the next try at the try's 16-day expiry). An update Q refuses has
//     none of its links followed and none of its tokens kept (always).
//   - G4HS: RK11: while a side that followed its peer's relay link holds
//     tokens from the peer's current mailbox naming a newer relay key of its
//     own, it judges neither "no valid standing token" (§8.6) nor "no
//     reconnect token", until those tokens' exp or RK13's cap.
//   - RSEENSUSP: RK12: relay links that pass rule C in a message refused
//     at step 1 (a suspended record) are kept as seen, within rule C's cap
//     of 32 seen links per peer.
//   - S1PAUSE: RK13: S1's 30 days do not run while P has accepted, within
//     the last 16 days, an authenticated message from Q that passed dedupe
//     and the ts window (an hs.resp, an hs.fin or a message under an epoch;
//     a reconnect hs.init alone does not count), capped at 60 days after
//     the second write. The pause intervals are kept as ground truth (a
//     failed write does not roll them back). The cap also bounds RK6, RK9,
//     RK10 and RK11.
//   - GRACE14: RK14's grace: the relay's rotation grace is 14 days (the
//     model's default is 7).
//   - HOLD: RK14's hold: a durable entry refused mailbox_unknown is held
//     (one anchor per peer, relay_held's since) until a follow re-addresses
//     it (fresh ts, new seq), or since + 60 days, when every held entry
//     ends not delivered and the connection becomes stale; a handshake
//     message is not held; after the limit, mailbox_unknown ends an entry
//     at once until the episode resets at a follow.
//   - TELL: RK14's telling: Q keeps its 201'd entries 60 days and pins them
//     at a follow; P sends relay.mailbox.closed{mailbox, last_msg_id} when
//     its collects of an old mailbox end, a durable message under its epoch
//     (it waits for S2, and is held while P has no epoch); Q re-deposits
//     the pinned entries above last_msg_id (fresh ts) and counts
//     message.delivery_unconfirmed 60 days after the follow without one; P
//     keeps the inner ids from that mailbox for dedupe until 60 days after
//     the telling.
var chosenRules = []string{"N1", "N2", "G2B", "L24", "BINDL", "RK5", "GRACE14", "HOLD", "TELL", "S1PAUSE", "R25", "R27", "S9END", "G4HS", "RSEENSUSP"}

const (
	holdLimit  = 60 * day // RK14: the hold's limit
	s1PauseFor = 16 * day // RK13: the pause after an authenticated message
	s1Cap      = 60 * day // RK13: the cap, 60 days after the second write
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

// ---------- RK13: S1's pause ----------

// tsWindow is §8.4's durable ts window, 16 days back. Its 5 minutes ahead
// is not modelled: the model's clocks are skewed by up to a day.
const tsWindow = 16 * day

// noteAuth: q accepted M from r (RK13's pause). Only an authenticated
// message counts: a handshake message whose signature q verified (hs.resp,
// hs.fin) or a message under an epoch; a reconnect hs.init alone does not
// (its signature is checked only at its hs.fin). It must have passed
// dedupe (handle returns earlier for a duplicate) and the ts window. The
// model applies §8.4's ts window only here, and only its past bound:
// acceptance itself does not judge ts (a model limit). A message re-sent
// with its ts kept (the S2 re-deposit of an hs.fin, built without one)
// counts.
func (w *World) noteAuth(q *Party, r *PeerRec, M *Msg) {
	if q.Copy || !w.ch("S1PAUSE") {
		return
	}
	if M.Kind == KInit && M.Epoch == 0 {
		w.stat("S1PAUSE: a reconnect hs.init does not pause S1")
		return
	}
	if M.Ts != 0 && q.now()-M.Ts > tsWindow {
		w.stat("S1PAUSE: outside the ts window, does not pause S1")
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

// ---------- RK13's cap on the other waits ----------

// rk13Cap: the end of S1's clock toward r (RK13's cap, 60 days after the
// second write); ok is false when p is not in its own S1 toward r.
func (p *Party) rk13Cap(r *PeerRec) (int64, bool) {
	if r.KeyFor == p.st.Relay {
		return 0, false
	}
	return p.sinceAfter(r.KeyFor) + s1Cap, true
}

// waitCap: how long RK6's and RK10's waits last: RK13's cap for a side in
// its own S1, else 60 days from `from` (the follow, the first refusal).
func (p *Party) waitCap(r *PeerRec, from int64) int64 {
	if c, ok := p.rk13Cap(r); ok {
		return c
	}
	return from + s1Cap
}

// rk11Wait (RK11): p has followed r's relay link and holds tokens from r's
// current mailbox, kept under rule T, that name a relay key of p's newer
// than its key for r. Then p judges neither "no valid standing token"
// (§8.6) nor "no reconnect token" toward r, until those tokens' exp or
// RK13's cap for p's own rotation.
func (p *Party) rk11Wait(r *PeerRec) bool {
	if !p.w.ch("G4HS") || r.Device || p.Device || len(r.RChain) == 0 {
		return false
	}
	c, ok := p.rk13Cap(r)
	if !ok || p.w.Now > c {
		return false
	}
	return slices.ContainsFunc(r.Toks, func(t Token) bool {
		return t.Iss == r.Relay && p.keyRank(t.Sub) > p.keyRank(r.KeyFor) && t.valid(p.w.Now)
	})
}

// rk10Limit: RK10's wait for links after mailbox_unknown, with no newer
// mailbox known, reached its limit: the connection becomes stale as S1
// does.
func (p *Party) rk10Limit(r *PeerRec) {
	if r.WaitTok != 0 || r.WaitUntil != 0 || r.Relay != r.WaitBox || r.Status != stActive {
		return
	}
	if p.w.Now > p.waitCap(r, r.WaitSince) {
		p.w.stat("R27: no newer mailbox by the wait's limit")
		p.markStale(r, "R27: no newer mailbox by the wait's limit"+p.relayMoved(r))
		p.h5(r, -1)
	}
}

// ---------- RK8 and rule U: following relay links ----------

// links24: m announces a newer relay key of r's by links from its sender
// (RK8): they verify, connect the sender to the announced key, pass rule
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

// rk8Check: RK8, before Q follows a reconnect's relay links L announcing
// P's key pk: "" to go on, else the reason Q refuses the message with:
// superseded_relay when Q has already followed P away from pk, else rule
// U's reason when its checks fail. Every link already followed (pk is Q's
// current key for P) changes nothing and goes on.
func (q *Party) rk8Check(r *PeerRec, L []RLink, pk Key) string {
	if pk == r.Relay {
		return ""
	}
	if r.relayRank(pk) >= 0 {
		return "superseded_relay"
	}
	skip := 0
	for skip < len(L) && slices.Contains(r.RChain, L[skip]) {
		skip++
	}
	if skip == len(L) || L[skip].Old != r.Relay {
		return "relay_rollback"
	}
	for _, l := range L[skip:] {
		if r.keeps(l.New) {
			return "relay_rollback"
		}
	}
	return ""
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
		if by, ok := q.w.rlinkBy[l]; ok && !q.Copy && q.w.party(by.By).Copy {
			// ground truth: Q follows the old copy's own relay rotation as
			// P's (§3.4.1 Residuals, bullets 2 and 3), as followIK does
			// for an identity link
			q.w.markDead(q.ID, r.ID, resCopyRotated, "followed the copy's relay link")
		}
	}
	r.Relay = L[len(L)-1].New
	r.Toks = slices.DeleteFunc(r.Toks, func(t Token) bool { return t.Iss != r.Relay })
	q.holdFollow(r)      // RK14
	q.pinKept(r, passed) // RK14
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
		if r.reconnectTok(r.KeyFor, r.Relay, q.w.Now).JTI == 0 {
			// RK6: no reconnect token in the message followed: the restart
			// waits for one for P's new mailbox (startHS, tick)
			q.w.stat("RK6: restart waits (no reconnect token in the message followed)")
			r.RK6Since = q.w.Now
		}
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

// ---------- RK14's hold ----------

// holdMU: RK14, between two vaults, an outbox entry refused
// mailbox_unknown is held while the connection exists and p has not
// followed r to a newer mailbox. One anchor per peer (relay_held's since,
// the first refusal of the episode). A handshake message is not held: it
// ends as a refusal of its carried token does. After the hold's limit in
// this episode, mailbox_unknown ends an entry at once.
func (p *Party) holdMU(r *PeerRec, e *Entry) {
	w := p.w
	switch {
	case e.M.Kind == KInit || e.M.Kind == KResp || e.M.Kind == KFin:
		e.Ended = true
		w.stat("HOLD: handshake message refused mailbox_unknown ends")
	case r.HoldOver:
		e.Ended = true
		w.stat("HOLD: mailbox_unknown after the hold's limit ends the entry")
		p.notDelivered(e, "not delivered: mailbox_unknown after the hold's limit")
	default:
		e.HeldMU = true
		if r.HoldSince == 0 {
			r.HoldSince = w.Now
			w.stat("HOLD: relay_held set")
		}
	}
}

// notDelivered: an entry ends not delivered (§8.3 case 5,
// message.not_delivered).
func (p *Party) notDelivered(e *Entry, fate string) {
	if e.M.Kind == KSession && e.M.Probe > 0 && !p.Copy && p.w.probeFate[e.M.Probe] == "" {
		p.w.probeFate[e.M.Probe] = fate
	}
}

// holdLimit: RK14, at relay_held's since + 60 days every entry held for r
// ends, not delivered, and the connection becomes stale.
func (p *Party) holdLimitTick(r *PeerRec) {
	w := p.w
	if !w.ch("HOLD") || r.HoldSince == 0 || w.Now < r.HoldSince+holdLimit {
		return
	}
	for i := range p.st.Out {
		e := &p.st.Out[i]
		if e.To == r.ID && e.HeldMU && !e.Done && !e.Ended {
			e.Ended = true
			w.stat("HOLD: ended at the hold's limit (not delivered)")
			p.notDelivered(e, "not delivered: the hold's limit")
		}
	}
	r.HoldSince, r.HoldOver = 0, true
	if r.Status == stActive {
		w.stat("HOLD: stale at the hold's limit")
		p.markStale(r, "RK14: the hold's limit")
		p.h5(r, -1)
	}
}

// relayMoved: RK14 "When both sides' old mailboxes end": p, in its own S1
// toward r, still holds deposits to r refused mailbox_unknown when S1 (or
// RK10's wait for links) ends the connection stale: the stale's reason is
// relay_moved.
func (p *Party) relayMoved(r *PeerRec) string {
	if !p.w.ch("HOLD") || r.KeyFor == p.st.Relay {
		return ""
	}
	if slices.ContainsFunc(p.st.Out, func(e Entry) bool { return e.To == r.ID && e.HeldMU && !e.Done && !e.Ended }) {
		p.w.stat("HOLD: stale with reason relay_moved")
		return " (relay_moved)"
	}
	return ""
}

// holdFollow: RK14, at a follow the hold episode ends: the held entries are
// re-addressed to the new mailbox, each with a fresh ts and a new seq (a
// mailbox_unknown proves the relay never stored it: not tried).
func (q *Party) holdFollow(r *PeerRec) {
	if !q.w.ch("HOLD") {
		return
	}
	for i := range q.st.Out {
		e := &q.st.Out[i]
		if e.To == r.ID && e.HeldMU && !e.Done && !e.Ended {
			e.HeldMU, e.Tried, e.Indef = false, false, false
			e.M.Ts = q.now()
			q.w.stat("HOLD: held entry re-addressed at a follow")
		}
	}
	if r.HoldSince != 0 || r.HoldOver {
		q.w.stat("HOLD: relay_held ends at a follow")
	}
	r.HoldSince, r.HoldOver = 0, false
}

// ---------- RK5's ik requirement ----------

// rk5OK: RK5, after the update's identity links are applied, the chain
// from the update's ik (the P-side signer of the epoch it travels under)
// ends at Q's current ik for P, or the update's ik is that ik.
func (q *Party) rk5OK(r *PeerRec, m *RMsg) bool {
	ep := r.epoch(m.P.Epoch)
	if ep == nil {
		return false
	}
	if ep.Signer == r.IK {
		return true
	}
	L := m.P.Rot
	if len(L) == 0 || L[0].Old != ep.Signer || L[len(L)-1].New != r.IK {
		return false
	}
	for i := 1; i < len(L); i++ {
		if L[i].Old != L[i-1].New {
			return false
		}
	}
	return true
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
		return e.To == to && (e.HoldSince != 0 || e.HeldMU) && !e.Done && !e.Ended
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

// ---------- RK14's telling (TELL) ----------

const keepFor = 60 * day // RK14 step 3: Q's window and pin; step 2: P's dedupe after the telling

// tell: mailbox k ended at the relay with msgs in it. Its owner's collects
// of k have ended (at the grace's end, or earlier with mailbox_unknown, or
// when the key was deleted), and P records last_msg_id: every message
// still in k when it ended P never acked, and the relay's msg_ids are in
// arrival order, so it is the smallest such id less one (the relay's last
// id if none). Model shortcut: P's record is made here, in its stored
// state, and P sends the telling at its next tick (an unlocked P's write).
func (w *World) tell(k Key, msgs []*RMsg) {
	if !w.ch("TELL") {
		return
	}
	o := w.keyOwner(k)
	if o < 0 || w.party(o).Copy || w.party(o).Device {
		return
	}
	owner := w.party(o)
	last := w.R.next
	for _, m := range msgs {
		last = min(last, m.ID-1)
	}
	t := tellRec{Box: k, Last: last}
	owner.st.ToTell = append(owner.st.ToTell, t)
	owner.stored.ToTell = append(owner.stored.ToTell, t)
	w.stat("TELL: collects of an old mailbox ended")
}

// sendTellings: RK14 step 2, P sends each connection to a vault
// relay.mailbox.closed{mailbox, last_msg_id}, a separate durable message
// under its then-current epoch (it waits for S2 during S1, and is held
// while P has no epoch). P keeps the inner ids it processed from that
// mailbox for dedupe until 60 days after.
func (p *Party) sendTellings() {
	if len(p.st.ToTell) == 0 {
		return
	}
	for _, t := range p.st.ToTell {
		for i := range p.st.Peers {
			r := &p.st.Peers[i]
			if r.Device || r.Status != stActive {
				continue
			}
			p.enqueue(r.ID, Msg{Kind: KClosed, ClosedBox: t.Box, LastMsgID: t.Last}, nil)
			p.w.stat("TELL: relay.mailbox.closed queued")
		}
		if p.st.DedupeEnd == nil {
			p.st.DedupeEnd = map[Key]int64{}
		}
		p.st.DedupeEnd[t.Box] = p.w.Now + keepFor
	}
	p.st.ToTell = nil
}

// noteSeenBox: P keeps, per mailbox, the inner ids it processed (so their
// dedupe can end 60 days after that mailbox's telling). Ground truth
// counts a message processed again after its dedupe ended (tickKept).
func (q *Party) noteSeenBox(m *RMsg) {
	w := q.w
	if !w.ch("TELL") {
		return
	}
	if q.st.SeenBox == nil {
		q.st.SeenBox = map[int]Key{}
	}
	q.st.SeenBox[m.P.Inner] = m.Box
	if !q.Copy && w.dedupeEnded[[2]int{int(q.ID), m.P.Inner}] {
		w.stat("TELL: a message processed again after its dedupe ended")
	}
}

// keep201: RK14 step 3, Q keeps an entry the relay accepted into a peer
// vault's mailbox, with its msg_id, for 60 days (durable messages that are
// deposited again as they are: not an update, which is never re-deposited
// as the same bytes, and not a handshake message).
func (p *Party) keep201(e *Entry, r *PeerRec, box Key, id int) {
	if !p.w.ch("TELL") || p.Device || r.Device {
		return
	}
	switch e.M.Kind {
	case KSession, KIdRot, KClosed:
	default:
		return
	}
	p.st.Kept = append(p.st.Kept, Kept{To: e.To, Box: box, MsgID: id, M: cloneMsg(e.M), At: p.w.Now})
}

// pinKept: RK14 step 3, Q follows P away from the mailboxes passed: it pins
// the entries it still keeps for them, until P's relay.mailbox.closed or
// 60 days after this follow.
func (q *Party) pinKept(r *PeerRec, passed []Key) {
	if !q.w.ch("TELL") {
		return
	}
	for i := range q.st.Kept {
		k := &q.st.Kept[i]
		if k.To == r.ID && k.PinUntil == 0 && slices.Contains(passed, k.Box) {
			k.PinUntil = q.w.Now + keepFor
			q.w.stat("TELL: entry pinned at a follow")
		}
	}
}

// closedFrom: RK14 steps 4 and 5, Q acts on relay.mailbox.closed only for a
// mailbox of P's it has followed P away from: it deposits again every
// pinned entry above last_msg_id (same inner id, fresh ts, a new seq, sealed
// under the epoch current then) and drops the rest. Otherwise it acks and
// ignores it.
func (q *Party) closedFrom(r *PeerRec, M *Msg, cell string) dec {
	w := q.w
	away := M.ClosedBox != r.Relay && slices.ContainsFunc(r.RChain, func(l RLink) bool { return l.Old == M.ClosedBox })
	if !away {
		w.stat("TELL: relay.mailbox.closed ignored (not a mailbox followed away from)")
		return dec{"ignore", "", cell + ":not-followed-away"}
	}
	q.st.Kept = slices.DeleteFunc(q.st.Kept, func(k Kept) bool {
		if k.To != r.ID || k.Box != M.ClosedBox || k.PinUntil == 0 {
			return false
		}
		if k.MsgID > M.LastMsgID {
			m := cloneMsg(k.M)
			m.Ts, m.Epoch = q.now(), 0
			q.st.Out = append(q.st.Out, Entry{ID: w.id(), To: r.ID, M: m})
			w.stat("TELL: re-deposited after the telling")
		} else {
			w.stat("TELL: pinned entry dropped (P collected it)")
		}
		return true
	})
	return dec{"accept", "", cell}
}

// tickKept: the end of Q's window (silently) and of a pin with no telling
// (message.delivery_unconfirmed, RK14 step 6); and the end of P's dedupe
// for a told mailbox.
func (p *Party) tickKept() {
	w := p.w
	if !w.ch("TELL") {
		return
	}
	p.st.Kept = slices.DeleteFunc(p.st.Kept, func(k Kept) bool {
		switch {
		case k.PinUntil != 0 && w.Now > k.PinUntil:
			w.stat("TELL: delivery_unconfirmed (no telling 60 days after the follow)")
			return true
		case k.PinUntil == 0 && w.Now > k.At+keepFor:
			return true
		}
		return false
	})
	for in, box := range p.st.SeenBox {
		if end, ok := p.st.DedupeEnd[box]; ok && w.Now > end {
			delete(p.st.Seen, in)
			delete(p.st.SeenBox, in)
			if !p.Copy {
				if w.dedupeEnded == nil {
					w.dedupeEnded = map[[2]int]bool{}
				}
				w.dedupeEnded[[2]int{int(p.ID), in}] = true
			}
		}
	}
}

// msgEpoch (RK7): the epoch a message from P travels under; an hs.resp
// or hs.fin, the one its handshake makes.
func msgEpoch(M *Msg) int {
	if M.Epoch == 0 && (M.Kind == KResp || M.Kind == KFin) {
		return M.NewEpoch
	}
	return M.Epoch
}

// noteAccKey (RK7): Q accepted M from P's relay key sender.
func (r *PeerRec) noteAccKey(M *Msg, sender Key) {
	ep, rk := msgEpoch(M), r.relayRank(sender)
	if ep == 0 || rk < 0 {
		return
	}
	for i := range r.AccKeys {
		if r.AccKeys[i].Ep == ep {
			r.AccKeys[i].Rank = max(r.AccKeys[i].Rank, rk)
			return
		}
	}
	r.AccKeys = append(r.AccKeys, accKey{ep, rk})
}

// n2: N2 (RK7), an hs.confirm or an hs.fin to an answer Q has open passes
// the cut-off of P's earlier key m came from. The pass closes per epoch:
// once Q has accepted, under that epoch or a later one, a message from a
// relay key of P's later than m's sender.
func (q *Party) n2(r *PeerRec, m *RMsg) bool {
	ok, closed := q.n2Pass(r, m)
	if closed {
		q.w.stat("N2: pass closed (a later key accepted under this epoch or a later one)")
	}
	if ok {
		q.w.stat("N2: " + kindName[m.P.Kind] + " passes the cut-off")
	}
	return ok
}

// n2Pass is n2 without side effects (steps14 asks it too); closed: the
// pass had closed for the message's epoch.
func (q *Party) n2Pass(r *PeerRec, m *RMsg) (ok, closed bool) {
	M := m.P
	if !q.w.ch("N2") || q.Device || r.Device {
		return false, false
	}
	ep, rk := msgEpoch(M), r.relayRank(m.Sender)
	for _, a := range r.AccKeys {
		if a.Ep >= ep && a.Rank > rk {
			return false, true
		}
	}
	switch M.Kind {
	case KConfirm:
		ep := r.epoch(M.Epoch)
		ok = ep != nil && ep.Signer == r.IK
	case KFin:
		for _, a := range r.Ans {
			ok = ok || (a.ID == M.HS && a.PeerIK == r.IK && M.Sig == a.PeerIK)
		}
	}
	return ok, false
}

// refusedReconnect: RK10, a definite refusal of my reconnect hs.init.
// Only a refusal tied to rotation is covered: any while I am in my own S1
// toward P, or mailbox_unknown (token_revoked on a reconnect token for an
// earlier key of mine is RK9's, R25). Any other stays silent: the try
// stays open, and the next one comes at its 16-day expiry (tick). A
// covered refusal ends the try at once. mailbox_unknown for P's mailbox
// as I know it, with no newer one known, is not counted: I wait for P's
// links, up to RK13's cap (in my own S1) or 60 days after the first such
// refusal. Any other covered refusal is a failed try of the reconnect
// bound; the next try starts at a newer mailbox (at once after
// mailbox_unknown), a new reconnect token, or the refused try's expiry.
func (p *Party) refusedReconnect(r *PeerRec, e *Entry, box Key, tok Token, err relayErr) {
	w := p.w
	o := r.Own
	if o == nil || !o.Reconnect || o.ID != e.M.HS {
		return
	}
	if r.KeyFor == p.st.Relay && err != mailboxUnknown {
		w.stat("R27: refusal not tied to rotation: silent, next try at the try's expiry (" + string(err) + ")")
		return
	}
	p.abandonOwn(r)
	wait := func(jti int, until int64) {
		if r.WaitBox == 0 {
			r.WaitSince = w.Now
		}
		r.WaitBox, r.WaitTok, r.WaitUntil = box, jti, until
	}
	if err == mailboxUnknown && box == r.Relay {
		w.stat("R27: refused at an earlier mailbox, no newer known: waits for the links")
		w.noteWait(p.ID, r.ID, "G9W")
		wait(0, 0)
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
	wait(tok.JTI, o.Started+w.hsLifeFor(true))
}
