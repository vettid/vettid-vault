package trustmodel

import (
	"fmt"
	"slices"
)

// The receiving side: acceptFrom (§3.4.1), Tables A and B, rules C, U, T,
// H5, "Epochs after an ik link", and the handlers it feeds.

type dec struct {
	Out    string // accept, follow, answer, ignore, refuse, abort, defer, suspend, drop, wait
	Reason string
	Cell   string
}

func (d dec) String() string {
	s := d.Out
	if d.Reason != "" {
		s += " (" + d.Reason + ")"
	}
	return s + " [" + d.Cell + "]"
}

var colName = [...]string{"session", "update", "token.issued", "identity.rotate", "hs.init", "hs.resp/fin", "hs.resp/fin"}
var rowName = [...]string{"current", "earlier-before", "earlier-after", "foreign"}

// handle processes one collected message (§8.3 step 2). It returns
// whether the message is acked.
func (q *Party) handle(m *RMsg, set []Key) bool {
	w := q.w
	M := m.P
	if q.st.Seen[M.Inner] {
		return true
	}
	r, why := q.locate(M)
	if r == nil {
		if why == "wait" {
			w.stat("wait:new-epoch-before-fin")
			return false // §6.3: left unacked until hs.fin
		}
		w.logf("%s: drops %s from box %d: %s", q.Name, kindName[M.Kind], m.Box, why)
		if M.Kind == KFin && !w.party(m.Actor).Copy {
			w.ttlFin[[2]PID{m.Actor, q.ID}] = "arrived-after-answer-expired"
		}
		return true
	}
	w.recordEvidence(q, r, M)
	pos := Pos{m.Box, m.ID, m.DepAt}
	d := q.acceptFrom(r, m, pos, set)
	w.stat("cell " + d.Cell)
	w.stat("out " + d.Out)
	w.logf("%s <- %s: %s via %d: %s", q.Name, w.party(r.ID).Name, describe(M), m.Sender, d)
	if d.Out == "defer" || d.Out == "wait" {
		return false
	}
	switch d.Out {
	case "accept", "follow", "answer", "ignore":
		q.st.Seen[M.Inner] = true
		w.checkI3(q, r, m, d)
	}
	return true
}

// locate finds the peer a message is from: by the epoch it opens under,
// the ctx of a sealed hs.init, or the handshake an answer belongs to.
func (q *Party) locate(M *Msg) (*PeerRec, string) {
	byEpoch := func(e int) *PeerRec {
		for i := range q.st.Peers {
			if q.st.Peers[i].epoch(e) != nil {
				return &q.st.Peers[i]
			}
		}
		return nil
	}
	switch M.Kind {
	case KResp:
		for i := range q.st.Peers {
			if o := q.st.Peers[i].Own; o != nil && o.ID == M.HS {
				return &q.st.Peers[i], ""
			}
		}
		return nil, "no open handshake (abandoned)"
	case KFin:
		for i := range q.st.Peers {
			for _, a := range q.st.Peers[i].Ans {
				if a.ID == M.HS {
					return &q.st.Peers[i], ""
				}
			}
		}
		return nil, "no answer awaiting it"
	case KInit:
		if M.Epoch == 0 {
			if r := byEpoch(M.Ctx); r != nil {
				return r, ""
			}
			return nil, "ctx names no epoch"
		}
	}
	if r := byEpoch(M.Epoch); r != nil {
		return r, ""
	}
	for i := range q.st.Peers {
		for _, a := range q.st.Peers[i].Ans {
			if a.NewEpoch == M.Epoch {
				return nil, "wait"
			}
		}
	}
	return nil, "cannot open"
}

func refuse(reason, cell string) dec { return dec{"refuse", reason, cell} }

// acceptFrom decides every message from P, in the order of §3.4.1.
func (q *Party) acceptFrom(r *PeerRec, m *RMsg, pos Pos, set []Key) dec {
	M := m.P
	col := colName[M.Kind]
	// (1) suspended
	if r.Status == stSuspended {
		return refuse("suspended", "A:suspended:"+col)
	}
	if r.Status == stStale {
		return dec{"drop", "stale", "model:stale"} // needs a new invitation or pairing
	}
	// Table A preamble: an hs.init's sender must be its from.relay.pk
	if M.Kind == KInit && m.Sender != M.FromRelay {
		return refuse("foreign_sender", "A:hs.init-sender-not-from.relay")
	}
	// (2) foreign
	rs := r.relayState(m.Sender, pos)
	if rs == rkForeign {
		return refuse("foreign_sender", "A:foreign:"+col)
	}
	// (3) evidence first: rule C on every link the message carries
	if d, stop := q.ruleC(r, M); stop {
		return d
	}
	cell := "A:" + rowName[rs] + ":" + col
	// (4) Table A
	switch M.Kind {
	case KSession:
		if rs == rkAfter {
			return refuse("superseded_relay", cell)
		}
		if d, bad := q.demoted(r, M, pos, cell); bad {
			return d
		}
		q.w.probes[M.Probe] = true
		return dec{"accept", "", cell}
	case KUpdate:
		return q.ruleU(r, m, pos, rs)
	case KTokIssued:
		if d, bad := q.demoted(r, M, pos, cell); bad {
			return d
		}
		return q.tokIssued(r, m, set, cell)
	case KIdRot:
		if rs == rkAfter {
			if q.allFollowed(r, M.Rot) {
				return dec{"ignore", "", cell + ":all-followed"}
			}
			return refuse("superseded_relay", cell)
		}
		if d, bad := q.demoted(r, M, pos, cell); bad {
			return d
		}
		return q.tableBRotate(r, M, pos)
	case KInit:
		if rs == rkAfter {
			return refuse("superseded_relay", cell)
		}
		if M.Epoch != 0 {
			if d, bad := q.demoted(r, M, pos, cell); bad {
				return d
			}
		}
		return q.tableBInit(r, m, pos)
	case KResp:
		if rs == rkAfter {
			return refuse("superseded_relay", cell+":handshake-kept")
		}
		return q.tableBResp(r, M, pos)
	case KFin:
		if rs == rkAfter {
			return refuse("superseded_relay", cell+":handshake-kept")
		}
		return q.tableBFin(r, M, pos)
	}
	return refuse("unexpected", "A:unknown-kind")
}

// demoted: "Epochs after an ik link": messages under a demoted epoch
// deposited after x are refused.
func (q *Party) demoted(r *PeerRec, M *Msg, pos Pos, cell string) (dec, bool) {
	if ep := r.epoch(M.Epoch); ep != nil && ep.Demoted && ep.DemotedAt.after(pos) {
		return refuse("ancestor_ik", "E:demoted-epoch"), true
	}
	return dec{}, false
}

func (q *Party) allFollowed(r *PeerRec, links []IKLink) bool {
	for _, l := range links {
		if !r.followed(l) {
			return false
		}
	}
	return true
}

// ---------- rule C ----------

func (q *Party) ruleC(r *PeerRec, M *Msg) (dec, bool) {
	for _, l := range M.Rot {
		if slices.Contains(r.Dropped, l) {
			continue // remembered as dropped: refused later, not a new conflict
		}
		for _, f := range r.Chain {
			if f.Old == l.Old && f.New != l.New {
				q.w.stat("ruleC:identity")
				if r.Device {
					return q.deviceConflict(r, "C:identity-device"), true
				}
				r.CandA, r.CandB = f, l
				q.suspend(r, "identity.rotate_conflict")
				return dec{"suspend", "conflict", "C:identity"}, true
			}
		}
	}
	if M.Kind == KUpdate {
		for _, l := range M.RLinks {
			for _, f := range r.RChain {
				if f.Old == l.Old && f.New != l.New {
					q.w.stat("ruleC:relay")
					if r.Device {
						return q.deviceConflict(r, "C:relay-device"), true
					}
					r.RelayFrk = true
					q.suspend(r, "connection.fork_suspected/relay")
					return dec{"suspend", "fork", "C:relay"}, true
				}
			}
		}
	}
	return dec{}, false
}

// deviceConflict: between a vault and its own device nothing suspends; the
// first successor stays, the other is refused, the member is told.
func (q *Party) deviceConflict(r *PeerRec, cell string) dec {
	if !q.Device {
		r.Status = stConflicted // the vault sends that device nothing more
	}
	r.Warned = true // the member is told (a feed item, or the app's lasting warning)
	return refuse("conflict", cell)
}

func (q *Party) suspend(r *PeerRec, ref string) {
	r.Status = stSuspended
	r.Ref = ref
	q.w.logf("%s SUSPENDS %s: %s", q.Name, q.w.party(r.ID).Name, ref)
	q.h5(r, 0)
}

// ---------- rule T ----------

// ruleT keeps the tokens that pass rule T for mailbox iss. unknown: a
// token names a mailbox Q does not yet know for P.
func (q *Party) ruleT(r *PeerRec, toks []Token, iss Key) (kept []Token, unknown bool) {
	for _, t := range toks {
		if q.w.issuer[t.JTI] != t.Iss || !t.valid(q.w.Now) {
			continue
		}
		mine := t.Sub == q.st.Relay
		for _, o := range q.st.Old {
			mine = mine || o.Key == t.Sub
		}
		if !mine {
			continue
		}
		if t.Iss != iss {
			if !r.keeps(t.Iss) {
				unknown = true
			}
			continue
		}
		kept = append(kept, t)
	}
	return kept, unknown
}

func (q *Party) keepTokens(r *PeerRec, toks []Token) {
	for _, t := range toks {
		if !slices.ContainsFunc(r.Toks, func(x Token) bool { return x.JTI == t.JTI }) {
			r.Toks = append(r.Toks, t)
		}
	}
	q.s2(r)
}

// s2: when P's token for my newer key arrives, my key for P advances (S2).
func (q *Party) s2(r *PeerRec) {
	best := r.KeyFor
	for _, t := range r.Toks {
		if !t.Reconnect && t.Iss == r.Relay && q.keyRank(t.Sub) > q.keyRank(best) {
			best = t.Sub
		}
	}
	if best == r.KeyFor {
		return
	}
	q.w.logf("%s: S2 key for %s advances %d -> %d", q.Name, q.w.party(r.ID).Name, r.KeyFor, best)
	q.w.stat("S2:advance")
	r.KeyFor = best
	r.RevokedAt = 0
	if o := r.Own; o != nil && o.Reconnect && !o.FinSent && o.Relay != best {
		q.abandonOwn(r)
		q.startHS(r, true)
	}
	for _, a := range r.Ans { // hs.resp deposited with the earlier key: again, same bytes
		q.enqueueRaw(r.ID, a.respMsg(q, r))
	}
	if r.LastFin != 0 {
		if ep := r.epoch(r.Cur); ep != nil {
			q.enqueueRaw(r.ID, Msg{Kind: KFin, Inner: r.LastFin, Epoch: r.Cur, HS: r.LastFinHS, NewEpoch: r.Cur, Sig: ep.Own, Reconnect: r.LastFinRC})
		}
	}
}

// tokIssued: Table A's relay.token.issued column, tokens by rule T.
func (q *Party) tokIssued(r *PeerRec, m *RMsg, set []Key, cell string) dec {
	kept, unknown := q.ruleT(r, m.P.Toks, r.Relay)
	if len(kept) == 0 && unknown {
		return q.deferOr(r, m, set, "token_unusable", "T:defer-unknown-iss")
	}
	q.keepTokens(r, kept)
	if len(kept) == 0 {
		cell += ":tokens-ignored"
	}
	return dec{"accept", "", cell}
}

// deferOr defers within the bounds, else refuses.
func (q *Party) deferOr(r *PeerRec, m *RMsg, set []Key, reason, cell string) dec {
	first, ok := q.st.First[m.ID]
	if !ok {
		first = q.w.Now
		q.st.First[m.ID] = first
	}
	n := 0
	for _, d := range r.Deferred {
		if d.Reason == reason && d.MsgID != m.ID {
			n++
		}
	}
	if n < 8 && (q.w.Now-first <= 2*visTimeout || q.otherBoxBehind(m, set)) {
		if !slices.ContainsFunc(r.Deferred, func(d deferral) bool { return d.MsgID == m.ID }) {
			r.Deferred = append(r.Deferred, deferral{m.ID, first, reason})
		}
		return dec{"defer", reason, cell}
	}
	r.Deferred = slices.DeleteFunc(r.Deferred, func(d deferral) bool { return d.MsgID == m.ID })
	return refuse(reason, cell+":bound-exceeded")
}

// ---------- rule U ----------

func (q *Party) ruleU(r *PeerRec, m *RMsg, pos Pos, rs rkSt) dec {
	M := m.P
	L := M.RLinks
	pre := "U(" + rowName[rs] + "):"
	ok := len(L) >= 1 && len(L) <= 32 && L[0].Old == m.Sender && L[len(L)-1].New == M.RelayPK
	for i := 1; ok && i < len(L); i++ {
		ok = L[i].Old == L[i-1].New
	}
	for _, l := range L {
		if _, made := q.w.rlinkBy[l]; !made {
			ok = false // signatures do not verify
		}
	}
	if !ok {
		if q.w.debugUnlinked {
			q.w.violate("DEBUG", "unlinked update %v sender %d pk %d actor %s", L, m.Sender, M.RelayPK, q.w.party(m.Actor).Name)
		}
		return refuse("relay_unlinked", pre+"unlinked")
	}
	skip := 0
	for skip < len(L) && slices.Contains(r.RChain, L[skip]) {
		skip++
	}
	if skip == len(L) {
		// duplicate: ignore, and send relay.token.issued again (F1)
		q.enqueue(r.ID, Msg{Kind: KTokIssued, Toks: []Token{{}}}, nil)
		return dec{"ignore", "", pre + "duplicate"}
	}
	if L[skip].Old != r.Relay {
		return refuse("relay_rollback", pre+"first-not-current")
	}
	for _, l := range L[skip:] {
		if r.keeps(l.New) {
			return refuse("relay_rollback", pre+"new-is-kept")
		}
	}
	kept, _ := q.ruleT(r, M.Toks, M.RelayPK)
	hasStanding := false
	for _, t := range kept {
		hasStanding = hasStanding || !t.Reconnect
	}
	if !hasStanding {
		return refuse("token_unusable", pre+"token")
	}
	// I3: never a relay key Q followed away from
	for _, l := range r.RChain {
		if l.Old == M.RelayPK {
			q.w.violate("I3", "%s makes current relay key %d it followed away from", q.Name, M.RelayPK)
		}
	}
	// one state write: links, passed keys with this cut-off, new key, tokens
	var revoke = map[Key][]int{}
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
	}
	r.Relay = M.RelayPK
	// SPEC FINDING (silent): tokens for P's earlier mailboxes are dropped here.
	r.Toks = slices.DeleteFunc(r.Toks, func(t Token) bool { return t.Iss != r.Relay })
	q.keepTokens(r, kept)
	q.enqueue(r.ID, Msg{Kind: KTokIssued, Toks: []Token{{}, {Reconnect: !r.Device}}}, nil)
	for box, jtis := range revoke {
		q.revokeAt(box, jtis)
	}
	return dec{"follow", "", pre + "follow"}
}

// revokeAt: S7, a denylist request signed by the key of the issuing mailbox.
func (q *Party) revokeAt(box Key, jtis []int) {
	if box == q.st.Relay || slices.ContainsFunc(q.st.Old, func(o OldKey) bool { return o.Key == box && q.w.Now < o.GraceEnd }) {
		q.st.Out = append(q.st.Out, Entry{ID: q.w.id(), Denylist: true, Box: box, With: box, Revoke: jtis})
	}
}

// ---------- Table B ----------

func (q *Party) tableBRotate(r *PeerRec, M *Msg, pos Pos) dec {
	i := 0
	for i < len(M.Rot) && r.followed(M.Rot[i]) {
		i++
	}
	if i == len(M.Rot) {
		// SPEC FINDING: the ik is undefined when every link is followed; the
		// model reads it as the Ancestor row's "every link already followed".
		return dec{"ignore", "", "B:ancestor:identity.rotate"}
	}
	st, _ := r.ikState(M.Rot[i].Old, nil)
	cell := "B:" + ikName[st] + ":identity.rotate"
	switch st {
	case ikCurrent:
		app, ok := r.resolve(M.Rot)
		if !ok {
			return refuse("unknown_ik", cell+":chain-rejected")
		}
		for _, l := range app {
			if r.isAncestor(l.New) || r.isRejected(l.New) {
				return refuse("ik_rollback", cell+":rollback")
			}
		}
		q.followIK(r, app, pos)
		q.h5(r, 0)
		return dec{"follow", "", cell}
	case ikAncestor:
		// SPEC FINDING: not every link followed, first unfollowed starts at an
		// ancestor (only with a statement dropped at resolve): no cell; refused.
		return refuse("rejected_ik", cell+":not-all-followed")
	case ikRejected:
		return refuse("rejected_ik", cell)
	}
	return refuse("unknown_ik", cell)
}

// followIK follows identity links at position x, with the epoch rule.
func (q *Party) followIK(r *PeerRec, app []IKLink, x Pos) {
	for _, l := range app {
		if r.isAncestor(l.New) || r.isRejected(l.New) {
			q.w.violate("I3", "%s makes current ancestor/rejected ik %d", q.Name, l.New)
		}
		r.Chain = append(r.Chain, l)
		r.IK, r.KEM = l.New, l.KEM
		key := [2]PID{q.ID, r.ID}
		q.w.ikPos[key] = append(q.w.ikPos[key], ikFollow{l, x})
		// Epochs after an ik link
		for j := range r.Epochs {
			ep := &r.Epochs[j]
			if (ep.Signer == l.Old || r.isAncestor(ep.Signer)) && !ep.Demoted && x.after(ep.Est) {
				ep.Demoted, ep.DemotedAt = true, x
				q.w.stat("epoch:demoted")
				q.w.logf("%s: epoch E%d of %s demoted (signer %d, after the link)", q.Name, ep.ID, q.w.party(r.ID).Name, ep.Signer)
				if r.Cur == ep.ID {
					r.Cur = 0
				}
			}
		}
	}
	if r.Cur == 0 && r.Status == stActive {
		q.abandonOwn(r)
		q.startHS(r, false) // a rekey sealed to the link's new_kem
	}
}

// forkEpoch: ctx names an epoch Q superseded by one signed by an ancestor ik.
func (q *Party) forkEpoch(r *PeerRec, ctx int) bool {
	for j, ep := range r.Epochs {
		if ep.ID == ctx && j+1 < len(r.Epochs) {
			next := r.Epochs[j+1]
			return r.isAncestor(next.Signer)
		}
	}
	return false
}

func (q *Party) tableBInit(r *PeerRec, m *RMsg, pos Pos) dec {
	M := m.P
	st, app := r.ikState(M.FromIK, M.Rot)
	cell := "B:" + ikName[st] + ":hs.init"
	switch st {
	case ikAncestor:
		return refuse("ancestor_ik", cell)
	case ikRejected:
		return refuse("rejected_ik", cell)
	case ikUnknown:
		return refuse("unknown_ik", cell)
	}
	// answer, under §6.2/§6.6's own checks
	fork := false
	if M.Reconnect {
		if slices.Contains(r.Answered, M.HS) {
			return refuse("reconnect_refused", cell+":replay")
		}
		last := r.lastEpoch()
		if last == nil || M.Ctx != last.ID {
			if !q.forkEpoch(r, M.Ctx) {
				return refuse("reconnect_refused", cell+":ctx")
			}
			fork = true // judged at hs.fin (§6.6, H5's exemption)
		}
	} else {
		if r.Cur == 0 || M.Ctx != r.Cur {
			if q.forkEpoch(r, M.Ctx) {
				q.suspend(r, "connection.fork_suspected/epoch")
				return dec{"suspend", "fork", cell + ":fork-epoch"}
			}
			return refuse("rekey_not_current_epoch", cell+":ctx")
		}
	}
	// crossing handshakes (§6.5; §6.6 "Between two persons"): answer as
	// usual; the lower th1 wins. Own higher: abandon it. Own lower: keep
	// both; the answer is dropped when the own one completes.
	// SPEC FINDING (outside §3.4.1): a rekey crossing a reconnect is not
	// covered by §6.5/§6.6; the model applies the th1 rule across purposes.
	if o := r.Own; o != nil && !o.FinSent {
		if o.ID > M.HS {
			q.abandonOwn(r)
		} else {
			cell += ":crossing-own-lower"
		}
	}
	// §6.6: a new reconnect hs.init from P that Q answers ends Q's earlier
	// answer to P's reconnect (rekeys: no such rule)
	for _, a := range slices.Clone(r.Ans) {
		if M.Reconnect && a.Reconnect && !a.Fork {
			q.dropAnswer(r, a.ID)
		}
	}
	var toks []Token
	box := Key(0)
	var tok Token
	if M.Reconnect {
		toks, _ = q.ruleT(r, M.Toks, M.FromRelay)
		r.Answered = append(r.Answered, M.HS)
		box = M.FromRelay
		for _, t := range toks {
			if !t.Reconnect {
				tok = t
			}
		}
	}
	ep := r.epoch(M.Ctx)
	own := q.st.IK
	if ep != nil {
		own = ep.Own
	}
	a := HS{ID: M.HS, Reconnect: M.Reconnect, Ctx: M.Ctx, PeerIK: M.FromIK, OwnIK: q.st.IK, Toks: toks,
		Links: app, Started: q.w.Now, NewEpoch: q.w.id(), Fork: fork, RespFrom: own, RespInner: q.w.id()}
	q.w.epTruth[a.NewEpoch] = [2]PID{m.Actor, q.ID}
	if M.Reconnect {
		a.RespToks = q.issue(r, q.st.Relay, true)
	}
	r.Ans = append(r.Ans, a)
	q.enqueueRaw(r.ID, a.respMsg(q, r), func(e *Entry) { e.Box, e.Tok = box, tok })
	return dec{"answer", "", cell}
}

// respMsg: the hs.resp of an answer (the same bytes each time).
func (a *HS) respMsg(q *Party, r *PeerRec) Msg {
	return Msg{Kind: KResp, Inner: a.RespInner, HS: a.ID, NewEpoch: a.NewEpoch, Sig: a.OwnIK,
		Rot: q.ownLinks(a.RespFrom), Reconnect: a.Reconnect, Toks: a.RespToks}
}

func (q *Party) tableBResp(r *PeerRec, M *Msg, pos Pos) dec {
	o := r.Own
	if life := map[bool]int64{false: hsLife, true: reconnectFail}[o.Reconnect]; q.w.Now-o.Started > life {
		q.abandonOwn(r) // model: an initiator's handshake expires before the responder's answer
		return dec{"drop", "expired", "hs.resp:own-handshake-expired"}
	}
	st, app := r.ikState(M.Sig, M.Rot)
	cell := "B:" + ikName[st] + ":hs.resp"
	switch st {
	case ikAncestor:
		q.abandonOwn(r)
		return dec{"abort", "ancestor_ik", cell}
	case ikRejected:
		q.abandonOwn(r)
		return dec{"abort", "rejected_ik", cell}
	case ikUnknown:
		q.abandonOwn(r)
		return dec{"abort", "unknown_ik", cell}
	}
	if len(app) > 0 {
		q.followIK(r, app, pos)
	}
	q.establish(r, M.NewEpoch, M.Sig, o.OwnIK, pos)
	for _, a := range slices.Clone(r.Ans) {
		if !a.Fork {
			q.dropAnswer(r, a.ID) // own completed first: the crossing answer is dropped
		}
	}
	if o.Reconnect {
		toks, _ := q.ruleT(r, M.Toks, r.Relay)
		q.keepTokens(r, toks)
	}
	r.Own = nil
	if q.st.IK != o.OwnIK {
		q.w.violate("S5", "%s would send hs.fin signed by superseded ik %d", q.Name, o.OwnIK)
	}
	fin := Msg{Kind: KFin, Epoch: M.NewEpoch, HS: M.HS, NewEpoch: M.NewEpoch, Sig: o.OwnIK, Reconnect: o.Reconnect}
	q.enqueue(r.ID, fin, nil)
	r.LastFin, r.LastFinHS, r.LastFinRC = q.st.Out[len(q.st.Out)-1].M.Inner, M.HS, o.Reconnect
	if len(app) > 0 {
		q.h5(r, 0)
	}
	return dec{"accept", "", cell}
}

func (q *Party) tableBFin(r *PeerRec, M *Msg, pos Pos) dec {
	var a HS
	for _, x := range r.Ans {
		if x.ID == M.HS {
			a = x
		}
	}
	if M.Sig != a.PeerIK {
		return dec{"drop", "sig_I", "hs.fin:sig-invalid:handshake-kept"}
	}
	st, app := r.ikState(a.PeerIK, a.Links)
	cell := "B:" + ikName[st] + ":hs.fin"
	switch st {
	case ikAncestor:
		if a.Fork {
			q.suspend(r, "connection.fork_suspected/epoch")
			return dec{"suspend", "fork", cell + ":fork-evidence"}
		}
		q.dropAnswer(r, a.ID)
		return refuse("ancestor_ik", cell)
	case ikRejected:
		q.dropAnswer(r, a.ID)
		return refuse("rejected_ik", cell)
	case ikUnknown:
		return refuse("unexpected", cell)
	}
	if a.Fork {
		q.suspend(r, "connection.fork_suspected/epoch")
		return dec{"suspend", "fork", cell + ":fork-evidence"}
	}
	q.removeAnswer(r, a.ID)
	if len(app) > 0 {
		q.followIK(r, app, pos)
	}
	q.establish(r, a.NewEpoch, a.PeerIK, a.OwnIK, pos)
	if a.Reconnect {
		toks, _ := q.ruleT(r, a.Toks, r.Relay)
		q.keepTokens(r, toks)
	}
	if r.Own != nil {
		q.abandonOwn(r) // §6.6: a verified hs.fin comes first
	}
	if len(app) > 0 {
		q.h5(r, a.ID)
	}
	return dec{"accept", "", cell}
}

func (q *Party) establish(r *PeerRec, id int, signer, own Key, pos Pos) {
	if signer != r.IK {
		q.w.violate("I3", "%s establishes E%d signed by %d, not its current ik %d for %s", q.Name, id, signer, r.IK, q.w.party(r.ID).Name)
	}
	for j := range r.Epochs {
		if r.Epochs[j].Superseded == 0 {
			r.Epochs[j].Superseded = q.w.Now
		}
	}
	r.Epochs = append(r.Epochs, Epoch{ID: id, Signer: signer, Own: own, Est: pos, EstAt: q.w.Now})
	r.Cur = id
	q.w.logf("%s: epoch E%d with %s established (signer %d)", q.Name, id, q.w.party(r.ID).Name, signer)
}

// ---------- H5 and handshake bookkeeping ----------

func (r *PeerRec) superseded(k Key, links []IKLink) bool {
	st, _ := r.ikState(k, links)
	return st != ikCurrent && st != ikReached
}

func (q *Party) h5(r *PeerRec, except int) {
	q.w.stat("H5")
	if r.Status == stSuspended || r.Status == stStale {
		q.abandonOwn(r)
		for len(r.Ans) > 0 {
			q.dropAnswer(r, r.Ans[0].ID)
		}
		return
	}
	if o := r.Own; o != nil && o.ID != except && r.superseded(o.PeerIK, nil) {
		rc := o.Reconnect
		q.abandonOwn(r)
		if !rc || r.RestartIK != r.IK {
			r.RestartIK = r.IK
			q.startHS(r, rc)
		}
	}
	for _, a := range slices.Clone(r.Ans) {
		if a.ID != except && !a.Fork && r.superseded(a.PeerIK, a.Links) {
			q.dropAnswer(r, a.ID)
		}
	}
}

func (q *Party) abandonOwn(r *PeerRec) {
	if r.Own == nil {
		return
	}
	q.revokeToks(r.Own.Toks)
	for i := range q.st.Out {
		if e := &q.st.Out[i]; e.M.Kind == KInit && e.M.HS == r.Own.ID && !e.Done {
			e.Ended = true // an abandoned hs.init is not sent
		}
	}
	r.Own = nil
}

func (q *Party) removeAnswer(r *PeerRec, id int) {
	r.Ans = slices.DeleteFunc(r.Ans, func(a HS) bool { return a.ID == id })
}

func (q *Party) dropAnswer(r *PeerRec, id int) {
	for i := range q.st.Out {
		if e := &q.st.Out[i]; e.M.Kind == KResp && e.M.HS == id && !e.Done {
			e.Ended = true // the hs.resp is not sent (§6.6)
		}
	}
	for _, a := range r.Ans {
		if a.ID == id {
			q.revokeToks(a.RespToks)
		}
	}
	q.removeAnswer(r, id)
}

func (q *Party) revokeToks(ts []Token) {
	by := map[Key][]int{}
	for _, t := range ts {
		by[t.Iss] = append(by[t.Iss], t.JTI)
	}
	for b, j := range by {
		q.revokeAt(b, j)
	}
}

func (q *Party) enqueueRaw(to PID, m Msg, f ...func(*Entry)) {
	e := Entry{ID: q.w.id(), To: to, M: m}
	for _, g := range f {
		if g != nil {
			g(&e)
		}
	}
	q.st.Out = append(q.st.Out, e)
}

// ---------- ground truth for I3 and I4 ----------

// recordEvidence notes the links a message carried; they count once the
// batch's write stores its processing (a crash before it loses nothing Q
// had processed).
func (w *World) recordEvidence(q *Party, r *PeerRec, M *Msg) {
	q.pendEvid = append(q.pendEvid, pendEv{r.ID, cloneMsg(*M)})
}

func (w *World) commitEvidence(q *Party, r *PeerRec, M *Msg) {
	key := [2]PID{q.ID, r.ID}
	if w.evid[key] == nil {
		w.evid[key] = map[Key]map[Key]bool{}
	}
	add := func(o, n Key) {
		if w.evid[key][o] == nil {
			w.evid[key][o] = map[Key]bool{}
		}
		w.evid[key][o][n] = true
		if w.evidKind[n] == "" {
			w.evidKind[n] = kindName[M.Kind]
		}
	}
	for _, l := range M.Rot {
		add(l.Old, l.New)
	}
	for _, l := range M.RLinks {
		add(l.Old, l.New)
	}
}

// checkI3: what Q accepts from an old copy, and epochs it set up.
func (w *World) checkI3(q *Party, r *PeerRec, m *RMsg, d dec) {
	if q.Copy {
		return
	}
	actor := w.party(m.Actor)
	if !actor.Copy || actor.Origin != r.ID {
		if !actor.Copy && m.P.Kind == KInit && m.P.FromIK == actor.st.IK && r.Status == stActive {
			if ep := r.epoch(r.Cur); ep != nil && w.copyEpochAfterR(q, r, ep.ID) {
				w.forkDue[[2]PID{q.ID, r.ID}] = ep.ID // must end suspended (a reconnect: at hs.fin)
			}
		}
		return
	}
	key := [2]PID{q.ID, r.ID}
	// relay clause: a key the copy holds that Q followed away from, by a link the original made after the copy
	for _, e := range r.Earlier {
		if e.Key != m.Sender || !e.Cut.after(Pos{m.Box, m.ID, m.DepAt}) {
			continue
		}
		for _, l := range r.RChain {
			if l.Old == e.Key && w.rlinkBy[l].By == r.ID && w.rlinkBy[l].Write > actor.SnapW {
				ok := m.P.Kind == KTokIssued || d.Out == "ignore"
				if !ok {
					w.violate("I3", "%s accepts %s from old copy %s after the cut-off (%s)", q.Name, kindName[m.P.Kind], actor.Name, d)
				}
			}
		}
	}
	// epoch clause
	if m.P.Epoch != 0 && w.copyEpochAfterR(q, r, m.P.Epoch) {
		for _, f := range w.ikPos[key] {
			if r.followed(f.L) && f.Pos.after(Pos{m.Box, m.ID, m.DepAt}) {
				w.violate("I3", "%s accepts %s under copy epoch E%d deposited after the ik link %v", q.Name, kindName[m.P.Kind], m.P.Epoch, f.L)
			}
		}
	}
}

// copyEpochAfterR: epoch e was set up with a copy of P taken before the
// first write of a rotation whose ik link Q has followed.
func (w *World) copyEpochAfterR(q *Party, r *PeerRec, e int) bool {
	tr, ok := w.epTruth[e]
	if !ok {
		return false
	}
	for _, a := range tr {
		c := w.party(a)
		if !c.Copy || c.Origin != r.ID {
			continue
		}
		for _, f := range w.ikPos[[2]PID{q.ID, r.ID}] {
			if by := w.iklinkBy[f.L]; r.followed(f.L) && by.By == r.ID && by.Write > c.SnapW {
				return true
			}
		}
	}
	return false
}

var _ = fmt.Sprint
