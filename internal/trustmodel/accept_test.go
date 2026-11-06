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

var colName = [...]string{"session", "update", "token.issued", "identity.rotate", "hs.init", "hs.resp/fin", "hs.resp/fin", "hs.confirm"}
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
		if !w.party(m.Actor).Copy {
			w.audits[pairKey(q.ID, w.party(m.Actor).Origin)]++ // unknown_kid and the like
		}
		if M.Feat {
			w.stat("F:features not taken (dropped: " + why + ")")
		}
		if M.Kind == KSession && M.Probe > 0 && w.probeFate[M.Probe] == "" && !q.Copy {
			w.probeFate[M.Probe] = "unreadable: " + why
		}
		if (M.Kind == KFin || M.Kind == KConfirm) && !w.party(m.Actor).Copy {
			w.ttlFin[[2]PID{m.Actor, q.ID}] = "arrived-after-answer-expired"
		}
		return true
	}
	pos := Pos{m.Box, m.ID, m.DepAt, m.Seq}
	// I4 (0.86.0): only messages from keys Q knows for P, or a handshake
	// Q can attribute to P (by its answer or open handshake)
	if !w.optA || M.Kind == KResp || M.Kind == KFin || r.relayState(m.Sender, pos) != rkForeign {
		w.recordEvidence(q, r, M)
	}
	ok14 := q.steps14(r, m, pos)
	q.beforeAccept(r, m, pos)
	d := q.acceptFrom(r, m, pos, set)
	if ok14 {
		q.seeFeatures(r, M) // R29-G2, D4
	}
	if w.noF5 && q.newSpec() && r.Pend != nil && M.Epoch == r.Pend.ID && M.Kind != KFin &&
		(d.Out == "accept" || d.Out == "answer" || d.Out == "follow" || d.Out == "ignore") {
		q.confirm(r) // switch noF5: the confirmation only once the handler has accepted the message
	}
	w.stat("cell " + d.Cell)
	w.stat("out " + d.Out)
	w.logf("%s <- %s: %s via %d: %s", q.Name, w.party(r.ID).Name, describe(M), m.Sender, d)
	if d.Out == "accept" || d.Out == "answer" {
		w.noteCopyUse(q, r.ID, M.Epoch)
	}
	if d.Out == "refuse" || d.Out == "drop" || d.Out == "abort" {
		w.audits[pairKey(q.ID, r.ID)]++
	}
	if d.Out == "defer" || d.Out == "wait" {
		return false
	}
	if M.Kind == KSession && M.Probe > 0 && !q.Copy && w.probeFate[M.Probe] == "" {
		w.probeFate[M.Probe] = d.Out + ":" + d.Reason
	}
	switch d.Out {
	case "accept", "follow", "answer", "ignore":
		q.st.Seen[M.Inner] = true
		w.checkI3(q, r, m, d)
		if q.newSpec() && M.Epoch != 0 && M.Kind != KFin {
			q.idResend(r, m)
		}
	}
	return true
}

// locate finds the peer a message is from: by the epoch it opens under,
// the ctx of a sealed hs.init, or the handshake an answer belongs to.
func (q *Party) locate(M *Msg) (*PeerRec, string) {
	byEpoch := func(e int) *PeerRec {
		for i := range q.st.Peers {
			if ep := q.st.Peers[i].epoch(e); ep != nil && (!ep.KeysGone || (M.Kind == KInit && M.Reconnect)) {
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
		if q.newSpec() && M.Kind == KUpdate && r.relayState(m.Sender, pos) != rkForeign {
			// 0.86.0: the relay links are checked by rule C first, so a
			// relay fork is recorded while suspended (resolve: not_found)
			if l, ok := r.relayConflict(M.RLinks); ok {
				r.RelayFrk = true
				q.w.stat("ruleC:relay-while-suspended")
				q.w.logf("%s: relay fork recorded while suspended (%v)", q.Name, l)
			}
		}
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
	if ep := r.epoch(M.Epoch); ep != nil && ep.Destroyed {
		if M.Ts > ep.DestroyTs { // F3: a later ts under a destroyed epoch is fork evidence
			q.w.hit("R6:fork-evidence")
			q.suspend(r, "connection.fork_suspected/epoch")
			return dec{"suspend", "fork", "E:destroyed-epoch-later-ts"}
		}
		q.w.hit("R6:superseded_epoch")
		return refuse("superseded_epoch", "E:superseded-epoch")
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
		// an update travels in session mode: under a demoted epoch it is
		// refused, under an ended one it is fork evidence (acceptFrom,
		// 0.86.2; R29-K9), as any message after step 3
		if d, bad := q.demoted(r, M, pos, cell); bad {
			return d
		}
		return q.ruleU(r, m, pos, rs)
	case KTokIssued:
		if d, bad := q.demoted(r, M, pos, cell); bad {
			return d
		}
		return q.tokIssued(r, m, set, cell)
	case KIdRot:
		if rs == rkAfter {
			if q.allFollowed(r, M.Rot) {
				// (0.87.1) Table A's "Earlier, after its cut-off" cell: every
				// link already followed: ignore, and R29-K9 is still judged
				q.w.hit("K9:judged-after-cut-off")
				if q.judgeAbandoned(r, M.Rot, M.Epoch) {
					return dec{"suspend", "fork", cell + ":all-followed:K9-flag"}
				}
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
		if q.newSpec() && !M.Reconnect && M.Epoch == 0 {
			q.w.hit("X6:sealed-rekey-refused")
			return refuse("malformed", "X6:sealed-rekey") // R29-X6 (§6.2): a rekey always travels in session mode
		}
		if q.newSpec() && !q.Device && r.Device && !M.Reconnect {
			q.w.hit("D3:device-rekey-refused")
			q.deviceNotice(r, "D3 refusal")
			return refuse("unexpected", "D3:device-rekey") // R29-D3: the vault answers no rekey from a device
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
	case KConfirm:
		// SPEC FINDING: hs.confirm has no column in Table A; the model
		// treats it as a session message.
		if rs == rkAfter {
			return refuse("superseded_relay", cell)
		}
		if d, bad := q.demoted(r, M, pos, cell); bad {
			return d
		}
		return dec{"accept", "", cell}
	}
	return refuse("unexpected", "A:unknown-kind")
}

// demoted: "Epochs after an ik link": messages under a demoted epoch
// deposited after x are refused.
func (q *Party) demoted(r *PeerRec, M *Msg, pos Pos, cell string) (dec, bool) {
	if ep := r.epoch(M.Epoch); ep != nil && ep.Ended {
		q.w.hit("K9:ended-message-suspends")
		q.w.logf("%s: a message under ended E%d from %s: fork evidence", q.Name, ep.ID, q.w.party(r.ID).Name)
		q.suspend(r, "connection.fork_suspected/epoch")
		return dec{"suspend", "fork", "E:ended-epoch"}, true
	}
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
		prior := slices.Clone(r.Chain)
		if q.newSpec() {
			prior = append(prior, r.Seen...) // 0.86.0: followed or seen
		}
		for _, f := range prior {
			if f.Old == l.Old && f.New != l.New && !slices.Contains(r.Dropped, f) {
				q.w.stat("ruleC:identity")
				if !r.followed(f) {
					q.w.stat("ruleC:identity-vs-seen")
				}
				if r.Device {
					q.w.hit("K8:device-conflict-refused")
					return q.deviceConflict(r, "C:identity-device"), true
				}
				q.w.hit("K8:second-successor-suspends")
				if !r.followed(f) {
					q.w.hit("K8:against-a-seen-link")
				}
				r.CandA, r.CandB = f, l
				q.suspend(r, "identity.rotate_conflict")
				return dec{"suspend", "conflict", "C:identity"}, true
			}
		}
	}
	if M.Kind == KUpdate {
		if _, bad := r.relayConflict(M.RLinks); bad {
			q.w.stat("ruleC:relay")
			if r.Device {
				return q.deviceConflict(r, "C:relay-device"), true
			}
			r.RelayFrk = true
			q.suspend(r, "connection.fork_suspected/relay")
			return dec{"suspend", "fork", "C:relay"}, true
		}
	}
	if q.newSpec() { // remember what passed as seen, one per old key
		for _, l := range M.Rot {
			if !slices.ContainsFunc(r.Seen, func(f IKLink) bool { return f.Old == l.Old }) && !slices.Contains(r.Dropped, l) {
				r.Seen = append(r.Seen, l)
				q.w.hit("K8:link-kept-as-seen")
			}
		}
		for _, l := range M.RLinks {
			if !slices.ContainsFunc(r.RSeen, func(f RLink) bool { return f.Old == l.Old }) {
				r.RSeen = append(r.RSeen, l)
			}
		}
	}
	return dec{}, false
}

// relayConflict: a relay link whose old key has another followed (or seen) successor.
func (r *PeerRec) relayConflict(links []RLink) (RLink, bool) {
	prior := append(slices.Clone(r.RChain), r.RSeen...)
	for _, l := range links {
		for _, f := range prior {
			if f.Old == l.Old && f.New != l.New {
				return l, true
			}
		}
	}
	return RLink{}, false
}

// deviceConflict: between a vault and its own device nothing suspends; the
// first successor stays, the other is refused, the member is told.
func (q *Party) deviceConflict(r *PeerRec, cell string) dec {
	if !q.Device {
		r.Status = stConflicted // the vault sends that device nothing more
	}
	r.Warned = true // the member is told (a feed item, or the app's lasting warning)
	q.w.feedItem(q.ID, r.ID, "rule C between a vault and its device")
	return refuse("conflict", cell)
}

func (q *Party) suspend(r *PeerRec, ref string) {
	r.Status = stSuspended
	r.Ref = ref
	q.w.suspAt[[2]PID{q.ID, r.ID}] = q.w.Now
	q.w.feedItem(q.ID, r.ID, "suspended: "+ref)
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
		id := r.Cur
		if r.Pend != nil {
			id = r.Pend.ID // §6.3.1: the hs.fin is under the pending epoch
		}
		if ep := r.epoch(id); ep != nil {
			q.enqueueRaw(r.ID, Msg{Kind: KFin, Inner: r.LastFin, Epoch: id, HS: r.LastFinHS, NewEpoch: id, Sig: ep.Own, Reconnect: r.LastFinRC})
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
		if q.judgeAbandoned(r, M.Rot, M.Epoch) { // R29-K9: judged also here
			return dec{"suspend", "fork", "B:ancestor:identity.rotate:K9-flag"}
		}
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
		pre := r.Cur
		if q.followIK(r, app, pos, true) {
			return dec{"suspend", "fork", cell + ":K4-flag"}
		}
		if q.f1Demote(r, M, app, pos, pre) {
			return dec{"suspend", "fork", cell + ":K7-flag"}
		}
		q.h5(r, 0) // may abandon the pending epoch at the link (K2)
		if q.judgeAbandoned(r, M.Rot, M.Epoch) { // R29-K9, also on the epoch just abandoned: K9 wins (ended, not demoted)
			return dec{"suspend", "fork", cell + ":K9-flag"}
		}
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

// followIK follows identity links at position x, with "Epochs after an
// ik link" (R29-K4): an epoch of P signed by the link's old_ik or an
// ancestor and established by a message deposited after x suspends if its
// received flag is set, else is demoted by position (audited
// connection.fork_suspected, ref epoch, no feed item). A demoted current
// epoch starts the reconnect after a demotion (K5) unless the caller is
// completing a handshake (restart false). It reports a suspension.
// followIK follows links at x.
func (q *Party) followIK(r *PeerRec, app []IKLink, x Pos, restart bool) bool {
	for _, l := range app {
		if r.isAncestor(l.New) || r.isRejected(l.New) {
			q.w.violate("I3", "%s makes current ancestor/rejected ik %d", q.Name, l.New)
		}
		r.Chain = append(r.Chain, l)
		r.IK, r.KEM = l.New, l.KEM
		key := [2]PID{q.ID, r.ID}
		q.w.ikPos[key] = append(q.w.ikPos[key], ikFollow{l, x})
		if q.newSpec() && r.Device {
			continue // R29-D1, D2: no demotion between a vault and its device
		}
		for j := range r.Epochs {
			ep := &r.Epochs[j]
			if !(ep.Signer == l.Old || r.isAncestor(ep.Signer)) || !x.after(ep.Est) {
				continue
			}
			if ep.Demoted && !(q.newSpec() && ep.Flag) {
				continue // already demoted (from its earlier position); judged again only by its flag
			}
			if q.newSpec() {
				// R29-K4 judges every such epoch at each link, one already
				// demoted at an earlier link included: a flag set since
				// (a message deposited before that link) suspends
				if ep.Flag {
					if ep.Demoted {
						q.w.hit("K4:flag-suspend-already-demoted")
					}
					q.w.hit("K4:flag-suspend")
					q.w.logf("%s: epoch E%d of %s after the link has its received flag set: a copy used it", q.Name, ep.ID, q.w.party(r.ID).Name)
					q.suspend(r, "connection.fork_suspected/epoch")
					return true
				}
				q.w.hit("K4:demote-audit")
				q.w.audits[pairKey(q.ID, r.ID)]++ // connection.fork_suspected (ref epoch): no feed item
			}
			ep.Demoted, ep.DemotedAt = true, x
			q.w.stat("epoch:demoted")
			q.w.logf("%s: epoch E%d of %s demoted (signer %d, after the link)", q.Name, ep.ID, q.w.party(r.ID).Name, ep.Signer)
			if r.Cur == ep.ID {
				r.Cur = 0
				if q.newSpec() {
					q.w.hit("K4:current-demoted")
				}
			}
		}
	}
	if r.Cur == 0 && r.Status == stActive && restart {
		if q.newSpec() {
			q.afterDemotion(r, "K5 reconnect (demotion by position)")
		} else {
			q.abandonOwn(r)
			q.startHS(r, false) // f4a4d97: a rekey sealed to the link's new_kem
		}
	}
	return false
}

// judgeAbandoned: R29-K9 (0.87.1, finding C), at P's identity.rotate under
// msgEp (also one whose links are all followed). An epoch Q began and
// abandoned while pending, later than msgEp, whose sig_R is by a link's
// old_ik or an ancestor, was never activated by P: a set flag suspends;
// otherwise it is ended (a later message under it suspends).
func (q *Party) judgeAbandoned(r *PeerRec, links []IKLink, msgEp int) bool {
	if !q.newSpec() || r.Device || r.Status != stActive {
		return false
	}
	im := slices.IndexFunc(r.Epochs, func(e Epoch) bool { return e.ID == msgEp })
	if im < 0 {
		return false
	}
	// what K9 judged, for the residual's bounds (I3, I7): this link was
	// carried by an identity.rotate, and every epoch up to msgEp was not
	// later than the epoch it traveled under
	for _, l := range links {
		if !slices.Contains(r.IdRotLinks, l) {
			r.IdRotLinks = append(r.IdRotLinks, l)
		}
		for j := 0; j <= im; j++ {
			if sp := (k9Spared{r.Epochs[j].ID, l}); !slices.Contains(r.K9Spared, sp) {
				r.K9Spared = append(r.K9Spared, sp)
			}
		}
	}
	for _, l := range links {
		for j := im + 1; j < len(r.Epochs); j++ {
			ep := &r.Epochs[j]
			if !ep.MineInit || !ep.Abandoned || ep.Ended || ep.Destroyed || !(ep.Signer == l.Old || r.isAncestor(ep.Signer)) {
				continue
			}
			if ep.Flag {
				q.w.hit("K9:flag-suspend")
				q.w.logf("%s: abandoned E%d of %s, later than E%d, has its received flag set: a copy used it", q.Name, ep.ID, q.w.party(r.ID).Name, msgEp)
				q.suspend(r, "connection.fork_suspected/epoch")
				return true
			}
			q.w.hit("K9:ended")
			q.w.audits[pairKey(q.ID, r.ID)]++ // connection.fork_suspected (ref epoch), no feed item
			ep.Ended = true
			r.AbanIDs = slices.DeleteFunc(r.AbanIDs, func(id int) bool { return id == ep.ID })
			q.w.logf("%s: abandoned E%d of %s ended (identity.rotate under E%d)", q.Name, ep.ID, q.w.party(r.ID).Name, msgEp)
		}
	}
	return false
}

// forkEpoch: ctx names an epoch Q superseded by one signed by an ancestor ik.
func (q *Party) forkEpoch(r *PeerRec, ctx int) bool {
	if q.newSpec() {
		// 0.86.0 (2da316e, F2): a ctx naming the current or the confirmed
		// epoch is ordinary; one older than the confirmed epoch, where an
		// epoch after it up to the confirmed one is signed by an ancestor
		// ik, is fork evidence. No deposit-order condition.
		if ctx == r.Cur || ctx == r.ConfID {
			return false
		}
		ic, ik := -1, -1
		for j, ep := range r.Epochs {
			if ep.ID == ctx {
				ic = j
			}
			if ep.ID == r.ConfID {
				ik = j
			}
		}
		if ic < 0 || ik <= ic {
			return false
		}
		// R29-F1: there is no own_copy exception
		for _, ep := range r.Epochs[ic+1 : ik+1] {
			if r.isAncestor(ep.Signer) {
				return true
			}
		}
		return false
	}
	for j, ep := range r.Epochs {
		if ep.ID == ctx {
			for _, next := range r.Epochs[j+1:] {
				if !next.Pending && !next.Abandoned {
					return r.isAncestor(next.Signer)
				}
			}
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
	fork, namedConf := false, false
	if M.Reconnect {
		if slices.Contains(r.Answered, M.HS) {
			return refuse("reconnect_refused", cell+":replay")
		}
		last := r.lastEpoch()
		ok := last != nil && M.Ctx == last.ID
		if q.respHalf() {
			// R29-X5 (§6.6 "Accepting ctx"): the current epoch ("last epoch"
			// means the current epoch), the own pending epoch, the confirmed
			// epoch (R4), an epoch abandoned while pending until a newer one
			// is confirmed; while its own reconnect is pending, only that one
			switch {
			case r.Pend != nil && r.Pend.Reconnect:
				ok = M.Ctx == r.Pend.ID
				q.w.hit("X5:own-reconnect-pending")
			case r.Cur != 0 && M.Ctx == r.Cur:
				ok = true
				q.w.hit("X5:current")
			case r.Pend != nil && M.Ctx == r.Pend.ID:
				ok = true
				q.w.hit("X5:own-pending")
			case r.ConfID != 0 && M.Ctx == r.ConfID:
				ok = true
				q.w.hit("X5:confirmed")
			case slices.Contains(r.AbanIDs, M.Ctx):
				ok = true
				q.w.hit("X5:abandoned-while-pending")
			default:
				ok = false
			}
			if ok && r.ConfID != r.Cur && M.Ctx == r.ConfID {
				namedConf = true // rule E at the verified hs.fin (F7)
				cell += ":confirmed-epoch"
				q.w.hit("R4:reconnect-names-confirmed")
			}
		}
		if !ok {
			if !q.forkEpoch(r, M.Ctx) {
				if q.respHalf() {
					q.w.hit("X5:refused")
				}
				return refuse("reconnect_refused", cell+":ctx")
			}
			q.w.hit("F1:fork-by-ctx-reconnect")
			fork = true // judged at hs.fin (§6.6, H5's exemption)
		}
	} else {
		if q.respHalf() && !q.w.noConfRekey && r.ConfID != 0 && r.ConfID != r.Cur && M.Ctx == r.ConfID && M.Epoch == r.ConfID {
			cell += ":confirmed-epoch" // §6.3.1: accepted as if current (F2: ordinary); my own rekey for it ends
			namedConf = true
			q.w.hit("R4:rekey-names-confirmed")
			if o := r.Own; o != nil && !o.Reconnect {
				q.abandonOwn(r)
			}
		} else if r.Cur == 0 || M.Ctx != r.Cur {
			if q.forkEpoch(r, M.Ctx) {
				q.w.hit("F1:fork-by-ctx-rekey")
				q.suspend(r, "connection.fork_suspected/epoch")
				return dec{"suspend", "fork", cell + ":fork-epoch"}
			}
			return refuse("rekey_not_current_epoch", cell+":ctx")
		}
	}
	// §6.3.1 crossing: I, holding a pending epoch, and a rekey under the current one
	if r.Pend != nil && !M.Reconnect && M.Ctx == r.Cur {
		if M.Ts <= r.Pend.RespTs {
			q.w.hit("X1:crossing-dropped")
			return dec{"drop", "crossing", cell + ":pending:ts-not-later"}
		}
		q.w.hit("X1:later-abandons")
		q.abandonPending(r, "a later rekey from the responder", false)
		cell += ":pending:ts-later"
	}
	// crossing handshakes (§6.5; §6.6 "Between two persons"): answer as
	// usual; the lower th1 wins. Own higher: abandon it. Own lower: keep
	// both; the answer is dropped when the own one completes.
	// lead item 4: the lower-th1 rule applies to any two crossing handshakes.
	if o := r.Own; o != nil && !o.FinSent {
		if o.ID > M.HS {
			q.w.hit("X2:own-higher-abandoned")
			q.abandonOwn(r)
		} else {
			q.w.hit("X2:own-lower-kept")
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
	return q.answerInit(r, m, cell, app, fork, namedConf)
}

// answerInit: the answer to an accepted hs.init (hs.resp queued, the
// answer kept until hs.fin).
func (q *Party) answerInit(r *PeerRec, m *RMsg, cell string, app []IKLink, fork, namedConf bool) dec {
	M := m.P
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
		Links: app, Started: q.w.Now, NewEpoch: q.w.id(), Fork: fork, RespFrom: own, RespInner: q.w.id(), RespRot: q.ownLinks(own),
		NamedConf: namedConf, InitTs: M.Ts, AnsTs: q.now()}
	actor := m.Actor
	if c := q.w.party(actor); c.Copy {
		// ground truth: a copy re-depositing the original's own queued
		// hs.init (the same bytes) is the original's handshake
		if o := q.w.party(c.Origin); o.st.peer(q.Origin) != nil {
			if own := o.st.peer(q.Origin).Own; own != nil && own.ID == M.HS {
				actor = c.Origin
			}
			if own := o.stored.peer(q.Origin).Own; own != nil && own.ID == M.HS {
				actor = c.Origin
			}
		}
	}
	q.w.epTruth[a.NewEpoch] = [2]PID{actor, q.ID}
	if M.Reconnect {
		a.RespToks = q.issue(r, q.st.Relay, true)
	}
	r.Ans = append(r.Ans, a)
	q.enqueueRaw(r.ID, a.respMsg(q, r), func(e *Entry) { e.Box, e.Tok = box, tok })
	return dec{"answer", "", cell}
}

// respMsg: the hs.resp of an answer (the same bytes each time).
func (a *HS) respMsg(q *Party, r *PeerRec) Msg {
	return Msg{Kind: KResp, Inner: a.RespInner, Ts: a.AnsTs, HS: a.ID, NewEpoch: a.NewEpoch, Sig: a.OwnIK,
		Rot: a.RespRot, Reconnect: a.Reconnect, Toks: a.RespToks}
}

func (q *Party) tableBResp(r *PeerRec, M *Msg, pos Pos) dec {
	o := r.Own
	if q.w.Now-o.Started > q.w.hsLifeFor(o.Reconnect) {
		if q.newSpec() {
			q.w.hit("L1:handshake-expired-at-hs.resp")
		}
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
	var extra []IKLink
	if st == ikCurrent {
		// Table B, Current: "accept, then H5 if links were appended": links
		// past the signing ik (an answer made before the responder
		// rotated), appended after the epoch is recorded
		if more, ok := r.resolve(M.Rot); ok && len(more) > 0 {
			extra = more
			cell += ":links-appended"
		}
	}
	if len(app) > 0 && q.followIK(r, app, pos, false) {
		return dec{"suspend", "fork", cell + ":K4-flag"}
	}
	if q.initHalf() {
		q.makePending(r, M.NewEpoch, M.Sig, o.OwnIK, pos, M.Ts, o.Reconnect)
	} else { // Config.OldRules: activation at hs.resp
		q.establish(r, M.NewEpoch, M.Sig, o.OwnIK, pos)
		r.Epochs[len(r.Epochs)-1].MineInit = true
	}
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
	if len(extra) > 0 {
		if q.followIK(r, extra, pos, false) {
			return dec{"suspend", "fork", cell + ":K4-flag"}
		}
		app = extra // H5 below
	}
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
	if q.w.Now-a.Started > q.w.answerLife() {
		if q.newSpec() {
			q.w.hit("L1:hs.fin-after-L")
		}
		q.w.ttlFin[[2]PID{r.ID, q.ID}] = "arrived-after-answer-expired"
		q.dropAnswer(r, a.ID)
		return dec{"drop", "expired", "hs.fin:answer-expired"}
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
	if len(app) > 0 && q.followIK(r, app, pos, false) {
		return dec{"suspend", "fork", cell + ":K4-flag"}
	}
	if r.Pend != nil {
		q.abandonPending(r, "the peer's handshake activated", false) // §6.3.1 (written)
	}
	if a.NamedConf && q.respHalf() && !q.Device { // R29-D2: a device applies no rule E
		q.ruleE(r, a.InitTs)
	}
	q.establish(r, a.NewEpoch, a.PeerIK, a.OwnIK, pos)
	if a.OwnIK != q.st.IK && q.newSpec() {
		q.w.violate("S5", "%s establishes an answer pinned to its superseded ik %d", q.Name, a.OwnIK)
	}
	if q.respHalf() {
		// §6.3.1 (revised): a later activation does not replace the confirmed
		// epoch; its keys run 46 days from the first activation superseding it
		if r.ConfID != 0 && r.ConfID != r.Cur && r.ConfUntil == 0 {
			r.ConfUntil = q.w.Now + aConfKeys
		}
		q.w.hit("R1:hs.confirm-queued")
		r.LastConfirm = q.w.Now
		q.enqueue(r.ID, Msg{Kind: KConfirm, Epoch: a.NewEpoch}, nil)
	}
	if a.Reconnect {
		toks, _ := q.ruleT(r, a.Toks, r.Relay)
		q.keepTokens(r, toks)
	}
	if r.Own != nil {
		q.w.hit("X2:fin-first")
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
	r.Epochs = append(r.Epochs, Epoch{ID: id, Signer: signer, Own: own, Est: pos, EstAt: q.w.Now, EverCur: true})
	r.Cur = id
	q.w.noteCurrent(q, id)
	q.releaseHeld(r) // R29-K5: a new epoch is current
	q.w.hasEpoch[[2]int{int(q.ID), id}] = true
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
		q.abandonPending(r, "suspended or stale", false)
		q.abandonOwn(r)
		for len(r.Ans) > 0 {
			q.dropAnswer(r, r.Ans[0].ID)
		}
		return
	}
	if o := r.Own; o != nil && o.ID != except && r.superseded(o.PeerIK, nil) {
		rc := o.Reconnect
		q.w.hit("K2:own-handshake-restarted")
		q.abandonOwn(r)
		if !rc || r.RestartIK != r.IK {
			r.RestartIK = r.IK
			q.startHS(r, rc)
		}
	}
	if pe := r.Pend; pe != nil && r.superseded(pe.Signer, nil) {
		// R29-K2, "Pending epochs at a link": its sig_R was made by a
		// superseded ik (P dropped that answer at S5): abandoned, and
		// demoted from the start (messages under it: ancestor_ik)
		id := pe.ID
		q.w.hit("K2:pending-abandoned-at-link")
		q.abandonPending(r, "H5: signer superseded", r.Own == nil)
		if ep := r.epoch(id); ep != nil && q.newSpec() {
			ep.AbanByLink = true
			ep.Demoted, ep.DemotedAt = true, Pos{Box: -1}
		}
	}
	for _, a := range slices.Clone(r.Ans) {
		if a.ID != except && !a.Fork && r.superseded(a.PeerIK, a.Links) {
			q.w.hit("K2:answer-dropped-H5")
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
		// ground truth: deposited after the cut-off (an equal deposited_at in
		// another mailbox counts as before: a stated residual)
		if e.Key != m.Sender || !(m.Seq > e.Cut.Seq) || (m.Box != e.Cut.Box && m.DepAt == e.Cut.DepAt) {
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
			if r.followed(f.L) && m.Seq > f.Pos.Seq && !(m.Box != f.Pos.Box && m.DepAt == f.Pos.DepAt) { // ground truth
				if q.Device {
					w.exempt("I3", resDevice)
					continue
				}
				if ep := r.epoch(m.P.Epoch); ep != nil && r.abandonedResidual(ep, f.L) {
					w.exempt("I3", resAbandonedEarlier)
					continue
				}
				w.violate("I3", "%s accepts %s under copy epoch E%d deposited after the ik link %v (epoch %s at %s)", q.Name, kindName[m.P.Kind], m.P.Epoch, f.L, r.epochState(m.P.Epoch), q.Name)
			}
		}
	}
}

// abandonedResidual: the residual "A copy using an epoch Q abandoned while
// pending, outside R29-K9" (owner decision b, 0.87.1) covers epoch ep for
// P's ik link l: an epoch Q began and abandoned while pending (not by a
// link: that one is demoted from the start, K2), not ended, which K9 did
// not judge: not later than the epoch of an identity.rotate carrying l, or
// no identity.rotate carrying l has been judged yet.
func (r *PeerRec) abandonedResidual(ep *Epoch, l IKLink) bool {
	if !ep.MineInit || !ep.Abandoned || ep.Ended || ep.AbanByLink {
		return false
	}
	return slices.Contains(r.K9Spared, k9Spared{ep.ID, l}) || !slices.Contains(r.IdRotLinks, l)
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

// f1Demote: R29-K7, strict F1. A link carried under an epoch E of P,
// while Q's current epoch (pre: before the link's demotions by position)
// is later than E and signed by the link's old_ik, shows that P never
// activated the epochs after E signed by that key, or that a copy did. Q
// takes every epoch of P after E whose P-side signer is the link's old_ik
// or an ancestor: if any has its received flag set, Q suspends; otherwise
// Q demotes them all and reconnects naming E (K5). It reports a suspension.
func (q *Party) f1Demote(r *PeerRec, M *Msg, app []IKLink, x Pos, pre int) bool {
	if !q.newSpec() || r.Device || r.Status != stActive || M.Epoch == 0 || pre == 0 || pre == M.Epoch || !r.newer(pre, M.Epoch) {
		return false
	}
	cur := r.epoch(pre)
	ie := slices.IndexFunc(r.Epochs, func(e Epoch) bool { return e.ID == M.Epoch })
	if cur == nil || ie < 0 {
		return false
	}
	for _, l := range app {
		if cur.Signer != l.Old {
			continue
		}
		var set []int
		flag := false
		for j := ie + 1; j < len(r.Epochs); j++ {
			if ep := &r.Epochs[j]; ep.Signer == l.Old || r.isAncestor(ep.Signer) {
				set = append(set, j)
				flag = flag || ep.Flag
			}
		}
		if flag {
			q.w.hit("K7:flag-suspend")
			q.w.logf("%s: strict F1 for %s (link under E%d): a later epoch has its received flag set", q.Name, q.w.party(r.ID).Name, M.Epoch)
			q.suspend(r, "connection.fork_suspected/epoch")
			return true
		}
		for _, j := range set {
			if ep := &r.Epochs[j]; !ep.Demoted {
				ep.Demoted, ep.DemotedAt = true, x
			}
		}
		q.w.hit("K7:demote")
		if len(set) > 1 {
			q.w.hit("K7:demote-several")
		}
		q.w.audits[pairKey(q.ID, r.ID)]++
		q.w.stat("A:F1-demoted")
		q.w.logf("%s: strict F1 for %s: %d epoch(s) after E%d DEMOTED; reconnect naming E%d", q.Name, q.w.party(r.ID).Name, len(set), M.Epoch, M.Epoch)
		r.Cur, r.DemName = 0, M.Epoch
		q.afterDemotion(r, "K7 reconnect (strict F1)")
		return false
	}
	return false
}

// epochState names an epoch's state for diagnostics.
func (r *PeerRec) epochState(id int) string {
	ep := r.epoch(id)
	switch {
	case ep == nil:
		return "unknown"
	case ep.Demoted:
		return "demoted"
	case ep.Destroyed:
		return "destroyed"
	case ep.Abandoned:
		return "abandoned while pending"
	case ep.Pending:
		return "pending"
	case ep.ID == r.Cur:
		return "current"
	}
	return "superseded"
}
