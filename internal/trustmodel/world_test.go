package trustmodel

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
	"strings"
)

// The world: parties, the relay, ground truth for the invariants, stats.

type Violation struct {
	Inv, Detail string
}

type World struct {
	Now           int64
	R             *Relay
	P             []*Party
	rng           *rand.Rand
	nID           int
	p429          float64 // chance a relay call is answered 429
	pRef          float64 // chance a rotate or registration is refused definitively
	holdRotate    bool
	optA          bool            // VAULT-MESSAGING 0.86.0 §6.3.1 option A (activation on confirmation)
	gate          bool            // Release A gate: activate on confirmation only toward peers that advertise it
	probeDep      map[int][2]PID  // session probes deposited by real parties (from, to)
	probeFate     map[int]string  // what became of each
	seq           int             // ground truth arrival order at the relay
	reverted      map[int]bool    // epochs destroyed by a revert
	hasEpoch      map[[2]int]bool // (party, epoch): the party ever held the epoch
	probeEpoch    map[int]int     // the epoch a probe was sealed under
	literalFork   bool            // read §3.4.1's fork sentence literally (no deposited-after condition) for the confirmed epoch
	debugUnlinked bool            // scenarios: the relay's rotate and registration get no answer

	issuer   map[int]Key    // jti -> iss: a token "verifies" only if its issuer minted it
	epTruth  map[int][2]PID // epoch -> (initiator actor, responder actor)
	rlinkBy  map[RLink]rot  // who made a relay link, at which of its writes
	iklinkBy map[IKLink]rot
	evid     map[[2]PID]map[Key]map[Key]bool // (Q, P) -> old -> news seen at step 3
	ikPos    map[[2]PID][]ikFollow           // (Q, P): identity links followed, with position
	answered map[int]bool                    // outbox entry ids answered 201
	ended    map[int]bool                    // outbox entry ids ended for a stated reason
	ever     map[PID]map[int]bool            // outbox entry ids ever stored, per party
	probes   map[int]bool                    // probes accepted

	viol     []Violation
	log      []string
	verbose  bool
	stats    map[string]int
	noLive   string            // why I1 is not checked in this run (a stated residual), or ""
	dead     map[PID]string    // parties whose liveness a stated residual ended
	ttlFin   map[[2]PID]string // (from, to): how an hs.resp or hs.fin was lost
	forkDue  map[[2]PID]int    // (Q, P): P's hs.init under its new ik found a copy's epoch current
	evidKind map[Key]string    // a successor key -> the kind of the first message that carried it
}

type rot struct {
	By    PID
	Write int
}

type ikFollow struct {
	L   IKLink
	Pos Pos
}

func newWorld(seed uint64) *World {
	w := &World{rng: rand.New(rand.NewPCG(seed, 7)), issuer: map[int]Key{}, epTruth: map[int][2]PID{},
		rlinkBy: map[RLink]rot{}, iklinkBy: map[IKLink]rot{}, evid: map[[2]PID]map[Key]map[Key]bool{},
		ikPos: map[[2]PID][]ikFollow{}, answered: map[int]bool{},
		ended: map[int]bool{}, ever: map[PID]map[int]bool{}, probes: map[int]bool{}, stats: map[string]int{}, dead: map[PID]string{}, ttlFin: map[[2]PID]string{}, probeDep: map[int][2]PID{}, probeFate: map[int]string{}, reverted: map[int]bool{}, hasEpoch: map[[2]int]bool{}, probeEpoch: map[int]int{}, forkDue: map[[2]PID]int{}, evidKind: map[Key]string{}}
	w.R = newRelay(w)
	w.Now = 1000 * day
	return w
}

func (w *World) id() int { w.nID++; return w.nID }
func (w *World) key() Key {
	return Key(w.id())
}
func (w *World) inject429() bool    { return w.p429 > 0 && w.rng.Float64() < w.p429 }
func (w *World) injectRefuse() bool { return w.pRef > 0 && w.rng.Float64() < w.pRef }

func (w *World) logf(format string, a ...any) {
	s := fmt.Sprintf("t=%s %s", w.clock(), fmt.Sprintf(format, a...))
	w.log = append(w.log, s)
}

func (w *World) clock() string {
	t := w.Now - 1000*day
	return fmt.Sprintf("%dd%02dh%02dm%02ds", t/day, t%day/hour, t%hour/minute, t%minute)
}

func (w *World) violate(inv, format string, a ...any) {
	d := fmt.Sprintf(format, a...)
	for _, v := range w.viol {
		if v.Inv == inv && v.Detail == d {
			return
		}
	}
	w.viol = append(w.viol, Violation{inv, d})
	w.logf("!!! %s VIOLATED: %s", inv, d)
}

func (w *World) stat(k string) { w.stats[k]++ }

func (w *World) party(id PID) *Party { return w.P[id] }

// owner: the original party holding relay key k (ground truth).
func (w *World) owner(k Key) PID {
	for _, p := range w.P {
		if !p.Copy && p.holds(k) {
			return p.ID
		}
	}
	return -1
}

func (w *World) mint(iss, sub Key, reconnect bool) Token {
	t := Token{JTI: w.id(), Iss: iss, Sub: sub, Reconnect: reconnect, Iat: w.Now}
	if reconnect {
		t.Exp = w.Now + reconnectLife
	} else {
		t.Exp = w.Now + standingLife
	}
	w.issuer[t.JTI] = iss
	return t
}

// Party is a vault, a device, or an old copy of one of them.
type Party struct {
	ID     PID
	Name   string
	Device bool
	Copy   bool
	Origin PID // a copy's original; itself otherwise
	SnapW  int // a copy: the write of the original it was taken at
	w      *World

	st, stored           State
	storedOut            map[int]bool
	Locked               bool
	writes               int
	crashAt              int
	failAt               int
	snapAt               int
	rotOK                bool // memory: the relay's rotate for the pending key succeeded
	unlocks              int
	collTo               map[Key]int64
	pendEvid             []pendEv // evidence seen in the batch not yet written
	OldConfirm           bool     // an earlier-release responder: no hs.confirm, no confirmed epoch
	Rel28                bool     // release <= 28: activates at hs.fin, no hs.confirm, rekeys while an answer awaits hs.fin
	Opt                  int      // a release-29 option (optFull, optR1, optR2, optR3)
	collectedSinceUnlock bool     // B is judged only after the first collect after an unlock
}

type pendEv struct {
	peer PID
	m    Msg
}

type abort struct{ why string }

func (p *Party) write() {
	p.writes++
	if p.crashAt == p.writes {
		p.crashAt = 0
		p.w.logf("%s: CRASH at write %d", p.Name, p.writes)
		p.restart(true)
		panic(abort{"crash"})
	}
	if p.failAt == p.writes {
		p.failAt = 0
		p.w.logf("%s: write %d FAILED", p.Name, p.writes)
		p.restart(false)
		panic(abort{"failed write"})
	}
	out := p.st.Out[:0]
	for _, e := range p.st.Out {
		if e.Done {
			p.w.answered[e.ID] = true
		} else if e.Ended {
			p.w.ended[e.ID] = true
		} else {
			out = append(out, e)
		}
	}
	p.st.Out = out
	for _, e := range p.pendEvid {
		if r := p.st.peer(e.peer); r != nil {
			p.w.commitEvidence(p, r, &e.m)
		}
	}
	p.pendEvid = nil
	p.stored = p.st.clone()
	p.storedOut = map[int]bool{}
	if p.w.ever[p.ID] == nil {
		p.w.ever[p.ID] = map[int]bool{}
	}
	for _, e := range p.st.Out {
		p.storedOut[e.ID] = true
		p.w.ever[p.ID][e.ID] = true
	}
	if p.snapAt == p.writes {
		p.snapAt = 0
		p.w.makeCopy(p)
	}
}

// restart drops memory and takes the stored state (I5: nothing stored is lost).
func (p *Party) restart(lock bool) {
	p.st = p.stored.clone()
	p.pendEvid = nil
	p.rotOK = false
	p.collTo = map[Key]int64{}
	if lock {
		p.Locked = true
	}
	if p.Copy {
		return
	}
	have := map[int]bool{}
	for _, e := range p.st.Out {
		have[e.ID] = true
	}
	for id := range p.w.ever[p.ID] {
		if !have[id] && !p.w.answered[id] && !p.w.ended[id] {
			p.w.violate("I5", "%s lost stored outbox entry %d at a restart", p.Name, id)
		}
	}
}

func (w *World) makeCopy(p *Party) {
	c := &Party{ID: PID(len(w.P)), Name: p.Name + "'", Device: p.Device, Copy: true, Origin: p.Origin, SnapW: p.writes,
		w: w, Locked: true, collTo: map[Key]int64{}}
	c.st = p.stored.clone()
	c.stored = p.stored.clone()
	c.Rel28, c.Opt, c.OldConfirm = p.Rel28, p.Opt, p.OldConfirm // the copy runs the same release
	c.storedOut = map[int]bool{}
	for _, e := range c.st.Out {
		c.storedOut[e.ID] = true
	}
	c.writes = p.writes
	w.P = append(w.P, c)
	w.logf("old copy %s taken at %s's write %d (relay %d, ik %d)", c.Name, p.Name, p.writes, c.st.Relay, c.st.IK)
}

// guard runs f, ending the operation on a crash or failed write.
func (p *Party) guard(f func()) (aborted bool) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(abort); !ok {
				panic(r)
			}
			aborted = true
		}
	}()
	f()
	return false
}

// myKeys are the relay keys a party holds: current, kept old ones, pending.
func (p *Party) myKeys() []Key {
	ks := []Key{p.st.Relay}
	for _, o := range p.st.Old {
		ks = append(ks, o.Key)
	}
	if p.st.Pend != nil {
		ks = append(ks, p.st.Pend.Key)
	}
	return ks
}

// keyRank orders my relay keys (old ones first).
func (p *Party) keyRank(k Key) int {
	for i, o := range p.st.Old {
		if o.Key == k {
			return i
		}
	}
	if k == p.st.Relay {
		return len(p.st.Old)
	}
	return -1
}

func (p *Party) enqueue(to PID, m Msg, f func(*Entry)) {
	m.Inner = p.w.id()
	if m.Ts == 0 {
		m.Ts = p.w.Now
	}
	e := Entry{ID: m.Inner, To: to, M: m}
	if f != nil {
		f(&e)
	}
	p.st.Out = append(p.st.Out, e)
}

// ---------- deposits (S1, S3, I5) ----------

// mintPass binds every token an entry will carry to the recipient's relay
// key as known now (S3), then stores it before anything leaves (I5).
func (p *Party) mintPass() {
	changed := false
	for i := range p.st.Out {
		e := &p.st.Out[i]
		r := p.st.peer(e.To)
		if r == nil || e.Done || e.Ended || r.Status != stActive {
			continue
		}
		switch e.M.Kind {
		case KUpdate:
			if e.Target != p.st.Relay && p.keyRank(e.Target) < 0 {
				continue // held: the key is still pending
			}
			links := p.linksFrom(r.KeyFor)
			if !slices.Equal(links, e.M.RLinks) || e.M.RelayPK != p.st.Relay || !p.tokFor(e.M.Toks, r, p.st.Relay) {
				e.M.RelayPK, e.M.RLinks = p.st.Relay, links
				e.M.Toks = p.issue(r, p.st.Relay, !r.Device)
				changed = true
			}
		case KInit, KResp:
			// S3: a held token minted for an earlier key of Q is minted again
			// (an hs.init not yet deposited; an hs.resp not yet deposited)
			if e.Tried || len(e.M.Toks) == 0 || p.subOK(e.M.Toks, r) {
				continue
			}
			box := p.st.Relay
			if e.M.Kind == KInit {
				box = e.With
			}
			e.M.Toks = p.issue(r, box, true)
			if o := r.Own; o != nil && e.M.Kind == KInit && o.ID == e.M.HS {
				o.Toks = e.M.Toks
			}
			for j := range r.Ans {
				if e.M.Kind == KResp && r.Ans[j].ID == e.M.HS {
					r.Ans[j].RespToks = e.M.Toks
				}
			}
			changed = true
		case KTokIssued:
			if !p.tokFor(e.M.Toks, r, p.st.Relay) {
				e.M.Toks = p.issue(r, p.st.Relay, len(e.M.Toks) > 1 || (len(e.M.Toks) == 1 && e.M.Toks[0].Reconnect))
				changed = true
			}
		}
	}
	if changed {
		p.write()
	}
}

func (p *Party) subOK(toks []Token, r *PeerRec) bool {
	for _, t := range toks {
		if t.Sub != r.Relay {
			return false
		}
	}
	return true
}

// tokFor: toks are bound to r's current relay key and issued by my mailbox box.
func (p *Party) tokFor(toks []Token, r *PeerRec, box Key) bool {
	if len(toks) == 0 {
		return false
	}
	for _, t := range toks {
		if t.Sub != r.Relay || t.Iss != box || t.Exp-p.w.Now < 10*day {
			return false
		}
	}
	return true
}

// issue mints a standing (and a reconnect) token for r at mailbox box.
func (p *Party) issue(r *PeerRec, box Key, reconnect bool) []Token {
	ts := []Token{p.w.mint(box, r.Relay, false)}
	if reconnect {
		ts = append(ts, p.w.mint(box, r.Relay, true))
	}
	r.Issued = append(r.Issued, ts...)
	return ts
}

// linksFrom: my signed relay links from k to my current key (rule U, S1).
func (p *Party) linksFrom(k Key) []RLink {
	var out []RLink
	at := k
	for at != p.st.Relay {
		found := false
		for _, l := range p.st.RLinks {
			if l.Old == at && (l.New == p.st.Relay || p.keyRank(l.New) >= 0) {
				out = append(out, l)
				at = l.New
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}
	return out
}

// ownLinks: my identity links from ik `from` to my current ik (S8).
func (p *Party) ownLinks(from Key) []IKLink {
	for i, l := range p.st.Chain {
		if l.Old == from {
			return slices.Clone(p.st.Chain[i:])
		}
	}
	return nil
}

// allowedWhileUnacked: S1's list of what goes to Q while my key for Q is not current.
func allowedWhileUnacked(e *Entry) bool {
	switch e.M.Kind {
	case KUpdate, KTokIssued:
		return true
	case KInit, KResp, KFin:
		return e.M.Reconnect
	}
	return false
}

// flush deposits the stored outbox (§8.3 step 5).
func (p *Party) flush() {
	if p.Locked {
		return
	}
	p.mintPass()
	indef := map[PID]bool{}
	for i := range p.st.Out {
		e := &p.st.Out[i]
		if e.Done || e.Ended || !p.storedOut[e.ID] {
			continue
		}
		if e.Denylist {
			if p.holds(e.With) {
				p.w.R.deny(e.Box, e.Revoke)
			}
			e.Done = true
			continue
		}
		r := p.st.peer(e.To)
		if r == nil || r.Status != stActive {
			e.Ended = true
			continue
		}
		if pe := r.Pend; pe != nil && pe.Reconnect && e.M.Kind != KInit && e.M.Kind != KResp && e.M.Kind != KFin && e.M.Kind != KConfirm && !e.Denylist {
			continue // §6.3.1: after a reconnect, nothing but the handshake until confirmation
		}
		if r.KeyFor != p.st.Relay && !allowedWhileUnacked(e) {
			continue // S1: held until Q's token for my current key arrives
		}
		if e.M.Kind == KUpdate {
			if r.KeyFor == p.st.Relay && p.keyRank(e.Target) >= 0 {
				e.Ended = true // the recipient has acknowledged: nothing to announce
				continue
			}
			if p.keyRank(e.Target) < 0 || indef[e.To] {
				continue // pending key (§3.4 step 1), or S1: an earlier deposit has no definite answer
			}
		}
		if e.M.Kind != KUpdate && e.M.Kind != KTokIssued && e.M.Kind != KInit && e.M.Kind != KResp && r.Cur == 0 {
			continue // demoted: nothing until a new epoch
		}
		p.deposit(e, r)
		if e.Indef {
			indef[e.To] = true
		}
	}
}

func (p *Party) holds(k Key) bool { return slices.Contains(p.myKeys(), k) }

func (p *Party) deposit(e *Entry, r *PeerRec) {
	w := p.w
	m := cloneMsg(e.M)
	with, box, tok := e.With, e.Box, e.Tok
	if with == 0 {
		with = r.KeyFor
	}
	if box == 0 {
		box = r.Relay
	}
	if !p.holds(with) {
		e.Ended = true
		return
	}
	if tok.JTI == 0 {
		tok = r.standing(with, box, w.Now)
	}
	if tok.JTI == 0 {
		if p.newSpec() && m.Kind == KResp && !m.Reconnect && !slices.Contains(r.DropAns, m.HS) {
			r.DropAns = append(r.DropAns, m.HS) // §6.3.1 (J)
		}
		if !r.Device && !(m.Kind == KInit && m.Reconnect) {
			p.wantReconnect(r)
		}
		return
	}
	if m.Kind == KInit {
		m.FromRelay = with // SPEC FINDING (silent): built when deposited, as S2 says for reconnects
	}
	// session mode: sealed under the current epoch at deposit
	switch m.Kind {
	case KSession, KUpdate, KTokIssued, KIdRot:
		if r.Cur == 0 {
			return
		}
		m.Epoch = r.Cur
		if m.Kind == KIdRot {
			// S8: rotations from the signer of the epoch it travels in
			if ep := r.epoch(r.Cur); ep != nil {
				if l := p.ownLinks(ep.Own); len(l) > 0 {
					m.Rot = l
				}
			}
		}
	}
	retry := e.Tried
	e.Tried = true
	p.checkI5(e, &m, r, retry)
	id, err := w.R.deposit(p.ID, with, tok, box, &m)
	w.stat("deposit:" + string(err))
	if err == okRes {
		e.Done, e.Indef = true, false
		if m.Kind == KSession && m.Probe > 0 && !p.Copy {
			w.probeDep[m.Probe] = [2]PID{p.ID, e.To}
			w.probeEpoch[m.Probe] = m.Epoch
		}
		w.logf("%s -> %s: %s deposited with %d to box %d (msg %d)%s", p.Name, w.party(e.To).Name, describe(&m), with, box, id, "")
		return
	}
	w.logf("%s -> %s: %s refused %s (with %d, box %d)", p.Name, w.party(e.To).Name, kindName[m.Kind], err, with, box)
	switch err {
	case rateLimited:
		e.Indef = true
	case tokenExpired:
		if r.Pend != nil {
			p.abandonPending(r, "token_expired", false) // §6.3.1
		}
		if !r.Device {
			p.wantReconnect(r)
		}
		r.dropTok(tok.JTI)
	case tokenRevoked:
		r.dropTok(tok.JTI)
		// S9: a token Q issued to an earlier key of mine that is still my key for Q
		if with != p.st.Relay && with == r.KeyFor && r.RevokedAt == 0 {
			r.RevokedAt = w.Now
		}
	case mailboxUnknown:
		if e.M.Kind == KResp && e.Box != 0 {
			e.Ended = true
		}
	default:
		e.Ended = true
	}
	if e.Tok.JTI != 0 && err.definite() {
		e.Ended = true // its one token is refused
	}
	if e.M.Kind == KUpdate && err.definite() && e.Resend {
		r.ResendEnd = true // (b): a definite answer ends the resends
		e.Ended = true
	}
}

func (r *PeerRec) dropTok(jti int) {
	r.Toks = slices.DeleteFunc(r.Toks, func(t Token) bool { return t.JTI == jti })
}

// standing: the newest valid standing token for depositing with key k to box.
func (r *PeerRec) standing(k, box Key, now int64) Token {
	var best Token
	for _, t := range r.Toks {
		if !t.Reconnect && t.Sub == k && t.Iss == box && t.valid(now) && t.Exp > best.Exp {
			best = t
		}
	}
	return best
}

func (r *PeerRec) reconnectTok(k, box Key, now int64) Token {
	for _, t := range r.Toks {
		if t.Reconnect && t.Sub == k && t.Iss == box && t.valid(now) {
			return t
		}
	}
	return Token{}
}

func (p *Party) checkI5(e *Entry, m *Msg, r *PeerRec, retry bool) {
	if p.Copy {
		return
	}
	w := p.w
	if !p.storedOut[e.ID] {
		w.violate("I5", "%s deposits entry %d before the write that stores it", p.Name, e.ID)
	}
	sr := p.stored.peer(r.ID)
	for _, t := range m.Toks {
		if m.Kind == KInit || m.Kind == KResp {
			// minted with the handshake (stored with it)
		}
		found := false
		for _, s := range sr.Issued {
			found = found || s.JTI == t.JTI
		}
		if !found {
			w.violate("I5", "%s sends token %d to %s before storing it", p.Name, t.JTI, w.party(r.ID).Name)
		}
		// SPEC FINDING: §6.3 resends an hs.resp as the same bytes; S3 would
		// re-mint. A retried hs.resp is exempt here.
		if t.Sub != r.Relay && !(retry && m.Kind == KResp) {
			w.violate("I2", "%s sends %s a token naming sub %d, not its relay key as known (%d)", p.Name, w.party(r.ID).Name, t.Sub, r.Relay)
		}
	}
	if m.Kind == KUpdate {
		if m.RelayPK != p.stored.Relay {
			w.violate("I5", "%s announces relay key %d before storing it current", p.Name, m.RelayPK)
		}
		for _, l := range m.RLinks {
			if !slices.Contains(p.stored.RLinks, l) {
				w.violate("I5", "%s sends relay link %v before storing it", p.Name, l)
			}
		}
	}
	if m.Kind == KIdRot || m.Kind == KInit || m.Kind == KResp {
		for _, l := range m.Rot {
			if !slices.Contains(p.stored.Chain, l) {
				w.violate("I5", "%s sends ik link %v before storing it", p.Name, l)
			}
		}
	}
}

func describe(m *Msg) string {
	var b strings.Builder
	b.WriteString(kindName[m.Kind])
	switch m.Kind {
	case KSession:
		fmt.Fprintf(&b, "#%d", m.Probe)
	case KUpdate:
		fmt.Fprintf(&b, "{pk %d links %v}", m.RelayPK, m.RLinks)
	case KTokIssued:
		for _, t := range m.Toks {
			fmt.Fprintf(&b, "{iss %d sub %d}", t.Iss, t.Sub)
		}
	case KIdRot:
		fmt.Fprintf(&b, "%v", m.Rot)
	case KInit:
		p := "rekey"
		if m.Reconnect {
			p = "reconnect"
		}
		fmt.Fprintf(&b, "{%s hs %d ctx %d ik %d relay %d rot %v}", p, m.HS, m.Ctx, m.FromIK, m.FromRelay, m.Rot)
	case KResp, KFin:
		fmt.Fprintf(&b, "{hs %d epoch %d sig %d rot %v}", m.HS, m.NewEpoch, m.Sig, m.Rot)
	}
	if m.Epoch != 0 {
		fmt.Fprintf(&b, " under E%d", m.Epoch)
	}
	return b.String()
}

// ---------- collecting (§12.2, §3.4.1 "Order of processing") ----------

// boxes Q collects from: current, the pending key's once rotated, old ones in grace.
func (p *Party) boxes() []Key {
	bs := []Key{p.st.Relay}
	if p.st.Pend != nil && p.rotOK {
		bs = append(bs, p.st.Pend.Key)
	}
	for _, o := range p.st.Old {
		if p.w.Now < o.GraceEnd {
			bs = append(bs, o.Key)
		}
	}
	return bs
}

// collectRound collects every mailbox once and processes one batch.
func (p *Party) collectRound(max int) int {
	if p.Locked {
		return 0
	}
	w := p.w
	start := w.Now
	p.collectedSinceUnlock = true
	var got []*RMsg
	var set []Key
	for _, b := range p.boxes() {
		ms, err := w.R.collect(b, max)
		if err == mailboxUnknown {
			delete(p.collTo, b)
			if b == p.st.Relay && p.st.Pend != nil && !p.st.Pend.Refused {
				// §12.2: mailbox_unknown starts the rotate / registration
				if p.guard(func() { p.completePending(false) }) {
					return 0
				}
			}
			continue
		}
		set = append(set, b)
		if len(ms) < max {
			p.collTo[b] = start - freshWindow
		}
		got = append(got, ms...)
	}
	multi := len(set) > 1
	minCT := int64(1 << 62)
	if multi {
		for _, b := range set {
			ct, ok := p.collTo[b]
			if !ok {
				ct = -1
			}
			minCT = min(minCT, ct)
		}
		sort.SliceStable(got, func(i, j int) bool {
			if got[i].DepAt != got[j].DepAt {
				return got[i].DepAt < got[j].DepAt
			}
			return got[i].ID < got[j].ID
		})
	}
	var batch []*RMsg
	for _, m := range got {
		if multi && m.DepAt > minCT {
			w.stat("order:held-past-collected-to")
			continue // left unacked
		}
		batch = append(batch, m)
	}
	if len(batch) == 0 {
		return len(got)
	}
	var acks []*RMsg
	p.guard(func() {
		for _, m := range batch {
			if p.handle(m, set) {
				acks = append(acks, m)
			}
		}
		p.reconfirm()
		p.write()
		for _, m := range acks {
			w.R.ack(m.Box, m.ID)
		}
		p.flush()
		p.startWanted()
	})
	return len(got)
}

// otherBoxBehind: another mailbox of Q has not been collected past depAt.
func (p *Party) otherBoxBehind(m *RMsg, set []Key) bool {
	for _, b := range set {
		if b != m.Box {
			if ct, ok := p.collTo[b]; !ok || ct < m.DepAt {
				return true
			}
		}
	}
	return false
}
