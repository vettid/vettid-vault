package trustmodel

import (
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"sort"
	"strings"
)

// Setup, actions, quiescence, the invariants, shrinking.

type Config struct {
	NoRelayRot bool // no relay-key rotation (the oracle config; release 29 builds none)
	OldApp     bool // the first device is an app from before release 29 (R29-D4)
	Skew       bool // each party's clock off by up to a day either way (the 2-day budget)
	OldRules   bool // f4a4d97 rules: no §6.3.1 (activation at hs.fin)
	Vaults     int  // 2 or 3
	Devices    bool // one device per vault
	P429       float64
	PRefuse    float64
}

func setup(cfg Config, seed uint64) *World {
	w := newWorld(seed)
	w.optA = !cfg.OldRules
	w.relayRot = !cfg.NoRelayRot
	w.p429, w.pRef = 0, 0
	mk := func(name string, dev bool) *Party {
		p := &Party{ID: PID(len(w.P)), Name: name, Device: dev, w: w, collTo: map[Key]int64{}}
		p.Origin = p.ID
		p.st = State{Relay: w.key(), IK: w.key(), KEM: w.key(), Seen: map[int]bool{}, First: map[int]int64{}}
		w.R.register(p.st.Relay)
		w.P = append(w.P, p)
		return p
	}
	names := []string{"P", "Q", "R"}
	for i := 0; i < cfg.Vaults; i++ {
		mk(names[i], false)
	}
	if cfg.Devices {
		for i := 0; i < cfg.Vaults; i++ {
			mk("D"+names[i], true)
		}
	}
	if cfg.OldApp && cfg.Devices {
		w.P[cfg.Vaults].OldApp = true
		w.logf("%s is an app from before release 29", w.P[cfg.Vaults].Name)
	}
	for _, p := range w.P {
		if cfg.Skew {
			p.Skew = int64(w.rng.IntN(int(2*day))) - day
		}
	}
	connect := func(a, b *Party, dev bool) {
		e := w.id()
		w.epTruth[e] = [2]PID{a.ID, b.ID}
		for _, x := range [][2]*Party{{a, b}, {b, a}} {
			me, it := x[0], x[1]
			me.st.Peers = append(me.st.Peers, PeerRec{ID: it.ID, Device: dev, IK: it.st.IK, KEM: it.st.KEM,
				Relay: it.st.Relay, KeyFor: me.st.Relay, Cur: e, ConfID: e,
				Epochs: []Epoch{{ID: e, Signer: it.st.IK, Own: me.st.IK, EstAt: w.Now, EverCur: true}}})
			w.hasEpoch[[2]int{int(me.ID), e}] = true
		}
		for _, x := range [][2]*Party{{a, b}, {b, a}} {
			me, it := x[0], x[1]
			r := me.st.peer(it.ID)
			toks := me.issue(r, me.st.Relay, !dev)
			it.st.peer(me.ID).Toks = toks
		}
	}
	for i := 0; i < cfg.Vaults; i++ {
		for j := i + 1; j < cfg.Vaults; j++ {
			connect(w.P[i], w.P[j], false)
		}
		if cfg.Devices {
			connect(w.P[i], w.P[cfg.Vaults+i], true)
		}
	}
	for _, p := range w.P {
		p.write()
		w.initIK[p.ID] = p.st.IK
	}
	w.p429, w.pRef = cfg.P429, cfg.PRefuse
	return w
}

func (w *World) real() []*Party {
	var out []*Party
	for _, p := range w.P {
		if !p.Copy {
			out = append(out, p)
		}
	}
	return out
}

func (w *World) vaults() []*Party {
	var out []*Party
	for _, p := range w.P {
		if !p.Copy && !p.Device {
			out = append(out, p)
		}
	}
	return out
}

func (w *World) copies() []*Party {
	var out []*Party
	for _, p := range w.P {
		if p.Copy {
			out = append(out, p)
		}
	}
	return out
}

// ---------- actions ----------

type Op int

const (
	opRotate Op = iota
	opRotateBoth
	opDevRotate
	opSend
	opCollect
	opCrash
	opFail
	opLock
	opUnlock
	opTime
	opSnap
	opCopyAct
	opCopyFork
	opCopySteal
	opCopyDelete
	opResolve
	opRekey
	opPeek
	opCopyRespond // reach: an old copy answers and confirms Q's handshake
	opCopyInit    // reach: an old copy makes a handshake with Q as initiator
	opFinLoss     // reach: hs.fin lost around a rotation
	numOps
)

var opName = [...]string{"rotate", "rotate-both", "device-rotate", "send", "collect", "crash-at", "fail-write-at",
	"lock", "unlock", "time", "snapshot", "copy-acts", "copy-forks", "copy-steals", "copy-deletes-mailbox",
	"resolve", "rekey", "peek(lease)", "copy-responds", "copy-initiates", "fin-loss"}

// weights of the random choice
var opWeight = [...]int{6, 2, 2, 8, 14, 3, 3, 4, 6, 8, 3, 3, 1, 1, 1, 2, 3, 3, 2, 2, 2}

type Action struct {
	Op      Op
	A, B, N int
	Seed    uint64
}

var jumps = [...]int64{61, 10 * minute, hour + 1, day + 1, 7*day + 1, 14*day + 1, 30*day + 1}

func (w *World) describeAction(a Action) string {
	pick := func(ps []*Party, i int) string {
		if len(ps) == 0 {
			return "-"
		}
		return ps[i%len(ps)].Name
	}
	switch a.Op {
	case opRotate:
		return fmt.Sprintf("rotate %s (%s)", pick(w.vaults(), a.A), pathName[a.B%3])
	case opRotateBoth:
		return fmt.Sprintf("rotate %s and %s at once", pick(w.vaults(), a.A), pick(w.vaults(), a.A+1))
	case opSend:
		return fmt.Sprintf("send %s -> peer #%d", pick(w.real(), a.A), a.B)
	case opCollect:
		return fmt.Sprintf("collect %s (%d rounds, max %d)", pick(w.real(), a.A), 1+a.N%3, collectMax(a.B))
	case opTime:
		return fmt.Sprintf("time +%ds", jumps[a.N%len(jumps)])
	case opCopyAct, opCopyFork, opCopySteal, opCopyDelete, opCopyRespond, opCopyInit:
		return fmt.Sprintf("%s %s (peer #%d, variant %d)", opName[a.Op], pick(w.copies(), a.A), a.B, a.N)
	case opCrash, opFail, opSnap:
		return fmt.Sprintf("%s %s +%d", opName[a.Op], pick(w.real(), a.A), 1+a.N%3)
	}
	return fmt.Sprintf("%s %s", opName[a.Op], pick(w.real(), a.A))
}

func collectMax(b int) int { return []int{1, 2, 3, maxCollect}[b%4] }

func randomAction(rng *rand.Rand) Action {
	total := 0
	for _, x := range opWeight {
		total += x
	}
	n := rng.IntN(total)
	op := Op(0)
	for n >= opWeight[op] {
		n -= opWeight[op]
		op++
	}
	return Action{Op: op, A: rng.IntN(64), B: rng.IntN(64), N: rng.IntN(64), Seed: rng.Uint64()}
}

func (w *World) exec(a Action) {
	w.rng = rand.New(rand.NewPCG(a.Seed, 11))
	w.stat("action:" + opName[a.Op])
	w.logf("== %s", w.describeAction(a))
	real, vs, cs := w.real(), w.vaults(), w.copies()
	p := real[a.A%len(real)]
	switch a.Op {
	case opRotate:
		v := vs[a.A%len(vs)]
		if !v.Locked {
			v.guard(func() { v.rotate(a.B % 3) })
		}
	case opRotateBoth:
		x, y := vs[a.A%len(vs)], vs[(a.A+1)%len(vs)]
		for _, v := range []*Party{x, y} {
			if !v.Locked {
				v.guard(func() { v.rotate(a.B % 3) })
			}
		}
	case opDevRotate:
		var ds []*Party
		for _, d := range real {
			if d.Device && !d.Locked {
				ds = append(ds, d)
			}
		}
		if len(ds) > 0 {
			d := ds[a.A%len(ds)]
			d.guard(func() { d.rotate(pathDevice) })
		}
	case opSend:
		if !p.Locked && len(p.st.Peers) > 0 {
			r := &p.st.Peers[a.B%len(p.st.Peers)]
			p.guard(func() {
				p.enqueue(r.ID, Msg{Kind: KSession, Probe: w.id()}, nil)
				p.write()
				p.flush()
			})
		}
	case opCollect:
		for i := 0; i <= a.N%3; i++ {
			p.collectRound(collectMax(a.B))
		}
	case opCrash:
		if !p.Locked {
			p.crashAt = p.writes + 1 + a.N%3
		}
	case opFail:
		if !p.Locked {
			p.failAt = p.writes + 1 + a.N%3
		}
	case opLock:
		p.Locked = true
		p.st = p.stored.clone() // memory ends with the lock
		p.rotOK = false
	case opUnlock:
		p.unlock()
	case opTime:
		w.advance(jumps[a.N%len(jumps)])
	case opSnap:
		if a.N%4 == 0 {
			w.makeCopy(p)
		} else {
			p.snapAt = p.writes + 1 + a.N%3
		}
	case opCopyAct, opCopyFork, opCopySteal, opCopyDelete:
		if len(cs) == 0 {
			return
		}
		c := cs[a.A%len(cs)]
		w.copyAction(c, a)
	case opResolve:
		if !p.Locked {
			p.guard(func() {
				for i := range p.st.Peers {
					p.resolve(&p.st.Peers[i])
				}
				p.write()
				p.flush()
			})
		}
	case opRekey:
		if !p.Locked && len(p.st.Peers) > 0 {
			r := &p.st.Peers[a.B%len(p.st.Peers)]
			p.guard(func() {
				p.startHS(r, false)
				p.write()
				p.flush()
			})
		}
	case opCopyRespond, opCopyInit:
		if len(cs) == 0 { // reach: take the copy now (the original may rotate after it)
			w.makeCopy(real[a.A%len(real)])
			cs = w.copies()
		}
		if c := cs[a.A%len(cs)]; a.Op == opCopyRespond {
			w.copyRespond(c, a)
		} else {
			w.copyInit(c, a)
		}
	case opFinLoss:
		w.finLoss(p, a)
	case opPeek:
		if !p.Locked {
			for _, b := range p.boxes() {
				w.R.collect(b, collectMax(a.B)) // leased, never acked: later messages pass them
			}
		}
	}
}

func (w *World) advance(d int64) {
	if d > hour {
		// unlocked parties are online: they collect before a long quiet spell
		for k := 0; k < 2; k++ {
			for _, p := range w.real() {
				for i := 0; i < 8 && p.collectRound(maxCollect) > 0; i++ {
				}
			}
			w.Now += visTimeout + freshWindow + 1
			d -= visTimeout + freshWindow + 1
			w.R.advance()
		}
	}
	// unlocked parties stay online: their timers run at least daily
	for first := true; d > 0; first = false {
		if !first {
			for _, p := range w.real() {
				for i := 0; i < 8 && p.collectRound(maxCollect) > 0; i++ {
				}
			}
		}
		step := min(d, day)
		d -= step
		w.Now += step
		w.R.advance()
		for _, p := range w.real() {
			p.tick()
		}
	}
}

func (w *World) copyAction(c *Party, a Action) {
	orig := w.party(c.Origin)
	if a.Op != opCopyDelete {
		for _, k := range c.myKeys() {
			if slices.Contains(orig.boxes(), k) && w.R.live(k) {
				// residual: the copy collects (and acks) a mailbox the original uses
				w.dead[c.Origin] = "an old copy collected from the original's mailbox (stated residual)"
			}
		}
	}
	switch a.Op {
	case opCopyAct:
		c.unlock()
		for i := 0; i < 2; i++ {
			c.collectRound(maxCollect)
		}
		c.guard(func() {
			if len(c.st.Peers) > 0 {
				r := &c.st.Peers[a.B%len(c.st.Peers)]
				c.enqueue(r.ID, Msg{Kind: KSession, Probe: w.id()}, nil)
				if a.N%2 == 0 {
					c.startHS(r, a.N%4 == 0)
				}
				c.write()
				c.flush()
			}
		})
	case opCopyFork:
		c.unlock()
		before := c.st.Relay
		c.guard(func() { c.rotate(pathCred) })
		if before == orig.st.Relay && c.st.Relay != before {
			// residual: the copy holds the live relay key and moved its mailbox
			w.dead[c.Origin] = "an old copy rotated the original's live mailbox (stated residual)"
		}
		for i := 0; i < 2; i++ {
			c.collectRound(maxCollect)
		}
	case opCopySteal:
		for _, k := range c.myKeys() {
			ms, _ := w.R.collect(k, maxCollect)
			for _, m := range ms {
				w.R.ack(k, m.ID)
			}
		}
	case opCopyDelete:
		if w.R.live(c.st.Relay) {
			w.R.remove(c.st.Relay, w.Now)
			if c.st.Relay == orig.st.Relay {
				w.dead[c.Origin] = "an old copy deleted the original's live mailbox (stated residual)"
			} else {
				w.noLive = "an old copy deleted a mailbox in its grace (stated residual)"
			}
		}
	}
	c.Locked = true
	c.st = c.stored.clone()
}

// resolve: connection.rotation.resolve with the candidate the members
// verified out of band (the original's).
func (q *Party) resolve(r *PeerRec) {
	if r.Status != stSuspended || r.RelayFrk || r.CandA == (IKLink{}) {
		return // not_found
	}
	w := q.w
	keep, drop := r.CandA, r.CandB
	if w.iklinkBy[r.CandB].By == r.ID {
		keep, drop = r.CandB, r.CandA
	}
	if i := slices.Index(r.Chain, drop); i >= 0 {
		r.Dropped = append(r.Dropped, r.Chain[i:]...)
		r.Chain = r.Chain[:i]
		r.IK = drop.Old
		if i > 0 {
			r.KEM = r.Chain[i-1].KEM
		}
	} else {
		r.Dropped = append(r.Dropped, drop)
	}
	r.Seen = slices.DeleteFunc(r.Seen, func(l IKLink) bool { return l == drop })
	if !r.followed(keep) && keep.Old == r.IK {
		r.Chain = append(r.Chain, keep)
		r.IK, r.KEM = keep.New, keep.KEM
	}
	w.logf("%s: resolve %s keeps %d", q.Name, w.party(r.ID).Name, r.IK)
	w.stat("resolve")
	r.Status, r.Ref, r.CandA, r.CandB = stActive, "", IKLink{}, IKLink{}
	q.h5(r, 0)
}

// ---------- quiescence and the invariants ----------

func (w *World) quiet() bool {
	for _, p := range w.real() {
		for _, k := range p.boxes() {
			if b := w.R.boxes[k]; b != nil && len(b.msgs) > 0 {
				return false
			}
		}
		for _, e := range p.st.Out {
			if !e.Done && !e.Ended {
				return false
			}
		}
		for _, r := range p.st.Peers {
			if r.Status == stActive && (r.Own != nil || len(r.Ans) > 0 || r.Pend != nil || len(r.Held) > 0) {
				return false
			}
		}
	}
	return true
}

// settle runs to quiescence as §3.4.1 I1 defines it: every party unlocked
// and online, no faults, leases expired, messages delivered and processed,
// time past every resend (an unlock) and handshake retry.
func (w *World) settle() {
	w.settleOnce()
	if w.optA {
		// 0.86.0 I1: quiescence includes one rekey interval (§6.5: 7 days
		// for devices) after the last rotation
		last := int64(0)
		for _, p := range w.real() {
			last = max(last, p.st.LastRot)
		}
		if last != 0 && w.Now < last+7*day+hour {
			w.advance(last + 7*day + hour - w.Now)
			w.settleOnce()
		}
	}
}

func (w *World) settleOnce() {
	w.p429, w.pRef = 0, 0
	for _, p := range w.real() {
		p.crashAt, p.failAt, p.snapAt = 0, 0, 0
		p.unlock()
	}
	calm := 0
	// R29-K6: a reconnect may take three tries of 16 days, so quiescence
	// (time past every handshake retry) may need more than 96 rounds
	for it := 0; it < 160 && calm < 3; it++ {
		for _, p := range w.real() {
			for i := 0; i < 8 && p.collectRound(maxCollect) > 0; i++ {
			}
		}
		if w.quiet() {
			calm++
		} else {
			calm = 0
		}
		switch {
		case (it == 31 || it == 63 || it == 95 || it == 127) && calm == 0:
			if w.optA {
				w.advance(aPendLife + 1) // past every lifetime of §6.3.1 (B)
			} else {
				w.advance(ansLife + 1) // past every handshake retry and answer expiry
			}
		case it%16 == 15:
			w.advance(day + 1)
		case it%8 == 7:
			w.advance(hour + 1)
			for _, p := range w.real() {
				p.Locked = true
				p.st = p.stored.clone()
				p.unlock()
			}
		default:
			w.advance(visTimeout + freshWindow + 1)
		}
	}
}

func pairName(w *World, a, b PID) string { return w.party(a).Name + "<->" + w.party(b).Name }

// checkEnd: I1 (at quiescence), I2 (at quiescence), I4.
func (w *World) checkEnd(liveness bool) {
	w.settle()
	if os.Getenv("TRUSTMODEL_EXTRA_DAY") != "" {
		// diagnostic: one more scheduled rekey (24 h) before I1
		w.advance(day + hour)
		w.settle()
	}
	// I4
	for key, olds := range w.evid {
		q := w.party(key[0])
		r := q.st.peer(key[1])
		if q.Copy || r == nil {
			continue
		}
		for old, news := range olds {
			var how []string
			for nw := range news {
				if !slices.ContainsFunc(r.Dropped, func(l IKLink) bool { return l.Old == old && l.New == nw }) {
					f := "unfollowed"
					if r.followed(IKLink{}) || slices.ContainsFunc(r.Chain, func(l IKLink) bool { return l.New == nw }) ||
						slices.ContainsFunc(r.RChain, func(l RLink) bool { return l.New == nw }) {
						f = "followed"
					}
					how = append(how, w.evidKind[nw]+"/"+f)
				}
			}
			sort.Strings(how)
			// a stale record (a new invitation is needed) is not checked
			if len(how) >= 2 && r.Status != stSuspended && r.Status != stConflicted && r.Status != stStale && !r.Warned {
				w.violate("I4", "%s saw two successors of %d from %s but is not suspended: carried in %s", q.Name, old, w.party(key[1]).Name, strings.Join(how, " + "))
			}
		}
	}
	// no suspension without a second copy (or a relay that misbehaved)
	for _, q := range w.real() {
		for _, r := range q.st.Peers {
			if r.Status != stSuspended {
				continue
			}
			two, other := false, false
			for _, c := range w.copies() {
				two = two || c.Origin == r.ID
				other = other || c.Origin == q.ID
			}
			switch {
			case !two && other:
				w.violate("I4-misattributed", "%s suspended %s (%s) as two copies; the copy is %s's own", q.Name, w.party(r.ID).Name, r.Ref, q.Name)
			case !two:
				w.violate("I4-false", "%s suspended %s (%s) but no second copy of it exists", q.Name, w.party(r.ID).Name, r.Ref)
			}
		}
	}
	for key, e := range w.forkDue {
		if r := w.party(key[0]).st.peer(key[1]); r.Status != stSuspended && r.Cur == e {
			if w.party(key[0]).Device {
				w.exempt("I3", resDevice)
				continue
			}
			w.violate("I3", "%s: %s's first handshake under its new ik found copy epoch E%d current, and %s did not suspend", w.party(key[0]).Name, w.party(key[1]).Name, e, w.party(key[0]).Name)
		}
	}
	if !liveness {
		return
	}
	if w.noLive != "" {
		w.stat("I1/I2 skipped: " + w.noLive)
		return
	}
	// I2 at quiescence
	for _, x := range w.real() {
		for _, r := range x.st.Peers {
			// SPEC FINDING (I2 wording): checked only for pairs active on both
			// sides; a holder whose peer went stale cannot learn its mailbox ended.
			o := w.party(r.ID).st.peer(x.ID)
			if w.dead[x.ID] != "" || w.dead[r.ID] != "" {
				continue
			}
			if r.Status != stActive || o == nil || o.Status != stActive || w.limits(x, &r) || w.limits(w.party(r.ID), o) {
				if r.Status == stActive {
					w.stat("I2 pair excluded: other side not active")
				}
				continue
			}
			inv2 := "I2"
			if c := w.lostLabel(x.ID, r.ID); c != "" {
				inv2 = "I2/hs-lost:" + c
			}
			for _, t := range r.Toks {
				if !x.holds(t.Sub) || (t.Sub == pendKey(x)) {
					w.violate(inv2, "%s holds a token from %s naming sub %d it does not have or keep", x.Name, w.party(r.ID).Name, t.Sub)
				}
				if !w.R.live(t.Iss) {
					w.violate(inv2, "%s holds a token from %s naming iss %d, no live mailbox", x.Name, w.party(r.ID).Name, t.Iss)
				}
			}
		}
	}
	type pair struct{ a, b *Party }
	var pairs []pair
	for _, x := range w.real() {
		for _, r := range x.st.Peers {
			y := w.party(r.ID)
			if x.ID < y.ID {
				pairs = append(pairs, pair{x, y})
			}
		}
	}
	probe := map[int]string{}
	probeOld := map[int][2]PID{} // probes between an old app and its vault
	for _, pr := range pairs {
		ra, rb := pr.a.st.peer(pr.b.ID), pr.b.st.peer(pr.a.ID)
		if why := w.dead[pr.a.ID] + w.dead[pr.b.ID]; why != "" {
			w.stat("I1 pair excluded: " + why)
			continue
		}
		if ra.Status != stActive || rb.Status != stActive {
			w.stat("I1 pair excluded: " + map[bool]string{true: "suspended/stale/conflict"}[true])
			continue
		}
		// an app from before release 29 may lose the connection (§3.4.1
		// Residuals, "Earlier releases are unsupported"), but the member is
		// still told (R29-D4): its failures are noted for I7, not exempted
		oldApp := w.residualOf(pr.a.ID, pr.b.ID) == resOldApp
		if w.limits(pr.a, ra) || w.limits(pr.b, rb) {
			// SPEC FINDING: §6.6 "Limits": the update cannot reach the peer
			// (resends ended by a definite refusal); the pair is dead but not
			// stale until S1's 30 days.
			w.stat("I1 pair excluded: resends ended (§6.6 Limits)")
			continue
		}
		if (pr.a.st.Pend != nil && pr.a.st.Pend.Refused) || (pr.b.st.Pend != nil && pr.b.st.Pend.Refused) {
			w.stat("I1 pair excluded: refused state")
			continue
		}
		name := pairName(w, pr.a.ID, pr.b.ID)
		inv1 := "I1"
		if c := w.lostLabel(pr.a.ID, pr.b.ID); c != "" {
			inv1 = "I1/hs-lost:" + c
		}
		k := pairKey(pr.a.ID, pr.b.ID)
		fail := func(inv, format string, a ...any) {
			if oldApp {
				w.oldAppDown(k, inv, fmt.Sprintf(format, a...))
				return
			}
			w.violate(inv, format, a...)
		}
		for _, s := range []struct {
			me, it *Party
			r      *PeerRec
		}{{pr.a, pr.b, ra}, {pr.b, pr.a, rb}} {
			if s.r.Relay != s.it.st.Relay {
				fail(inv1, "%s: %s has relay key %d for %s, which is at %d", name, s.me.Name, s.r.Relay, s.it.Name, s.it.st.Relay)
			}
			if s.r.IK != s.it.st.IK {
				fail(inv1, "%s: %s has ik %d for %s, which is at %d", name, s.me.Name, s.r.IK, s.it.Name, s.it.st.IK)
			}
			if s.r.KeyFor != s.me.st.Relay || s.r.standing(s.me.st.Relay, s.it.st.Relay, w.Now).JTI == 0 {
				fail(inv1, "%s: %s holds no token passing rule T for %s's current mailbox (key for it %d, own %d)", name, s.me.Name, s.it.Name, s.r.KeyFor, s.me.st.Relay)
			}
			for _, e := range s.me.st.Out {
				if e.To == s.it.ID && !e.Done && !e.Ended {
					fail(inv1, "%s: %s still holds %s for %s", name, s.me.Name, kindName[e.M.Kind], s.it.Name)
					break
				}
			}
			if len(s.r.Held) > 0 {
				fail(inv1, "%s: %s still holds %d held message(s) for %s (R29-K5)", name, s.me.Name, len(s.r.Held), s.it.Name)
			}
		}
		if ra.Cur == 0 || ra.Cur != rb.Cur {
			fail(inv1, "%s: current epochs differ (E%d vs E%d)", name, ra.Cur, rb.Cur)
		} else if w.optA {
			// R29 I6: after an ik rotation of either side, an epoch whose
			// signer is the new ik is current at both sides
			for _, s := range []struct {
				it  *Party
				at  *PeerRec // the peer's record of it
				own *PeerRec // its own record
			}{{pr.b, ra, rb}, {pr.a, rb, ra}} {
				if s.it.st.IK == w.initIK[s.it.ID] {
					continue
				}
				ep, mine := s.at.epoch(s.at.Cur), s.own.epoch(s.own.Cur)
				if ep == nil || mine == nil || ep.Signer != s.it.st.IK || mine.Own != s.it.st.IK {
					sig, own := Key(0), Key(0)
					if ep != nil {
						sig = ep.Signer
					}
					if mine != nil {
						own = mine.Own
					}
					fail("I6", "%s: after %s's rotation the current epoch E%d is signed by %d (peer's record) / %d (own record), not its new ik %d",
						name, s.it.Name, ra.Cur, sig, own, s.it.st.IK)
				}
			}
		}
		for _, s := range [][2]*Party{{pr.a, pr.b}, {pr.b, pr.a}} {
			id := w.id()
			probe[id] = s[0].Name + "->" + s[1].Name
			if oldApp {
				probeOld[id] = k
			}
			me := s[0]
			me.guard(func() {
				me.enqueue(s[1].ID, Msg{Kind: KSession, Probe: id}, nil)
				me.write()
				me.flush()
			})
		}
	}
	w.settle()
	ids := make([]int, 0, len(probe))
	for id := range probe {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		if !w.probes[id] {
			if k, ok := probeOld[id]; ok {
				w.oldAppDown(k, "I1", "a message "+probe[id]+" was not accepted at quiescence")
				continue
			}
			w.violate("I1", "a message %s was not accepted at quiescence", probe[id])
		}
	}
	// message loss: every session message a real party deposited was opened
	// or refused with a reason (or lost as the spec states: TTL, old mailbox)
	pids := make([]int, 0, len(w.probeDep))
	for id := range w.probeDep {
		pids = append(pids, id)
	}
	sort.Ints(pids)
	stale := false
	for _, x := range w.real() {
		for _, r := range x.st.Peers {
			o := w.party(r.ID).st.peer(x.ID)
			if x.ID < r.ID && (r.Status == stStale || (o != nil && o.Status == stStale)) {
				ref := r.Ref
				if r.Status != stStale {
					ref = o.Ref
				}
				w.stat("end-stale pair: " + ref)
				if w.lostLabel(x.ID, r.ID) != "" {
					w.stat("end-stale pair after a lost hs.fin/hs.confirm")
				}
				stale = true
			}
		}
	}
	if stale {
		w.stat("end-stale run")
	}
	// I1-stale-split: a pair that ends stale having split first
	keys := make([][2]PID, 0, len(w.staleAt))
	for k := range w.staleAt {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i][0] < keys[j][0] || (keys[i][0] == keys[j][0] && keys[i][1] < keys[j][1])
	})
	for _, k := range keys {
		a, b := w.party(k[0]).st.peer(k[1]), w.party(k[1]).st.peer(k[0])
		endsStale := (a != nil && a.Status == stStale) || (b != nil && b.Status == stStale)
		if cause := w.staleAt[k]; cause != "" && endsStale && w.dead[k[0]] == "" && w.dead[k[1]] == "" {
			w.stat("I7: stale after a split (visible)") // was the model's I1-stale-split; R29 §10: a split ending stale is visible
		}
	}
	for _, id := range pids {
		ft := w.probeFate[id]
		pr := w.probeDep[id]
		if w.dead[pr[0]] != "" || w.dead[pr[1]] != "" || w.probes[id] {
			continue
		}
		if res := w.residualOf(pr[0], pr[1]); res == resOldApp && !strings.HasPrefix(w.probeFate[id], "accept") {
			w.oldAppDown(pairKey(pr[0], pr[1]), "I1-loss", "a message "+w.party(pr[0]).Name+"->"+w.party(pr[1]).Name+" was lost ("+ft+")")
			continue
		}
		switch {
		case strings.HasPrefix(ft, "unreadable"):
			inv := "I1-loss"
			if ep := w.probeEpoch[id]; !w.hasEpoch[[2]int{int(pr[1]), ep}] {
				inv = "I1-loss/split" // under an epoch the receiver never activated
			}
			w.violate(inv, "a message %s->%s was silently unreadable (%s)", w.party(pr[0]).Name, w.party(pr[1]).Name, ft)
		case ft == "":
			w.violate("I1-loss", "a message %s->%s vanished (no fate)", w.party(pr[0]).Name, w.party(pr[1]).Name)
		}
	}
}

// limits: §6.6 "Limits": x's recipient has not followed x's new address
// and cannot any more (resends ended, or no standing token for the old
// key, and the old mailbox is gone), but is not yet stale (S1: 30 days).
func (w *World) limits(x *Party, r *PeerRec) bool {
	if r.KeyFor == x.st.Relay {
		return false
	}
	return r.ResendEnd || (r.standing(r.KeyFor, r.Relay, w.Now).JTI == 0 && !w.R.live(r.KeyFor))
}

func pendKey(p *Party) Key {
	if p.st.Pend != nil {
		return p.st.Pend.Key
	}
	return -1
}

// ---------- running and shrinking ----------

type Result struct {
	W    *World
	Viol []Violation
}

func runActions(cfg Config, seed uint64, acts []Action, verbose bool) *World {
	w := setup(cfg, seed)
	w.verbose = verbose
	w.debugUnlinked = os.Getenv("TRUSTMODEL_DEBUG") != ""
	w.ruleEKeepFin = os.Getenv("TRUSTMODEL_RULEEFIN") == "keep"
	defer w.expoStats()
	defer w.rcStats()
	for _, a := range acts {
		w.exec(a)
		w.monitor()
		if len(w.viol) > 0 {
			return w
		}
	}
	w.checkEnd(true)
	w.monitor()
	w.checkI7()
	return w
}

// shrink removes actions while the same invariant still fails (replay).
func shrink(cfg Config, seed uint64, acts []Action, inv string) []Action {
	cur := slices.Clone(acts)
	for chunk := len(cur) / 2; chunk >= 1; chunk /= 2 {
		for i := 0; i+chunk <= len(cur); {
			try := append(slices.Clone(cur[:i]), cur[i+chunk:]...)
			if len(try) == len(cur) {
				i += chunk
				continue
			}
			w := runActions(cfg, seed, try, false)
			if len(w.viol) > 0 && w.viol[0].Inv == inv {
				cur = try
			} else {
				i += chunk
			}
		}
	}
	return cur
}

func traceOf(w *World) string {
	return strings.Join(w.log, "\n")
}
