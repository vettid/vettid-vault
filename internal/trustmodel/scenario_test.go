package trustmodel

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// Deterministic regression scenarios for the known findings. Each must
// pass under the f4a4d97 rules; a failure is a finding.

type scen struct {
	t *testing.T
	w *World
}

func newScen(t *testing.T, vaults int) *scen {
	w := setup(Config{Vaults: vaults}, 1)
	return &scen{t, w}
}

// newScenOld: the f4a4d97 rules (no §6.3.1).
func newScenOld(t *testing.T, vaults int) *scen {
	w := setup(Config{Vaults: vaults, OldRules: true}, 1)
	return &scen{t, w}
}

func (s *scen) noViolation(prefix string) {
	s.t.Helper()
	for _, v := range s.w.viol {
		if strings.HasPrefix(v.Inv, prefix) {
			s.t.Errorf("violation %s: %s\ntrace:\n  %s", v.Inv, v.Detail, strings.Join(s.w.log, "\n  "))
			return
		}
	}
}

func (s *scen) p(i int) *Party { return s.w.P[i] }

func (s *scen) do(p *Party, f func()) {
	if p.guard(f) {
		s.t.Fatalf("%s aborted", p.Name)
	}
}

// drain: p collects and processes until its mailboxes are empty.
func (s *scen) drain(ps ...*Party) {
	for _, p := range ps {
		for i := 0; i < 16 && p.collectRound(maxCollect) > 0; i++ {
		}
	}
}

// run: everyone online for n rounds of collect, then time past the freshness window.
func (s *scen) run(n int, ps ...*Party) {
	for i := 0; i < n; i++ {
		s.drain(ps...)
		s.tick(visTimeout + freshWindow + 1)
	}
}

func (s *scen) tick(d int64) {
	s.w.Now += d
	s.w.R.advance()
}

func (s *scen) lock(p *Party) { p.Locked = true; p.st = p.stored.clone() }

func (s *scen) rotate(p *Party, path int) { s.do(p, func() { p.rotate(path) }) }

// peek leases every message now in p's mailboxes, so later ones pass them.
func (s *scen) peek(p *Party) {
	for _, b := range p.boxes() {
		s.w.R.collect(b, maxCollect)
	}
}

func (s *scen) done(liveness bool, extra ...func() string) {
	s.w.checkEnd(liveness)
	var bad []string
	for _, v := range s.w.viol {
		bad = append(bad, v.Inv+": "+v.Detail)
	}
	for _, f := range extra {
		if msg := f(); msg != "" {
			bad = append(bad, msg)
		}
	}
	if os.Getenv("TRUSTMODEL_TRACE") != "" {
		s.t.Logf("trace:\n  %s", strings.Join(s.w.log, "\n  "))
	}
	if len(bad) > 0 {
		s.t.Errorf("FINDING:\n  %s\ntrace:\n  %s", strings.Join(bad, "\n  "), strings.Join(s.w.log, "\n  "))
	}
}

func (s *scen) suspended(q, p *Party) func() string {
	return func() string {
		if r := q.st.peer(p.ID); r.Status != stSuspended {
			return q.Name + " is not suspended for " + p.Name
		}
		return ""
	}
}

func (s *scen) cellSeen(cell string) func() string {
	return func() string {
		if s.w.stats["cell "+cell] == 0 {
			return "cell " + cell + " never decided"
		}
		return ""
	}
}

// Lead H1: chained relay rotations past the grace while Q is locked.
func TestScenarioLeadH1ChainedPastGrace(t *testing.T) {
	s := newScen(t, 2)
	P, Q := s.p(0), s.p(1)
	s.lock(Q)
	s.rotate(P, pathCred) // K0 -> K1
	s.tick(graceLen + day)
	s.drain(P)
	s.rotate(P, pathCred) // K1 -> K2; K1's mailbox ends below
	s.tick(graceLen + day)
	s.drain(P)
	s.do(Q, Q.unlock)
	s.run(4, Q, P)
	s.done(true) // only the second update is left (the first expired): its chain from K0 carries Q
}

// Lead H1, variant: both updates still at the relay; K1's mailbox has ended.
func TestScenarioLeadH1ChainedPastGraceBothUpdates(t *testing.T) {
	s := newScen(t, 2)
	P, Q := s.p(0), s.p(1)
	s.lock(Q)
	s.rotate(P, pathCred) // K0 -> K1
	s.tick(hour)
	s.rotate(P, pathCred) // K1 -> K2
	s.tick(graceLen + 2*hour)
	s.drain(P)
	s.do(Q, Q.unlock)
	s.run(4, Q, P)
	s.done(true, s.cellSeen("U(earlier-after):follow"))
}

// Lead H3: chained ik links, reordered within one mailbox.
func TestScenarioLeadH3ChainedIKReordered(t *testing.T) {
	s := newScen(t, 2)
	P, Q := s.p(0), s.p(1)
	s.w.holdRotate = true // relay keys stay pending; the ik links go out
	s.rotate(P, pathCred)
	s.peek(Q) // the first identity.rotate is leased: the second passes it
	s.rotate(P, pathCred)
	s.w.holdRotate = false
	s.drain(Q)
	s.run(6, Q, P)
	s.done(true, s.cellSeen("B:ancestor:identity.rotate"))
}

// N1: a rotation while an own answer awaits hs.fin (S5).
func TestScenarioN1RotationWhileAnswerAwaitsFin(t *testing.T) {
	for _, reorder := range []bool{false, true} {
		s := newScen(t, 2)
		P, Q := s.p(0), s.p(1)
		s.do(Q, func() { Q.startHS(Q.st.peer(P.ID), false); Q.write(); Q.flush() })
		s.drain(P) // P answers: its answer awaits hs.fin
		s.rotate(P, pathCred)
		if reorder {
			s.peek(Q) // hs.resp and identity.rotate leased in turn
			s.tick(visTimeout + 1)
		}
		s.run(6, Q, P)
		s.done(true)
	}
}

// N2: a restarted rekey answered before identity.rotate is processed.
func TestScenarioN2RestartedRekeyBeforeRotate(t *testing.T) {
	s := newScen(t, 2)
	P, Q := s.p(0), s.p(1)
	s.w.holdRotate = true
	s.do(P, func() { P.startHS(P.st.peer(Q.ID), false); P.write(); P.flush() }) // P's rekey
	s.rotate(P, pathCred)                                                       // S5: abandoned, restarted after identity.rotate
	// deliver the restarted hs.init first: lease the identity.rotate
	for _, m := range s.w.R.boxes[Q.st.Relay].msgs {
		if m.P.Kind == KIdRot {
			m.leaseUntil = s.w.Now + visTimeout
		}
	}
	s.drain(Q)
	s.w.holdRotate = false
	s.run(6, Q, P)
	s.done(true, s.cellSeen("B:reached:hs.init"))
}

// Design H1: both vaults rotate at once.
func TestScenarioDesignH1BothRotate(t *testing.T) {
	s := newScen(t, 2)
	P, Q := s.p(0), s.p(1)
	s.rotate(P, pathCred)
	s.rotate(Q, pathRecovery)
	s.run(6, P, Q)
	s.done(true)
}

// Design H2: fork evidence from an earlier key (after the cut-off).
func TestScenarioDesignH2ForkFromEarlierKey(t *testing.T) {
	s := newScen(t, 2)
	P, Q := s.p(0), s.p(1)
	s.w.makeCopy(P)
	C := s.w.P[len(s.w.P)-1]
	s.rotate(P, pathRecovery)
	s.run(4, Q, P) // Q follows: K0 is earlier, with its cut-off
	s.do(C, C.unlock)
	s.rotate(C, pathCred) // a second successor of ik0 and of K0, deposited with K0
	s.run(2, Q)
	s.done(false, s.suspended(Q, P))
}

// Design H3: a reconnect before the peer follows (during the grace).
func TestScenarioDesignH3ReconnectBeforeFollow(t *testing.T) {
	s := newScen(t, 2)
	P, Q := s.p(0), s.p(1)
	s.lock(Q)
	s.tick(25 * day)
	s.w.p429 = 1 // the update gets no answer until P's standing token has expired
	s.rotate(P, pathCred)
	s.tick(5*day + hour) // P's standing token for Q's mailbox has expired; K0 is in its grace
	s.w.p429 = 0
	s.do(P, func() { P.tick() })
	s.do(Q, Q.unlock)
	s.run(6, Q, P)
	s.done(true, s.cellSeen("B:current:hs.init"), func() string {
		if !slices.ContainsFunc(s.w.log, func(l string) bool {
			return strings.Contains(l, "P -> Q: hs.init{reconnect") && strings.Contains(l, "relay 1 ")
		}) {
			return "P sent no reconnect announcing its old key"
		}
		return ""
	})
}

// #204 finding 1: fork evidence on a reconnect survives a rotation (H5's
// exemption). Under the f4a4d97 rules; under §6.3.1 see TestFindingE.
func TestScenario204F1ForkReconnectSurvives(t *testing.T) {
	s := newScenOld(t, 2)
	P, Q := s.p(0), s.p(1)
	s.w.makeCopy(P)
	C := s.w.P[len(s.w.P)-1]
	s.do(C, C.unlock)
	s.do(C, func() { C.startHS(C.st.peer(Q.ID), false); C.write(); C.flush() }) // the copy rekeys: E2 signed by ik0
	s.run(3, Q, C)
	s.w.holdRotate = true
	s.rotate(P, pathCred) // the relay key stays pending; the identity link goes out
	s.do(P, func() { r := P.st.peer(Q.ID); P.abandonOwn(r); P.startHS(r, true); P.write(); P.flush() })
	s.run(6, Q, P)
	s.w.holdRotate = false
	s.done(false, s.suspended(Q, P))
}

// #204 finding 2: a peer rotates while its own reconnect is open.
func TestScenario204F2RotateWhileOwnReconnect(t *testing.T) {
	s := newScen(t, 2)
	P, Q := s.p(0), s.p(1)
	s.do(P, func() { P.startHS(P.st.peer(Q.ID), true); P.write(); P.flush() })
	s.drain(Q) // Q answers the reconnect pinned to ik0
	s.rotate(P, pathCred)
	s.run(6, P, Q)
	s.done(true)
}

// #204 finding 3: handshakes pinned to a candidate rejected at resolve do not complete.
func TestScenario204F3ResolveRejected(t *testing.T) {
	s := newScen(t, 2)
	P, Q := s.p(0), s.p(1)
	s.w.makeCopy(P)
	C := s.w.P[len(s.w.P)-1]
	s.do(C, C.unlock)
	s.w.holdRotate = true
	s.rotate(C, pathCred) // the copy's ik0 -> X reaches Q first
	s.run(1, Q)
	s.do(C, func() { C.startHS(C.st.peer(Q.ID), false); C.write(); C.flush() }) // pinned to X
	s.run(1, Q)
	s.rotate(P, pathCred) // the original's ik0 -> ik1: a conflict
	s.run(1, Q)
	s.do(Q, func() { Q.resolve(Q.st.peer(P.ID)); Q.write(); Q.flush() })
	s.run(6, C, Q, P)
	s.w.holdRotate = false
	s.done(false, func() string {
		r := Q.st.peer(P.ID)
		for _, e := range r.Epochs {
			if r.isRejected(e.Signer) && e.EstAt >= s.w.Now-hour {
				return "an epoch signed by the rejected ik was established after resolve"
			}
		}
		return ""
	})
}

// #204 finding 4: rule C on an hs.resp's rotations.
func TestScenario204F4ConflictInResp(t *testing.T) {
	s := newScen(t, 2)
	P, Q := s.p(0), s.p(1)
	s.rotate(P, pathCred) // R1 completes
	s.run(4, Q, P)
	s.w.makeCopy(P) // holds K1 and ik1
	C := s.w.P[len(s.w.P)-1]
	s.w.holdRotate = true
	s.rotate(P, pathCred) // R2: ik1 -> ik2 goes out, K2 stays pending
	s.run(1, Q)           // Q follows ik1 -> ik2
	s.do(C, C.unlock)
	s.w.p429 = 1
	s.rotate(C, pathCred) // the copy: ik1 -> X (its relay key stays pending)
	s.w.p429 = 0
	// the copy chooses not to send its identity.rotate: only its hs.resp will carry the link
	C.st.Out = slices.DeleteFunc(C.st.Out, func(e Entry) bool { return e.M.Kind == KIdRot })
	s.do(C, C.write)
	s.run(1, Q)
	s.do(Q, func() { r := Q.st.peer(P.ID); Q.abandonOwn(r); Q.startHS(r, false); Q.write(); Q.flush() })
	s.run(2, C) // the copy answers with rotations [ik1 -> X]
	s.run(2, Q)
	s.w.holdRotate = false
	s.done(false, s.suspended(Q, P), func() string {
		if s.w.stats["ruleC:identity"] == 0 || Q.st.peer(P.ID).CandB.New == 0 {
			return "the conflict was not found in the hs.resp"
		}
		return ""
	})
}
