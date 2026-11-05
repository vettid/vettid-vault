package trustmodel

import (
	"strings"
	"testing"
)

// The review's blind spots (#542): explicit old-copy behaviours, a relay
// that reorders asserted positions, and release <= 28 parties.

func (s *scen) lease(p *Party, k Kind, d int64) {
	for _, b := range p.boxes() {
		if mb := s.w.R.boxes[b]; mb != nil {
			for _, m := range mb.msgs {
				if m.P.Kind == k {
					m.leaseUntil = s.w.Now + d
				}
			}
		}
	}
}

func (s *scen) find(p *Party, k Kind) *RMsg {
	for _, b := range p.boxes() {
		if mb := s.w.R.boxes[b]; mb != nil {
			for _, m := range mb.msgs {
				if m.P.Kind == k {
					return m
				}
			}
		}
	}
	return nil
}

func (s *scen) report(name string, viols ...string) {
	s.t.Helper()
	var got []string
	for _, v := range s.w.viol {
		got = append(got, v.Inv+": "+v.Detail)
	}
	s.t.Logf("%s: %d violation(s)\n  %s", name, len(got), strings.Join(got, "\n  "))
	for _, want := range viols {
		found := false
		for _, v := range s.w.viol {
			found = found || strings.HasPrefix(v.Inv, want)
		}
		if !found {
			s.t.Errorf("%s: expected a %s violation\n  %s", name, want, strings.Join(s.w.log, "\n  "))
		}
	}
}

// F1: the copy holds R's answer (taken after hs.resp, before R's rotation),
// collects I's hs.fin from R's old mailbox during the grace, establishes E1
// and deposits hs.confirm with R's earlier relay key. I confirms E1; the
// real R dropped its answer at S5 and stays on E0: a split.
func TestBlindF1CopyFinishesAnswer(t *testing.T) {
	s := newScen(t, 2)
	I, R := s.p(0), s.p(1)
	s.do(I, func() { I.startHS(I.st.peer(R.ID), false); I.write(); I.flush() })
	s.run(1, R) // R answers
	s.w.makeCopy(R)
	C := s.w.P[len(s.w.P)-1]
	s.rotate(R, pathCred)         // S5: R drops its answer; K0 enters its grace
	s.lease(I, KIdRot, 30*minute) // delivered late (the relay's order, or a slow peer)
	s.lease(I, KUpdate, 30*minute)
	s.lease(I, KInit, 30*minute)
	s.run(1, I) // I: pending E1, hs.fin to R's K0
	s.do(C, C.unlock)
	s.run(1, C) // the copy takes the hs.fin from K0, activates E1, hs.confirm with K0
	s.run(1, I) // I confirms E1
	s.lock(C)
	s.run(8, R, I)
	s.w.checkEnd(true)
	stale := I.st.peer(R.ID).Status == stStale || R.st.peer(I.ID).Status == stStale
	s.report("F1")
	t.Logf("F1 (2da316e): F1 demotions %d; pair stale at the end: %v", s.w.stats["A:F1-demoted"], stale)
	// 2da316e: R's link under E0 shows R never activated E1: I demotes it
	// and reconnects naming E0. Fixed if the pair converges.
	if stale || len(s.w.viol) > 0 || s.w.stats["A:F1-demoted"] == 0 {
		t.Errorf("F1 still stands under 2da316e")
	}
}

// F2a: the relay asserts an honest S5 hs.fin as deposited after the link:
// R demotes E1 and the restarted rekey naming E0 is taken as fork
// evidence: a forced suspension with no second copy.
func TestBlindF2aForcedSuspension(t *testing.T) {
	s := newScen(t, 2)
	I, R := s.p(0), s.p(1)
	s.w.holdRotate = true
	s.do(I, func() { I.startHS(I.st.peer(R.ID), false); I.write(); I.flush() })
	s.run(1, R)
	s.run(1, I)           // pending E1, hs.fin out (signed ik0)
	s.rotate(I, pathCred) // S5: E1 abandoned; identity.rotate; rekey again naming E0
	fin, rot := s.find(R, KFin), s.find(R, KIdRot)
	if fin == nil || rot == nil {
		t.Fatalf("setup: no hs.fin or identity.rotate at R")
	}
	s.w.R.swapPos(R.st.Relay, fin, rot) // delivered fin first, asserted after the link
	s.run(6, R, I)
	s.w.holdRotate = false
	s.w.checkEnd(false)
	s.report("F2a") // 2da316e (F2): the ctx rule by confirmed epoch, no deposit order: no forced suspension
	if len(s.w.viol) > 0 {
		t.Errorf("F2a still stands under 2da316e")
	}
}

// F2b: an old copy's epoch made after the original's link, asserted by the
// relay as before it: not demoted; the original's rekey naming E0 is
// ordinary and destroys the copy's epoch: the fork is never reported.
func TestBlindF2bHiddenFork(t *testing.T) {
	s := newScen(t, 2)
	P, Q := s.p(0), s.p(1)
	s.w.makeCopy(P)
	C := s.w.P[len(s.w.P)-1]
	s.w.holdRotate = true
	s.rotate(P, pathCred) // the link x (identity.rotate) is in Q's mailbox
	rot := s.find(Q, KIdRot)
	rot.leaseUntil = s.w.Now + 2*hour // delivered late
	s.do(C, C.unlock)
	s.do(C, func() { C.startHS(C.st.peer(Q.ID), false); C.write(); C.flush() })
	s.run(1, Q) // Q answers the copy
	s.run(1, C) // the copy: hs.fin
	if fin := s.find(Q, KFin); fin != nil {
		s.w.R.swapPos(Q.st.Relay, fin, rot) // asserted before the link
	}
	s.run(2, Q, C)
	s.lock(C)
	s.tick(2 * hour)
	s.run(8, Q, P)
	s.w.holdRotate = false
	r := Q.st.peer(P.ID)
	t.Logf("Q's epochs for P: cur E%d %+v", r.Cur, r.Epochs)
	copyCur := false
	for _, a := range s.w.epTruth[r.Cur] {
		copyCur = copyCur || s.w.party(a).Copy
	}
	t.Logf("F2b (2da316e): Q suspended %v, Q's current epoch the copy's %v, F1 demotions %d, rule E destroyed %d",
		r.Status == stSuspended, copyCur, s.w.stats["A:F1-demoted"], s.w.stats["A:destroyed-later-epoch"])
	// 2da316e: the copy's epoch is demoted by the F1 rule (the link under
	// E0); it is ended but not reported as a fork (relay residual).
	if copyCur {
		t.Errorf("F2b still stands under 2da316e: the copy's epoch is current\n  %s", strings.Join(s.w.log, "\n  "))
	}
	s.w.checkEnd(false)
	t.Logf("F2b at the end: Q-P status %d (2 = stale: the original needs a new invitation)", Q.st.peer(P.ID).Status)
}

// F3: two copies on a (service-like) connection. The original confirmed E1
// but Q has not yet received anything under it; the copy reconnects naming
// E0 (Q's confirmed epoch): rule E destroys E1, the original's messages are
// refused superseded_epoch, and Q never suspends.
func TestBlindF3RuleEHidesTwoCopies(t *testing.T) {
	s := newScen(t, 2)
	P, Q := s.p(0), s.p(1)
	s.w.makeCopy(P)
	C := s.w.P[len(s.w.P)-1]
	s.do(P, func() { P.startHS(P.st.peer(Q.ID), false); P.write(); P.flush() })
	s.run(1, Q) // Q answers
	s.run(1, P) // P pending E1, hs.fin
	s.run(1, Q) // Q activates E1 (confirmed epoch stays E0), hs.confirm
	s.run(1, P) // P confirms E1
	s.do(C, C.unlock)
	s.do(C, func() { C.startHS(C.st.peer(Q.ID), true); C.write(); C.flush() }) // the copy reconnects naming E0
	s.run(3, Q, C)
	s.lock(C)
	s.do(P, func() { P.enqueue(Q.ID, Msg{Kind: KSession, Probe: s.w.id()}, nil); P.write(); P.flush() })
	s.run(3, Q, P)
	r := Q.st.peer(P.ID)
	t.Logf("F3: destroyed %d, superseded_epoch refusals %d, Q suspended %v",
		s.w.stats["A:destroyed-later-epoch"], s.w.stats["cell E:superseded-epoch"], r.Status == stSuspended)
	// 2da316e (F3): a later-ts message under the destroyed epoch is fork evidence
	if r.Status != stSuspended {
		t.Errorf("F3 still stands under 2da316e\n  %s", strings.Join(s.w.log, "\n  "))
	}
}
