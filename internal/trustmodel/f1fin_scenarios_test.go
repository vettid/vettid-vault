package trustmodel

import (
	"testing"
)

// Deterministic scenarios for Strict F1 on the links applied at a rekey's
// verified hs.fin (VAULT-MESSAGING 0.90.4, an erratum to §3.4.1 Strict
// F1). An old copy of P, taken before P's ik rotation, rekeys with Q under
// E0 and finishes first, so the copy's epoch Ec (signed by P's old ik) is
// current at Q when P's own rekey, carrying the link old -> new, reaches
// its hs.fin. Strict F1 runs there with E = E0 (the epoch the rekey
// traveled under). P's identity.rotate is lost, so the link arrives only
// in the rekey (the case 0.90.4 closes).

// f1FinSetup runs the scenario up to P's hs.fin waiting in Q's mailbox.
// It returns the copy, E0, the copy's epoch Ec and P's new epoch Ep.
func f1FinSetup(t *testing.T, off ...bool) (s *scen, P, Q, c *Party, e0, ec, ep int) {
	s = newScen(t, 2)
	s.w.relayRot = false
	s.w.noF1Fin = len(off) > 0 && off[0]
	P, Q = s.p(0), s.p(1)
	e0 = Q.st.peer(P.ID).Cur
	s.w.makeCopy(P)
	c = s.w.P[len(s.w.P)-1]
	c.Locked = false
	// the copy's rekey under E0, answered first
	s.do(c, func() { c.startHS(c.st.peer(Q.ID), false); c.write(); c.flush() })
	s.drain(Q)
	// P rotates its ik; its identity.rotate is lost; its rekey under E0
	// carries the link and is answered
	s.rotate(P, pathCred)
	s.dropAt(Q, KIdRot)
	if Q.st.peer(P.ID).IK == P.st.IK {
		t.Fatalf("setup: Q already follows P's new ik\n  %s", s.trace())
	}
	s.drain(Q)
	if n := len(Q.st.peer(P.ID).Ans); n != 2 {
		t.Fatalf("setup: Q holds %d answers, want the copy's and P's\n  %s", n, s.trace())
	}
	// the copy takes its own hs.resp (deposited first) and sends hs.fin
	c.collectRound(1)
	if c.st.peer(Q.ID).Pend == nil {
		t.Fatalf("setup: the copy holds no pending epoch\n  %s", s.trace())
	}
	ec = c.st.peer(Q.ID).Pend.ID
	// Q establishes the copy's epoch before P's hs.fin exists
	s.drain(Q)
	if r := Q.st.peer(P.ID); r.Cur != ec {
		t.Fatalf("setup: the copy's E%d is not current at Q (E%d)\n  %s", ec, r.Cur, s.trace())
	}
	// P takes its hs.resp and sends hs.fin
	s.drain(P)
	if P.st.peer(Q.ID).Pend == nil {
		t.Fatalf("setup: P holds no pending epoch\n  %s", s.trace())
	}
	ep = P.st.peer(Q.ID).Pend.ID
	return s, P, Q, c, e0, ec, ep
}

// Flag clear: at P's hs.fin, the copy's epoch is demoted (audited
// connection.fork_suspected, no feed item, no reconnect), and P's epoch is
// established.
func TestF1AtFinFlagClearDemotes(t *testing.T) {
	s, P, Q, c, _, ec, ep := f1FinSetup(t)
	k := pairKey(P.ID, Q.ID)
	audits, feed := s.w.audits[k], len(s.w.feed[k])
	s.drain(Q)
	r := Q.st.peer(P.ID)
	e := r.epoch(ec)
	if e == nil || !e.Demoted || r.Status != stActive || r.Cur != ep || r.IK != P.st.IK {
		t.Fatalf("want E%d demoted and E%d current: Ec %+v, current E%d, status %d\n  %s", ec, ep, e, r.Cur, r.Status, s.trace())
	}
	if s.w.stats["R29 K7:demote-at-hs.fin"] == 0 {
		t.Errorf("the demotion was not Strict F1 at hs.fin")
	}
	if s.w.audits[k] <= audits || len(s.w.feed[k]) != feed {
		t.Errorf("want an audit entry and no feed item: audits %d -> %d, feed %d -> %d", audits, s.w.audits[k], feed, len(s.w.feed[k]))
	}
	if r.Own != nil && r.Own.Reconnect {
		t.Errorf("Strict F1 at hs.fin started a reconnect")
	}
	// the copy's later message under its epoch is refused
	s.inject(c, P, Q, Msg{Kind: KSession, Epoch: ec, Probe: s.w.id()})
	s.drain(Q)
	s.noViolation("I3")
}

// Flag set: the copy sent a message under its epoch, which Q accepted (its
// received flag is set); at P's hs.fin Q suspends, and P's epoch is not
// established.
func TestF1AtFinFlagSetSuspends(t *testing.T) {
	s, P, Q, c, _, ec, ep := f1FinSetup(t)
	// the copy's message under Ec goes before P's hs.fin
	s.hold(Q, KFin)
	s.inject(c, P, Q, Msg{Kind: KSession, Epoch: ec, Probe: s.w.id()})
	s.drain(Q)
	r := Q.st.peer(P.ID)
	if e := r.epoch(ec); e == nil || !e.Flag {
		t.Fatalf("the copy's message did not set E%d's flag\n  %s", ec, s.trace())
	}
	s.release(Q, KFin)
	s.drain(Q)
	if r.Status != stSuspended || r.Ref != "connection.fork_suspected/epoch" || s.w.stats["R29 K7:flag-suspend"] == 0 {
		t.Fatalf("want Q suspended at P's hs.fin: status %d (%s)\n  %s", r.Status, r.Ref, s.trace())
	}
	if r.epoch(ep) != nil && r.Cur == ep {
		t.Errorf("P's E%d was established", ep)
	}
}

// Without Strict F1 at hs.fin (before 0.90.4) the copy's epoch is not
// demoted at P's hs.fin, and Q accepts the copy's later message under it
// (I3's last clause; the vault does the same before 0.90.4).
func TestF1AtFinOffLeavesCopyEpoch(t *testing.T) {
	s, P, Q, c, _, ec, _ := f1FinSetup(t, true)
	s.drain(Q)
	r := Q.st.peer(P.ID)
	if e := r.epoch(ec); e == nil || e.Demoted {
		t.Fatalf("without the rule E%d should stay undemoted: %+v", ec, e)
	}
	s.inject(c, P, Q, Msg{Kind: KSession, Epoch: ec, Probe: s.w.id()})
	s.drain(Q)
	found := false
	for _, v := range s.w.viol {
		found = found || v.Inv == "I3"
	}
	if !found {
		t.Errorf("without the rule, I3 should report the copy's message under E%d\n  %s", ec, s.trace())
	}
}
