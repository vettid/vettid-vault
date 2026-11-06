package trustmodel

import (
	"slices"
	"testing"
)

// Deterministic scenarios for R29-K9 (VAULT-MESSAGING 0.87.1 §3.4.1
// "Epochs abandoned while pending, at P's identity.rotate"), R29-K2's
// pending epoch at a link, and R29-K4's flag-set branch: the cases the
// §6.3.2 row for K9 lists as gaps. Each fails when its rule is broken.

// inject deposits M to `to` as `as` would (its key and token for `to`),
// with actor as the ground-truth depositor (an old copy of `as`, or `as`).
func (s *scen) inject(actor, as, to *Party, M Msg) {
	s.t.Helper()
	r := as.st.peer(to.ID)
	M.Inner = s.w.id()
	if M.Ts == 0 {
		M.Ts = s.w.Now
	}
	if _, err := s.w.R.deposit(actor.ID, r.KeyFor, r.standing(r.KeyFor, r.Relay, s.w.Now), r.Relay, &M); err != okRes {
		s.t.Fatalf("inject: deposit refused (%v)", err)
	}
}

// hold leases every message of kind k now in p's mailboxes for a day, so
// that p processes later ones first; release ends the lease.
func (s *scen) hold(p *Party, k Kind) {
	for _, b := range p.boxes() {
		if mb := s.w.R.boxes[b]; mb != nil {
			for _, m := range mb.msgs {
				if m.P.Kind == k {
					m.leaseUntil = s.w.Now + day
				}
			}
		}
	}
}

func (s *scen) release(p *Party, k Kind) {
	for _, b := range p.boxes() {
		if mb := s.w.R.boxes[b]; mb != nil {
			for _, m := range mb.msgs {
				if m.P.Kind == k {
					m.leaseUntil = 0
				}
			}
		}
	}
}

// k9Setup: Q rekeys with P; P answers; Q holds E1 pending; Q's hs.fin is
// lost, so P never activates E1; Q then abandons E1 while pending (for
// want of a token, §6.3.1; called directly). A copy of P is taken now,
// before P's rotation. It returns E0, E1 and the copy.
func k9Setup(t *testing.T) (s *scen, P, Q, c *Party, e0, e1 int) {
	s = newScen(t, 2)
	s.w.relayRot = false
	P, Q = s.p(0), s.p(1)
	e0, e1 = s.pendingAt(Q, P)
	if s.dropAt(P, KFin) == 0 {
		t.Fatalf("setup: no hs.fin to lose")
	}
	s.do(Q, func() { Q.abandonPending(Q.st.peer(P.ID), "no valid standing token", false); Q.write() })
	s.w.makeCopy(P)
	c = s.w.P[len(s.w.P)-1]
	return s, P, Q, c, e0, e1
}

// K9, flag set: the copy sends under E1 before P's identity.rotate (Q
// processes it without confirming E1, and sets its flag); at P's
// identity.rotate under E0, E1 is later than E0 and signed by the link's
// old ik: Q suspends.
func TestR29K9FlagSetSuspends(t *testing.T) {
	s, P, Q, c, _, e1 := k9Setup(t)
	s.inject(c, P, Q, Msg{Kind: KSession, Epoch: e1, Probe: s.w.id()})
	s.run(1, Q)
	r := Q.st.peer(P.ID)
	if ep := r.epoch(e1); ep == nil || !ep.Flag || r.Status != stActive {
		t.Fatalf("the copy's message under E%d did not set its flag: %+v\n  %s", e1, ep, s.trace())
	}
	s.rotate(P, pathCred)
	s.run(1, Q)
	if r.Status != stSuspended || r.Ref != "connection.fork_suspected/epoch" || s.w.stats["R29 K9:flag-suspend"] == 0 {
		t.Fatalf("K9 with the flag set: Q status %d (%s)\n  %s", r.Status, r.Ref, s.trace())
	}
	s.done(false, s.suspended(Q, P))
}

// K9, flag clear: at P's identity.rotate, E1 is ended (audited
// connection.fork_suspected, no feed item, no suspension); the copy's
// later message under it is fork evidence and Q suspends.
func TestR29K9FlagClearEndsThenSuspends(t *testing.T) {
	s, P, Q, c, _, e1 := k9Setup(t)
	s.rotate(P, pathCred)
	k := pairKey(P.ID, Q.ID)
	audits := s.w.audits[k]
	s.run(1, Q)
	r := Q.st.peer(P.ID)
	if ep := r.epoch(e1); ep == nil || !ep.Ended || r.Status != stActive {
		t.Fatalf("K9 with the flag clear: E%d %+v, status %d\n  %s", e1, ep, r.Status, s.trace())
	}
	if s.w.audits[k] <= audits || len(s.w.feed[k]) != 0 {
		t.Errorf("want an audit entry and no feed item: audits %d -> %d, feed %v", audits, s.w.audits[k], s.w.feed[k])
	}
	s.inject(c, P, Q, Msg{Kind: KSession, Epoch: e1, Probe: s.w.id()})
	s.run(1, Q)
	if r.Status != stSuspended || s.w.stats["R29 K9:ended-message-suspends"] == 0 {
		t.Fatalf("a message under the ended E%d did not suspend: status %d\n  %s", e1, r.Status, s.trace())
	}
	s.done(false, s.suspended(Q, P))
}

// A reconnect naming an epoch K9 ended is refused as one naming an epoch Q
// does not keep (§6.6), not taken as fork evidence.
func TestR29K9ReconnectNamingEndedRefused(t *testing.T) {
	s, P, Q, _, _, e1 := k9Setup(t)
	r := Q.st.peer(P.ID)
	if !slices.Contains(r.AbanIDs, e1) {
		t.Fatalf("setup: E%d is not kept for a reconnect's ctx", e1)
	}
	s.rotate(P, pathCred)
	s.run(1, Q)
	if ep := r.epoch(e1); ep == nil || !ep.Ended {
		t.Fatalf("setup: E%d not ended", e1)
	}
	pr := P.st.peer(Q.ID)
	answers, refused := s.w.stats["out answer"], s.w.stats["cell B:current:hs.init:ctx"]
	s.inject(P, P, Q, Msg{Kind: KInit, Reconnect: true, HS: s.w.id(), Ctx: e1, FromIK: P.st.IK, FromKEM: P.st.KEM, FromRelay: pr.KeyFor})
	s.run(1, Q)
	if r.Status != stActive || s.w.stats["cell B:current:hs.init:ctx"] != refused+1 || s.w.stats["out answer"] != answers {
		t.Fatalf("a reconnect naming the ended E%d: status %d\n  %s", e1, r.Status, s.trace())
	}
}

// A link first followed from an hs.resp (Q's later rekey, answered by P
// after its rotation), or applied at an hs.fin (P's rekey after its
// rotation), judges nothing: E1 stays abandoned until P's identity.rotate,
// which then ends it.
func TestR29K9NothingJudgedBeforeIdentityRotate(t *testing.T) {
	for _, via := range []string{"hs.resp", "hs.fin"} {
		t.Run(via, func(t *testing.T) {
			s, P, Q, _, _, e1 := k9Setup(t)
			s.rotate(P, pathCred)
			s.hold(Q, KIdRot)
			r := Q.st.peer(P.ID)
			if via == "hs.resp" {
				s.hold(Q, KInit) // P's restarted rekey (S5) waits too
				s.do(Q, func() { Q.startHS(r, false); Q.write(); Q.flush() })
				s.run(1, P) // P answers under its new ik, with its link
				s.run(1, Q) // Q follows the link at hs.resp
			} else {
				s.do(P, func() { P.startHS(P.st.peer(Q.ID), false); P.write(); P.flush() })
				s.run(1, Q) // Q answers
				s.run(1, P) // P: pending, hs.fin
				s.run(1, Q) // Q applies the link at hs.fin
			}
			if r.IK != P.st.IK {
				t.Fatalf("setup: Q did not follow P's link by %s (ik %d, P at %d)\n  %s", via, r.IK, P.st.IK, s.trace())
			}
			if ep := r.epoch(e1); ep == nil || ep.Ended || s.w.stats["R29 K9:ended"] != 0 {
				t.Fatalf("a link by %s judged E%d: %+v", via, e1, ep)
			}
			s.release(Q, KIdRot)
			s.release(Q, KInit)
			s.run(1, Q)
			if ep := r.epoch(e1); ep == nil || !ep.Ended || r.Status != stActive {
				t.Fatalf("P's identity.rotate did not end E%d: %+v, status %d\n  %s", e1, ep, r.Status, s.trace())
			}
		})
	}
}

// An honest P that activated E1 (its hs.confirm lost) sends its
// identity.rotate under E1: K9 judges only epochs later than E1, so E1,
// which Q abandoned while pending, is neither ended nor a reason to
// suspend.
func TestR29K9HonestActivatedNotJudged(t *testing.T) {
	s := newScen(t, 2)
	s.w.relayRot = false
	P, Q := s.p(0), s.p(1)
	_, e1 := s.lostConfirm(Q, P)
	r := Q.st.peer(P.ID)
	s.do(Q, func() { Q.abandonPending(r, "no valid standing token", false); Q.write() })
	s.rotate(P, pathCred)
	s.run(1, Q)
	ep := r.epoch(e1)
	if ep == nil || ep.Ended || r.Status != stActive || s.w.stats["R29 K9:ended"] != 0 || s.w.stats["R29 K9:flag-suspend"] != 0 {
		t.Fatalf("an honest P's identity.rotate under E%d was judged: %+v, status %d\n  %s", e1, ep, r.Status, s.trace())
	}
	if r.IK != P.st.IK {
		t.Fatalf("Q did not follow P's link")
	}
	s.run(6, P, Q)
	s.done(true)
}

// R29-K2: Q's pending E1 whose sig_R is by the link's old ik is abandoned
// at the link. Followed in P's identity.rotate, K9 ends it (a later message
// under it suspends); followed outside one, it is demoted from the start (a
// later message under it is refused, ancestor_ik).
func TestR29K2PendingEpochAtLink(t *testing.T) {
	for _, via := range []string{"identity.rotate", "other"} {
		t.Run(via, func(t *testing.T) {
			s := newScen(t, 2)
			s.w.relayRot = false
			P, Q := s.p(0), s.p(1)
			_, e1 := s.pendingAt(Q, P)
			if s.dropAt(P, KFin) == 0 {
				t.Fatalf("setup: no hs.fin to lose")
			}
			s.w.makeCopy(P)
			c := s.w.P[len(s.w.P)-1]
			s.rotate(P, pathCred)
			r := Q.st.peer(P.ID)
			if via == "identity.rotate" {
				s.run(1, Q)
			} else {
				s.dropAt(Q, KIdRot)
				l := P.st.Chain[len(P.st.Chain)-1]
				s.do(Q, func() {
					Q.followIK(r, []IKLink{l}, Pos{Box: Q.st.Relay, ID: 1 << 30, DepAt: s.w.Now, Seq: 1 << 30}, false)
					Q.h5(r, 0)
					Q.write()
				})
			}
			ep := r.epoch(e1)
			if r.Pend != nil || ep == nil || !ep.Abandoned || !ep.AbanByLink || s.w.stats["R29 K2:pending-abandoned-at-link"] == 0 {
				t.Fatalf("K2 did not abandon the pending E%d at the link: %+v\n  %s", e1, ep, s.trace())
			}
			if via == "identity.rotate" && !ep.Ended {
				t.Fatalf("K9 did not end E%d: %+v", e1, ep)
			}
			if via == "other" && (!ep.Demoted || ep.DemotedAt.Box != -1 || ep.Ended) {
				t.Fatalf("E%d not demoted from the start: %+v", e1, ep)
			}
			probe := s.w.id()
			s.inject(c, P, Q, Msg{Kind: KSession, Epoch: e1, Probe: probe})
			s.run(1, Q)
			switch via {
			case "identity.rotate":
				if r.Status != stSuspended {
					t.Fatalf("a message under the ended E%d did not suspend\n  %s", e1, s.trace())
				}
			default:
				if r.Status != stActive || s.w.probes[probe] || s.w.stats["cell E:demoted-epoch"] == 0 {
					t.Fatalf("a message under the demoted E%d was not refused (ancestor_ik)\n  %s", e1, s.trace())
				}
			}
		})
	}
}

// R29-K4, flag set: an old copy of P rekeys with Q after P's rotation, but
// Q processes it before P's identity.rotate (a lease); the copy confirms
// and sends under the new epoch E2, which sets its flag. When the link
// arrives, E2 (signed by the link's old ik, established after the link's
// position) has its flag set: Q suspends.
func TestR29K4FlagSetSuspends(t *testing.T) {
	s := newScen(t, 2)
	s.w.relayRot = false
	P, Q := s.p(0), s.p(1)
	s.w.makeCopy(P)
	c := s.w.P[len(s.w.P)-1]
	s.rotate(P, pathCred)
	s.hold(Q, KIdRot)
	c.unlock()
	s.do(c, func() { c.startHS(c.st.peer(Q.ID), false); c.write(); c.flush() })
	s.run(1, Q) // Q answers the copy
	s.run(1, c) // the copy: pending, hs.fin
	s.run(1, Q) // Q activates the copy's epoch, hs.confirm
	s.run(1, c) // the copy confirms
	s.do(c, func() { c.enqueue(Q.ID, Msg{Kind: KSession, Probe: s.w.id()}, nil); c.write(); c.flush() })
	s.run(1, Q)
	r := Q.st.peer(P.ID)
	ep := r.epoch(r.Cur)
	if ep == nil || !ep.Flag || r.Status != stActive {
		t.Fatalf("setup: the copy's epoch is not current with its flag set at Q: %+v\n  %s", ep, s.trace())
	}
	s.release(Q, KIdRot)
	s.run(1, Q)
	if r.Status != stSuspended || s.w.stats["R29 K4:flag-suspend"] == 0 {
		t.Fatalf("K4 with the flag set: status %d (%s)\n  %s", r.Status, r.Ref, s.trace())
	}
}
