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
// under it suspends); followed outside one (applied at the hs.fin of P's
// reconnect), it is demoted from the start (a later message under it is
// refused, ancestor_ik).
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
				// the link reaches Q in P's reconnect, applied at its hs.fin
				// (a rekey's hs.init would abandon E1 at the crossing first,
				// and Q, holding E1 pending, has no handshake of its own for
				// an hs.resp to answer)
				s.dropAt(Q, KIdRot)
				s.dropAt(Q, KInit) // P's restarted rekey
				rp := P.st.peer(Q.ID)
				s.do(P, func() { P.abandonOwn(rp); P.startHS(rp, true); P.write(); P.flush() })
				s.run(1, Q) // Q answers P's reconnect (links kept for hs.fin)
				s.run(1, P) // P: pending, hs.fin
				s.dropAt(Q, KIdRot)
				s.run(1, Q) // Q applies the link at hs.fin
				if r.IK != P.st.IK {
					t.Fatalf("setup: Q did not follow P's link at hs.fin\n  %s", s.trace())
				}
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

// R29-K9 on Table A's "Earlier, after its cut-off" row (relay-key rotation
// on): Q has followed P's relay update (cut-off) and P's ik link (at an
// hs.fin, which judges nothing); P's identity.rotate itself never reached
// Q. An old copy of P taken after the rotation's first write (it holds the
// old relay key and the new link, §3.4.1 Residuals) deposits an
// identity.rotate under E0 from the old key after the cut-off: every link
// is followed, so it is ignored, and K9 is still judged: E1, abandoned
// while pending and later than E0, is ended.
func TestR29K9AfterCutOffIgnoreJudged(t *testing.T) {
	s := newScen(t, 2)
	P, Q := s.p(0), s.p(1)
	if !s.w.relayRot {
		t.Fatalf("setup: relay-key rotation is off")
	}
	e0, e1 := s.pendingAt(Q, P)
	if s.dropAt(P, KFin) == 0 {
		t.Fatalf("setup: no hs.fin to lose")
	}
	r := Q.st.peer(P.ID)
	s.do(Q, func() { Q.abandonPending(r, "no valid standing token", false); Q.write() })
	s.rotate(P, pathCred)
	s.w.makeCopy(P)
	c := s.w.P[len(s.w.P)-1]
	for i := 0; i < 10; i++ {
		s.dropAt(Q, KIdRot) // P's own identity.rotate never reaches Q
		s.run(1, P, Q)
	}
	if r.IK != P.st.IK || r.Relay != P.st.Relay || len(r.Earlier) == 0 {
		t.Fatalf("setup: Q did not follow both links (ik %d/%d, relay %d/%d)\n  %s", r.IK, P.st.IK, r.Relay, P.st.Relay, s.trace())
	}
	if ep := r.epoch(e1); ep == nil || ep.Ended {
		t.Fatalf("setup: E%d already judged: %+v\n  %s", e1, ep, s.trace())
	}
	cr := c.st.peer(Q.ID)
	old := r.Earlier[0].Key
	tok := cr.standing(old, cr.Relay, s.w.Now)
	M := Msg{Kind: KIdRot, Inner: s.w.id(), Epoch: e0, Rot: slices.Clone(P.st.Chain), Ts: s.w.Now}
	if _, err := s.w.R.deposit(c.ID, old, tok, Q.st.Relay, &M); err != okRes {
		t.Fatalf("setup: the copy's deposit was refused (%v)", err)
	}
	s.run(1, Q)
	if s.w.stats["cell A:earlier-after:identity.rotate:all-followed"] == 0 || s.w.stats["R29 K9:judged-after-cut-off"] == 0 {
		t.Fatalf("not decided by Table A's after-cut-off ignore\n  %s", s.trace())
	}
	if ep := r.epoch(e1); ep == nil || !ep.Ended || r.Status != stActive {
		t.Fatalf("K9 not judged at the ignore: E%d %+v, status %d\n  %s", e1, ep, r.Status, s.trace())
	}
	// the model's reading: the ended-epoch check runs where rule E's
	// destroyed check does (before Table A), so the copy's message under E1
	// from the earlier key after its cut-off is fork evidence, not merely
	// refused (superseded_relay)
	S := Msg{Kind: KSession, Inner: s.w.id(), Epoch: e1, Probe: s.w.id(), Ts: s.w.Now}
	if _, err := s.w.R.deposit(c.ID, old, tok, Q.st.Relay, &S); err != okRes {
		t.Fatalf("the copy's second deposit was refused (%v)", err)
	}
	s.run(1, Q)
	if r.Status != stSuspended || s.w.stats["cell E:ended-epoch"] == 0 {
		t.Fatalf("a message under the ended E%d from an earlier key after its cut-off did not suspend: status %d\n  %s", e1, r.Status, s.trace())
	}
}

// R29-K4 at a later link judges an epoch an earlier link already demoted:
// a flag set since (by a message deposited before the earlier link, which
// is accepted) suspends. P rotates twice (a->b, then b->c); both
// identity.rotates wait. The old copy (taken before both) sets up E2 with
// Q, established after both links. At the first link E2 is demoted by
// position, its flag clear; its flag is then set (as a message deposited
// before that link would set it; set directly, since one mailbox cannot
// order such a message after E2's hs.fin); the second link suspends.
func TestR29K4AlreadyDemotedFlagSuspends(t *testing.T) {
	s := newScen(t, 2)
	s.w.relayRot = false
	P, Q := s.p(0), s.p(1)
	s.w.makeCopy(P)
	c := s.w.P[len(s.w.P)-1]
	s.rotate(P, pathCred) // a->b
	s.rotate(P, pathCred) // b->c
	s.hold(Q, KIdRot)
	s.hold(Q, KInit) // P's restarted handshakes wait; only the links matter here
	c.unlock()
	s.do(c, func() { c.startHS(c.st.peer(Q.ID), false); c.write(); c.flush() })
	s.run(1, Q) // Q answers the copy
	s.run(1, c) // the copy: pending, hs.fin
	s.run(1, Q) // Q activates the copy's epoch E2 (flag clear: only hs.fin)
	c.Locked, c.st = true, c.stored.clone()
	r := Q.st.peer(P.ID)
	e2 := r.Cur
	if ep := r.epoch(e2); ep == nil || ep.Flag {
		t.Fatalf("setup: E%d %+v\n  %s", e2, ep, s.trace())
	}
	var ids []*RMsg
	for _, m := range s.w.R.boxes[Q.st.Relay].msgs {
		if m.P.Kind == KIdRot {
			ids = append(ids, m)
		}
	}
	if len(ids) != 2 {
		t.Fatalf("setup: %d identity.rotate waiting, want 2", len(ids))
	}
	ids[0].leaseUntil = 0
	s.run(1, Q) // the first link: E2 demoted by position, flag clear
	ep := r.epoch(e2)
	if ep == nil || !ep.Demoted || r.Status != stActive {
		t.Fatalf("setup: E%d not demoted at the first link: %+v\n  %s", e2, ep, s.trace())
	}
	s.do(Q, func() { r.epoch(e2).Flag = true; Q.write() })
	ids[1].leaseUntil = 0
	s.run(1, Q)
	if r.Status != stSuspended || s.w.stats["R29 K4:flag-suspend-already-demoted"] == 0 {
		t.Fatalf("K4 at the second link did not judge the demoted E%d's flag: status %d\n  %s", e2, r.Status, s.trace())
	}
}

// Signer ancestry is judged against the link's old ik, not P's current
// ik. An honest sequence: P rotates a->b and its identity.rotate M1 under
// E0 is delayed; Q learns a->b from P's hs.resp to Q's rekey, so E1
// (signer b) goes pending; Q abandons E1; P had activated E1 and its
// hs.confirm sets E1's flag; P rotates b->c (under E1); M1 then arrives
// under E0. Every link of M1 is followed; E1's signer b is not a->b's old
// ik a nor an ancestor of it, so K9 neither suspends nor ends E1.
func TestR29K9SignerAncestryOfTheLink(t *testing.T) {
	s := newScen(t, 2)
	s.w.relayRot = false
	P, Q := s.p(0), s.p(1)
	s.rotate(P, pathCred) // a->b; M1 under E0
	s.hold(Q, KIdRot)
	s.hold(Q, KInit) // P's restarted rekey waits too
	r := Q.st.peer(P.ID)
	s.do(Q, func() { Q.startHS(r, false); Q.write(); Q.flush() })
	s.run(1, P) // P answers under b, with a->b
	s.run(1, Q) // Q follows a->b at hs.resp; E1 (signer b) pending; hs.fin
	if r.Pend == nil || r.IK != P.st.IK {
		t.Fatalf("setup: Q has no pending E1 signed by P's new ik\n  %s", s.trace())
	}
	e1 := r.Pend.ID
	s.do(Q, func() { Q.abandonPending(r, "no valid standing token", false); Q.write() })
	s.run(1, P) // P activates E1 at hs.fin, hs.confirm
	s.run(1, Q) // E1's flag set (processed without confirming)
	if ep := r.epoch(e1); ep == nil || !ep.Flag || !ep.Abandoned {
		t.Fatalf("setup: E%d %+v\n  %s", e1, ep, s.trace())
	}
	if P.st.peer(Q.ID).Cur != e1 {
		t.Fatalf("setup: P is not on E%d", e1)
	}
	s.rotate(P, pathCred) // b->c, under E1
	s.hold(Q, KInit)
	s.run(1, Q)
	if r.IK != P.st.IK || r.Status != stActive {
		t.Fatalf("setup: Q did not follow b->c (status %d)\n  %s", r.Status, s.trace())
	}
	s.release(Q, KIdRot) // M1, a->b under E0
	s.run(1, Q)
	if ep := r.epoch(e1); r.Status != stActive || ep == nil || ep.Ended {
		t.Fatalf("an honest P's delayed identity.rotate judged E%d: status %d (%s), %+v\n  %s", e1, r.Status, r.Ref, ep, s.trace())
	}
}

// (0.88.2, owner decision a; §6.6 "The links of a refused reconnect")
// Shape: Q reconnects to P; P answers; Q holds the reconnect pending (its
// hs.fin sent, then lost). P rotates (S5 drops its answer), and its
// identity.rotate never reaches Q (dropped here; in the review's runs it
// was refused or out of reach). P then reconnects, carrying its link. Q
// refuses that reconnect, only because its own is pending. With the rule
// Q follows the link in the refusing write: H5 abandons Q's pending
// reconnect (K2, signed by P's old ik), Q reconnects again under P's new
// ik and the pair converges. Without it (World.noRefusedLinks) Q never
// learns P's new ik, refuses every reconnect of P's, and its pending
// reconnect reaches B: the pair ends stale.
func TestR29RefusedReconnectLinks(t *testing.T) {
	bothWays(t, func(t *testing.T, off bool) {
		s := newScen(t, 2)
		s.w.relayRot = false
		s.w.noRefusedLinks = off
		P, Q := s.p(0), s.p(1)
		rq := Q.st.peer(P.ID)
		s.do(Q, func() { Q.startHS(rq, true); Q.write(); Q.flush() })
		s.run(1, P) // P answers Q's reconnect
		s.run(1, Q) // Q: pending reconnect, hs.fin
		if rq.Pend == nil || !rq.Pend.Reconnect {
			t.Fatalf("setup: Q holds no pending reconnect\n  %s", s.trace())
		}
		s.dropAt(P, KFin)
		s.rotate(P, pathCred) // S5: P drops its answer
		s.dropAt(Q, KIdRot)   // P's identity.rotate never reaches Q
		s.dropAt(Q, KInit)    // nor P's restarted rekey
		rp := P.st.peer(Q.ID)
		s.do(P, func() { P.abandonOwn(rp); P.startHS(rp, true); P.write(); P.flush() })
		s.run(1, Q) // Q refuses P's reconnect (its own is pending)
		learned := Q.st.peer(P.ID).IK == P.st.IK
		if !off && (!learned || s.w.stats["R29 X5:refused-links-followed"] == 0) {
			t.Fatalf("Q did not follow the refused reconnect's link\n  %s", s.trace())
		}
		if off && learned {
			t.Fatalf("off: Q learned P's new ik some other way\n  %s", s.trace())
		}
		for d := 0; d < 50; d++ {
			s.dropAt(Q, KIdRot) // P's identity.rotate (and its resends) stay out of reach
			s.run(1, P, Q)
			s.tick(day)
			s.do(P, P.tick)
			s.do(Q, Q.tick)
		}
		rq, rp = Q.st.peer(P.ID), P.st.peer(Q.ID)
		stale := rq.Status == stStale || rp.Status == stStale
		t.Logf("off %v: Q %d (%s) E%d, P %d (%s) E%d", off, rq.Status, rq.Ref, rq.Cur, rp.Status, rp.Ref, rp.Cur)
		if !off && (stale || rq.Cur == 0 || rq.Cur != rp.Cur) {
			t.Fatalf("with the rule the pair did not converge\n  %s", s.trace())
		}
		if off && !stale {
			t.Fatalf("off: the pair did not end stale; the scenario does not test the rule\n  %s", s.trace())
		}
	})
}
