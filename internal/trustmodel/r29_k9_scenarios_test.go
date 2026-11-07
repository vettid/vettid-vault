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

// Mirrors vettid-vault TestR29RefusedReconnectLinksFollowed
// (vault/r29_review4_test.go at a00cad4): the same shape and outcome. Q
// reconnects to P; P answers; Q holds the reconnect pending (sig_R by P's
// ik a) and its hs.fin is lost. P rotates a->b (S5 drops its answer); its
// identity.rotate and restarted rekey do not reach Q. P reconnects,
// carrying a->b; Q refuses it (its own reconnect is pending) but follows
// the link in the same write: K2 abandons Q's pending epoch (signed by a),
// nothing is answered, K9 judges nothing, and Q starts its own reconnect
// again under P's new ik, and nothing else (no rekey). The pair converges
// through it. Off (World.noRefusedLinks): Q never learns P's ik and both
// end stale.
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
		pend := rq.Pend.ID
		s.dropAt(P, KFin)
		s.rotate(P, pathCred) // S5: P drops its answer
		s.dropAt(Q, KIdRot)   // P's identity.rotate does not reach Q
		s.dropAt(Q, KInit)    // nor P's restarted rekey
		rp := P.st.peer(Q.ID)
		answers, refused := s.w.stats["out answer"], s.w.stats["R29 X5:refused"]
		s.do(P, func() { P.abandonOwn(rp); P.startHS(rp, true); P.write(); P.flush() })
		s.run(1, Q) // Q refuses P's reconnect (its own is pending)
		rq = Q.st.peer(P.ID)
		if s.w.stats["R29 X5:refused"] == refused {
			t.Fatalf("setup: P's reconnect was not refused\n  %s", s.trace())
		}
		learned := rq.IK == P.st.IK
		if off {
			if learned {
				t.Fatalf("off: Q learned P's new ik some other way\n  %s", s.trace())
			}
		} else {
			if !learned || s.w.stats["R29 X5:refused-links-followed"] == 0 {
				t.Fatalf("the refused reconnect's links were not followed\n  %s", s.trace())
			}
			if ep := rq.epoch(pend); ep == nil || !ep.Abandoned || !ep.AbanByLink || (rq.Pend != nil && rq.Pend.ID == pend) {
				t.Fatalf("Q's pending epoch signed by the old ik was not abandoned by the link: %+v\n  %s", ep, s.trace())
			}
			if s.w.stats["out answer"] != answers {
				t.Fatalf("something was answered beside the refusal")
			}
			for _, e := range rq.Epochs {
				if e.Ended {
					t.Fatalf("K9 judged at a refused reconnect")
				}
			}
			if o := rq.Own; o == nil || !o.Reconnect || o.PeerIK != P.st.IK || s.w.stats["R29 X5:refused-links-restart"] != 1 {
				t.Fatalf("Q's own reconnect, ended by the links, was not started again (once) under P's new ik\n  %s", s.trace())
			}
		}
		if !off {
			// converges through Q's restarted reconnect, P not trying again
			s.dropAt(Q, KInit)
			s.run(4, P, Q)
			rq, rp = Q.st.peer(P.ID), P.st.peer(Q.ID)
			if rq.Cur == 0 || rq.Cur != rp.Cur || rq.Pend != nil || rp.Pend != nil {
				t.Fatalf("the pair did not converge through Q's restarted reconnect: Q E%d, P E%d\n  %s", rq.Cur, rp.Cur, s.trace())
			}
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

// Mirrors vettid-vault TestR29RefusedReconnectLinksAllOrNothing
// (vault/r29_review4_test.go at a00cad4): Q's own reconnect pending; P rotates a->b
// and its identity.rotate does not reach Q; a reconnect carrying a->b and
// then b->a (back to an ik left behind, an ik rollback) is refused, and
// none of its links is followed: Q's chain and pending epoch are unchanged.
func TestR29RefusedReconnectLinksAllOrNothing(t *testing.T) {
	s := newScen(t, 2)
	s.w.relayRot = false
	P, Q := s.p(0), s.p(1)
	rq := Q.st.peer(P.ID)
	e0 := rq.Cur
	s.do(Q, func() { Q.startHS(rq, true); Q.write(); Q.flush() })
	s.run(1, P)
	s.run(1, Q)
	if rq.Pend == nil || !rq.Pend.Reconnect {
		t.Fatalf("setup: Q holds no pending reconnect\n  %s", s.trace())
	}
	pend := rq.Pend.ID
	s.dropAt(P, KFin)
	a, aKEM := P.st.IK, P.st.KEM
	s.rotate(P, pathCred) // a->b
	s.dropAt(Q, KIdRot)
	s.dropAt(Q, KInit)
	r1 := P.st.Chain[len(P.st.Chain)-1]
	r2 := IKLink{Old: r1.New, New: a, KEM: aKEM} // b->a, signed by b and a (P holds both)
	s.w.iklinkBy[r2] = rot{P.ID, P.writes}
	chain := len(rq.Chain)
	pr := P.st.peer(Q.ID)
	s.inject(P, P, Q, Msg{Kind: KInit, Reconnect: true, HS: s.w.id(), Ctx: e0, FromIK: a, FromKEM: aKEM, FromRelay: pr.KeyFor, Rot: []IKLink{r1, r2}})
	s.run(1, Q)
	rq = Q.st.peer(P.ID)
	if s.w.stats["cell B:current:hs.init:ctx"] == 0 {
		t.Fatalf("setup: not refused\n  %s", s.trace())
	}
	if len(rq.Chain) != chain || rq.Pend == nil || rq.Pend.ID != pend || s.w.stats["R29 X5:refused-links-followed"] != 0 {
		t.Fatalf("a link of a refused reconnect was followed although another would be refused\n  %s", s.trace())
	}
}

// Mirrors vettid-vault TestR29RefusedReconnectLinksNotForForkCtx
// (vault/r29_review4_test.go at a00cad4): a refused reconnect whose ctx
// would not otherwise be accepted (there, Fork-by-ctx evidence: an epoch
// older than the confirmed one, signed by an ancestor of the ik reached)
// has nothing followed. Q has E1 confirmed after E0 and its own reconnect
// pending; a reconnect carrying P's new link and naming E0 is refused and
// Q's ik and pending epoch are unchanged.
func TestR29RefusedReconnectLinksNotForForkCtx(t *testing.T) {
	s := newScen(t, 2)
	s.w.relayRot = false
	P, Q := s.p(0), s.p(1)
	rq := Q.st.peer(P.ID)
	e0 := rq.Cur
	s.do(Q, func() { Q.startHS(rq, false); Q.write(); Q.flush() })
	s.run(3, P, Q) // E1 confirmed at both
	rq = Q.st.peer(P.ID)
	if rq.Cur == e0 || rq.ConfID == e0 {
		t.Fatalf("setup: no newer confirmed epoch\n  %s", s.trace())
	}
	s.do(Q, func() { Q.startHS(rq, true); Q.write(); Q.flush() })
	s.run(1, P)
	s.run(1, Q)
	rq = Q.st.peer(P.ID)
	if rq.Pend == nil || !rq.Pend.Reconnect {
		t.Fatalf("setup: Q's reconnect not pending\n  %s", s.trace())
	}
	pend, ik := rq.Pend.ID, rq.IK
	s.dropAt(P, KFin)
	s.rotate(P, pathCred)
	s.dropAt(Q, KIdRot)
	s.dropAt(Q, KInit)
	pr := P.st.peer(Q.ID)
	s.inject(P, P, Q, Msg{Kind: KInit, Reconnect: true, HS: s.w.id(), Ctx: e0, FromIK: P.st.IK, FromKEM: P.st.KEM, FromRelay: pr.KeyFor, Rot: slices.Clone(P.st.Chain)})
	s.run(1, Q)
	rq = Q.st.peer(P.ID)
	if rq.IK != ik || rq.Pend == nil || rq.Pend.ID != pend || s.w.stats["R29 X5:refused-links-followed"] != 0 {
		t.Fatalf("the links of a reconnect whose ctx would not otherwise be accepted were followed\n  %s", s.trace())
	}
	if rq.Status != stActive {
		t.Fatalf("refused, it suspended (status %d)", rq.Status)
	}
}

// (0.88.2, owner decision a, GC 01M6SEMS129B3R1QGQ49063G5P) "Fork by ctx"
// skips an epoch Q began and abandoned while pending: it never became
// current, so P never used it. The shape of random seed
// 6415563950766347103 (TRUSTMODEL_ROTBURST=1), where two honest vaults
// ended suspended (I4-false):
//  1. Q rotates and rekeys P from E0; P answers; Q holds E1 pending (signed
//     by P's ik a) and its hs.fin goes out.
//  2. Q rotates again (S5 abandons E1); P rotates a->b, and its
//     identity.rotate and its rekey naming E0 are delayed (a lease).
//  3. P drops Q's hs.fin (no answer awaiting it) and answers Q's next
//     rekey; Q follows a->b at that hs.resp, and E2 (signer b) is
//     confirmed at both sides.
//  4. P's delayed rekey (ctx E0) arrives: E0 is older than the confirmed
//     E2, and the only epoch in between signed by an ancestor of b is E1,
//     Q's own abandoned one. Q must not suspend. Off (World.noForkSkipAban,
//     the rule before 0.88.2): it suspends.
func TestR29ForkByCtxSkipsAbandoned(t *testing.T) {
	bothWays(t, func(t *testing.T, off bool) {
		s := newScen(t, 2)
		s.w.relayRot = false
		s.w.noForkSkipAban = off
		P, Q := s.p(0), s.p(1)
		e0 := Q.st.peer(P.ID).Cur
		s.rotate(Q, pathCred) // Q rotates; its identity.rotate and rekey from E0
		s.drain(P)            // P follows and answers
		s.drain(Q)            // Q: E1 pending (signer a), hs.fin
		rq := Q.st.peer(P.ID)
		if rq.Pend == nil {
			t.Fatalf("setup: Q holds no pending epoch\n  %s", s.trace())
		}
		e1 := rq.Pend.ID
		s.rotate(Q, pathCred) // S5: E1 abandoned
		if ep := Q.st.peer(P.ID).epoch(e1); ep == nil || !ep.Abandoned || !ep.MineInit {
			t.Fatalf("setup: E%d not abandoned while pending", e1)
		}
		s.rotate(P, pathCred) // a->b: identity.rotate and a rekey naming E0
		s.hold(Q, KIdRot)
		s.hold(Q, KInit) // both delayed
		for i := 0; i < 3; i++ {
			s.drain(P) // P drops Q's hs.fin, answers Q's rekey (with a->b)
			s.drain(Q) // Q: E2 pending (signer b), hs.fin; then confirmed
		}
		rq = Q.st.peer(P.ID)
		if rq.IK != P.st.IK || rq.ConfID == e0 || rq.Cur == e0 || rq.Status != stActive {
			t.Fatalf("setup: Q has no newer confirmed epoch signed by P's new ik (cur E%d conf E%d)\n  %s", rq.Cur, rq.ConfID, s.trace())
		}
		s.release(Q, KIdRot)
		s.release(Q, KInit)
		s.drain(Q) // P's delayed identity.rotate and rekey naming E0
		rq = Q.st.peer(P.ID)
		t.Logf("off %v: Q status %d (%s)", off, rq.Status, rq.Ref)
		if !off && (rq.Status != stActive || s.w.stats["R29 F1:fork-by-ctx-skipped-abandoned"] == 0) {
			t.Fatalf("Q suspended an honest P by Fork by ctx over its own abandoned E%d\n  %s", e1, s.trace())
		}
		if off && rq.Status != stSuspended {
			t.Fatalf("off: no suspension; the scenario does not test the rule\n  %s", s.trace())
		}
		if !off {
			s.run(4, P, Q)
			s.done(true)
		}
	})
}

// (0.88.2, owner decision a, GC 01M6SPZ1QXHR5G7DRR96CHW17P) §3.4.1 H5: a
// new answered reconnect from P does not end Q's earlier answer to P's
// reconnect pinned to the same ik; the first verified hs.fin establishes.
// The shape of random seed 10393024044262541112 (and 13144670517934401752,
// 13990320060266243842, 471004796172726989, 975096784083377806): P's
// reconnect R1 is delayed (a lease); P abandons it and reconnects again
// (R2); Q answers R2, P holds R2's epoch pending and sends hs.fin; then
// R1 reaches Q and is answered too. With the rule, R2's hs.fin still
// finds its answer and the pair converges. Off (World.noKeepAnswers, the
// rule before 0.88.2): R1's answer ends R2's, R2's hs.fin finds nothing,
// and the pair does not converge (in the random runs it ended stale).
func TestR29KeepReconnectAnswers(t *testing.T) {
	bothWays(t, func(t *testing.T, off bool) {
		s := newScen(t, 2)
		s.w.relayRot = false
		s.w.noKeepAnswers = off
		P, Q := s.p(0), s.p(1)
		rp := P.st.peer(Q.ID)
		s.do(P, func() { P.startHS(rp, true); P.write(); P.flush() }) // R1
		s.hold(Q, KInit)                                              // R1 delayed
		rp = P.st.peer(Q.ID)
		s.do(P, func() { P.abandonOwn(rp); P.startHS(rp, true); P.write(); P.flush() }) // R2
		s.drain(Q)                                                                      // Q answers R2
		s.drain(P)                                                                      // P: R2's epoch pending, hs.fin
		rp = P.st.peer(Q.ID)
		if rp.Pend == nil || !rp.Pend.Reconnect {
			t.Fatalf("setup: P holds no pending reconnect\n  %s", s.trace())
		}
		e2 := rp.Pend.ID
		s.release(Q, KInit)
		s.drain(Q) // R1 answered too, then R2's hs.fin
		rq := Q.st.peer(P.ID)
		if !off && rq.Cur != e2 {
			t.Fatalf("R2's hs.fin did not establish E%d (Q on E%d)\n  %s", e2, rq.Cur, s.trace())
		}
		if off && rq.Cur == e2 {
			t.Fatalf("off: R2's hs.fin still established E%d; the scenario does not test the rule\n  %s", e2, s.trace())
		}
		if !off && slices.ContainsFunc(rq.Ans, func(a HS) bool { return a.Reconnect }) {
			t.Fatalf("the other answers to P's reconnects were not dropped at the verified hs.fin")
		}
		for d := 0; d < 40; d++ {
			s.run(1, P, Q)
			s.tick(day)
			s.do(P, P.tick)
			s.do(Q, Q.tick)
		}
		rq, rp = Q.st.peer(P.ID), P.st.peer(Q.ID)
		converged := rq.Status == stActive && rp.Status == stActive && rp.Cur != 0 && rp.Cur == rq.Cur
		t.Logf("off %v: P %d (%s) E%d, Q %d (%s) E%d", off, rp.Status, rp.Ref, rp.Cur, rq.Status, rq.Ref, rq.Cur)
		if !off && !converged {
			t.Fatalf("with the rule the pair did not converge\n  %s", s.trace())
		}
		if off && converged {
			t.Fatalf("off: the pair converged; the scenario does not test the rule\n  %s", s.trace())
		}
	})
}

// (0.88.2, owner decision a, GC 01M6SPZ1QXHR5G7DRR96CHW17P) "Fork by ctx"
// also skips an epoch Q demoted whose received flag is clear. The shape of
// random seed 14692306168500431478 (TRUSTMODEL_ROTBURST=1): P rekeys
// (E1), Q activates E1 at hs.fin; P rotates right after (S5 abandons E1)
// and its identity.rotate under E0 makes Q's strict F1 demote E1 (flag
// clear) and reconnect naming E0, which completes (E2 confirmed). P's
// restarted rekey naming E0, delayed until then, arrives: E0 is older
// than the confirmed E2 and the only epoch between signed by an ancestor
// is the demoted E1. Q must not suspend. Off (World.noForkSkipDemoted):
// it suspends.
func TestR29ForkByCtxSkipsDemoted(t *testing.T) {
	bothWays(t, func(t *testing.T, off bool) {
		s := newScen(t, 2)
		s.w.relayRot = false
		s.w.noForkSkipDemoted = off
		P, Q := s.p(0), s.p(1)
		e0 := Q.st.peer(P.ID).Cur
		_, e1 := s.pendingAt(P, Q) // P: E1 pending, hs.fin to Q
		s.rotate(P, pathCred)      // S5 abandons E1; identity.rotate under E0, rekey naming E0
		s.hold(Q, KInit)           // P's restarted rekey delayed
		for i := 0; i < 4; i++ {
			s.drain(Q) // E1 at hs.fin, then the link: strict F1 demotes E1, reconnect naming E0
			s.drain(P)
		}
		rq := Q.st.peer(P.ID)
		if ep := rq.epoch(e1); ep == nil || !ep.Demoted || ep.Flag {
			t.Fatalf("setup: E%d not demoted with its flag clear: %+v\n  %s", e1, ep, s.trace())
		}
		if rq.Cur == 0 || rq.Cur == e0 || rq.ConfID == e0 || rq.Status != stActive {
			t.Fatalf("setup: no newer confirmed epoch at Q (cur E%d conf E%d)\n  %s", rq.Cur, rq.ConfID, s.trace())
		}
		s.release(Q, KInit)
		s.drain(Q) // P's delayed rekey naming E0
		rq = Q.st.peer(P.ID)
		t.Logf("off %v: Q status %d (%s)", off, rq.Status, rq.Ref)
		if !off && (rq.Status != stActive || s.w.stats["R29 F1:fork-by-ctx-skipped-demoted"] == 0) {
			t.Fatalf("Q suspended an honest P by Fork by ctx over the demoted E%d\n  %s", e1, s.trace())
		}
		if off && rq.Status != stSuspended {
			t.Fatalf("off: no suspension; the scenario does not test the rule\n  %s", s.trace())
		}
	})
}
