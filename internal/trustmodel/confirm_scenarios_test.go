package trustmodel

import (
	"slices"
	"strings"
	"testing"
)

// Scenarios for VAULT-MESSAGING 0.86.0 §6.3.1 (option A).

// dropAt removes every message of kind k now waiting in p's mailboxes (a loss).
func (s *scen) dropAt(p *Party, k Kind) int {
	n := 0
	for _, b := range p.boxes() {
		if mb := s.w.R.boxes[b]; mb != nil {
			kept := mb.msgs[:0]
			for _, m := range mb.msgs {
				if m.P.Kind == k {
					n++
					continue
				}
				kept = append(kept, m)
			}
			mb.msgs = kept
		}
	}
	return n
}

// A lost hs.confirm, the initiator locked past B (32 days), and past the
// responder's 46 days for the confirmed epoch's keys.
func TestScenarioALostConfirmInitiatorLocked(t *testing.T) {
	for _, away := range []int64{33 * day, 47 * day} {
		// 47 days is past the responder's 46 days for the confirmed epoch: see TestFindingG
		s := newScen(t, 2)
		P, Q := s.p(0), s.p(1)
		s.do(P, func() { P.startHS(P.st.peer(Q.ID), false); P.write(); P.flush() })
		s.run(1, Q) // Q answers
		s.run(1, P) // P: pending, hs.fin
		s.run(1, Q) // Q activates, hs.confirm
		if s.dropAt(P, KConfirm) == 0 {
			t.Fatalf("no hs.confirm to lose")
		}
		s.lock(P)
		s.tick(away)
		s.w.checkEnd(true)
		stale := P.st.peer(Q.ID).Status == stStale || Q.st.peer(P.ID).Status == stStale
		t.Logf("away %dd: abandoned at B %d, confirmed %d, stale %v", away/day, s.w.stats["A:abandoned:B passed"], s.w.stats["A:confirmed"], stale)
		// revised §6.3.1 (G): ids kept, so both recover
		s.noViolation("I")
		if stale {
			t.Errorf("%d days: the pair went stale (finding G still stands)", away/day)
		}
	}
}

// Crossing rekeys on each side of §6.3.1's ts rule.
func TestScenarioACrossingTs(t *testing.T) {
	// (1) a crossing rekey (its ts not later than the hs.resp's): dropped; P's establishes at hs.fin
	s := newScen(t, 2)
	P, Q := s.p(0), s.p(1)
	s.do(P, func() { P.startHS(P.st.peer(Q.ID), false); P.write(); P.flush() })
	s.do(Q, func() { Q.startHS(Q.st.peer(P.ID), false); Q.write(); Q.flush() }) // Q's own, same instant
	s.drain(Q)                                                                  // Q answers P's (P's th1 is lower)
	for _, m := range s.w.R.boxes[P.st.Relay].msgs {
		if m.P.Kind == KInit {
			m.leaseUntil = s.w.Now + visTimeout + 30 // Q's hs.init reaches P after the hs.resp
		}
	}
	s.run(1, P) // P: pending
	s.run(1, P) // then Q's hs.init: its ts is the hs.resp's
	s.run(6, Q, P)
	s.done(true, s.cellSeen("B:current:hs.init:pending:ts-not-later"))

	// (2) a later rekey: Q's answer ended without hs.fin (lost); P abandons its pending epoch and answers
	s = newScen(t, 2)
	P, Q = s.p(0), s.p(1)
	s.do(P, func() { P.startHS(P.st.peer(Q.ID), false); P.write(); P.flush() })
	s.run(1, Q)
	s.run(1, P)
	s.dropAt(Q, KFin)
	s.tick(aAnsLife + hour)
	s.do(Q, func() { Q.tick() }) // the answer expires; Q starts its own rekey
	s.run(6, P, Q)
	s.done(true, s.cellSeen("B:current:hs.init:pending:ts-later"))
}

// A device (reference-client role) as responder and as initiator, with a
// lost hs.fin in each role.
func TestScenarioADevice(t *testing.T) {
	for _, devInit := range []bool{false, true} {
		w := setup(Config{Vaults: 1, Devices: true}, 1)
		s := &scen{t, w}
		V, D := s.p(0), s.p(1)
		I, R := V, D
		if devInit {
			I, R = D, V
		}
		s.do(I, func() { I.startHS(I.st.peer(R.ID), false); I.write(); I.flush() })
		s.run(1, R)
		s.run(1, I)
		if s.dropAt(R, KFin) == 0 {
			t.Fatalf("no hs.fin to lose")
		}
		s.run(4, V, D)
		s.done(true)
		t.Logf("device initiates %v: confirmed %d, abandoned %v", devInit, s.w.stats["A:confirmed"], s.w.stats)
	}
}

// An earlier-release device: it sends no hs.confirm and keeps no confirmed
// epoch; it confirms with its first ordinary message.
func TestScenarioAOlderDevice(t *testing.T) {
	w := setup(Config{Vaults: 1, Devices: true}, 1)
	s := &scen{t, w}
	V, D := s.p(0), s.p(1)
	D.OldConfirm = true
	s.do(V, func() { V.startHS(V.st.peer(D.ID), false); V.write(); V.flush() })
	s.run(2, D, V)
	if V.st.peer(D.ID).Pend == nil {
		t.Fatalf("the vault's epoch is not pending")
	}
	s.do(D, func() { D.enqueue(V.ID, Msg{Kind: KSession, Probe: s.w.id()}, nil); D.write(); D.flush() })
	s.run(2, V, D)
	if V.st.peer(D.ID).Pend != nil {
		t.Errorf("the device's first message did not confirm")
	}
	s.done(true)
}

// The drafter's case: the initiator's own S5 abandons pending E1 after its
// hs.fin (old ik) is out; the responder activates E1; the restarted rekey
// under the new ik names E0 (the responder's confirmed epoch). It must not
// suspend. literal: §3.4.1's fork sentence read without the
// deposited-after condition, which §6.3.1 says applies first.
func TestScenarioAS5AbandonAfterFin(t *testing.T) {
	for _, literal := range []bool{false, true} {
		s := newScen(t, 2)
		s.w.literalFork = literal
		P, Q := s.p(0), s.p(1)
		s.w.holdRotate = true
		s.do(P, func() { P.startHS(P.st.peer(Q.ID), false); P.write(); P.flush() })
		s.run(1, Q)           // Q answers
		s.run(1, P)           // P: pending E1, hs.fin signed by ik0
		s.rotate(P, pathCred) // S5: E1 abandoned; rekey again under ik1 naming E0
		s.w.holdRotate = false
		s.run(6, Q, P)
		susp := Q.st.peer(P.ID).Status == stSuspended
		if literal {
			if !susp {
				t.Errorf("literal reading: expected a suspension")
			} else {
				t.Logf("literal reading of §3.4.1's sentence: Q suspends (the ambiguity)")
			}
			continue
		}
		if susp {
			t.Errorf("Q suspended in the drafter's S5 case\n  %s", strings.Join(s.w.log, "\n  "))
		}
		s.done(true, s.cellSeen("B:current:hs.init:confirmed-epoch"))
	}
}

// Drafter's scenario (I): R's identity.rotate expires while I is locked
// with a pending epoch; I's next message under the old epoch makes R
// resend it; I follows, abandons the pending epoch and rekeys.
func TestScenarioAIdentityResend(t *testing.T) {
	s := newScen(t, 2)
	P, Q := s.p(0), s.p(1)
	s.w.holdRotate = true // only the ik moves
	s.do(P, func() { P.startHS(P.st.peer(Q.ID), false); P.write(); P.flush() })
	s.run(1, Q) // Q answers
	s.run(1, P) // P: pending E1, hs.fin out
	s.lock(P)
	s.rotate(Q, pathCred) // S5: Q drops its answer; identity.rotate to P
	s.run(1, Q)           // the hs.fin arrives: no answer, dropped
	s.tick(msgTTL + hour) // the identity.rotate expires while P is locked
	s.do(P, P.unlock)
	s.do(P, func() { P.enqueue(Q.ID, Msg{Kind: KSession, Probe: s.w.id()}, nil); P.write(); P.flush() })
	s.run(6, Q, P)
	s.w.holdRotate = false
	s.done(true, func() string {
		if s.w.stats["A:identity.rotate-resent"] == 0 {
			return "no identity.rotate resend"
		}
		return ""
	})
}

// Finding J fixed: an answer to a rekey that R cannot deposit (no valid
// standing token for I) ends at once, and R reconnects.
func TestScenarioAUndepositableAnswer(t *testing.T) {
	s := newScen(t, 2)
	P, Q := s.p(0), s.p(1)
	Q.st.peer(P.ID).Toks = slices.DeleteFunc(Q.st.peer(P.ID).Toks, func(tk Token) bool { return !tk.Reconnect })
	s.do(Q, Q.write) // Q's standing token for P is gone (as if expired)
	s.do(P, func() { P.startHS(P.st.peer(Q.ID), false); P.write(); P.flush() })
	s.run(6, Q, P)
	s.done(true, func() string {
		if s.w.stats["A:answer-undepositable"] == 0 {
			return "the answer was not ended"
		}
		return ""
	})
}
