package trustmodel

import (
	"slices"
	"strings"
	"testing"
)

// Pinned reproductions of the SPEC FINDINGS the random runs found. Each
// test passes while the f4a4d97 rules stand (it asserts the violation),
// and fails once the rules change so that the violation is gone.

func expectViolation(t *testing.T, s *scen, inv string) {
	t.Helper()
	for _, v := range s.w.viol {
		if strings.HasPrefix(v.Inv, inv) {
			t.Logf("reproduced %s: %s", v.Inv, v.Detail)
			return
		}
	}
	t.Errorf("finding no longer reproduces (%s); trace:\n  %s", inv, strings.Join(s.w.log, "\n  "))
}

// Finding A (I4, rule C): a second successor that reaches Q only in an
// hs.init's rotations is forgotten when that handshake does not finish, so
// Q follows the other successor and never suspends.
func TestFindingA_EvidenceInUnfinishedHandshakeIsForgotten(t *testing.T) {
	s := newScen(t, 2)
	P, Q := s.p(0), s.p(1)
	s.w.makeCopy(P)
	C := s.w.P[len(s.w.P)-1]
	s.do(C, C.unlock)
	s.w.holdRotate = true
	s.w.p429 = 1
	s.rotate(C, pathCred) // the copy: ik0 -> X; it sends no identity.rotate
	s.w.p429 = 0
	C.st.Out = slices.DeleteFunc(C.st.Out, func(e Entry) bool { return e.M.Kind != KInit })
	s.do(C, func() { C.startHS(C.st.peer(Q.ID), false); C.write(); C.flush() }) // its rekey carries [ik0 -> X]
	s.run(2, Q)                                                                 // Q answers (Table B: reached); state changes only at hs.fin
	s.lock(C)                                                                   // the copy never sends hs.fin
	s.rotate(P, pathCred)                                                       // the original: ik0 -> ik1
	s.w.holdRotate = false
	s.run(4, Q, P)
	s.w.checkEnd(false)
	expectViolation(t, s, "I4")
}

// Finding B (I4, step order, rule C for relay links): while Q is suspended
// for an identity conflict, the copy's relay update is refused at step 1,
// before step 3's evidence; resolve then resumes the connection although
// a relay fork was seen ("the only exit is a new invitation").
func TestFindingB_RelayForkHiddenByIdentityResolve(t *testing.T) {
	s := newScen(t, 2)
	P, Q := s.p(0), s.p(1)
	s.w.makeCopy(P)
	C := s.w.P[len(s.w.P)-1]
	s.rotate(P, pathRecovery) // ik0 -> ik1, K0 -> K1
	s.run(1, Q)               // Q follows both
	s.do(C, C.unlock)
	s.rotate(C, pathCred) // the copy: ik0 -> X, K0 -> K0'
	s.run(2, Q)           // identity conflict: suspend; the relay update: refused (suspended)
	s.do(Q, func() { Q.resolve(Q.st.peer(P.ID)); Q.write(); Q.flush() })
	if Q.st.peer(P.ID).Status != stActive {
		t.Fatalf("resolve did not resume (relay fork recorded): the finding is gone")
	}
	s.run(3, Q, P)
	s.w.checkEnd(false)
	expectViolation(t, s, "I4")
}

// Finding C (I1; §6.3/§6.5, outside §3.4.1): an hs.fin that never reaches
// the responder (relay TTL while it is locked) leaves the pair on two
// epochs for good: the initiator's rekeys name an epoch the responder never
// established, the responder's are refused rekey_not_current_epoch, and no
// reconnect is triggered (standing tokens are valid).
func TestFindingC_LostFinDivergesEpochs(t *testing.T) {
	s := newScen(t, 2)
	P, Q := s.p(0), s.p(1)
	s.do(P, func() { P.startHS(P.st.peer(Q.ID), false); P.write(); P.flush() })
	s.run(1, Q) // Q answers
	s.lock(Q)
	s.run(2, P) // P establishes and sends hs.fin
	s.tick(msgTTL + hour)
	s.w.checkEnd(true)
	expectViolation(t, s, "I1/hs-lost:expired-at-relay-TTL")
}

// Finding C, variant inside §3.4.1's scope: the hs.fin sits in Q's old
// mailbox, and Q, locked after its own rotation, misses the grace.
func TestFindingC2_FinLostWithOldMailbox(t *testing.T) {
	s := newScen(t, 2)
	P, Q := s.p(0), s.p(1)
	s.do(P, func() { P.startHS(P.st.peer(Q.ID), false); P.write(); P.flush() })
	s.run(1, Q)           // Q answers
	s.run(2, P)           // P establishes; its hs.fin goes to Q's current mailbox K0
	s.rotate(Q, pathCred) // before collecting it, Q rotates: K0 enters its grace
	s.lock(Q)
	s.tick(graceLen + hour)
	s.w.checkEnd(true)
	expectViolation(t, s, "I1/hs-lost")
}

// Finding D (I1's exclusions vs §6.6 "Limits" and S1): both vaults rotate
// and lock before collecting; each one's update sits in the other's old
// mailbox, which ends at the grace. The pair is dead (resends end with
// mailbox_unknown, no reconnect path) but is neither stale nor excluded
// from I1 until S1's 30 days.
func TestFindingD_DeadButNotStaleAfterBothMissTheGrace(t *testing.T) {
	s := newScen(t, 2)
	P, Q := s.p(0), s.p(1)
	s.rotate(P, pathCred)
	s.rotate(Q, pathCred)
	s.lock(P)
	s.lock(Q)
	s.tick(graceLen + hour)
	s.do(P, P.unlock)
	s.do(Q, Q.unlock)
	s.run(8, P, Q)
	rp, rq := P.st.peer(Q.ID), Q.st.peer(P.ID)
	if rp.Status != stActive || rq.Status != stActive || rp.Relay == Q.st.Relay || rq.Relay == P.st.Relay {
		t.Fatalf("finding no longer reproduces: P %d/%d Q %d/%d", rp.Status, rp.Relay, rq.Status, rq.Relay)
	}
	if !s.w.limits(P, rp) || !s.w.limits(Q, rq) {
		t.Errorf("the model's Limits exclusion does not name this pair")
	}
	t.Logf("reproduced: %s and %s hold each other's old relay keys (%d, %d), both records active; S1 stales them at day 30",
		P.Name, Q.Name, rp.Relay, rq.Relay)
}
