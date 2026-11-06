package trustmodel

import "testing"

// Deterministic scenarios for the release-29 rules (VAULT-MESSAGING 0.87.0
// §6.3.2), one per gap the rule list names where the model can drive it.

// R29-F3, R29-K7: P rekeys E0->E1, sends hs.fin, rotates before any
// hs.confirm and sends identity.rotate under E0. Only hs.fin travelled
// under E1, so E1's received flag is clear: Q demotes E1 (strict F1) and
// reconnects naming E0, which P accepts (or P's restarted rekey from E0
// wins the crossing, R29-X2). No suspension.
func TestR29F3HonestRotateAfterFin(t *testing.T) {
	s := newScen(t, 2)
	s.w.relayRot = false
	P, Q := s.p(0), s.p(1)
	e0 := Q.st.peer(P.ID).Cur
	s.do(P, func() { P.startHS(P.st.peer(Q.ID), false); P.write(); P.flush() })
	s.run(1, Q) // Q answers
	s.run(1, P) // P: pending E1, hs.fin
	e1 := P.st.peer(Q.ID).Pend.ID
	s.rotate(P, pathCred) // S5: E1 abandoned; identity.rotate under E0
	s.run(1, Q)           // hs.fin (Q activates E1), then the link under E0
	r := Q.st.peer(P.ID)
	if ep := r.epoch(e1); ep == nil || ep.Flag || !ep.Demoted {
		t.Fatalf("E%d at Q: %+v (want demoted, flag clear)\n  %s", e1, ep, s.trace())
	}
	if r.Status != stActive || s.w.stats["R29 K7:reconnect-names-E"] == 0 {
		t.Fatalf("Q did not start the reconnect naming E%d (status %d)\n  %s", e0, r.Status, s.trace())
	}
	// (P's restarted rekey, with the lower th1, may win the crossing: X2)
	s.run(8, P, Q)
	s.done(true)
	if r := Q.st.peer(P.ID); r.Status != stActive || s.w.stats["R29 K7:demote"] == 0 {
		t.Errorf("want strict F1's demotion and an active pair; status %d", r.Status)
	}
}

// R29-F3: hs.confirm alone sets the flag, and a delivered hs.fin leaves it
// clear at the responder.
func TestR29F3FlagByConfirmNotFin(t *testing.T) {
	s := newScen(t, 2)
	I, R := s.p(0), s.p(1)
	_, e1 := s.pendingAt(I, R)
	s.run(1, R) // R activates E1 at hs.fin, queues hs.confirm
	if ep := R.st.peer(I.ID).epoch(e1); ep == nil || ep.Flag {
		t.Fatalf("R's E%d flag set by hs.fin: %+v", e1, ep)
	}
	s.run(1, I) // I confirms E1 with R's hs.confirm
	if ep := I.st.peer(R.ID).epoch(e1); ep == nil || !ep.Flag {
		t.Fatalf("I's E%d flag not set by hs.confirm: %+v", e1, ep)
	}
	s.done(true)
}
