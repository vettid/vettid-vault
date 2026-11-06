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

// R29-D3, D4: a rekey hs.init from an app from before release 29 is
// refused (unexpected), and the member is told once.
func TestR29D3D4OldAppRekeyRefused(t *testing.T) {
	w := setup(Config{Vaults: 1, Devices: true, OldApp: true}, 1)
	s := &scen{t, w}
	V, D := s.p(0), s.p(1)
	for i := 0; i < 2; i++ {
		s.do(D, func() { D.startHS(D.st.peer(V.ID), false); D.write(); D.flush() })
		s.drain(V)
		s.do(D, func() { D.abandonOwn(D.st.peer(V.ID)); D.write() })
	}
	r := V.st.peer(D.ID)
	t.Logf("D3 refusals %d, notices %v", s.w.stats["R29 D3:device-rekey-refused"], s.w.feed)
	if s.w.stats["R29 D3:device-rekey-refused"] != 2 || s.w.stats["out answer"] != 0 {
		t.Errorf("the vault did not refuse both rekeys")
	}
	if !r.Notice || len(s.w.feed[pairKey(V.ID, D.ID)]) != 1 {
		t.Errorf("want one device.update_needed notice, got %v", s.w.feed)
	}
}

// R29-D2: a release-29 device starts no rekey.
func TestR29D2DeviceStartsNoRekey(t *testing.T) {
	w := setup(Config{Vaults: 1, Devices: true}, 1)
	s := &scen{t, w}
	V, D := s.p(0), s.p(1)
	s.do(D, func() { D.startHS(D.st.peer(V.ID), false); D.write(); D.flush() })
	if D.st.peer(V.ID).Own != nil {
		t.Errorf("the device started a rekey")
	}
}

// R29-X6: a sealed-mode hs.init with purpose rekey is refused as malformed.
func TestR29X6SealedRekeyRefused(t *testing.T) {
	w := setup(Config{Vaults: 2}, 1)
	P, Q := w.P[0], w.P[1]
	r := Q.st.peer(P.ID)
	m := &RMsg{ID: 10, Box: Q.st.Relay, DepAt: w.Now, Sender: r.Relay, Seq: 10, Actor: P.ID,
		P: &Msg{Kind: KInit, Inner: w.id(), HS: w.id(), Ctx: r.Cur, FromIK: r.IK, FromRelay: r.Relay, Ts: w.Now}}
	d := Q.acceptFrom(r, m, Pos{m.Box, m.ID, m.DepAt, m.Seq}, []Key{Q.st.Relay})
	if d.Out != "refuse" || d.Reason != "malformed" {
		t.Errorf("a sealed rekey: %s", d)
	}
}

// R29-K6, X4: P reconnects to Q, which never answers (locked). One
// reconnect at a time; each try fails at 16 days; the third failure for
// the same named epoch makes the connection stale.
func TestR29K6ThirdFailureStale(t *testing.T) {
	s := newScen(t, 2)
	s.w.relayRot = false
	P, Q := s.p(0), s.p(1)
	s.longTokens(400 * day)
	s.lock(Q)
	r := P.st.peer(Q.ID)
	s.do(P, func() { P.startHS(r, true); P.write(); P.flush() })
	first := r.Own
	s.do(P, func() { P.startHS(r, true) }) // X4: a second trigger starts nothing
	if r.Own != first || s.w.stats["R29 X4:one-reconnect-at-a-time"] == 0 {
		t.Fatalf("a second reconnect started")
	}
	for d := 0; d < 60 && r.Status == stActive; d++ {
		s.tick(day)
		s.do(P, P.tick)
	}
	t.Logf("tries failed %d; status %d (%s) after %s", s.w.stats["R29 K6:try-failed"], r.Status, r.Ref, s.w.clock())
	if r.Status != stStale || r.Ref != "K6: third failed try" || s.w.stats["R29 K6:try-failed"] != 3 {
		t.Errorf("want stale at the third failed try")
	}
}

// R29-R6: under an epoch rule E destroyed, an authenticated message with a
// later inner ts than the recorded one is fork evidence; an earlier one is
// refused superseded_epoch.
func TestR29R6SupersededEpoch(t *testing.T) {
	for _, later := range []bool{false, true} {
		w := setup(Config{Vaults: 2}, 1)
		P, Q := w.P[0], w.P[1]
		r := Q.st.peer(P.ID)
		e1 := w.id()
		r.Epochs = append(r.Epochs, Epoch{ID: e1, Signer: r.IK, Own: Q.st.IK, EstAt: w.Now, EverCur: true, Destroyed: true, DestroyTs: w.Now})
		ts := w.Now - hour
		if later {
			ts = w.Now + hour
		}
		m := &RMsg{ID: 10, Box: Q.st.Relay, DepAt: w.Now, Sender: r.Relay, Seq: 10, Actor: P.ID,
			P: &Msg{Kind: KSession, Inner: w.id(), Epoch: e1, Probe: w.id(), Ts: ts}}
		d := Q.acceptFrom(r, m, Pos{m.Box, m.ID, m.DepAt, m.Seq}, []Key{Q.st.Relay})
		t.Logf("later ts %v: %s", later, d)
		if later && (d.Out != "suspend" || r.Status != stSuspended) {
			t.Errorf("a later ts under a destroyed epoch: %s", d)
		}
		if !later && d.Reason != "superseded_epoch" {
			t.Errorf("an earlier ts under a destroyed epoch: %s", d)
		}
	}
}
