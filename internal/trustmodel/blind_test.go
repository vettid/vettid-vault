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

// Lead item 2: a release-28 initiator's hs.fin is lost toward a release-29
// (R1) responder. The 28 side activated at hs.resp; R stays on E0.
func TestLeadR28FinLostToward29(t *testing.T) {
	w := setup(Config{Vaults: 2, Rel28: []bool{true, false}, Opt: optR1}, 1)
	s := &scen{t, w}
	I, R := s.p(0), s.p(1)
	s.do(I, func() { I.startHS(I.st.peer(R.ID), false); I.write(); I.flush() })
	s.run(1, R) // R answers
	s.run(1, I) // I (r28) activates E1 at hs.resp, sends hs.fin
	if s.dropAt(R, KFin) == 0 {
		t.Fatalf("no hs.fin to lose")
	}
	s.w.checkEnd(true)
	ri, rr := I.st.peer(R.ID), R.st.peer(I.ID)
	t.Logf("lead item 2: I(r28) cur E%d status %d (%s); R cur E%d status %d (%s); violations %d",
		ri.Cur, ri.Status, ri.Ref, rr.Cur, rr.Status, rr.Ref, len(s.w.viol))
	for _, v := range s.w.viol {
		t.Logf("  %s: %s", v.Inv, v.Detail)
	}
}

// Lead item 3: the I4-misattributed run (seed 16663332612404948059, R1
// with 28) must be clean, and the fork still found by rule C.
func TestLeadMisattributedSeed(t *testing.T) {
	w := runSeed(t, 16663332612404948059, map[string]string{"TRUSTMODEL_OPT": "1", "TRUSTMODEL_MIXED": "1"})
	// a92a6eb's exception needs "Q received no message from P under it";
	// here Q did (R's identity.rotate under E74), so Q still suspends R
	// although the copy is Q's own: reported, not failed.
	for _, v := range w.viol {
		t.Errorf("still: %s: %s", v.Inv, v.Detail) // lead fix A: must be clean
	}
	if len(w.viol) > 0 {
		for _, l := range w.log {
			if strings.Contains(l, "SUSP") || strings.Contains(l, "DEMOT") || strings.Contains(l, "E78") || strings.Contains(l, "ROTATE") || strings.Contains(l, "identity.rotate[") {
				t.Log(l)
			}
		}
	}
	t.Logf("own_copy audits %d, rule C identity conflicts %d, suspensions: %d",
		w.stats["A:fork_suspected(own_copy)"], w.stats["ruleC:identity"], w.stats["out suspend"])
}

// a92a6eb: the two sides disagree on the gate. The rotating responder P
// has seen I's features and drops its answer at S5; I has not seen P's,
// so it activated at hs.fin. P's identity.rotate under E0 makes I demote
// E1 and reconnect naming E0 (§3.4.1 "Epochs after an ik link").
func TestGateDisagreementS5Repaired(t *testing.T) {
	w := setup(Config{Vaults: 2, Opt: optR1}, 1)
	s := &scen{t, w}
	I, P := s.p(0), s.p(1)
	I.st.peer(P.ID).PeerA = false // I has not yet seen P's features
	s.do(I, I.write)
	s.w.holdRotate = true
	s.do(I, func() { I.startHS(I.st.peer(P.ID), false); I.write(); I.flush() })
	s.run(1, P)           // P answers
	s.lease(I, KResp, 0)  // (no-op: keep order)
	s.rotate(P, pathCred) // P sees the gate: drops its answer
	s.run(1, I)           // I: hs.resp -> activates E1 at hs.fin; then P's identity.rotate under E0
	s.w.holdRotate = false
	s.run(8, I, P)
	s.w.checkEnd(true)
	s.report("gate-disagreement")
	t.Logf("F1 demotions %d, fix B kept %d, reverts %d, rule E destroyed %d, reconnects %d",
		s.w.stats["A:F1-demoted"], s.w.stats["A:F1-fixB-kept"], s.w.stats["A:reverted"], s.w.stats["A:destroyed-later-epoch"], s.w.stats["start:reconnect"])
	// with lead fix B the demotion no longer applies here (I's own ungated
	// epoch, link under its predecessor); the pair must still converge
	if len(s.w.viol) > 0 {
		t.Errorf("gate disagreement not repaired")
	}
}

// Lead fix A: the own_copy exception (every such epoch one Q began) cannot
// hide a real fork of P: P's old copy forks P's ik and reconnects naming
// E0; Q's exception applies (audit, no suspension); when the original's
// real link arrives, rule C suspends.
func TestLeadFixAOwnCopyCannotHideFork(t *testing.T) {
	w := setup(Config{Vaults: 2}, 1)
	P, Q := w.P[0], w.P[1]
	r := Q.st.peer(P.ID)
	e0, ik0 := r.Cur, r.IK
	e1 := w.id()
	r.Epochs = append(r.Epochs, Epoch{ID: e1, Signer: ik0, Own: Q.st.IK, EstAt: w.Now, MineInit: true, GotFromPeer: true})
	r.Epochs[0].Superseded = w.Now
	r.Cur, r.ConfID = e1, e1
	x := w.key()
	fork := IKLink{ik0, x, w.key()} // the copy's second successor, followed first
	w.iklinkBy[fork] = rot{PID(99), 1}
	r.Chain = append(r.Chain, fork)
	r.IK, r.KEM = x, fork.KEM
	init := &RMsg{ID: 10, Box: Q.st.Relay, DepAt: w.Now, Sender: r.Relay, Seq: 10, Actor: P.ID,
		P: &Msg{Kind: KInit, Inner: w.id(), Reconnect: true, HS: w.id(), Ctx: e0, FromIK: x, FromRelay: r.Relay, Ts: w.Now}}
	d := Q.acceptFrom(r, init, Pos{init.Box, init.ID, init.DepAt, init.Seq}, []Key{Q.st.Relay})
	t.Logf("the copy's reconnect naming E%d: %s; own_copy audits %d", e0, d, w.stats["A:fork_suspected(own_copy)"])
	if r.Status == stSuspended || w.stats["A:fork_suspected(own_copy)"] == 0 {
		t.Errorf("fix A: the exception did not apply")
	}
	ik1 := w.key()
	real := IKLink{ik0, ik1, w.key()} // the original's link
	w.iklinkBy[real] = rot{P.ID, 2}
	rot := &RMsg{ID: 11, Box: Q.st.Relay, DepAt: w.Now, Sender: r.Relay, Seq: 11, Actor: P.ID,
		P: &Msg{Kind: KIdRot, Inner: w.id(), Epoch: r.Cur, Rot: []IKLink{real}, Ts: w.Now}}
	d = Q.acceptFrom(r, rot, Pos{rot.Box, rot.ID, rot.DepAt, rot.Seq}, []Key{Q.st.Relay})
	t.Logf("the original's link: %s", d)
	if r.Status != stSuspended {
		t.Errorf("fix A: rule C did not suspend on the real link")
	}
}

func runSeed(t *testing.T, rs uint64, env map[string]string) *World {
	for k, v := range env {
		t.Setenv(k, v)
	}
	cfg, acts := genRun(rs, 40)
	return runActions(cfg, rs, acts, false)
}

// Lead fix B: seed 8756148401117559123 (R1, gate unseen) was a false
// suspension; under fix B (TRUSTMODEL_FIXB=fixb) it must be clean. The
// default (strict) keeps the false suspension: the stated cost of the
// lead's choice (gate unseen is the worst case).
func TestLeadFixBSeed(t *testing.T) {
	w := runSeed(t, 8756148401117559123, map[string]string{"TRUSTMODEL_OPT": "1", "TRUSTMODEL_UNSEEN": "1", "TRUSTMODEL_FIXB": "fixb"})
	t.Logf("fix B kept %d, F1 demotions %d", w.stats["A:F1-fixB-kept"], w.stats["A:F1-demoted"])
	for _, v := range w.viol {
		t.Errorf("%s: %s", v.Inv, v.Detail)
	}
}

// h2: the lead's H2 (an old copy's epoch made just before the original's
// rotation must not survive the link). window: the alternative F1 rule.
func h2(t *testing.T, window bool) *scen { return h2x(t, window, !window) } // default: strict

func h2s(t *testing.T) *scen { return h2x(t, false, true) }

func h2b(t *testing.T) *scen { return h2x(t, false, false) } // fix B as in 9f1a0da

func h2x(t *testing.T, window, strict bool) *scen {
	s := newScen(t, 2)
	s.w.f1Window, s.w.fixBStrict = window, strict
	P, Q := s.p(0), s.p(1)
	s.w.makeCopy(P)
	C := s.w.P[len(s.w.P)-1]
	s.do(C, C.unlock)
	s.do(C, func() { C.startHS(C.st.peer(Q.ID), false); C.write(); C.flush() })
	s.run(3, Q, C)
	s.w.holdRotate = true
	s.rotate(P, pathCred)
	s.do(P, func() { r := P.st.peer(Q.ID); P.abandonOwn(r); P.startHS(r, true); P.write(); P.flush() })
	s.run(6, Q, P)
	s.do(C, C.unlock)
	s.do(C, func() { C.enqueue(Q.ID, Msg{Kind: KSession, Probe: s.w.id()}, nil); C.write(); C.flush() })
	s.run(2, Q)
	s.w.holdRotate = false
	s.w.checkEnd(false)
	return s
}

func TestLeadH2StillCaught(t *testing.T) {
	s := h2(t, false)
	s.noViolation("I3")
	t.Logf("H2 (fix B rule): F1 demotions %d, destroyed %d, violations %d", s.w.stats["A:F1-demoted"], s.w.stats["A:destroyed-later-epoch"], len(s.w.viol))
}

func TestLeadH2UnderTimeWindow(t *testing.T) {
	s := h2(t, true)
	var got []string
	for _, v := range s.w.viol {
		got = append(got, v.Inv+": "+v.Detail)
	}
	t.Logf("H2 under the time-window rule: window skips %d, F1 demotions %d, rule E destroyed %d, fork suspensions %d, Q-P status %d, violations:\n  %s",
		s.w.stats["A:F1-window-skipped"], s.w.stats["A:F1-demoted"], s.w.stats["A:destroyed-later-epoch"], s.w.stats["out suspend"],
		s.p(1).st.peer(s.p(0).ID).Status, strings.Join(got, "\n  "))
	for _, l := range s.w.log {
		if strings.Contains(l, "SUSP") || strings.Contains(l, "DESTROY") || strings.Contains(l, "P' -> Q: session") || strings.Contains(l, "Q <- P: session") {
			t.Log(l)
		}
	}
}

// TestLeadFixBVariants: the named seeds and H2 under each F1 variant
// (TRUSTMODEL_FIXB: "" = fix B as committed, strict, window). It logs;
// the comparison is for the lead.
func TestLeadFixBVariants(t *testing.T) {
	seeds := []struct {
		name string
		rs   uint64
		env  map[string]string
	}{
		{"I3 copy answers, R2 gate on", 5707634071088938680, map[string]string{"TRUSTMODEL_OPT": "2"}},
		{"I3 copy answers, R2 mix28", 14995905639264089123, map[string]string{"TRUSTMODEL_OPT": "2", "TRUSTMODEL_MIXED": "1"}},
		{"I4-false, R1 unseen", 8756148401117559123, map[string]string{"TRUSTMODEL_OPT": "1", "TRUSTMODEL_UNSEEN": "1"}},
		{"I4-misattributed, R1 gate on", 16663332612404948059, map[string]string{"TRUSTMODEL_OPT": "1"}},
	}
	for _, v := range []string{"fixb", "strict", "window"} {
		for _, sd := range seeds {
			t.Run(v+"/"+sd.name, func(t *testing.T) {
				env := map[string]string{"TRUSTMODEL_FIXB": v}
				for k, x := range sd.env {
					env[k] = x
				}
				w := runSeed(t, sd.rs, env)
				var got []string
				for _, x := range w.viol {
					got = append(got, x.Inv+": "+x.Detail)
				}
				t.Logf("variant %q seed %d: kept %d, F1 demoted %d, window skipped %d; violations %v",
					v, sd.rs, w.stats["A:F1-fixB-kept"], w.stats["A:F1-demoted"], w.stats["A:F1-window-skipped"], got)
			})
		}
		t.Run(v+"/H2", func(t *testing.T) {
			t.Setenv("TRUSTMODEL_FIXB", v)
			hs := h2v(t, v)
			var got []string
			for _, x := range hs.w.viol {
				got = append(got, x.Inv+": "+x.Detail)
			}
			t.Logf("H2 variant %q: kept %d, F1 demoted %d, window skipped %d, rule E destroyed %d, suspensions %d; violations %v",
				v, hs.w.stats["A:F1-fixB-kept"], hs.w.stats["A:F1-demoted"], hs.w.stats["A:F1-window-skipped"],
				hs.w.stats["A:destroyed-later-epoch"], hs.w.stats["out suspend"], got)
		})
	}
}

// h2v: H2 under a TRUSTMODEL_FIXB variant.
func h2v(t *testing.T, v string) *scen {
	switch v {
	case "window":
		return h2(t, true)
	case "strict":
		return h2s(t)
	}
	return h2b(t)
}
