package trustmodel

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// Deterministic scenarios for §3.4.2 RK14 (VAULT-MESSAGING 0.90.0): the
// hold and the telling, each with its switch on (the message arrives) and
// off (it does not). The randomized runs reach these cases only in runs
// with a lock near the grace, so these pin them.

// rk14World: two vaults with every rule of §3.4.2, except those in off.
func rk14World(off ...string) (*scen, *Party, *Party) {
	w := setup(Config{Vaults: 2}, 1)
	w.chosen = map[string]bool{}
	for _, r := range chosenRules {
		w.chosen[r] = true
	}
	for _, r := range off {
		delete(w.chosen, r)
	}
	s := &scen{w: w}
	return s, w.P[0], w.P[1]
}

// online: every party unlocked collects, and its timers run, for days;
// each locks and unlocks once a day (an unlock resends an unacknowledged
// update, §3.4 (b)).
func (s *scen) online(days int, ps ...*Party) {
	for d := 0; d < days; d++ {
		for _, p := range ps {
			s.lock(p)
			s.do(p, func() { p.unlock() })
		}
		for i := 0; i < 4; i++ {
			s.drain(ps...)
			s.tick(visTimeout + freshWindow + 1)
		}
		s.tick(day)
		for _, p := range ps {
			p.tick()
		}
	}
	s.drain(ps...)
}

func (s *scen) traceIf() {
	if os.Getenv("TRUSTMODEL_TRACE") != "" {
		s.t.Logf("trace:\n  %s", strings.Join(s.w.log, "\n  "))
	}
}

// rk14Hold: Q queues a message to P and is locked before depositing it; P
// rotates its relay key; Q stays locked past P's grace (P's update
// resends keep it within the relay's 14 days). At Q's unlock its
// deposit to P's old mailbox is refused mailbox_unknown. With HOLD the
// entry is held, then re-addressed when Q follows P's update; without it
// (0.88) the entry ends and Q makes P stale.
func rk14Hold(t *testing.T, off ...string) (delivered bool, s *scen, P, Q *Party) {
	s, P, Q = rk14World(off...)
	s.t = t
	s.online(2, P, Q)
	probe := s.w.id()
	s.do(Q, func() {
		Q.enqueue(P.ID, Msg{Kind: KSession, Probe: probe}, nil)
		Q.write()
	})
	s.lock(Q)
	s.rotate(P, pathCred)
	s.online(15, P)
	s.do(Q, func() { Q.unlock() })
	s.online(3, P, Q)
	delivered = s.w.probes[probe]
	s.w.checkEnd(true)
	s.traceIf()
	return delivered, s, P, Q
}

func TestRK14HoldReaddressedAtFollow(t *testing.T) {
	ok, s, P, Q := rk14Hold(t)
	if !ok || Q.st.peer(P.ID).Status != stActive {
		t.Fatalf("with HOLD the held message must arrive at the follow (arrived %v, status %d)\n  %s", ok, Q.st.peer(P.ID).Status, strings.Join(s.w.log, "\n  "))
	}
	if s.w.stats["HOLD: held entry re-addressed at a follow"] == 0 {
		t.Errorf("the message arrived without being held and re-addressed")
	}
	if len(s.w.viol) > 0 {
		t.Errorf("violations with HOLD: %v", s.w.viol)
	}
	ok, _, P, Q = rk14Hold(t, "HOLD")
	if ok || Q.st.peer(P.ID).Status != stStale {
		t.Errorf("without HOLD (0.88) mailbox_unknown should end the message and the connection (arrived %v)", ok)
	}
}

// rk14Tell: P rotates its relay key; Q deposits a message to P's old
// mailbox K before it has collected P's update, then follows; P is locked
// until after K's grace, so K ends with the message in it. With TELL, P's
// relay.mailbox.closed has Q deposit it again; without it, it is lost.
func rk14Tell(t *testing.T, off ...string) (delivered bool, s *scen) {
	s, P, Q := rk14World(off...)
	s.t = t
	s.online(2, P, Q)
	s.rotate(P, pathCred)
	s.lock(P)
	probe := s.w.id()
	s.do(Q, func() {
		Q.enqueue(P.ID, Msg{Kind: KSession, Probe: probe}, nil)
		Q.write()
		Q.flush()
	})
	s.online(15, Q)
	s.do(P, func() { P.unlock() })
	s.online(5, P, Q)
	delivered = s.w.probes[probe]
	s.w.checkEnd(true)
	s.traceIf()
	return delivered, s
}

func TestRK14TellingRedeposits(t *testing.T) {
	ok, s := rk14Tell(t)
	if !ok {
		t.Fatalf("with TELL the message in the ended mailbox must arrive\n  %s", strings.Join(s.w.log, "\n  "))
	}
	if s.w.stats["TELL: re-deposited after the telling"] == 0 {
		t.Errorf("the message arrived without the telling")
	}
	if len(s.w.viol) > 0 {
		t.Errorf("violations with TELL: %v", s.w.viol)
	}
	ok, s = rk14Tell(t, "TELL")
	if ok {
		t.Errorf("without TELL the message deleted with the old mailbox should be lost")
	}
	if !slices.ContainsFunc(s.w.viol, func(v Violation) bool {
		return v.Inv == "I1-loss" && strings.Contains(v.Detail, "deleted with an old mailbox")
	}) {
		t.Errorf("without TELL, I1-loss should report the message deleted with the old mailbox; violations %v", s.w.viol)
	}
}

// TestRK5OffI3: with RK5's ik requirement off, the I3 check from ground
// truth (checkRK5Copy) fires on runs where Q follows an old copy's relay
// link, the copy taken before Q's current ik for P; with RK5 on it does
// not. The run seeds are from TRUSTMODEL_ROTBURST at master seed 1.
func TestRK5OffI3(t *testing.T) {
	t.Setenv("TRUSTMODEL_RELAYROT", "1")
	t.Setenv("TRUSTMODEL_CHOSEN", "1")
	t.Setenv("TRUSTMODEL_ROTBURST", "1")
	for _, rs := range []uint64{2079705939960222102, 5465547818700648244} {
		i3 := func() bool {
			cfg, acts := genRun(rs, 40)
			w := runActions(cfg, rs, acts, false)
			return slices.ContainsFunc(w.viol, func(v Violation) bool {
				return v.Inv == "I3" && strings.Contains(v.Detail, "of old copy")
			})
		}
		t.Setenv("TRUSTMODEL_CH", "-RK5")
		if !i3() {
			t.Errorf("run seed %d: with RK5 off, the I3 check should fire", rs)
		}
		t.Setenv("TRUSTMODEL_CH", "")
		if i3() {
			t.Errorf("run seed %d: with RK5 on, the I3 check fired", rs)
		}
	}
}
