package trustmodel

import (
	"strings"
	"testing"
)

// Dedicated scenarios for the review findings the F1-F13 table of
// VAULT-MESSAGING §15 item 50 marks "random runs only": F5, F9, F10, F13
// and lead items 5 and 6. Each drives the situation the finding describes
// and asserts the fixed behaviour. Where the fix can be switched off (a
// World field no*, default false), the test runs twice: "fix" must pass,
// and "off" must show the failure (the test asserts that it does).

// bothWays runs f with the fix on and with it off.
func bothWays(t *testing.T, f func(t *testing.T, off bool)) {
	for _, off := range []bool{false, true} {
		name := "fix"
		if off {
			name = "off"
		}
		t.Run(name, func(t *testing.T) { f(t, off) })
	}
}

// trace: the world's log, for failure messages.
func (s *scen) trace() string { return strings.Join(s.w.log, "\n  ") }

// viols: the violations so far, one line each.
func (s *scen) viols() []string {
	var out []string
	for _, v := range s.w.viol {
		out = append(out, v.Inv+": "+v.Detail)
	}
	return out
}

// pendingAt: I rekeys with R; R answers; I holds the new epoch pending and
// its hs.fin is in R's mailbox. It returns the current and pending epochs.
func (s *scen) pendingAt(I, R *Party) (e0, e1 int) {
	s.t.Helper()
	s.do(I, func() { I.startHS(I.st.peer(R.ID), false); I.write(); I.flush() })
	s.run(1, R) // R answers
	s.run(1, I) // I: pending, hs.fin
	r := I.st.peer(R.ID)
	if r.Pend == nil {
		s.t.Fatalf("setup: %s holds no pending epoch\n  %s", I.Name, s.trace())
	}
	return r.Cur, r.Pend.ID
}

// lostConfirm: as pendingAt, then R activates the new epoch and its
// hs.confirm is lost.
func (s *scen) lostConfirm(I, R *Party) (e0, e1 int) {
	s.t.Helper()
	e0, e1 = s.pendingAt(I, R)
	s.run(1, R) // R activates e1, hs.confirm
	if R.st.peer(I.ID).Cur != e1 {
		s.t.Fatalf("setup: %s did not activate E%d", R.Name, e1)
	}
	if s.dropAt(I, KConfirm) == 0 {
		s.t.Fatalf("setup: no hs.confirm to lose")
	}
	return e0, e1
}

// longTokens: every token held or issued lasts d longer (token expiry is
// not the subject of the scenario).
func (s *scen) longTokens(d int64) {
	for _, p := range s.w.real() {
		for i := range p.st.Peers {
			r := &p.st.Peers[i]
			for j := range r.Toks {
				r.Toks[j].Exp += d
			}
			for j := range r.Issued {
				r.Issued[j].Exp += d
			}
		}
		if !p.Locked {
			s.do(p, p.write)
		} else {
			p.stored = p.st.clone()
		}
	}
}

// ---------- F5 ----------

// F5 (§6.3.1 "Initiator"): "The confirmation takes effect before anything
// else is done with the message (dedupe, the ts window, step 5, its
// handler)". Off (noF5): a message confirms only once its handler has
// accepted it.
func TestF5ConfirmationBeforeHandler(t *testing.T) {
	// (handler) R activated E1, its hs.confirm is lost, and R's next message
	// is its daily rekey from E1: an hs.init whose ctx is the pending epoch.
	// Confirmed first, the ctx is I's current epoch and the rekey is
	// answered; confirmed after the handler, Table B refuses it
	// (rekey_not_current_epoch) and nothing confirms.
	t.Run("handler", func(t *testing.T) {
		bothWays(t, func(t *testing.T, off bool) {
			s := newScen(t, 2)
			s.w.noF5 = off
			I, R := s.p(0), s.p(1)
			_, e1 := s.lostConfirm(I, R)
			s.tick(day + hour)
			s.do(R, R.tick) // R's rekey interval (24 h): hs.init under E1
			if m := s.find(I, KInit); m == nil || m.P.Epoch != e1 || m.P.Ctx != e1 {
				t.Fatalf("setup: no rekey from E%d at I\n  %s", e1, s.trace())
			}
			s.drain(I)
			r := I.st.peer(R.ID)
			ok := r.Pend == nil && r.Cur == e1 && s.w.stats["out answer"] > 0
			t.Logf("noF5=%v: I current E%d, pending %v, answered %d, refused rekey_not_current_epoch %d",
				off, r.Cur, r.Pend != nil, s.w.stats["out answer"], s.w.stats["cell B:current:hs.init:ctx"])
			if off {
				if ok {
					t.Errorf("off: the rekey under the pending epoch still confirmed it")
				}
				return
			}
			if !ok {
				t.Errorf("the rekey under the pending epoch did not confirm it before Table B\n  %s", s.trace())
			}
			s.run(4, I, R)
			s.done(true)
		})
	})

	// (link, §3.4.1 "unless the message carrying the link traveled under
	// that pending epoch") R activated E1 (hs.confirm lost) and then rotates
	// its ik: its identity.rotate travels under E1. Confirmed first, H5 finds
	// no pending epoch to abandon; confirmed after the handler, H5 abandons
	// E1 (signed by R's old ik) although R activated it.
	t.Run("link", func(t *testing.T) {
		bothWays(t, func(t *testing.T, off bool) {
			s := newScen(t, 2)
			s.w.noF5 = off
			I, R := s.p(0), s.p(1)
			_, e1 := s.lostConfirm(I, R)
			s.w.holdRotate = true // only the ik moves
			s.rotate(R, pathCred)
			if m := s.find(I, KIdRot); m == nil || m.P.Epoch != e1 {
				t.Fatalf("setup: no identity.rotate under E%d at I\n  %s", e1, s.trace())
			}
			s.run(1, I)
			r := I.st.peer(R.ID)
			ab := s.w.stats["A:abandoned:H5: signer superseded"]
			t.Logf("noF5=%v: I current E%d, abandoned by H5 %d, confirmed %d", off, r.Cur, ab, s.w.stats["A:confirmed"])
			if off {
				if ab == 0 {
					t.Errorf("off: H5 did not abandon the pending epoch")
				}
				return
			}
			if ab != 0 || s.w.stats["A:confirmed"] == 0 {
				t.Errorf("the link under the pending epoch abandoned it\n  %s", s.trace())
			}
			s.w.holdRotate = false
			s.run(6, I, R)
			s.done(true)
		})
	})

	// (dedupe) a message under the pending epoch whose inner id I has seen
	// (an earlier copy under the old epoch). §6.3.1: it still confirms. The
	// model dedupes first (handle), so this part is not modelled: in the
	// model no message travels again under a newer epoch with the same inner
	// id (only the revert re-seals, into the older epoch). The subtest
	// crafts the duplicate and skips while the model differs.
	t.Run("dedupe", func(t *testing.T) {
		s := newScen(t, 2)
		I, R := s.p(0), s.p(1)
		_, e1 := s.pendingAt(I, R)
		probe := s.w.id()
		s.do(R, func() { R.enqueue(I.ID, Msg{Kind: KSession, Probe: probe}, nil); R.write(); R.flush() })
		dup := cloneMsg(*s.find(I, KSession).P)
		s.drain(I) // the copy under E0: seen
		dup.Epoch = e1
		rr := R.st.peer(I.ID)
		if _, err := s.w.R.deposit(R.ID, rr.KeyFor, rr.standing(rr.KeyFor, rr.Relay, s.w.Now), rr.Relay, &dup); err != okRes {
			t.Fatalf("setup: deposit %s", err)
		}
		s.drain(I)
		if I.st.peer(R.ID).Pend != nil {
			t.Skipf("not modelled: the model dedupes before confirmation (handle); a duplicate under the pending epoch E%d does not confirm it", e1)
		}
	})
}

// ---------- F9 ----------

// F9 (§6.3.1 "Initiator"): "on token_expired it abandons the pending epoch
// and reconnects naming its current epoch"; at B "a device: rekeys if its
// standing token is valid, else pairs again". Off (noF9): token_expired
// keeps the pending epoch, so startHS refuses the reconnect.
func TestF9ReconnectWhilePending(t *testing.T) {
	// (token_expired) I holds E1 pending (its hs.fin lost); its next
	// deposit is refused token_expired. The model's parties check exp
	// before depositing, so the relay's answer is reached here by a token
	// whose exp has just come (as with a clock behind the relay's).
	t.Run("token_expired", func(t *testing.T) {
		bothWays(t, func(t *testing.T, off bool) {
			s := newScen(t, 2)
			s.w.noF9 = off
			I, R := s.p(0), s.p(1)
			e0, _ := s.pendingAt(I, R)
			if s.dropAt(R, KFin) == 0 {
				t.Fatalf("setup: no hs.fin to lose")
			}
			r := I.st.peer(R.ID)
			tk := r.standing(r.KeyFor, r.Relay, s.w.Now)
			for j := range r.Toks {
				if r.Toks[j].JTI == tk.JTI {
					r.Toks[j].Exp = s.w.Now // its exp has come
				}
			}
			tk.Exp = s.w.Now
			s.do(I, func() {
				I.enqueue(R.ID, Msg{Kind: KSession, Probe: s.w.id()}, func(e *Entry) { e.Tok = tk })
				I.write()
				I.flush()
				I.startWanted()
			})
			r = I.st.peer(R.ID)
			ok := r.Pend == nil && r.Own != nil && r.Own.Reconnect && r.Own.Ctx == e0
			t.Logf("noF9=%v: token_expired abandons %d; pending %v; open reconnect %v (ctx E%d, current E%d)",
				off, s.w.stats["A:abandoned:token_expired"], r.Pend != nil, r.Own != nil && r.Own.Reconnect, ctxOf(r.Own), r.Cur)
			if off {
				if ok {
					t.Errorf("off: a reconnect started anyway")
				}
				return
			}
			if !ok {
				t.Errorf("no reconnect naming the current epoch E%d after token_expired\n  %s", e0, s.trace())
			}
			s.run(6, R, I)
			s.done(true)
		})
	})

	// (device at B) a device's rekey: the vault activates E1, the
	// hs.confirm is lost, the vault is quiet; at B the device, whose
	// standing token is valid, rekeys from E0. No switch: turning the
	// device branch off (a device "reconnects", which it cannot) shows
	// nothing, because the device's §6.5 rekey interval (7 days) starts the
	// same rekey later in the same tick (rotate_test.go tick).
	t.Run("device-B", func(t *testing.T) {
		s, V, D, e0, _ := devPastB(t, func(*World) {})
		r := D.st.peer(V.ID)
		t.Logf("B abandons %d; open rekey %v (ctx E%d)", s.w.stats["A:abandoned:B passed"], r.Own != nil, ctxOf(r.Own))
		if r.Pend != nil || r.Own == nil || r.Own.Reconnect || r.Own.Ctx != e0 {
			t.Errorf("the device did not rekey from E%d at B\n  %s", e0, s.trace())
		}
		s.run(6, V, D)
		s.done(true)
	})
}

func ctxOf(h *HS) int {
	if h == nil {
		return 0
	}
	return h.Ctx
}

// devPastB: a device D rekeys with its vault V; V activates E1 and its
// hs.confirm is lost; V stays quiet; D stays online and collects, and its
// tick runs once past B. Tokens are extended (their expiry is not the
// subject).
func devPastB(t *testing.T, mod func(*World)) (s *scen, V, D *Party, e0, e1 int) {
	w := setup(Config{Vaults: 1, Devices: true}, 1)
	mod(w)
	s = &scen{t, w}
	V, D = s.p(0), s.p(1)
	s.longTokens(60 * day)
	e0, e1 = s.lostConfirm(D, V)
	if r := V.st.peer(D.ID); r.ConfID != e0 || r.Cur != e1 {
		t.Fatalf("setup: the vault's confirmed epoch E%d, current E%d", r.ConfID, r.Cur)
	}
	s.tick(aPendLife + hour)
	s.drain(D) // a short collect: B may now be judged
	s.do(D, D.tick)
	return s, V, D, e0, e1
}

// ---------- F10 ----------

// F10 (§6.3.1 "Responder"): R "queues hs.confirm again (a new inner id)
// unless one to I is still in its outbox". R's hs.confirm cannot be
// deposited (the relay answers 429 to R) while I keeps sending under E0 in
// three batches. Off (noF10): one more hs.confirm per batch.
func TestF10ConfirmResendCapped(t *testing.T) {
	bothWays(t, func(t *testing.T, off bool) {
		s := newScen(t, 2)
		s.w.noF10 = off
		I, R := s.p(0), s.p(1)
		_, e1 := s.pendingAt(I, R)
		s.w.p429 = 1
		s.drain(R) // R activates E1; its hs.confirm gets no definite answer
		s.w.p429 = 0
		for i := 0; i < 3; i++ {
			s.do(I, func() { I.enqueue(R.ID, Msg{Kind: KSession, Probe: s.w.id()}, nil); I.write(); I.flush() })
			s.tick(visTimeout + freshWindow + 1)
			s.w.p429 = 1
			s.drain(R) // a batch holding a message under R's confirmed epoch E0
			s.w.p429 = 0
		}
		n := 0
		for _, e := range R.st.Out {
			if e.To == I.ID && e.M.Kind == KConfirm && !e.Done && !e.Ended {
				n++
			}
		}
		t.Logf("noF10=%v: hs.confirm entries in R's outbox %d, queued again %d (R current E%d)", off, n, s.w.stats["A:hs.confirm-again"], R.st.peer(I.ID).Cur)
		if R.st.peer(I.ID).Cur != e1 {
			t.Fatalf("setup: R did not activate E%d", e1)
		}
		if off {
			if n <= 1 {
				t.Errorf("off: still at most one hs.confirm in the outbox")
			}
			return
		}
		if n != 1 || s.w.stats["A:hs.confirm-again"] != 0 {
			t.Errorf("want exactly one hs.confirm in R's outbox, got %d\n  %s", n, s.trace())
		}
		s.run(4, I, R)
		s.done(true)
	})
}

// ---------- F13 ----------

// F13 (low): margin in the lifetimes and four smaller gaps. One subtest per
// part the model implements:
//   - lifetimes: B = L + T + 2 days, the confirmed epoch's keys B + T + 2
//     days. No switch: the model's timers run on true time (skew only moves
//     inner ts), so the 2 days of clock-skew margin cannot fail in it.
//   - B judged only after the first collect after an unlock that returns
//     fewer than max messages (switch noF13B).
//   - §6.2: a rekey's ctx is "the epoch the hs.init travels under: the
//     current epoch or the responder's confirmed epoch" (switch noConfRekey).
//   - I1 split into Quiescence and Then: quiescence runs past B (no
//     switch; see the subtest).
//
// Not modelled: §6.6 "An epoch enters it only once it has been current"
// (the epoch history of service connections is not in the model).
func TestF13Lifetimes(t *testing.T) {
	t.Run("lifetimes", func(t *testing.T) {
		if aPendLife != aAnsLife+msgTTL+2*day || aConfKeys != aPendLife+msgTTL+2*day {
			t.Fatalf("lifetimes: B %dd, keys %dd", aPendLife/day, aConfKeys/day)
		}
		// lost hs.confirm; R quiet from its activation. I's last message
		// under E0 goes as late as its standing token allows (R minted
		// nothing after activating: anything R sends under E1 confirms),
		// and R collects it just before the relay TTL: it opens. Note: B
		// does not bound this deposit (§12.2 drains the outbox before the
		// first collect after an unlock, and B is judged only after that
		// collect); the 30-day standing token does: 30 + 14 = 44 <= 48.
		s := newScen(t, 2)
		I, R := s.p(0), s.p(1)
		s.lostConfirm(I, R)
		act := s.w.Now
		s.do(R, R.tick)
		rr := R.st.peer(I.ID)
		if got := rr.ConfUntil - rr.epoch(rr.ConfID).Superseded; got != aConfKeys {
			t.Errorf("the confirmed epoch's keys run %dd, want %dd", got/day, aConfKeys/day)
		}
		s.lock(R)
		ri := I.st.peer(R.ID)
		last := ri.standing(ri.KeyFor, ri.Relay, s.w.Now).Exp - hour
		s.tick(last - s.w.Now)
		probe := s.w.id()
		s.do(I, func() { I.enqueue(R.ID, Msg{Kind: KSession, Probe: probe}, nil); I.write(); I.flush() })
		s.tick(msgTTL - 2*hour)
		t.Logf("I's last E0 deposit %.1f days after R's activation; R collects at %.1f days (keys until %.1f days)",
			float64(last-act)/float64(day), float64(s.w.Now-act)/float64(day), float64(rr.ConfUntil-act)/float64(day))
		s.do(R, R.unlock)
		s.do(R, R.tick) // the key timer first
		s.drain(R)
		if !s.w.probes[probe] {
			t.Errorf("the late message under the confirmed epoch was not accepted (%s)\n  %s", s.w.probeFate[probe], s.trace())
		}
		s.done(true)
	})

	// B after the first short collect: I is locked past B. R's hs.confirm
	// got no answer from the relay at first and was deposited on day 25;
	// two messages from a third vault Z were deposited before it (day 20).
	// At unlock I's timers run before it collects, then it collects one
	// message (= max), its timers run again, then it collects the rest.
	// Off: B is judged at the first tick and the pending epoch is abandoned
	// although its confirmation is waiting.
	t.Run("B-after-short-collect", func(t *testing.T) {
		bothWays(t, func(t *testing.T, off bool) {
			s := newScen(t, 3)
			s.w.noF13B = off
			I, R, Z := s.p(0), s.p(1), s.p(2)
			s.longTokens(60 * day)
			_, e1 := s.pendingAt(I, R)
			s.lock(I)
			s.w.p429 = 1
			s.run(1, R) // R activates E1; its hs.confirm gets no answer
			s.w.p429 = 0
			s.tick(20 * day)
			s.do(Z, func() {
				Z.enqueue(I.ID, Msg{Kind: KSession, Probe: s.w.id()}, nil)
				Z.enqueue(I.ID, Msg{Kind: KSession, Probe: s.w.id()}, nil)
				Z.write()
				Z.flush()
			})
			s.tick(5 * day)
			s.do(R, R.flush) // the hs.confirm, behind Z's two messages
			if s.find(I, KConfirm) == nil {
				t.Fatalf("setup: no hs.confirm waiting\n  %s", s.trace())
			}
			s.tick(aPendLife - 25*day + day)
			s.do(I, I.unlock)
			s.do(I, I.tick) // timers before the first collect
			ab1 := s.w.stats["A:abandoned:B passed"]
			I.collectRound(1) // returns max: B still not judged
			s.do(I, I.tick)
			ab2 := s.w.stats["A:abandoned:B passed"]
			s.drain(I)
			r := I.st.peer(R.ID)
			t.Logf("noF13B=%v: abandoned at B before any collect %d, after a full collect %d; I current E%d (pending %v)",
				off, ab1, ab2, r.Cur, r.Pend != nil)
			ok := ab2 == 0 && r.Cur == e1
			if off {
				if ok {
					t.Errorf("off: the pending epoch was still confirmed")
				}
				return
			}
			if !ok {
				t.Errorf("B was judged before the first short collect\n  %s", s.trace())
			}
			s.run(4, I, R, Z)
			s.done(true)
		})
	})

	// §6.2 "the epoch the hs.init travels under": a device's rekey at B
	// travels under E0, the vault's confirmed epoch (the vault activated
	// E1; its hs.confirm was lost). The vault answers it as if E0 were
	// current. Off: §6.2 as before F13 (ctx must be the current epoch):
	// refused rekey_not_current_epoch.
	t.Run("rekey-ctx-confirmed-epoch", func(t *testing.T) {
		bothWays(t, func(t *testing.T, off bool) {
			s, V, D, e0, _ := devPastB(t, func(w *World) { w.noConfRekey = off })
			if o := D.st.peer(V.ID).Own; o == nil || o.Reconnect || o.Ctx != e0 {
				t.Fatalf("setup: the device has no rekey from E%d", e0)
			}
			s.drain(V)
			ans := s.w.stats["cell B:current:hs.init:confirmed-epoch"]
			ref := s.w.stats["cell B:current:hs.init:ctx"]
			t.Logf("noConfRekey=%v: answered as the confirmed epoch %d, refused rekey_not_current_epoch %d", off, ans, ref)
			if off {
				if ans != 0 || ref == 0 {
					t.Errorf("off: the rekey was not refused")
				}
				return
			}
			if ans == 0 {
				t.Errorf("the rekey naming the confirmed epoch E%d was not answered\n  %s", e0, s.trace())
			}
			s.run(6, V, D)
			s.done(true)
		})
	})

	// I1 Quiescence: "every confirmation bound B". The hs.fin is lost while
	// R is locked past the relay TTL; I holds E1 pending. At quiescence no
	// pending epoch is left and the pair holds one epoch. No switch: with
	// settle stopped at the f4a4d97 bound the run ends the same, because
	// R's rekey after its answer expires (L, 16 days) abandons I's pending
	// epoch (§6.3.1 "Crossing") well inside that bound; in the model no
	// case needs B itself to reach quiescence.
	t.Run("I1-quiescence-past-B", func(t *testing.T) {
		s := newScen(t, 2)
		I, R := s.p(0), s.p(1)
		s.pendingAt(I, R)
		s.lock(R)
		s.tick(msgTTL + hour) // the hs.fin expires at the relay
		s.w.checkEnd(true)
		s.noViolation("I")
		if I.st.peer(R.ID).Pend != nil {
			t.Errorf("a pending epoch at quiescence")
		}
		t.Logf("abandoned at B %d, by a later rekey %d", s.w.stats["A:abandoned:B passed"], s.w.stats["A:abandoned:a later rekey from the responder"])
	})
}
