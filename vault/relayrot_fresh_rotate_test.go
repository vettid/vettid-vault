package vault

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayclient"
)

// A rotate that succeeds and a registration after it answered 201 (the
// relay created the mailbox afresh after all): every held token is minted
// again, backdated as any other (RELAY-PROTOCOL §5.2), once
// freshMailboxWait has run after that answer (RELAY-PROTOCOL §6.10).
func TestRelayRotRegisteredAfreshAfterTheRotate(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	pmb := fx.pendingMailbox()
	held := fx.pending().Held["c1"].Standing
	fx.w.onRotate = func() {
		fx.w.mu.Lock()
		delete(fx.w.live, pmb) // gone again before the registration
		fx.w.mu.Unlock()
	}
	fx.setClk(fx.clk.Add(2 * time.Minute))
	fx.batch()
	answered := fx.clk
	if pr := fx.pending(); fx.mailbox() == pmb || pr == nil || !pr.Created.Equal(answered) {
		t.Fatal("made current before the wait after a mailbox created afresh")
	}
	fx.w.onRotate = nil // the mailbox made afresh stays
	fx.setClk(answered.Add(freshMailboxWait))
	fx.batch()
	if fx.mailbox() != pmb {
		t.Fatalf("mailbox %s, want %s", fx.mailbox(), pmb)
	}
	fx.do(func(m *Manager) {
		tok := m.st.Relay.Recipients["c1"].Standing
		c, err := parseOwnToken(m, tok)
		if tok == held || err != nil || !c.Iat.Equal(fx.clk.Truncate(time.Second).Add(-tokenBackdate)) || c.Iat.Before(answered.Add(90*time.Second)) {
			t.Fatalf("held token re-minted %v, iat %v (now %v) %v", tok != held, c.Iat, fx.clk, err)
		}
	})
}

// A 201 after a rotate while a wait is already stored: the mailbox was
// made afresh again, and the wait starts again from that answer.
func TestRelayRotRegisteredAfreshAgainRenewsTheWait(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	pmb := fx.pendingMailbox()
	fx.w.onRotate = func() {
		fx.w.mu.Lock()
		delete(fx.w.live, pmb) // gone again before each registration
		fx.w.mu.Unlock()
	}
	fx.setClk(fx.clk.Add(2 * time.Minute))
	fx.batch()
	first := fx.pending().Created
	fx.setClk(first.Add(freshMailboxWait))
	fx.batch()
	if pr := fx.pending(); fx.mailbox() == pmb || pr == nil || !pr.Created.Equal(fx.clk) {
		t.Fatalf("a second 201 did not start the wait again (created %v)", createdOf(pr))
	}
	fx.w.onRotate = nil
	fx.setClk(fx.clk.Add(freshMailboxWait))
	fx.batch()
	if fx.mailbox() != pmb {
		t.Fatal("not made current after the renewed wait")
	}
}

// An unlock while the wait of a mailbox made afresh runs makes no attempt
// and audits no identity.rotation_failed: the relay answered.
func TestRelayRotFreshWaitNotAuditedAtUnlock(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	cur := fx.mailbox() // read before the relay's lock: the vault takes its own first
	fx.w.mu.Lock()
	delete(fx.w.live, cur) // past the grace
	fx.w.mu.Unlock()
	fx.setClk(fx.clk.Add(2 * time.Minute))
	fx.batch()
	if pr := fx.pending(); pr == nil || pr.Created.IsZero() {
		t.Fatal("no wait stored")
	}
	n0 := len(fx.acts("identity.rotation_failed"))
	rot0, reg0 := fx.w.log()
	fx.restart()
	rot, reg := fx.w.log()
	if n := len(fx.acts("identity.rotation_failed")); n != n0 || len(rot) != len(rot0) || len(reg) != len(reg0) {
		t.Fatalf("at the unlock within the wait: audits %d (before %d), attempts %v %v", n, n0, rot[len(rot0):], reg[len(reg0):])
	}
}

// The wait covers RELAY-PROTOCOL §6.10's 90 seconds after the deletion,
// on every path that mints a token on the new mailbox (the held tokens
// minted again, and mintStanding, which the unlock tokens of the answer
// that completes the key use), with the vault's clock behind the relay's
// by up to §4.1's 90 seconds; and no token's iat is after the relay's now
// with the vault's clock ahead by up to §5.2's 60 seconds. The iat is
// compared as minted, a number the relay reads on its own clock.
func TestRelayRotFreshMailboxWaitCoversTheSkew(t *testing.T) {
	if freshMailboxWait != 241*time.Second {
		t.Fatalf("freshMailboxWait %v", freshMailboxWait)
	}
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	pmb := fx.pendingMailbox()
	fx.w.onRotate = func() {
		fx.w.mu.Lock()
		delete(fx.w.live, pmb)
		fx.w.mu.Unlock()
	}
	// A fraction of a second on the vault's clock: iat drops it.
	fx.setClk(fx.clk.Truncate(time.Second).Add(2*time.Minute + 999*time.Millisecond))
	fx.batch()
	answered := fx.clk
	if pr := fx.pending(); pr == nil || !pr.Created.Equal(answered) {
		t.Fatal("no wait stored")
	}
	fx.w.onRotate = nil
	fx.setClk(answered.Add(freshMailboxWait)) // the first moment the wait allows
	fx.batch()
	if fx.mailbox() != pmb {
		t.Fatal("not made current after the wait")
	}
	minted := fx.clk
	type tok struct {
		path string
		iat  time.Time
	}
	var toks []tok
	fx.do(func(m *Manager) {
		for id, r := range m.st.Relay.Recipients {
			for kind, s := range map[string]string{"standing": r.Standing, "reconnect": r.Reconnect} {
				if s == "" {
					continue
				}
				c, err := parseOwnToken(m, s)
				if err != nil {
					t.Fatal(err)
				}
				toks = append(toks, tok{"held " + kind + " " + id, c.Iat})
			}
		}
		for _, p := range m.relayRecipients() {
			s, _, err := m.mintStanding(p, m.now(), nil)
			if err != nil {
				t.Fatal(err)
			}
			c, err := parseOwnToken(m, s)
			if err != nil {
				t.Fatal(err)
			}
			toks = append(toks, tok{"mintStanding " + p.ID, c.Iat})
		}
	})
	if len(toks) < 3 {
		t.Fatalf("tokens %v", toks)
	}
	for _, k := range toks {
		// skew: the relay's clock minus the vault's (behind: positive).
		for _, skew := range []time.Duration{-tokenBackdate, -30 * time.Second, 0, 30 * time.Second, collectedToWindow} {
			for _, lag := range []time.Duration{0, 500 * time.Millisecond, 10 * time.Second} {
				// The deletion came lag before the answer, both on the relay's clock.
				deletion := answered.Add(skew).Add(-lag)
				if k.iat.Before(deletion.Add(freshMailboxTombstone)) {
					t.Errorf("%s, skew %v, lag %v: iat %v before the tombstone's bound %v", k.path, skew, lag, k.iat, deletion.Add(freshMailboxTombstone))
				}
			}
			if relayNow := minted.Add(skew); k.iat.After(relayNow) {
				t.Errorf("%s, skew %v: iat %v after the relay's now %v", k.path, skew, k.iat, relayNow)
			}
		}
	}
}

// The answer's time of a mailbox made afresh is stored before the key is
// completed: while no state write succeeds the key stays pending past the
// wait, with no attempt (a lock or a restart would forget the wait, and a
// repeated rotate answered 200 would complete it at once), and the first
// write that stores the wait lets it complete.
func TestRelayRotFreshWaitUnstoredFailsClosed(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	pmb, old := fx.pendingMailbox(), fx.mailbox()
	fx.w.onRotate = func() {
		fx.w.mu.Lock()
		delete(fx.w.live, pmb)
		fx.w.mu.Unlock()
		fx.fs.setFail(1 << 20) // every write after the answer fails
	}
	batch := func() { _ = fx.m.ProcessBatch(context.Background(), &fakeCollector{}, nil) } // the writes fail
	fx.setClk(fx.clk.Add(2 * time.Minute))
	batch()
	answered := fx.clk
	if pr := fx.pending(); pr == nil || !pr.Created.Equal(answered) {
		t.Fatal("no wait in memory")
	}
	fx.w.onRotate = nil
	rot0, reg0 := fx.w.log()
	fx.setClk(answered.Add(freshMailboxWait))
	// The step itself: a batch whose writes fail stops before it.
	fx.do(func(m *Manager) { m.relayKeyStep(context.Background(), false) })
	rot, reg := fx.w.log()
	if pr := fx.pending(); fx.mailbox() != old || pr == nil || !pr.Created.Equal(answered) || len(rot) != len(rot0) || len(reg) != len(reg0) {
		t.Fatalf("completed (or attempted) with the wait unstored: mailbox %s, pending %v, attempts %v %v", fx.mailbox(), pr != nil, rot[len(rot0):], reg[len(reg0):])
	}
	fx.fs.setFail(0)
	fx.setClk(fx.clk.Add(relayRetryWait(8))) // past any sooner retry's wait
	fx.batch()
	if fx.mailbox() != pmb {
		t.Fatal("not completed once the wait was stored")
	}
}

// The wait runs from when the answer came, not from when the call began:
// a deletion during the call (a slow rotate, the successor gone again
// before the registration), with the relay's clock ahead of the vault's
// by all of §4.1's 90 seconds, still lies §6.10's 90 seconds before every
// held token's iat.
func TestRelayRotFreshWaitCountsFromTheAnswer(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	pmb := fx.pendingMailbox()
	fx.setClk(fx.clk.Truncate(time.Second).Add(2 * time.Minute))
	deleted := fx.clk.Add(5 * time.Second) // the vault's clock when the relay deletes
	fx.w.onRotate = func() {
		fx.setClk(deleted) // the call takes 5 s
		fx.w.mu.Lock()
		delete(fx.w.live, pmb)
		fx.w.mu.Unlock()
	}
	fx.batch()
	pr := fx.pending()
	if pr == nil || !pr.Created.Equal(deleted) {
		t.Fatalf("the wait's start %v, want the answer's %v", createdOf(pr), deleted)
	}
	fx.w.onRotate = nil
	fx.setClk(pr.Created.Add(freshMailboxWait))
	fx.batch()
	if fx.mailbox() != pmb {
		t.Fatal("not made current after the wait")
	}
	bound := deleted.Add(collectedToWindow).Add(freshMailboxTombstone) // on the relay's clock
	fx.do(func(m *Manager) {
		for id, r := range m.st.Relay.Recipients {
			for _, s := range []string{r.Standing, r.Reconnect} {
				if s == "" {
					continue
				}
				c, err := parseOwnToken(m, s)
				if err != nil || c.Iat.Before(bound) {
					t.Fatalf("%s: iat %v before the tombstone's bound %v (%v)", id, c.Iat, bound, err)
				}
			}
		}
	})
}

// A recovery's open: the inherited key's mailbox made afresh waits from
// when the answer came, not from the open's own time.
func TestRelayRotInheritedFreshWaitCountsFromTheAnswer(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	pmb := fx.pendingMailbox()
	opened := fx.clk
	answered := opened.Add(5 * time.Second)
	fx.w.onRotate = func() {
		fx.setClk(answered)
		fx.w.mu.Lock()
		delete(fx.w.live, pmb)
		fx.w.mu.Unlock()
	}
	fx.do(func(m *Manager) {
		m.inheritedKeyAtOpen(context.Background(), RecoveryOpenParams{Options: fx.fixture.opts}, opened)
	})
	if pr := fx.pending(); pr == nil || !pr.Created.Equal(answered) {
		t.Fatalf("the wait's start %v, want the answer's %v", createdOf(pr), answered)
	}
}

// createdOf is pr's Created (zero for none), for a failure's message.
func createdOf(pr *PendingRelay) time.Time {
	if pr == nil {
		return time.Time{}
	}
	return pr.Created
}

// A recovery's open over a key whose stored Created wait has run: a lost
// run of this open may have had the mailbox made afresh again, its 201 newer
// than Created, so an "exists" answer does not complete the key at the
// open; it is marked Unconfirmed and waits.
func TestRelayRotInheritedOpenOverARunCreatedWaitDoesNotComplete(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	pmb := fx.pendingMailbox()
	fx.do(func(m *Manager) { m.st.Relay.Pending.Created = fx.clk.Add(-3 * freshMailboxWait) })
	fx.do(func(m *Manager) {
		m.inheritedKeyAtOpen(context.Background(), RecoveryOpenParams{Options: fx.fixture.opts}, fx.clk)
	})
	if pr := fx.pending(); pr == nil || fx.pendingMailbox() != pmb || pr.Unconfirmed.IsZero() {
		t.Fatalf("completed at the open, or not marked: pending %v", pr)
	}
}

// A key completed after its Unconfirmed mark's wait has every held token
// minted again: the held tokens were minted before a lost run's deletion
// could have come, so their iat may fall inside the tombstone's window.
func TestRelayRotInheritedMarkCompletionMintsAgain(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	pmb := fx.pendingMailbox()
	fx.setClk(fx.clk.Add(time.Hour))
	fx.do(func(m *Manager) {
		m.inheritedKeyAtOpen(context.Background(), RecoveryOpenParams{Options: fx.fixture.opts}, fx.clk)
	})
	pr := fx.pending()
	if pr == nil || pr.Unconfirmed.IsZero() {
		t.Fatalf("not marked: %v", pr)
	}
	mark := pr.Unconfirmed
	fx.setClk(mark.Add(freshMailboxWait))
	fx.batch()
	if fx.mailbox() != pmb {
		t.Fatal("not made current after the wait")
	}
	fx.heldMintedSince(mark)
}

// The rotate succeeds and the registration after it gets no answer: it may
// have made the successor afresh (a lost 201), so the key is not completed
// at once; it waits freshMailboxWait from the answer, and the attempt after
// the wait completes it, its held tokens minted again.
func TestRelayRotRegistrationAfterARotateUnansweredWaits(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	pmb := fx.pendingMailbox()
	fx.w.mu.Lock()
	fx.w.register = []error{relayErr(503, "")} // the registration after the rotate: no answer
	fx.w.mu.Unlock()
	fx.setClk(fx.clk.Add(time.Hour))
	fx.batch() // the sooner retry: the rotate answered, the registration not
	pr := fx.pending()
	if pr == nil || fx.pendingMailbox() != pmb || pr.Created.IsZero() {
		t.Fatalf("completed at once, or no wait: pending %v", pr)
	}
	if n := len(fx.acts("identity.rotation_failed")); n != 1 {
		t.Fatalf("the restarted wait audited %d times, want 1", n)
	}
	fx.setClk(pr.Created.Add(freshMailboxWait - time.Second))
	fx.batch()
	if fx.pendingMailbox() != pmb {
		t.Fatal("completed inside the wait")
	}
	fx.setClk(pr.Created.Add(freshMailboxWait))
	fx.batch()
	if fx.mailbox() != pmb {
		t.Fatal("not made current after the wait")
	}
	fx.heldMintedSince(pr.Created)
}

// heldMintedSince checks that every held token of the current key was
// minted at or after from (iat).
func (fx *rotFx) heldMintedSince(from time.Time) {
	fx.t.Helper()
	checked := 0
	fx.do(func(m *Manager) {
		for id, r := range m.st.Relay.Recipients {
			for _, s := range []string{r.Standing, r.Reconnect} {
				if s == "" {
					continue
				}
				c, err := parseOwnToken(m, s)
				if err != nil || c.Iat.Before(from) {
					fx.t.Fatalf("%s: iat %v before %v (%v)", id, c.Iat, from, err)
				}
				checked++
			}
		}
	})
	if checked == 0 {
		fx.t.Fatal("no held token to check")
	}
}

// The registration after a rotate that succeeded is refused by the relay
// itself: a 429 with retry_after carried nothing out, so nothing was made
// afresh; the retry_after is honored (no registration before it runs out)
// and the unlock's failed attempt is audited. A definite refusal of that
// registration created nothing either: the key is completed at once. A cut
// call (the context ended) may have been a 201: the key waits.
func TestRelayRotRegistrationAfterARotateRelaysOwnRefusal(t *testing.T) {
	t.Run("429 retry_after", func(t *testing.T) {
		fx := newRotFx(t)
		fx.w.rotate = []error{relayErr(503, "")}
		if err := fx.credRotate(); err != nil {
			t.Fatal(err)
		}
		pmb := fx.pendingMailbox()
		fx.w.mu.Lock()
		fx.w.register = []error{&relayclient.Error{Status: 429, Code: "rate_limited", RetryAfter: 7200}}
		fx.w.mu.Unlock()
		fx.setClk(fx.clk.Add(time.Hour))
		fx.restart() // the unlock's attempt
		pr := fx.pending()
		if pr == nil || fx.pendingMailbox() != pmb || !pr.Created.IsZero() || !pr.RetryAfter.Equal(fx.clk.Add(2*time.Hour)) {
			t.Fatalf("pending %+v: want the retry_after kept, no wait", pr)
		}
		if n := len(fx.acts("identity.rotation_failed")); n != 1 {
			t.Fatalf("audited %d times, want 1", n)
		}
		_, regs0 := fx.w.log()
		for range 5 {
			fx.setClk(fx.clk.Add(20 * time.Minute))
			fx.batch()
		}
		if _, regs := fx.w.log(); len(regs) != len(regs0) {
			t.Fatalf("registered inside the retry_after: %v", regs[len(regs0):])
		}
	})
	t.Run("definite refusal", func(t *testing.T) {
		fx := newRotFx(t)
		fx.w.rotate = []error{relayErr(503, "")}
		if err := fx.credRotate(); err != nil {
			t.Fatal(err)
		}
		pmb := fx.pendingMailbox()
		fx.w.mu.Lock()
		fx.w.register = []error{relayErr(400, "bad_request")}
		fx.w.mu.Unlock()
		fx.setClk(fx.clk.Add(time.Hour))
		fx.batch()
		if fx.mailbox() != pmb {
			t.Fatalf("not completed at once: pending %+v", fx.pending())
		}
	})
	t.Run("cut call", func(t *testing.T) {
		fx := newRotFx(t)
		fx.w.rotate = []error{relayErr(503, "")}
		if err := fx.credRotate(); err != nil {
			t.Fatal(err)
		}
		pmb := fx.pendingMailbox()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		fx.w.onRotate = cancel // the call is cut after the rotate, before the registration's answer
		fx.w.mu.Lock()
		fx.w.register = []error{context.Canceled}
		fx.w.mu.Unlock()
		fx.setClk(fx.clk.Add(time.Hour))
		fx.do(func(m *Manager) { m.relayKeyStep(ctx, false) })
		fx.w.onRotate = nil
		if pr := fx.pending(); pr == nil || fx.pendingMailbox() != pmb || pr.Created.IsZero() {
			t.Fatalf("pending %+v: want the wait", pr)
		}
	})
}

// The registration after a rotate answers 201 (the successor made afresh)
// and the write that stores its time fails; the vault then crashes. The
// attempt stored before the call tells the next run that such an answer may
// have been lost: the unlock does not complete the key (a rotate within the
// grace would answer 200 and the registration 200), it waits
// freshMailboxWait from that run, and the attempt after the wait completes
// it.
func TestRelayRotCreatedAnswerLostAtACrashWaits(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	pmb := fx.pendingMailbox()
	fx.w.onRotate = func() {
		fx.w.mu.Lock()
		delete(fx.w.live, pmb) // the successor gone again: the registration makes it afresh (201)
		fx.w.mu.Unlock()
		fx.fs.setFail(1 << 20) // and every write after the rotate fails
	}
	fx.setClk(fx.clk.Add(time.Hour))
	fx.do(func(m *Manager) { m.relayKeyStep(context.Background(), false) }) // the sooner retry
	if pr := fx.pending(); pr == nil || pr.Created.IsZero() {
		t.Fatalf("no 201 kept in memory: %+v", pr)
	}
	fx.w.onRotate = nil
	fx.fs.setFail(0)
	rot0, _ := fx.w.log()
	fx.crash() // the 201's time was never stored
	if rot, _ := fx.w.log(); len(rot) != len(rot0) || fx.pendingMailbox() != pmb {
		t.Fatalf("the unlock attempted at once: rotates %v, pending %s", rot, fx.pendingMailbox())
	}
	pr := fx.pending()
	if pr == nil || pr.Unconfirmed.IsZero() {
		t.Fatalf("pending %+v: not marked", pr)
	}
	fx.setClk(pr.Unconfirmed.Add(freshMailboxWait - time.Second))
	fx.batch()
	if fx.pendingMailbox() != pmb {
		t.Fatal("completed inside the wait")
	}
	fx.setClk(pr.Unconfirmed.Add(freshMailboxWait))
	fx.batch()
	if fx.mailbox() != pmb {
		t.Fatal("not made current after the wait")
	}
}

// The attempt's own write before the call fails: no call is made (it fails
// closed), and nothing of the attempt stays in memory.
func TestRelayRotAttemptNotStoredMakesNoCall(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	for _, at := range []string{"state", "header"} {
		rot0, _ := fx.w.log()
		fx.fs.mu.Lock()
		if at == "state" {
			fx.fs.failState = 1
		} else {
			fx.fs.failHeader = 1 // the state put stored, the header put not
		}
		fx.fs.mu.Unlock()
		fx.setClk(fx.clk.Add(time.Hour))
		fx.batch()
		if rot, _ := fx.w.log(); len(rot) != len(rot0) {
			t.Fatalf("%s: a call without the attempt stored: rotates %v", at, rot)
		}
		if pr := fx.pending(); pr == nil || !pr.Attempt.IsZero() {
			t.Fatalf("%s: pending %+v", at, pr)
		}
	}
}

// An attempt stored by a run whose answer may have made the mailbox afresh,
// that answer's own write lost: whatever else holds of the pending key
// (the refused state, a retry_after run out, an older wait run out), the
// next run's unlock and sooner retries make no attempt before
// freshMailboxWait has run from that run, and one is made after it.
func TestRelayRotStoredAttemptWaitsWhateverTheGate(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(pr *PendingRelay, now time.Time)
	}{
		{"plain", func(*PendingRelay, time.Time) {}},
		{"refused", func(pr *PendingRelay, _ time.Time) { pr.Refused = "forbidden" }},
		{"retry_after run out", func(pr *PendingRelay, now time.Time) { pr.RetryAfter = now.Add(-time.Minute) }},
		// Running at the next run, out inside the mark's wait: the mark is
		// set all the same.
		{"retry_after running", func(pr *PendingRelay, now time.Time) { pr.RetryAfter = now.Add(7 * time.Minute) }},
		{"older wait run out", func(pr *PendingRelay, now time.Time) { pr.Created = now.Add(-time.Hour) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newRotFx(t)
			fx.w.rotate = []error{relayErr(503, "")}
			if err := fx.credRotate(); err != nil {
				t.Fatal(err)
			}
			fx.setClk(fx.clk.Add(time.Hour))
			fx.do(func(m *Manager) {
				pr := m.st.Relay.Pending
				tc.set(pr, m.now())
				pr.Attempt = m.now().UTC()
				m.dirty = true
				if err := m.persist(context.Background(), false); err != nil {
					t.Fatal(err)
				}
			})
			calls := func() int { rot, regs := fx.w.log(); return len(rot) + len(regs) }
			c0 := calls()
			fx.setClk(fx.clk.Add(5 * time.Minute)) // the next run comes later than the attempt
			start := fx.clk
			fx.crash() // the unlock finds the attempt
			pr := fx.pending()
			if calls() != c0 || pr == nil || pr.Unconfirmed.Before(start) || !pr.Attempt.IsZero() {
				t.Fatalf("an attempt at once, or not marked: calls %d→%d, pending %+v", c0, calls(), pr)
			}
			// The mark was stored by its own write: a crash now keeps it, and
			// the run after does not mark again at its own time.
			mark := pr.Unconfirmed
			fx.setClk(fx.clk.Add(time.Minute))
			fx.crash()
			if pr = fx.pending(); pr == nil || !pr.Unconfirmed.Equal(mark) || calls() != c0 {
				t.Fatalf("the mark not stored by its own write: pending %+v (mark %v)", pr, mark)
			}
			fx.setClk(pr.Unconfirmed.Add(freshMailboxWait - time.Second))
			fx.batch()
			fx.restart()
			if calls() != c0 {
				t.Fatalf("an attempt inside the wait: calls %d→%d", c0, calls())
			}
			fx.setClk(pr.Unconfirmed.Add(freshMailboxWait))
			fx.restart()
			if calls() == c0 {
				t.Fatal("no attempt after the wait")
			}
		})
	}
}
