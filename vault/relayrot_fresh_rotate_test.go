package vault

import (
	"context"
	"testing"
	"time"
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
		t.Fatalf("a second 201 did not start the wait again (created %v)", pr)
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
