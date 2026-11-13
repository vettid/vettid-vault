package vault

import (
	"testing"
	"time"
)

// A rotate that succeeds and a registration after it answered 201 (the
// relay created the mailbox afresh after all): every held token is minted
// again, never backdated, once freshMailboxWait has run after that answer
// (RELAY-PROTOCOL §6.10).
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
		if tok == held || err != nil || !c.Iat.Equal(fx.clk.Truncate(time.Second)) || c.Iat.Before(answered.Add(90*time.Second)) {
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
	fx.w.mu.Lock()
	delete(fx.w.live, fx.mailbox()) // past the grace
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
