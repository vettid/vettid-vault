package vault

import (
	"testing"
	"time"
)

// A rotate that succeeds and a registration after it answered 201 (the
// relay created the mailbox afresh after all): every held token is minted
// again with iat at that time, never backdated (RELAY-PROTOCOL §6.10).
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
	if fx.mailbox() != pmb {
		t.Fatalf("mailbox %s, want %s", fx.mailbox(), pmb)
	}
	fx.do(func(m *Manager) {
		tok := m.st.Relay.Recipients["c1"].Standing
		c, err := parseOwnToken(m, tok)
		if tok == held || err != nil || !c.Iat.Equal(fx.clk.Truncate(time.Second)) {
			t.Fatalf("held token re-minted %v, iat %v (now %v) %v", tok != held, c.Iat, fx.clk, err)
		}
	})
}
