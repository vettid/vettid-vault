package vault

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

// recoveryWaits: only for the recovery that marked the key, while that
// recovery's invite is pending and unexpired and the current mailbox
// lives; another recovery's invite does not hold the key.
func TestRelayRotRecoveryWaitsScope(t *testing.T) {
	fx := newRotFx(t)
	fx.do(func(m *Manager) {
		now := m.now()
		pr := &PendingRelay{Recovery: "r1"}
		inv := func(id string, exp time.Time) *Invite {
			return &Invite{ID: id, Kind: KindApp, Exp: exp, CreatedBy: inviteByRecovery}
		}
		m.st.Invites["r2"] = inv("r2", now.Add(time.Hour))
		if m.recoveryWaits(pr) {
			t.Fatal("waits for another recovery's invite")
		}
		m.st.Invites["r1"] = inv("r1", now.Add(time.Hour))
		if !m.recoveryWaits(pr) {
			t.Fatal("does not wait for its own recovery's invite")
		}
		m.st.Invites["r1"].Exp = now
		if m.recoveryWaits(pr) {
			t.Fatal("waits past the invite's expiry")
		}
		m.st.Invites["r1"].Exp = now.Add(time.Hour)
		m.st.Relay.Collect.Stopped = now
		if m.recoveryWaits(pr) {
			t.Fatal("waits with the current mailbox gone")
		}
		m.st.Relay.Collect.Stopped = time.Time{}
		if m.recoveryWaits(&PendingRelay{}) {
			t.Fatal("an unmarked key waits")
		}
	})
}

// setRecoveredInvite moves the wait's mark to a later recovery's invite
// only for the same phone (its identity key).
func TestRelayRotRecoveredInviteMovesTheMarkForTheSamePhoneOnly(t *testing.T) {
	a := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, 32)).Public().(ed25519.PublicKey)
	b := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, 32)).Public().(ed25519.PublicKey)
	for _, c := range []struct {
		name string
		ik   ed25519.PublicKey
		want string
	}{{"same phone", a, "r2"}, {"another phone", b, "r1"}} {
		fx := newRotFx(t)
		fx.do(func(m *Manager) {
			now := m.now()
			m.st.Relay.Pending = &PendingRelay{Recovery: "r1"}
			m.st.Invites["r1"] = &Invite{ID: "r1", Kind: KindApp, Exp: now.Add(time.Hour), EnrollIK: a, CreatedBy: inviteByRecovery}
			m.setRecoveredInvite(&Invite{ID: "r2", Kind: KindApp, Exp: now.Add(time.Hour), EnrollIK: c.ik, CreatedBy: inviteByRecovery}, now)
			if got := m.st.Relay.Pending.Recovery; got != c.want {
				t.Fatalf("%s: mark %q, want %q", c.name, got, c.want)
			}
			m.st.Relay.Pending = nil
		})
	}
}

// A ceiling stays while ids given are still unprocessed, however old,
// even with nothing held.
func TestRelayRotCeilingStaysWhileUnprocessed(t *testing.T) {
	t0 := time.Now()
	bound := 3 * time.Minute
	r := &MailboxCollect{}
	r.given("03", t0)
	r.Ceiling, r.CeilingAt = "09", t0
	r.pruneUnhanded(map[string]bool{"03": true}, nil, t0.Add(time.Hour), bound)
	if r.Ceiling != "09" || len(r.Unprocessed) != 1 {
		t.Fatalf("ceiling %q, unprocessed %v", r.Ceiling, r.Unprocessed)
	}
}
