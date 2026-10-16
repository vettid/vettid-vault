package vault

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

// A lost ok (owner decision of 2026-10-16, §11.14.6): the recovered phone's
// invite marks it until it pairs. It outlives its expiry (housekeeping
// keeps it, the header keeps the phone's unlock key), the phone's unlock
// renews it and restarts its pairing, only that phone has it, and a later
// recovery's phone replaces it.
func TestRecoveredInviteUntilPairing(t *testing.T) {
	f := newOpenFixture(t)
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("open: %+v", out)
	}
	phone := f.phone.Public().(ed25519.PublicKey)
	m.mu.Lock()
	inv := m.recoveredInvite(phone)
	if inv == nil {
		m.mu.Unlock()
		t.Fatal("no recovered invite")
	}
	if m.recoveredInvite(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)).Public().(ed25519.PublicKey)) != nil {
		m.mu.Unlock()
		t.Fatal("another device matches the recovered invite")
	}
	// Two days on, past its expiry: housekeeping keeps it, the header
	// keeps the phone's unlock key.
	later := f.clock.Add(48 * time.Hour)
	m.housekeeping(later)
	m.syncUnlockKeys()
	if m.recoveredInvite(phone) == nil || findUnlockKey(m.hdr, phone) == nil {
		m.mu.Unlock()
		t.Fatal("the recovered phone lost its invite or unlock key at the expiry")
	}
	// The phone's unlock: the bundle again, the invite usable again.
	inv.Used = true
	b := m.resumeLostOK(inv, later)
	if len(b) == 0 || inv.Used || !inv.Exp.Equal(later.Add(RecoveryValidity)) {
		m.mu.Unlock()
		t.Fatalf("resume: bundle %d used %v exp %v", len(b), inv.Used, inv.Exp)
	}
	// A later recovery's phone replaces it.
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x62}, 32)).Public().(ed25519.PublicKey)
	m.setRecoveredInvite(&Invite{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T99", Kind: KindApp, Exp: later.Add(RecoveryValidity), EnrollIK: other,
		EnrollKEM: inv.EnrollKEM, CreatedBy: inviteByRecovery}, later)
	if m.recoveredInvite(phone) != nil || m.recoveredInvite(other) == nil {
		m.mu.Unlock()
		t.Fatal("a later recovery did not replace the earlier phone")
	}
	m.syncUnlockKeys()
	if findUnlockKey(m.hdr, phone) != nil {
		m.mu.Unlock()
		t.Fatal("the replaced phone keeps an unlock key")
	}
	m.mu.Unlock()
	m.Crash()
}
