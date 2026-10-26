package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/vettid/vettid-vault/vault/store"
)

// VAULT-MESSAGING 0.63.2 (§11.14.2, §11.14.6 "A lost ok"): an unlock
// that completes step 3 of a recovery's replacement ends the recovery
// record, whichever is current, in the same header write as step 3, as
// the repeated open's step 3 does. A later open of that recovery is then
// refused no_recovery and uses no attempt.

// addStoredUnlockKey adds an unlock key for ik to the stored header (an
// app other than the recovered phone).
func (f *openFixture) addStoredUnlockKey(ik ed25519.PublicKey) {
	f.t.Helper()
	ctx := context.Background()
	key := store.HeaderKey(f.vid, testRelease.PCR0)
	_, ver, err := f.st.Get(ctx, key)
	if err != nil {
		f.t.Fatal(err)
	}
	h := f.storedHeader()
	h.UnlockKeys = append(h.UnlockKeys, UnlockKey{DeviceID: "other-app", IK: ik, KEM: bytes.Repeat([]byte{0x71}, 32), Attestation: attBinding("other-app-key")})
	b, err := sealHeader(ctx, f.opts.Sealer, h)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.st.Put(ctx, key, b, ver); err != nil {
		f.t.Fatal(err)
	}
}

// pairRecoveredPhone completes the recovered phone's first handshake as
// handshakes.go does for a recovering peer.
func pairRecoveredPhone(t *testing.T, m *Manager, phone ed25519.PrivateKey) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	ik := phone.Public().(ed25519.PublicKey)
	inv := m.recoveredInvite(ik)
	if inv == nil {
		t.Fatal("no recovered invite to pair with")
	}
	p := &Peer{ID: "recovered-phone", Kind: KindApp, State: PeerActive, IK: ik, KEM: inv.EnrollKEM, Attestation: inv.EnrollAttest,
		Relay: PeerRelay{PK: inv.EnrollRelayPK}, Recovering: true}
	m.st.Devices[p.ID] = p
	m.recoveredPhonePaired(p, m.now())
	m.dirty = true
	if m.recoveredInvite(ik) != nil {
		t.Fatal("the pairing kept the recovered invite")
	}
}

func TestLostOKUnlockEndsTheRecovery(t *testing.T) {
	f := newOpenFixture(t)
	a1 := attBinding("attested-key-one")
	phone := f.phone
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x70}, 32))
	f.reRegister(rebindR1, phone, a1)
	f.stopAfterStep2(rebindR1, phone, a1)
	f.opts.Features = append(f.opts.Features, &gateFeature{ready: true})
	used := f.used()
	// While the recovery is registered another app is refused.
	f.addStoredUnlockKey(other.Public().(ed25519.PublicKey))
	if m, out := f.unlockAs(other, attBinding("other-app-key")); m != nil || out.Code != CodeRecoveryPending {
		t.Fatalf("another app during the recovery: %+v", out)
	}
	// The lost-ok unlock completes step 3 and ends the recovery.
	m, uo := f.unlockAs(phone, a1)
	if m == nil || !uo.OK || len(uo.VaultBundle) == 0 {
		t.Fatalf("lost-ok unlock: %+v", uo)
	}
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h := f.storedHeader(); h.Next != nil || h.Recovery != nil {
		t.Fatalf("after the unlock: next %v, recovery %+v", h.Next != nil, h.Recovery)
	}
	// A later open of that recovery: no_recovery, no attempt.
	if m, out := f.openAttested(rebindR1, phone, a1); m != nil || out.Code != OpenNoRecovery || !out.Drop || out.AttemptUsed() {
		t.Fatalf("open after the completion: %+v", out)
	}
	if f.used() != used {
		t.Fatalf("attempts used %d, before %d", f.used(), used)
	}
	// Before its pairing the phone's unlock still carries the bundle (a
	// lost ok), through its invite, which it renews.
	m, uo = f.unlockAs(phone, a1)
	if m == nil || !uo.OK || len(uo.VaultBundle) == 0 || uo.CredentialBackup != nil {
		t.Fatalf("lost-ok unlock before the pairing: %+v", uo)
	}
	pairRecoveredPhone(t, m, phone)
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	// After the pairing no unlock result carries the bundle.
	m, uo = f.unlockAs(phone, a1)
	if m == nil || !uo.OK || len(uo.VaultBundle) != 0 || uo.CredentialBackup != nil {
		t.Fatalf("unlock after the pairing: %+v", uo)
	}
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Another app is no longer refused recovery_pending.
	f.addStoredUnlockKey(other.Public().(ed25519.PublicKey))
	if m, out := f.unlockAs(other, attBinding("other-app-key")); out.Code == CodeRecoveryPending {
		t.Fatalf("another app after the completion: %+v", out)
	} else if m != nil {
		m.Crash()
	}
}

// The crash points of the unlock that completes step 3: a failed state
// write or a failed header write after the state write stores no end of
// the recovery; the record and the `next` part stay, and a repeated open
// completes through the `next` wrap without an attempt.
func TestLostOKUnlockCrashPointsKeepTheRecovery(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fault func(*faultStore)
	}{
		{"state write fails", func(s *faultStore) { s.failState = 1 }},
		{"header write fails after the state write", func(s *faultStore) { s.failHeader = 1 }},
		{"header write lost after the state write", func(s *faultStore) { s.loseHeader = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOpenFixture(t)
			a1 := attBinding("attested-key-one")
			phone := f.phone
			f.reRegister(rebindR1, phone, a1)
			f.stopAfterStep2(rebindR1, phone, a1)
			f.opts.Features = append(f.opts.Features, &gateFeature{ready: true})
			used := f.used()
			tc.fault(f.st)
			m, uo := f.unlockAs(phone, a1)
			if m != nil {
				// A lost header write is answered ok (the store said
				// "written"); the vault runs on and stores nothing more.
				m.Crash()
			} else if uo.OK {
				t.Fatalf("unlock: %+v", uo)
			}
			h := f.storedHeader()
			if h.Next == nil || h.Recovery == nil || h.Recovery.ID != rebindR1 {
				t.Fatalf("stored header: next %v, recovery %+v", h.Next != nil, h.Recovery)
			}
			m, out := f.openAttested(rebindR1, phone, a1)
			if m == nil || !out.OK || out.AttemptUsed() || f.used() != used {
				t.Fatalf("repeated open: %+v (used %d, before %d)", out, f.used(), used)
			}
			if err := m.Lock(context.Background()); err != nil {
				t.Fatal(err)
			}
			if h := f.storedHeader(); h.Next != nil || h.Recovery != nil {
				t.Fatal("the repeated open did not complete")
			}
		})
	}
}

// The unlock ends whichever recovery record is current: the phone's
// earlier attested key completes the replacement that recovery R1's open
// stored, while R2 (the same identity registered again) is the current
// record.
func TestLostOKUnlockEndsTheCurrentRecovery(t *testing.T) {
	f := newOpenFixture(t)
	a1, a2 := attBinding("attested-key-one"), attBinding("attested-key-two")
	phone := f.phone
	f.reRegister(rebindR1, phone, a1)
	f.stopAfterStep2(rebindR1, phone, a1)
	f.reRegister(rebindR2, phone, a2)
	if h := f.storedHeader(); h.Recovery == nil || h.Recovery.ID != rebindR2 || h.Next == nil {
		t.Fatal("not R2 over R1's stored step 2")
	}
	f.opts.Features = append(f.opts.Features, &gateFeature{ready: true})
	used := f.used()
	ik := phone.Public().(ed25519.PublicKey)
	// The completing unlock is the recovered phone's lost ok: the bundle,
	// a token, no credential_backup, and its invitation (R1's, ctx = R1)
	// renewed.
	m, uo := f.unlockAs(phone, a1)
	if m == nil || !uo.OK || len(uo.VaultBundle) == 0 || uo.Token == "" || uo.CredentialBackup != nil {
		t.Fatalf("unlock: %+v", uo)
	}
	m.mu.Lock()
	inv := m.recoveredInvite(ik)
	if inv == nil || inv.ID != rebindR1 || inv.Used || !inv.Exp.Equal(f.clock.Add(RecoveredInviteWindow)) || !sameAttestedKey(inv.EnrollAttest, a1) {
		m.mu.Unlock()
		t.Fatalf("invite after the completing unlock: %+v", inv)
	}
	m.mu.Unlock()
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h := f.storedHeader(); h.Next != nil || h.Recovery != nil {
		t.Fatalf("R2 not ended: %+v", h.Recovery)
	}
	if m, out := f.openAttested(rebindR2, phone, a2); m != nil || out.Code != OpenNoRecovery || out.AttemptUsed() || f.used() != used {
		t.Fatalf("open of R2 after the completion: %+v", out)
	}
	// The phone pairs with ctx = R1 (the invitation stays R1's), and the
	// stored binding is the key whose unlock answered the ok, A1.
	m, uo = f.unlockAs(phone, a1)
	if m == nil || !uo.OK || len(uo.VaultBundle) == 0 || uo.Token == "" {
		t.Fatalf("lost-ok unlock before the pairing: %+v", uo)
	}
	m.mu.Lock()
	inv = m.recoveredInvite(ik)
	m.mu.Unlock()
	if inv == nil || inv.ID != rebindR1 {
		t.Fatalf("pairing ctx: %+v", inv)
	}
	pairRecoveredPhone(t, m, phone)
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if k := findUnlockKey(f.storedHeader(), ik); k == nil || !sameAttestedKey(k.Attestation, a1) {
		t.Fatal("the binding after the pairing is not A1")
	}
	m, uo = f.unlockAs(phone, a1)
	if m == nil || !uo.OK || len(uo.VaultBundle) != 0 {
		t.Fatalf("unlock after the pairing: %+v", uo)
	}
	m.Crash()
}

// An earlier identity (E) whose open stored step 2 cannot complete step 3
// by an unlock while another identity's (N's) recovery is registered: it
// is refused recovery_pending before the PIN (§11.11.4), and nothing
// changes. N's repeated open completes it without an attempt; after that
// E's unlock succeeds.
func TestEarlierIdentityUnlockWhileAnotherRecoveryIsRegistered(t *testing.T) {
	f := newOpenFixture(t)
	a1, a2 := attBinding("earlier-identity-key"), attBinding("new-identity-key")
	earlier := f.phone
	f.reRegister(rebindR1, earlier, a1)
	f.stopAfterStep2(rebindR1, earlier, a1)
	newer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x63}, 32))
	f.reRegister(rebindR2, newer, a2)
	f.opts.Features = append(f.opts.Features, &gateFeature{ready: true})
	used := f.used()
	if m, out := f.unlockAs(earlier, a1); m != nil || out.Code != CodeRecoveryPending {
		t.Fatalf("E's unlock while N's recovery is registered: %+v", out)
	}
	if h := f.storedHeader(); h.Next == nil || h.Recovery == nil || h.Recovery.ID != rebindR2 {
		t.Fatal("the refused unlock changed the header")
	}
	m, out := f.openAttested(rebindR2, newer, a2)
	if m == nil || !out.OK || out.AttemptUsed() || f.used() != used {
		t.Fatalf("N's repeated open: %+v", out)
	}
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	m, uo := f.unlockAs(earlier, a1)
	if m == nil || !uo.OK || len(uo.VaultBundle) == 0 {
		t.Fatalf("E's unlock after the completion: %+v", uo)
	}
	m.Crash()
}

// The recovered phone whose unlock finishes step 3 while its record is
// still registered is answered as its lost ok even when the vault shows
// no credential with a backup copy (here a gate that is not ready): its
// recovery completed at the open, so the registered phone's no_backup
// refusal (§11.11.5 step 1), which would cancel the recovery, is not
// applied. It gets the bundle and the record ends.
func TestLostOKUnlockIsNotRefusedNoBackup(t *testing.T) {
	f := newOpenFixture(t)
	a1 := attBinding("attested-key-one")
	phone := f.phone
	f.reRegister(rebindR1, phone, a1)
	f.stopAfterStep2(rebindR1, phone, a1)
	f.opts.Features = append(f.opts.Features, &gateFeature{ready: false})
	m, uo := f.unlockAs(phone, a1)
	if m == nil || !uo.OK || uo.Code == CodeNoBackup || len(uo.VaultBundle) == 0 || uo.Token == "" || uo.CredentialBackup != nil {
		t.Fatalf("lost-ok unlock without a ready credential: %+v", uo)
	}
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h := f.storedHeader(); h.Next != nil || h.Recovery != nil {
		t.Fatalf("after the unlock: next %v, recovery %+v", h.Next != nil, h.Recovery)
	}
}
