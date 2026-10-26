package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// A phone that could not tell (VAULT-MESSAGING §11.14.6): the same identity
// (ik) registered again for a later recovery, with a new attested key,
// after the earlier recovery's open stored step 2 and not step 3. The
// repeat through the `next` wrap sets the recovered invite again from the
// current registration (ctx = the current recovery_id, the new binding),
// renews it, and the header binds the new attested key; a different
// identity's invite is kept and renewed.

const (
	rebindR1 = "01JB2Z6V9K3M4N5P6Q7R8S9TA1"
	rebindR2 = "01JB2Z6V9K3M4N5P6Q7R8S9TA2"
)

// attBinding is an Android binding for the attested key pk.
func attBinding(pk string) json.RawMessage {
	return json.RawMessage(`{"platform":"android","pk":"` + base64.StdEncoding.EncodeToString([]byte(pk)) + `","counter":0}`)
}

// attFor answers a device check for the phone whose attested key is now
// cur: the binding must be for that key (as an assertion verifies only
// against its own key).
func attFor(cur json.RawMessage) func(json.RawMessage) (json.RawMessage, error) {
	return func(b json.RawMessage) (json.RawMessage, error) {
		if !sameAttestedKey(b, cur) {
			return nil, ErrDeviceAttestation
		}
		return b, nil
	}
}

// reRegister requests recovery id and registers phone (an identity) with
// binding att and the fixture's K.
func (f *openFixture) reRegister(id string, phone ed25519.PrivateKey, att json.RawMessage) {
	f.t.Helper()
	ctx := context.Background()
	p := HeaderParams{Options: f.opts, VaultID: f.vid, UserGUID: "u1"}
	code, rec, _, err := RecoveryRequest(ctx, p, id, RecoveryDelay)
	if err != nil {
		f.t.Fatal(err)
	}
	if d := rec.NotBefore.Sub(f.clock) + time.Hour; d > 0 {
		f.clock = f.clock.Add(d)
		f.bucket.Advance(d)
	}
	app := RecoveryApp{IK: phone.Public().(ed25519.PublicKey), KEM: bytes.Repeat([]byte{phone[0]}, 32), RelayPK: bytes.Repeat([]byte{phone[0] + 1}, 32),
		APIKey: []byte("phone-app-key")}
	if err := RecoveryRegister(ctx, p, id, code, app, func() (json.RawMessage, error) { return att, nil }); err != nil {
		f.t.Fatal(err)
	}
}

func (f *openFixture) openAttested(id string, phone ed25519.PrivateKey, cur json.RawMessage) (*Manager, *RecoveryOpenOutcome) {
	check := attFor(cur)
	return RecoveryOpen(context.Background(), RecoveryOpenParams{Options: f.opts, VaultID: f.vid, UserGUID: "u1", RecoveryID: id,
		DeviceIK: phone.Public().(ed25519.PublicKey), PIN: testPIN, Password: []byte(rPW), UnlockSecret: f.phoneUS,
		VerifyDevice: func(a *RecoveryApp) (json.RawMessage, error) { return check(a.Attestation) },
		Manifest: func(uint64) (*ManifestView, error) {
			return &ManifestView{Serial: 1, Own: ReleaseEntry{PCR0: testRelease.PCR0, Number: testRelease.Number}}, nil
		}})
}

// unlockAs is the phone's alternate-channel unlock asserting with cur.
func (f *openFixture) unlockAs(phone ed25519.PrivateKey, cur json.RawMessage) (*Manager, *AltUnlockOutcome) {
	check := attFor(cur)
	own := ReleaseEntry{PCR0: testRelease.PCR0, Number: testRelease.Number, Status: "active"}
	return UnlockAlt(context.Background(), AltUnlockParams{Options: f.opts, VaultID: f.vid, UserGUID: "u1", DeviceIK: phone.Public().(ed25519.PublicKey),
		PIN: testPIN, UnlockSecret: f.phoneUS,
		VerifyDevice: func(k *UnlockKey) (json.RawMessage, error) { return check(k.Attestation) },
		Manifest: func(seen uint64) (*ManifestView, error) {
			return &ManifestView{Serial: seen + 1, Own: own, Lookup: func(string) (ReleaseEntry, bool) { return own, true }}, nil
		},
		OwnKeyCheck: func(context.Context, ReleaseEntry) (*SealKeyRecord, error) {
			return &SealKeyRecord{VerifiedBy: testRelease.PCR0}, nil
		}})
}

// stopAfterStep2 runs a right open of recovery id whose step-3 header
// write fails: steps 1 and 2 are stored, the answer is retry.
func (f *openFixture) stopAfterStep2(id string, phone ed25519.PrivateKey, cur json.RawMessage) {
	f.t.Helper()
	f.st.passHeader, f.st.failHeader = 1, 1
	m, out := f.openAttested(id, phone, cur)
	if m != nil || out.Code != OpenRetry || !out.Counted {
		f.t.Fatalf("open stopped after step 2: %+v", out)
	}
	if h := f.storedHeader(); h.Next == nil || f.storedStateVersion() != h.Next.DEKVersion {
		f.t.Fatal("not a completion stopped after step 2")
	}
}

func recoveryInvites(m *Manager) []*Invite {
	var out []*Invite
	for _, inv := range m.st.Invites {
		if inv.CreatedBy == inviteByRecovery {
			out = append(out, inv)
		}
	}
	return out
}

func TestRecoveryRepeatRebindsTheSameIdentity(t *testing.T) {
	t.Run("step 2 stored", func(t *testing.T) { testRebind(t, true) })
	// The branch whose step 2 was not stored already set the invite from
	// the current registration; the same identity with a new key had no
	// test there either.
	t.Run("step 1 only", func(t *testing.T) { testRebind(t, false) })
}

func testRebind(t *testing.T, step2 bool) {
	f := newOpenFixture(t)
	a1, a2 := attBinding("attested-key-one"), attBinding("attested-key-two")
	phone := f.phone
	ik := phone.Public().(ed25519.PublicKey)
	f.reRegister(rebindR1, phone, a1)
	if step2 {
		f.stopAfterStep2(rebindR1, phone, a1)
	} else {
		f.st.failState = 1
		if m, out := f.openAttested(rebindR1, phone, a1); m != nil || out.Code != OpenRetry || !out.Counted {
			t.Fatalf("open stopped after step 1: %+v", out)
		}
		if h := f.storedHeader(); h.Next == nil || f.storedStateVersion() == h.Next.DEKVersion {
			t.Fatal("not a completion stopped after step 1")
		}
	}
	// R1 ends (a new request replaces it); the same identity registers R2
	// with a new attested key, two days on (the R1 invite has expired).
	f.clock = f.clock.Add(24 * time.Hour)
	f.bucket.Advance(24 * time.Hour)
	f.reRegister(rebindR2, phone, a2)
	// The earlier attested key fails the current registration's check.
	if m, out := f.openAttested(rebindR2, phone, a1); m != nil || out.Code != CodeAttestation {
		t.Fatalf("open asserting with the earlier key: %+v", out)
	}
	m, out := f.openAttested(rebindR2, phone, a2)
	if m == nil || !out.OK || out.Counted {
		t.Fatalf("repeat: %+v", out)
	}
	invs := recoveryInvites(m)
	if len(invs) != 1 || m.st.Invites[rebindR1] != nil {
		t.Fatalf("recovered invites: %d, R1's kept: %v", len(invs), m.st.Invites[rebindR1] != nil)
	}
	inv := m.st.Invites[rebindR2]
	if inv == nil || !bytes.Equal(inv.EnrollIK, ik) || !sameAttestedKey(inv.EnrollAttest, a2) || inv.Used ||
		!inv.Exp.Equal(f.clock.Add(RecoveredInviteWindow)) || !bytes.Equal(inv.EnrollKEM, bytes.Repeat([]byte{phone[0]}, 32)) {
		t.Fatalf("invite: %+v", inv)
	}
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := f.storedHeader()
	if h.Next != nil || h.Recovery != nil {
		t.Fatal("not completed")
	}
	if k := findUnlockKey(h, ik); k == nil || !sameAttestedKey(k.Attestation, a2) {
		t.Fatalf("the header binds %s", k.Attestation)
	}
	// The phone's lost-ok unlock with its current key gets the bundle; the
	// earlier key is refused.
	if m, out := f.unlockAs(phone, a1); m != nil || out.OK || out.Code != CodeAttestation {
		t.Fatalf("unlock with the earlier key: %+v", out)
	}
	m, uo := f.unlockAs(phone, a2)
	if m == nil || !uo.OK || len(uo.VaultBundle) == 0 {
		t.Fatalf("unlock with the current key: %+v", uo)
	}
	if inv := m.st.Invites[rebindR2]; inv == nil || m.st.Invites[rebindR1] != nil {
		t.Fatal("the unlock changed the invite")
	}
	m.Crash()
}

// The phone registered a new identity for R2 after its earlier identity's
// run of R1 stored step 2: the repeat keeps the earlier identity's
// invitation (§11.14.6 "the repeat keeps that invitation") and renews it.
func TestRecoveryRepeatKeepsTheEarlierIdentity(t *testing.T) {
	f := newOpenFixture(t)
	a1, a2 := attBinding("earlier-identity-key"), attBinding("new-identity-key")
	earlier := f.phone
	f.reRegister(rebindR1, earlier, a1)
	f.stopAfterStep2(rebindR1, earlier, a1)
	f.clock = f.clock.Add(24 * time.Hour)
	f.bucket.Advance(24 * time.Hour)
	newer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x63}, 32))
	f.reRegister(rebindR2, newer, a2)
	m, out := f.openAttested(rebindR2, newer, a2)
	if m == nil || !out.OK || out.Counted {
		t.Fatalf("repeat: %+v", out)
	}
	invs := recoveryInvites(m)
	inv := m.st.Invites[rebindR1]
	if len(invs) != 1 || inv == nil || !bytes.Equal(inv.EnrollIK, earlier.Public().(ed25519.PublicKey)) ||
		!sameAttestedKey(inv.EnrollAttest, a1) || inv.Used || !inv.Exp.Equal(f.clock.Add(RecoveredInviteWindow)) {
		t.Fatalf("invites %d, R1 %+v", len(invs), inv)
	}
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := f.storedHeader()
	if k := findUnlockKey(h, earlier.Public().(ed25519.PublicKey)); k == nil || !sameAttestedKey(k.Attestation, a1) {
		t.Fatal("the earlier identity is not the unlock key")
	}
	if findUnlockKey(h, newer.Public().(ed25519.PublicKey)) != nil {
		t.Fatal("the new identity is an unlock key")
	}
	m, uo := f.unlockAs(earlier, a1)
	if m == nil || !uo.OK || len(uo.VaultBundle) == 0 {
		t.Fatalf("the earlier identity's unlock: %+v", uo)
	}
	m.Crash()
}

// A repeat of the same recovery whose step 2 is stored renews the invite
// and restarts its pairing (a first handshake begun is dropped).
func TestRecoveryRepeatRenewsTheInvite(t *testing.T) {
	f := newOpenFixture(t)
	a1 := attBinding("attested-key-one")
	f.reRegister(rebindR1, f.phone, a1)
	f.stopAfterStep2(rebindR1, f.phone, a1)
	f.clock = f.clock.Add(2 * time.Hour) // the invite is renewed from this repeat
	m, out := f.openAttested(rebindR1, f.phone, a1)
	if m == nil || !out.OK || out.Counted {
		t.Fatalf("repeat: %+v", out)
	}
	defer m.Crash()
	inv := m.st.Invites[rebindR1]
	if inv == nil || inv.Used || !inv.Exp.Equal(f.clock.Add(RecoveredInviteWindow)) || len(recoveryInvites(m)) != 1 {
		t.Fatalf("invite: %+v", inv)
	}
	// The renewal itself: a handshake begun with the invite is dropped.
	m.mu.Lock()
	defer m.mu.Unlock()
	inv.Used = true
	m.st.Awaiting = map[string]*AwaitingHS{"aw1": {ID: "aw1", InviteID: rebindR1}}
	later := f.clock.Add(time.Hour)
	m.resumeRecoveredInvite(m.hdr.Recovery, f.phone.Public().(ed25519.PublicKey), later)
	if inv.Used || !inv.Exp.Equal(later.Add(RecoveredInviteWindow)) || len(m.st.Awaiting) != 0 {
		t.Fatalf("renewal: used %v exp %v awaiting %d", inv.Used, inv.Exp, len(m.st.Awaiting))
	}
	// A phone that has paired has no recovered invite: nothing is made.
	delete(m.st.Invites, rebindR1)
	m.resumeRecoveredInvite(m.hdr.Recovery, f.phone.Public().(ed25519.PublicKey), later)
	if len(recoveryInvites(m)) != 0 {
		t.Fatal("a repeat after the pairing made an invite")
	}
}

// The header keeps a recovered phone's binding only for the attested key
// its invite names: the same key keeps its advanced counter, another key
// (the same ik registered again) takes the invite's binding.
func TestSyncUnlockKeysRecoveredBindingSameKey(t *testing.T) {
	f := newOpenFixture(t)
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("open: %+v", out)
	}
	defer m.Crash()
	m.mu.Lock()
	defer m.mu.Unlock()
	ik := f.phone.Public().(ed25519.PublicKey)
	inv := m.recoveredInvite(ik)
	if inv == nil {
		t.Fatal("no recovered invite")
	}
	ios := func(pk, kid string, ctr int) json.RawMessage {
		e := base64.StdEncoding.EncodeToString
		return json.RawMessage(`{"platform":"ios","pk":"` + e([]byte(pk)) + `","key_id":"` + e([]byte(kid)) + `","counter":` + string(rune('0'+ctr)) + `}`)
	}
	set := func(b json.RawMessage) {
		for i := range m.hdr.UnlockKeys {
			if bytes.Equal(m.hdr.UnlockKeys[i].IK, ik) {
				m.hdr.UnlockKeys[i].Attestation = b
			}
		}
	}
	got := func() json.RawMessage { return findUnlockKey(m.hdr, ik).Attestation }
	inv.EnrollAttest = ios("key-one", "kid-one", 0)
	m.syncUnlockKeys()
	// Same key, advanced counter: the header's binding is kept.
	set(ios("key-one", "kid-one", 5))
	m.syncUnlockKeys()
	if !bytes.Equal(got(), ios("key-one", "kid-one", 5)) {
		t.Fatalf("same key: %s", got())
	}
	// A new attested key for the same ik: the invite's binding.
	inv.EnrollAttest = ios("key-two", "kid-two", 0)
	m.syncUnlockKeys()
	if !bytes.Equal(got(), inv.EnrollAttest) {
		t.Fatalf("new key: %s", got())
	}
	// The same public key under another key id, another platform, or a
	// binding that cannot be read: the invite's.
	for _, b := range []json.RawMessage{ios("key-two", "kid-other", 7), attBinding("key-two"), json.RawMessage(`{`), json.RawMessage(`{}`)} {
		set(b)
		m.syncUnlockKeys()
		if !bytes.Equal(got(), inv.EnrollAttest) {
			t.Fatalf("%s kept: %s", b, got())
		}
	}
	if sameAttestedKey(json.RawMessage(`{}`), json.RawMessage(`{}`)) || sameAttestedKey(nil, nil) {
		t.Fatal("a binding without a key matched")
	}
}

// The accepted gap (crash point b): the repeat for R2 stores its state
// (the invite rebound to R2 and A2) and its step-3 header write fails.
// The header's `next` part still names the phone with A1, so its A2
// unlock is refused until it opens R2 again; that repeat is idempotent.
func TestRecoveryRepeatStep3LostKeepsTheGap(t *testing.T) {
	f := newOpenFixture(t)
	a1, a2 := attBinding("attested-key-one"), attBinding("attested-key-two")
	phone := f.phone
	ik := phone.Public().(ed25519.PublicKey)
	f.reRegister(rebindR1, phone, a1)
	f.stopAfterStep2(rebindR1, phone, a1)
	f.reRegister(rebindR2, phone, a2)
	f.st.failHeader = 1
	if m, out := f.openAttested(rebindR2, phone, a2); m != nil || out.Code != OpenRetry || out.Counted {
		t.Fatalf("repeat whose step 3 fails: %+v", out)
	}
	if h := f.storedHeader(); h.Next == nil || h.Recovery == nil || h.Recovery.ID != rebindR2 || !sameAttestedKey(h.Next.App.Attestation, a1) {
		t.Fatal("not the gap: the header should still hold R2 and the next part with A1")
	}
	if m, out := f.unlockAs(phone, a2); m != nil || out.OK || out.Code != CodeAttestation {
		t.Fatalf("A2 unlock in the gap: %+v", out)
	}
	m, out := f.openAttested(rebindR2, phone, a2)
	if m == nil || !out.OK || out.Counted {
		t.Fatalf("the repeat again: %+v", out)
	}
	if inv := m.st.Invites[rebindR2]; inv == nil || !sameAttestedKey(inv.EnrollAttest, a2) || len(recoveryInvites(m)) != 1 {
		t.Fatalf("invite after the repeat: %+v", inv)
	}
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if k := findUnlockKey(f.storedHeader(), ik); k == nil || !sameAttestedKey(k.Attestation, a2) {
		t.Fatal("the header does not bind A2")
	}
	m, uo := f.unlockAs(phone, a2)
	if m == nil || !uo.OK || len(uo.VaultBundle) == 0 {
		t.Fatalf("A2 unlock after the repeat: %+v", uo)
	}
	m.Crash()
}

// In the same gap the phone unlocks with its earlier key A1, which the
// header's `next` part still names (it was proved for R1). That unlock
// completes the replacement, and the header it writes binds the invite's
// A2: the earlier key opens the vault no more.
func TestRecoveryRepeatGapA1UnlockEndsWithA2(t *testing.T) {
	f := newOpenFixture(t)
	a1, a2 := attBinding("attested-key-one"), attBinding("attested-key-two")
	phone := f.phone
	ik := phone.Public().(ed25519.PublicKey)
	f.reRegister(rebindR1, phone, a1)
	f.stopAfterStep2(rebindR1, phone, a1)
	f.reRegister(rebindR2, phone, a2)
	f.st.failHeader = 1
	if m, out := f.openAttested(rebindR2, phone, a2); m != nil || out.Code != OpenRetry || out.Counted {
		t.Fatalf("repeat whose step 3 fails: %+v", out)
	}
	// The vault has a credential with its backup copy (else the unlock
	// of the registered phone cancels the recovery, no_backup).
	f.opts.Features = append(f.opts.Features, &gateFeature{ready: true})
	m, uo := f.unlockAs(phone, a1)
	if m == nil || !uo.OK {
		t.Fatalf("A1 unlock in the gap: %+v", uo)
	}
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := f.storedHeader()
	if k := findUnlockKey(h, ik); k == nil || !sameAttestedKey(k.Attestation, a2) {
		var got json.RawMessage
		if k != nil {
			got = k.Attestation
		}
		t.Fatalf("after the A1 unlock the header binds %s (next %v)", got, h.Next != nil)
	}
	if m, out := f.unlockAs(phone, a1); m != nil || out.OK {
		t.Fatalf("A1 unlock after the header binds A2: %+v", out)
	}
	m, uo = f.unlockAs(phone, a2)
	if m == nil || !uo.OK {
		t.Fatalf("A2 unlock: %+v", uo)
	}
	m.Crash()
}
