package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"
)

// The recovered phone's wait (recoveryWaits, a reading of this release):
// only the recovery's own relay key waits for the phone's first handshake,
// and only while the current mailbox lives; an inherited key never waits
// (§3.4 "A recovery's inherited key", "Retrying with the same key":
// mailbox_unknown while a key is pending starts the same path).

// phoneUnlockOut is the recovered phone's own unlock (a lost ok before its
// first handshake carries the vault's bundle again, resumeLostOK).
func (f *openFixture) phoneUnlockOut() (*Manager, *AltUnlockOutcome) {
	own := ReleaseEntry{PCR0: testRelease.PCR0, Number: testRelease.Number, Status: "active"}
	return UnlockAlt(context.Background(), AltUnlockParams{Options: f.opts, VaultID: f.vid, UserGUID: "u1",
		DeviceIK: f.phone.Public().(ed25519.PublicKey), PIN: testPIN, UnlockSecret: f.phoneUS,
		VerifyDevice: func(k *UnlockKey) (json.RawMessage, error) { return k.Attestation, nil },
		Manifest: func(seen uint64) (*ManifestView, error) {
			return &ManifestView{Serial: seen + 1, Own: own, Lookup: func(string) (ReleaseEntry, bool) { return own, true }}, nil
		},
		OwnKeyCheck: func(context.Context, ReleaseEntry) (*SealKeyRecord, error) {
			return &SealKeyRecord{VerifiedBy: testRelease.PCR0}, nil
		}})
}

// phoneUnlock is phoneUnlockOut, which must succeed.
func (f *openFixture) phoneUnlock(t *testing.T) (*Manager, *AltUnlockOutcome) {
	t.Helper()
	m, out := f.phoneUnlockOut()
	if m == nil || !out.OK {
		t.Fatalf("phone unlock %+v", out)
	}
	return m, out
}

func ownRelayState(m *Manager) RelayState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.st.Relay
}

func recoveryInvitePending(m *Manager) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, inv := range m.st.Invites {
		if inv.CreatedBy == inviteByRecovery {
			return true
		}
	}
	return false
}

// bundleNames reports whether a vault_bundle names mailbox mb.
func bundleNames(b []byte, mb string) bool { return mb != "" && bytes.Contains(b, []byte(`"`+mb+`"`)) }

// The inherited key's attempt at the open gets no definite answer after
// the old mailbox answered mailbox_unknown (the registration 503): the
// open goes on, its vault_bundle naming the gone mailbox, and the phone
// cannot pair there. Its lost-ok unlock makes the vault's one attempt of
// that unlock before the bundle: still no answer, the unlock is answered
// retry (no recovery attempt spent); once the relay answers, the next
// unlock completes the key (and the next key owed) and its bundle names
// the new mailbox, which the phone pairs with: within its two tries.
func TestRelayRotInheritedUnansweredAtTheOpenIsNotHeldByThePhone(t *testing.T) {
	io := newInheritedOpen(t, func(rw *rotWorld, k, _ string) {
		delete(rw.live, k)
		rw.register = []error{relayErr(503, "")}
	})
	rs := ownRelayState(io.m)
	if io.m.pendingMailbox() != io.p || rs.Collect.Stopped.IsZero() || rs.Pending.Recovery != "" {
		t.Fatalf("after the open: pending %s, relay %+v", io.m.pendingMailbox(), rs)
	}
	if !bundleNames(io.out.VaultBundle, io.k) {
		t.Fatal("the open's bundle does not name the mailbox it had")
	}
	if err := io.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	used := io.f.used()

	// First try: the relay still fails; the unlock is answered retry.
	io.rw.mu.Lock()
	io.rw.register = []error{relayErr(503, "")}
	io.rw.mu.Unlock()
	if m, uo := io.f.phoneUnlockOut(); m != nil || uo.OK || uo.Code != CodeRetry || len(uo.VaultBundle) != 0 {
		t.Fatalf("unlock with the relay failing: %+v", uo)
	}
	// Second try: the relay answers the inherited key (its registration);
	// the next key owed, stored by its second write, gets a 503. The
	// attempt is made before the bundle, which names the new current
	// mailbox.
	io.rw.mu.Lock()
	io.rw.rotate = []error{nil, relayErr(503, "")}
	io.rw.mu.Unlock()
	io.f.clock = io.f.clock.Add(time.Hour)
	m, uo := io.f.phoneUnlock(t)
	defer m.Crash()
	rs = ownRelayState(m)
	if rs.Mailbox != io.p || rs.Pending == nil || !io.registered(io.p) {
		t.Fatalf("not completed at the unlock: %+v", rs)
	}
	if !bundleNames(uo.VaultBundle, rs.Mailbox) || bundleNames(uo.VaultBundle, io.k) {
		t.Fatal("the unlock's bundle does not carry the current address")
	}
	// One attempt per unlock: Start makes no second one.
	rot0, reg0 := io.rw.log()
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rot, reg := io.rw.log(); len(rot) != len(rot0) || len(reg) != len(reg0) {
		t.Fatalf("a second attempt at the same unlock: %v %v", rot[len(rot0):], reg[len(reg0):])
	}
	if io.f.used() != used {
		t.Fatalf("the unlocks spent recovery attempts: %d, before %d", io.f.used(), used)
	}
	pairRecoveredPhone(t, m, io.f.phone)
}

// The same at the open's own run: its sooner retries complete the
// inherited key while the phone has not paired.
func TestRelayRotInheritedUnansweredAtTheOpenRetriedSooner(t *testing.T) {
	io := newInheritedOpen(t, func(rw *rotWorld, k, _ string) {
		delete(rw.live, k)
		rw.register = []error{relayErr(429, "rate_limited")}
	})
	rot0, reg0 := io.rw.log()
	if err := io.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	rot, reg := io.rw.log()
	rs := ownRelayState(io.m)
	if len(rot) <= len(rot0) || len(reg) <= len(reg0) || rs.Pending != nil || rs.Mailbox == io.k || !recoveryInvitePending(io.m) {
		t.Fatalf("rotates %v, registrations %v, relay %+v", rot, reg, rs)
	}
}

// The recovery's own key waits for the phone while the current mailbox
// lives; once that mailbox answers mailbox_unknown it no longer waits:
// the collect loop's mailbox_unknown starts the rotate and the
// registration, a failed one is retried sooner, and the phone's own
// unlock then carries the new address.
func TestRelayRotRecoveryOwnKeyAfterMailboxUnknown(t *testing.T) {
	f := newOpenFixture(t)
	rw := newRotWorld()
	f.opts.RelayKeyRotation, f.opts.RelayKeyRotationUnfinished = true, true
	f.opts.Relay = func(base string, key ed25519.PrivateKey) Relay {
		rw.mu.Lock()
		rw.live[mailboxOf(key)] = true
		rw.mu.Unlock()
		return &rotRelay{stubRelay: &stubRelay{base: base, key: key}, key: key, w: rw}
	}
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("open %+v", out)
	}
	defer func() { m.Crash() }()
	own, k := m.pendingMailbox(), ownRelayState(m).Mailbox
	rw.mu.Lock()
	delete(rw.live, own) // not yet made by a rotate
	rw.mu.Unlock()
	if rs := ownRelayState(m); rs.Pending == nil || rs.Pending.Recovery != recID || own == "" {
		t.Fatalf("the recovery's own key: %+v", rs.Pending)
	}
	// While the current mailbox lives: no attempt.
	_, reg0 := rw.log()
	if err := m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	if rot, reg := rw.log(); len(rot) != 0 || len(reg) != len(reg0) {
		t.Fatalf("attempted before the phone paired: %v %v", rot, reg)
	}
	// The current mailbox is gone: the collect loop's mailbox_unknown.
	rw.mu.Lock()
	delete(rw.live, k)
	rw.register = []error{relayErr(503, "")}
	rw.mu.Unlock()
	if err := m.relayMailboxUnknown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rot, reg := rw.log(); len(rot) != 1 || len(reg) != len(reg0)+1 || reg[len(reg)-1] != own {
		t.Fatalf("mailbox_unknown made no attempt: %v %v", rot, reg)
	}
	// The sooner retry, once its wait has run.
	f.clock = f.clock.Add(2 * time.Minute)
	if err := m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	rs := ownRelayState(m)
	if rs.Pending != nil || rs.Mailbox != own || !recoveryInvitePending(m) {
		t.Fatalf("not recovered: %+v", rs)
	}
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	m, uo := f.phoneUnlock(t)
	if !bundleNames(uo.VaultBundle, own) || bundleNames(uo.VaultBundle, k) {
		t.Fatal("the phone's unlock does not carry the current address")
	}
}

// An unlock whose attempt the wait skips audits no
// identity.rotation_failed: nothing failed.
func TestRelayRotRecoveryOwnKeyWaitNotAudited(t *testing.T) {
	f := newOpenFixture(t)
	rw := newRotWorld()
	f.opts.RelayKeyRotation, f.opts.RelayKeyRotationUnfinished = true, true
	f.opts.Relay = func(base string, key ed25519.PrivateKey) Relay {
		rw.live[mailboxOf(key)] = true
		return &rotRelay{stubRelay: &stubRelay{base: base, key: key}, key: key, w: rw}
	}
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("open %+v", out)
	}
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	sink := &recSink{}
	f.opts.Features = append(f.opts.Features, sink)
	m, _ = f.phoneUnlock(t)
	defer m.Crash()
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	n := 0
	for _, a := range sink.got {
		if a.Kind == "identity.rotation_failed" {
			n++
		}
	}
	m.mu.Unlock()
	if rot, _ := rw.log(); len(rot) != 0 || n != 0 {
		t.Fatalf("rotates %v, identity.rotation_failed %d", rot, n)
	}
}

// rotOpenFixture is an open fixture whose vault rotates its relay key on
// a relay that can rotate (every key's mailbox live once its Relay is
// built).
func rotOpenFixture(t *testing.T) (*openFixture, *rotWorld) {
	f := newOpenFixture(t)
	rw := newRotWorld()
	f.opts.RelayKeyRotation, f.opts.RelayKeyRotationUnfinished = true, true
	f.opts.Relay = func(base string, key ed25519.PrivateKey) Relay {
		rw.mu.Lock()
		rw.live[mailboxOf(key)] = true
		rw.mu.Unlock()
		return &rotRelay{stubRelay: &stubRelay{base: base, key: key}, key: key, w: rw}
	}
	return f, rw
}

func pendingRecovery(m *Manager) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if pr := m.st.Relay.Pending; pr != nil {
		return pr.Recovery
	}
	return ""
}

// The same phone registered again for a later recovery, after the earlier
// recovery's open stored step 2 (its own relay key pending) and lost its
// ok: the repeat through the `next` wrap replaces the invite, and the key
// still waits for the phone's first handshake, now under the later
// recovery.
func TestRelayRotRecoveryOwnKeyWaitFollowsTheSamePhone(t *testing.T) {
	f, rw := rotOpenFixture(t)
	a1, a2 := attBinding("attested-key-one"), attBinding("attested-key-two")
	f.reRegister(rebindR1, f.phone, a1)
	f.stopAfterStep2(rebindR1, f.phone, a1)
	f.clock = f.clock.Add(24 * time.Hour)
	f.bucket.Advance(24 * time.Hour)
	f.reRegister(rebindR2, f.phone, a2)
	m, out := f.openAttested(rebindR2, f.phone, a2)
	if m == nil || !out.OK {
		t.Fatalf("repeat: %+v", out)
	}
	defer m.Crash()
	if got := pendingRecovery(m); got != rebindR2 {
		t.Fatalf("the pending key's recovery %q, want %q", got, rebindR2)
	}
	if err := m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	if rot, _ := rw.log(); len(rot) != 0 {
		t.Fatalf("rotated before the phone's first handshake: %v", rot)
	}
	pairRecoveredPhone(t, m, f.phone)
	if err := m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	if rot, _ := rw.log(); len(rot) != 1 {
		t.Fatalf("rotates after the pairing: %v", rot)
	}
}

// A later recovery opening over the key an earlier recovery's open stored
// (the same phone, never paired, registered again): to this open the key
// is inherited, its mark is cleared, and it does not wait for the phone.
func TestRelayRotSecondRecoveryInheritsTheKeyWithoutTheWait(t *testing.T) {
	f, rw := rotOpenFixture(t)
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK || pendingRecovery(m) != recID {
		t.Fatalf("first open %+v, recovery %q", out, pendingRecovery(m))
	}
	pend := m.pendingMailbox()
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.clock = f.clock.Add(24 * time.Hour)
	f.bucket.Advance(24 * time.Hour)
	if err := headerTx(context.Background(), HeaderParams{Options: f.opts, VaultID: f.vid, UserGUID: "u1"}, func(h *Header, _ time.Time) (bool, error) {
		h.HasCredential = true // as the fixture's first request
		yes := true
		h.CredentialBackup = &yes
		return false, nil
	}); err != nil {
		t.Fatal(err)
	}
	a2 := attBinding("attested-key-two")
	f.reRegister(rebindR2, f.phone, a2)
	rw.mu.Lock()
	rw.rotate = []error{relayErr(503, "")} // the open's one attempt: no answer
	rw.mu.Unlock()
	m, out = f.openAttested(rebindR2, f.phone, a2)
	if m == nil || !out.OK {
		t.Fatalf("second open %+v", out)
	}
	defer m.Crash()
	if m.pendingMailbox() != pend || pendingRecovery(m) != "" || !recoveryInvitePending(m) {
		t.Fatalf("pending %s (want %s), recovery %q", m.pendingMailbox(), pend, pendingRecovery(m))
	}
	rot0, _ := rw.log()
	if err := m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	if rot, _ := rw.log(); len(rot) <= len(rot0) {
		t.Fatalf("the inherited key waited: rotates %v", rot)
	}
}
