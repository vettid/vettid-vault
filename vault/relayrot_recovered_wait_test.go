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

// phoneUnlock is the recovered phone's own unlock (a lost ok before its
// first handshake carries the vault's bundle again, resumeLostOK).
func (f *openFixture) phoneUnlock(t *testing.T) (*Manager, *AltUnlockOutcome) {
	t.Helper()
	own := ReleaseEntry{PCR0: testRelease.PCR0, Number: testRelease.Number, Status: "active"}
	m, out := UnlockAlt(context.Background(), AltUnlockParams{Options: f.opts, VaultID: f.vid, UserGUID: "u1",
		DeviceIK: f.phone.Public().(ed25519.PublicKey), PIN: testPIN, UnlockSecret: f.phoneUS,
		VerifyDevice: func(k *UnlockKey) (json.RawMessage, error) { return k.Attestation, nil },
		Manifest: func(seen uint64) (*ManifestView, error) {
			return &ManifestView{Serial: seen + 1, Own: own, Lookup: func(string) (ReleaseEntry, bool) { return own, true }}, nil
		},
		OwnKeyCheck: func(context.Context, ReleaseEntry) (*SealKeyRecord, error) {
			return &SealKeyRecord{VerifiedBy: testRelease.PCR0}, nil
		}})
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
// open goes on, its vault_bundle naming the gone mailbox. The phone cannot
// pair there; the inherited key does not wait for it: the next unlock's
// attempt completes it (and the next key owed), and the phone's own unlock
// then carries the new address.
func TestRelayRotInheritedUnansweredAtTheOpenIsNotHeldByThePhone(t *testing.T) {
	io := newInheritedOpen(t, func(rw *rotWorld, k, _ string) {
		delete(rw.live, k)
		rw.register = []error{relayErr(503, "")}
	})
	rs := ownRelayState(io.m)
	if io.m.pendingMailbox() != io.p || rs.Collect.Stopped.IsZero() || rs.Pending.Recovery != "" {
		t.Fatalf("after the open: pending %s, relay %+v", io.m.pendingMailbox(), rs)
	}
	if err := io.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	rot0, reg0 := io.rw.log()

	// The phone's lost-ok unlock: the vault's attempt at it completes the
	// inherited key although the phone has not paired.
	sink := &recSink{}
	io.f.opts.Features = append(io.f.opts.Features, sink)
	m, uo := io.f.phoneUnlock(t)
	if !bundleNames(uo.VaultBundle, io.k) {
		t.Fatal("the unlock's bundle does not name the vault's current (gone) mailbox")
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	rot, reg := io.rw.log()
	if len(rot) <= len(rot0) || len(reg) <= len(reg0) || !io.registered(io.p) {
		t.Fatalf("no attempt after the open: rotates %v, registrations %v", rot, reg)
	}
	rs = ownRelayState(m)
	if rs.Pending != nil || rs.Mailbox == io.k || rs.Mailbox == io.p || !recoveryInvitePending(m) {
		t.Fatalf("not recovered: %+v (invite pending %v)", rs, recoveryInvitePending(m))
	}
	cur := rs.Mailbox
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The phone's next unlock carries the current address.
	m, uo = io.f.phoneUnlock(t)
	defer m.Crash()
	if !bundleNames(uo.VaultBundle, cur) || bundleNames(uo.VaultBundle, io.k) {
		t.Fatal("the phone's unlock does not carry the current address")
	}
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

// An unlock whose attempt the wait skips audits identity.rotation_failed
// for the key left pending, once.
func TestRelayRotRecoveryOwnKeyWaitAuditedAtUnlock(t *testing.T) {
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
	if rot, _ := rw.log(); len(rot) != 0 || n != 1 {
		t.Fatalf("rotates %v, identity.rotation_failed %d", rot, n)
	}
}
