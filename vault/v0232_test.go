package vault

import (
	"context"
	"encoding/json"
	"testing"
)

// VAULT-MESSAGING 0.23.2 (§10.9): vault.unlocked names the app that
// unlocked; vault.locked names the owner device whose vault.lock locked
// it, and no device for any other lock.

func (r *recSink) find(kind string) (Activity, bool) {
	for _, a := range r.got {
		if a.Kind == kind {
			return a, true
		}
	}
	return Activity{}, false
}

// deviceUnlock locks d's vault and unlocks it as d's app (§11.4), with
// the device, manifest and key checks stubbed.
func deviceUnlock(t *testing.T, d *devFixture, before func(*Manager)) *Manager {
	t.Helper()
	ctx := context.Background()
	if before != nil {
		before(d.m)
	}
	if err := d.m.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	own := ReleaseEntry{PCR0: testRelease.PCR0, Number: testRelease.Number, Status: "active"}
	m, out := UnlockAlt(ctx, AltUnlockParams{Options: d.opts, VaultID: d.vid, UserGUID: "u1", DeviceIK: d.devPeer.IK, PIN: testPIN,
		VerifyDevice: func(k *UnlockKey) (json.RawMessage, error) { return k.Attestation, nil },
		Manifest: func(seen uint64) (*ManifestView, error) {
			return &ManifestView{Serial: seen + 1, Own: own, Lookup: func(string) (ReleaseEntry, bool) { return own, true }}, nil
		},
		OwnKeyCheck: func(context.Context, ReleaseEntry) (*SealKeyRecord, error) {
			return &SealKeyRecord{VerifiedBy: testRelease.PCR0}, nil
		}})
	if m == nil || !out.OK {
		t.Fatalf("unlock: %+v", out)
	}
	return m
}

func TestUnlockedNamesDevice(t *testing.T) {
	d := newDevFixture(t)
	m := deviceUnlock(t, d, nil)
	s := &recSink{}
	m.addFeature(s)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a, ok := s.find("vault.unlocked"); !ok || a.DeviceID != d.devPeer.ID {
		t.Fatalf("vault.unlocked: %+v %v", a, ok)
	}
	_ = m.Lock(context.Background())
}

// The confirming unlock at a move's new release (§11.10.4) names the app.
func TestUnlockedNamesDeviceOnMoveConfirmation(t *testing.T) {
	d := newDevFixture(t)
	m := deviceUnlock(t, d, func(m *Manager) {
		m.st.ReleaseMove = &ReleaseMove{To: testRelease.PCR0, ToRelease: testRelease.Number, From: "old", ApprovedBy: d.devPeer.ID}
	})
	if m.st.ReleaseMove != nil {
		t.Fatal("move not confirmed")
	}
	s := &recSink{}
	m.addFeature(s)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a, ok := s.find("vault.unlocked"); !ok || a.DeviceID != d.devPeer.ID {
		t.Fatalf("vault.unlocked: %+v %v", a, ok)
	}
	_ = m.Lock(context.Background())
}

// A PIN-only (development) unlock has no device.
func TestUnlockedPINOnlyNoDevice(t *testing.T) {
	f := newFixture(t)
	if err := f.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	m, out := UnlockAlt(context.Background(), AltUnlockParams{Options: f.opts, VaultID: f.vid, PIN: testPIN, pinOnly: true})
	if m == nil || !out.OK {
		t.Fatalf("unlock: %+v", out)
	}
	s := &recSink{}
	m.addFeature(s)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a, ok := s.find("vault.unlocked"); !ok || a.DeviceID != "" {
		t.Fatalf("vault.unlocked: %+v %v", a, ok)
	}
	_ = m.Lock(context.Background())
}

func TestLockedNamesRequestingDevice(t *testing.T) {
	d := newDevFixture(t)
	s := &recSink{}
	d.m.addFeature(s)
	if err := d.send("vault.lock", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if !d.m.Locked() {
		t.Fatal("not locked")
	}
	if a, ok := s.find("vault.locked"); !ok || a.DeviceID != d.devPeer.ID {
		t.Fatalf("vault.locked: %+v %v", a, ok)
	}
}

func TestLockedByHostNoDevice(t *testing.T) {
	for _, reason := range []string{"", "recovery"} {
		d := newDevFixture(t)
		s := &recSink{}
		d.m.addFeature(s)
		d.m.lockBy = d.devPeer.ID // a device's lock still pending: the host's lock wins
		if err := d.m.LockReason(context.Background(), reason); err != nil {
			t.Fatal(err)
		}
		if a, ok := s.find("vault.locked"); !ok || a.DeviceID != "" {
			t.Fatalf("%q: vault.locked: %+v %v", reason, a, ok)
		}
	}
}

// The owner check's lock (§3.6.4) is the vault's, even when a device's
// vault.lock is in the same batch.
func TestLockedByOwnerCheckNoDevice(t *testing.T) {
	d := newDevFixture(t)
	s := &recSink{}
	d.m.addFeature(s)
	d.m.mu.Lock()
	d.m.lockBy = d.devPeer.ID
	d.m.lockPending, d.m.lockReason = true, LockOwnerCheck
	err := d.m.lockLocked(context.Background())
	d.m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if a, ok := s.find("vault.locked"); !ok || a.DeviceID != "" {
		t.Fatalf("vault.locked: %+v %v", a, ok)
	}
}
