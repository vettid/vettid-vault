package vault

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// VAULT-MESSAGING 0.49.0 §11.5, §11.11.4: an owner app's unlock with
// cancel_recovery reports the recovery it ended (the outcome's marker id
// and its unlocked or moved lifecycle event) only when the cancel is
// stored.

const cancelledRecID = "01JB2Z6V9K3M4N5P6Q7R8S9T32"

// cancelFixture is a dev fixture whose vault is locked with a recovery
// in its header; before, if set, runs on the running vault first.
func cancelFixture(t *testing.T, before func(*Manager)) *devFixture {
	t.Helper()
	d := newDevFixture(t)
	if before != nil {
		before(d.m)
	}
	if err := d.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	p := HeaderParams{Options: d.opts, VaultID: d.vid, UserGUID: "u1"}
	if err := headerTx(context.Background(), p, func(h *Header, now time.Time) (bool, error) {
		h.Recovery = &RecoveryRecord{ID: cancelledRecID, State: RecoveryPending, RequestedAt: now, NotBefore: now.Add(time.Hour), Expires: now.Add(48 * time.Hour)}
		return false, nil
	}); err != nil {
		t.Fatal(err)
	}
	return d
}

// cancelUnlock unlocks d's vault as d's app with cancel_recovery; tweak,
// if set, changes the parameters.
func cancelUnlock(d *devFixture, opts Options, tweak func(*AltUnlockParams)) (*Manager, *AltUnlockOutcome) {
	own := ReleaseEntry{PCR0: testRelease.PCR0, Number: testRelease.Number, Status: "active"}
	p := AltUnlockParams{Options: opts, VaultID: d.vid, UserGUID: "u1", DeviceIK: d.devPeer.IK, PIN: testPIN, UnlockSecret: testSecret,
		CancelRecovery: true,
		VerifyDevice:   func(k *UnlockKey) (json.RawMessage, error) { return k.Attestation, nil },
		Manifest: func(seen uint64) (*ManifestView, error) {
			return &ManifestView{Serial: seen + 1, Own: own, Lookup: func(string) (ReleaseEntry, bool) { return own, true }}, nil
		},
		OwnKeyCheck: func(context.Context, ReleaseEntry) (*SealKeyRecord, error) {
			return &SealKeyRecord{VerifiedBy: testRelease.PCR0}, nil
		}}
	if tweak != nil {
		tweak(&p)
	}
	return UnlockAlt(context.Background(), p)
}

func storedRecovery(t *testing.T, d *devFixture) *RecoveryRecord {
	t.Helper()
	return storedHeader(t, d).Recovery
}

// eventIDs maps each lifecycle event to its cancelled_recovery_id.
func eventIDs(evs []LifecycleEvent) (names []string, ids map[string]string) {
	ids = map[string]string{}
	for _, e := range evs {
		names = append(names, e.Event)
		ids[e.Event] = e.CancelledRecoveryID
	}
	return names, ids
}

func TestUnlockCancelReportsTheRecovery(t *testing.T) {
	d := cancelFixture(t, nil)
	m, out := cancelUnlock(d, d.opts, nil)
	if m == nil || !out.OK || !out.RecoveryCancelled {
		t.Fatalf("unlock: %+v", out)
	}
	defer m.Crash()
	if out.CancelledMarker() != cancelledRecID {
		t.Fatalf("marker id %q", out.CancelledMarker())
	}
	names, ids := eventIDs(out.Events)
	if ids["unlocked"] != cancelledRecID {
		t.Fatalf("events %v, unlocked carries %q", names, ids["unlocked"])
	}
	for _, e := range out.Events {
		if e.Event != "unlocked" && e.CancelledRecoveryID != "" {
			t.Fatalf("%s carries the id", e.Event)
		}
	}
	if r := storedRecovery(t, d); r != nil {
		t.Fatalf("the recovery was not cancelled: %+v", r)
	}
}

// An unlock without cancel_recovery is refused recovery_pending and
// reports nothing; one that cancels nothing (no recovery) reports nothing.
func TestUnlockWithoutCancelReportsNothing(t *testing.T) {
	d := cancelFixture(t, nil)
	if m, out := cancelUnlock(d, d.opts, func(p *AltUnlockParams) { p.CancelRecovery = false }); m != nil || out.Code != CodeRecoveryPending ||
		out.CancelledMarker() != "" || len(out.Events) != 0 {
		t.Fatalf("without cancel_recovery: %+v", out)
	}
	d2 := newDevFixture(t)
	if err := d2.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	m, out := cancelUnlock(d2, d2.opts, nil)
	if m == nil || !out.OK || out.RecoveryCancelled || out.CancelledMarker() != "" {
		t.Fatalf("no recovery: %+v", out)
	}
	defer m.Crash()
	for _, e := range out.Events {
		if e.CancelledRecoveryID != "" {
			t.Fatalf("%s carries an id", e.Event)
		}
	}
}

// A cancel whose writes fail: RecoveryCancelled was set when the PIN
// matched, but the result is not ok, so there is no marker and no event
// field, and the stored header keeps the recovery.
func TestUnlockCancelPersistFailureReportsNothing(t *testing.T) {
	d := cancelFixture(t, nil)
	fs := &faultStore{Store: d.store, failState: 1}
	opts := d.opts
	opts.Store = fs
	m, out := cancelUnlock(d, opts, nil)
	if m != nil || out.OK || !out.RecoveryCancelled {
		t.Fatalf("unlock with a failed write: %+v", out)
	}
	if out.CancelledMarker() != "" {
		t.Fatalf("marker id %q after a failed write", out.CancelledMarker())
	}
	for _, e := range out.Events {
		if e.CancelledRecoveryID != "" {
			t.Fatalf("%s carries the id after a failed write", e.Event)
		}
	}
	if r := storedRecovery(t, d); r == nil || r.ID != cancelledRecID {
		t.Fatalf("stored recovery %+v", r)
	}
}

// A pending move abandoned by this unlock: unlocked (from the resume)
// carries the id, the moved that follows does not.
func TestUnlockCancelAbandonedMove(t *testing.T) {
	const target = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"
	d := cancelFixture(t, func(m *Manager) {
		m.st.ReleaseMove = &ReleaseMove{To: target, ToRelease: testRelease.Number + 1, From: testRelease.PCR0, ApprovedBy: "dev1"}
	})
	m, out := cancelUnlock(d, d.opts, func(p *AltUnlockParams) {
		p.Update = &UpdateRequest{To: testRelease.PCR0, ToRelease: testRelease.Number,
			VerifyApproval: func(k *UnlockKey) (json.RawMessage, error) { return k.Attestation, nil }}
	})
	if m == nil || !out.OK || out.Update == nil || out.Update.Result != UpdateAbandoned {
		t.Fatalf("abandon: %+v %+v", out, out.Update)
	}
	defer m.Crash()
	names, ids := eventIDs(out.Events)
	if ids["unlocked"] != cancelledRecID || ids["moved"] != "" {
		t.Fatalf("events %v: unlocked %q, moved %q", names, ids["unlocked"], ids["moved"])
	}
	if _, ok := ids["moved"]; !ok {
		t.Fatalf("no moved event: %v", names)
	}
}

// A pending move completed by this unlock emits no unlocked: its moved
// event carries the id.
func TestUnlockCancelCompletedMove(t *testing.T) {
	const target = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
	d := cancelFixture(t, func(m *Manager) {
		m.st.ReleaseMove = &ReleaseMove{To: target, ToRelease: testRelease.Number + 1, From: testRelease.PCR0, ApprovedBy: "dev1"}
	})
	own := ReleaseEntry{PCR0: testRelease.PCR0, Number: testRelease.Number, Status: "active"}
	next := ReleaseEntry{PCR0: target, Number: testRelease.Number + 1, Status: "active"}
	m, out := cancelUnlock(d, d.opts, func(p *AltUnlockParams) {
		p.Manifest = func(seen uint64) (*ManifestView, error) {
			return &ManifestView{Serial: seen + 1, Own: own, Lookup: func(pcr0 string) (ReleaseEntry, bool) {
				if pcr0 == target {
					return next, true
				}
				return own, true
			}}, nil
		}
		p.SealerFor = func(context.Context, ReleaseEntry) (Sealer, *SealKeyRecord, error) {
			return d.opts.Sealer, &SealKeyRecord{VerifiedBy: testRelease.PCR0}, nil
		}
	})
	if m != nil || !out.OK || out.Update == nil || out.Update.Result != UpdateMoved {
		t.Fatalf("move: %+v %+v", out, out.Update)
	}
	names, ids := eventIDs(out.Events)
	if _, ok := ids["unlocked"]; ok || ids["moved"] != cancelledRecID {
		t.Fatalf("events %v: moved %q", names, ids["moved"])
	}
	if out.CancelledMarker() != cancelledRecID {
		t.Fatalf("marker id %q", out.CancelledMarker())
	}
}

// The marker names the recovery the header holds when the unlock runs,
// whatever recovery the member API meant when it queued the unlock (the
// queue is not ordered).
func TestUnlockCancelNamesTheHeadersRecovery(t *testing.T) {
	const newer = "01JB2Z6V9K3M4N5P6Q7R8S9T40"
	d := cancelFixture(t, nil)
	p := HeaderParams{Options: d.opts, VaultID: d.vid, UserGUID: "u1"}
	if err := headerTx(context.Background(), p, func(h *Header, now time.Time) (bool, error) {
		h.Recovery = &RecoveryRecord{ID: newer, State: RecoveryPending, RequestedAt: now, NotBefore: now.Add(time.Hour), Expires: now.Add(48 * time.Hour)}
		return false, nil
	}); err != nil {
		t.Fatal(err)
	}
	m, out := cancelUnlock(d, d.opts, nil)
	if m == nil || !out.OK {
		t.Fatalf("unlock: %+v", out)
	}
	defer m.Crash()
	if out.CancelledMarker() != newer {
		t.Fatalf("marker id %q, want the header's %q", out.CancelledMarker(), newer)
	}
}
