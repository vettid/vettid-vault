package vault

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"
)

// The edges of the relay-key rotation's waits and of the recovered phone's
// attempt before its bundle (§3.4 "Retrying with the same key", "A
// recovery's inherited key"; §11.14.6 "A lost ok").

// newInheritedFixture is newInheritedOpen without the open: the vault
// holds an inherited pending key on a relay that can rotate; before, if
// set, runs on the running vault after the key is stored, and its
// changes are stored with it.
func newInheritedFixture(t *testing.T, before func(f *openFixture), script func(rw *rotWorld, k, p string)) *inheritedOpen {
	io := &inheritedOpen{rw: newRotWorld()}
	io.f = newOpenFixtureWith(t, func(f *openFixture) {
		f.m.mu.Lock()
		defer f.m.mu.Unlock()
		f.m.opt.RelayKeyRotation = true
		for range 2 {
			if err := f.m.rotateKeys(f.clock, true); err != nil {
				t.Fatal(err)
			}
		}
		io.k, io.p = f.m.st.Relay.Mailbox, f.m.pendingMailbox()
		if before != nil {
			before(f)
		}
		if err := f.m.persist(context.Background(), false); err != nil {
			t.Fatal(err)
		}
	})
	io.f.opts.RelayKeyRotation, io.f.opts.RelayKeyRotationUnfinished = true, true
	io.f.opts.Relay = func(base string, key ed25519.PrivateKey) Relay {
		return &rotRelay{stubRelay: &stubRelay{base: base, key: key}, key: key, w: io.rw}
	}
	io.rw.live[io.k] = true
	if script != nil {
		script(io.rw, io.k, io.p)
	}
	return io
}

// phoneUnlockWith is the recovered phone's own unlock (phoneUnlockOut)
// with its parameters changed by tweak.
func (f *openFixture) phoneUnlockWith(tweak func(*AltUnlockParams)) (*Manager, *AltUnlockOutcome) {
	own := ReleaseEntry{PCR0: testRelease.PCR0, Number: testRelease.Number, Status: "active"}
	p := AltUnlockParams{Options: f.opts, VaultID: f.vid, UserGUID: "u1",
		DeviceIK: f.phone.Public().(ed25519.PublicKey), PIN: testPIN, UnlockSecret: f.phoneUS,
		VerifyDevice: func(k *UnlockKey) (json.RawMessage, error) { return k.Attestation, nil },
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

// countActsLocked counts the activities of kind a sink recorded, under the manager's lock.
func countActsLocked(m *Manager, sink *recSink, kind string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, a := range sink.got {
		if a.Kind == kind {
			n++
		}
	}
	return n
}

// The open's attempt on an inherited key whose mailbox was made afresh
// shortly before (the answer's time stored with the key) is not made
// while freshMailboxWait runs: no rotate, no registration, the key stays
// pending with its time unchanged, and nothing is audited (the relay
// answered; nothing failed).
func TestRelayRotInheritedFreshWaitAtTheOpenMakesNoCall(t *testing.T) {
	// The fixture's clock moves 98 hours between the stored state and the
	// open: the answer is 10 seconds before the open.
	var created time.Time
	io := newInheritedFixture(t, func(f *openFixture) {
		created = f.clock.Add(98*time.Hour - 10*time.Second).UTC()
		f.m.st.Relay.Pending.Created = created
	}, nil)
	if !io.f.clock.Equal(created.Add(10 * time.Second)) {
		t.Fatalf("the open's clock %v, the answer %v", io.f.clock, created)
	}
	sink := &recSink{}
	io.f.opts.Features = append(io.f.opts.Features, sink)
	m, out := io.f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("open %+v", out)
	}
	defer m.Crash()
	io.m = m
	if rot, reg := io.rw.log(); len(rot) != 0 || len(reg) != 0 {
		t.Fatalf("rotates %v, registers %v", rot, reg)
	}
	rs := ownRelayState(m)
	if m.pendingMailbox() != io.p || rs.Mailbox != io.k || rs.Pending == nil || !rs.Pending.Created.Equal(created) {
		t.Fatalf("pending %s, relay %+v", m.pendingMailbox(), rs)
	}
	if n := countActsLocked(m, sink, "identity.rotation_failed"); n != 0 {
		t.Fatalf("identity.rotation_failed %d", n)
	}
}

// goneMailboxLocked is newInheritedOpen whose current mailbox is gone (its
// collects ended on mailbox_unknown) with the inherited key pending after
// the open's attempt got no definite answer; the vault is locked again
// and the relay's next registration fails too.
func goneMailboxLocked(t *testing.T) *inheritedOpen {
	io := newInheritedOpen(t, func(rw *rotWorld, k, _ string) {
		delete(rw.live, k)
		rw.register = []error{relayErr(503, "")}
	})
	if rs := ownRelayState(io.m); io.m.pendingMailbox() != io.p || rs.Collect.Stopped.IsZero() {
		t.Fatalf("after the open: pending %s, relay %+v", io.m.pendingMailbox(), rs)
	}
	if err := io.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	io.rw.mu.Lock()
	io.rw.register = []error{relayErr(503, "")}
	io.rw.mu.Unlock()
	return io
}

// unlockMakesNoAttempt runs the recovered phone's unlock (tweaked) and
// checks that it answers ok without a relay call, the key still pending.
func (io *inheritedOpen) unlockMakesNoAttempt(t *testing.T, tweak func(*AltUnlockParams)) *AltUnlockOutcome {
	t.Helper()
	rot0, reg0 := io.rw.log()
	m, uo := io.f.phoneUnlockWith(tweak)
	if m == nil || !uo.OK || uo.Code == CodeRetry {
		t.Fatalf("unlock %+v", uo)
	}
	t.Cleanup(m.Crash)
	if rot, reg := io.rw.log(); len(rot) != len(rot0) || len(reg) != len(reg0) {
		t.Fatalf("relay calls at the unlock: rotates %v, registers %v", rot[len(rot0):], reg[len(reg0):])
	}
	if m.pendingMailbox() != io.p {
		t.Fatalf("pending %s", m.pendingMailbox())
	}
	return uo
}

// §3.4, §11.14.6 "A lost ok": the recovered phone's unlock that cancels a
// recovery (§11.11.4) carries what only an ok reports, so it makes no
// relay-key attempt before its bundle, even with the current mailbox gone
// and a key pending: it answers ok, and Start's attempt covers the key.
func TestRelayRotRecoveredUnlockCancellingARecoveryMakesNoAttempt(t *testing.T) {
	io := goneMailboxLocked(t)
	p := HeaderParams{Options: io.f.opts, VaultID: io.f.vid, UserGUID: "u1"}
	if err := headerTx(context.Background(), p, func(h *Header, now time.Time) (bool, error) {
		h.Recovery = &RecoveryRecord{ID: cancelledRecID, State: RecoveryPending, RequestedAt: now, NotBefore: now.Add(time.Hour),
			Expires: now.Add(48 * time.Hour)}
		return false, nil
	}); err != nil {
		t.Fatal(err)
	}
	uo := io.unlockMakesNoAttempt(t, func(p *AltUnlockParams) { p.CancelRecovery = true })
	if !uo.RecoveryCancelled {
		t.Fatalf("not cancelled: %+v", uo)
	}
}

// The same for the recovered phone's unlock whose release update is
// refused (§11.10.4 step 4: a refusal still unlocks, and reports it).
func TestRelayRotRecoveredUnlockWithARefusedUpdateMakesNoAttempt(t *testing.T) {
	io := goneMailboxLocked(t)
	uo := io.unlockMakesNoAttempt(t, func(p *AltUnlockParams) {
		p.Update = &UpdateRequest{To: "unknown-release", ToRelease: testRelease.Number + 1}
	})
	if uo.Update == nil || uo.Update.Result != UpdateRefused {
		t.Fatalf("update %+v", uo.Update)
	}
}

// Without either, the same unlock makes the attempt and answers retry.
func TestRelayRotRecoveredUnlockGoneMailboxRetries(t *testing.T) {
	io := goneMailboxLocked(t)
	if m, uo := io.f.phoneUnlockOut(); m != nil || uo.OK || uo.Code != CodeRetry {
		t.Fatalf("unlock %+v", uo)
	}
}

// The same for the recovered phone's unlock that confirms a release move
// at this release (§11.10.4: the confirmation is stored by its flush).
func TestRelayRotRecoveredUnlockConfirmingAMoveMakesNoAttempt(t *testing.T) {
	io := newInheritedOpen(t, func(rw *rotWorld, k, _ string) {
		delete(rw.live, k)
		rw.register = []error{relayErr(503, "")}
	})
	io.m.mu.Lock()
	io.m.st.ReleaseMove = &ReleaseMove{To: testRelease.PCR0, ToRelease: testRelease.Number, From: "earlier-release"}
	io.m.dirty = true
	err := io.m.persist(context.Background(), false)
	io.m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := io.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	io.rw.mu.Lock()
	io.rw.register = []error{relayErr(503, "")}
	io.rw.mu.Unlock()
	io.unlockMakesNoAttempt(t, nil)
}

// The same for the recovered phone's unlock that completes its recovery's
// DEK replacement (§11.14.2 step 3), the open having stored steps 1 and 2
// and its step-3 header write having failed.
func TestRelayRotRecoveredUnlockCompletingTheReplacementMakesNoAttempt(t *testing.T) {
	io := newInheritedFixture(t, nil, func(rw *rotWorld, k, _ string) {
		delete(rw.live, k)
		rw.register = []error{relayErr(503, "")}
	})
	io.f.st.mu.Lock()
	io.f.st.passHeader, io.f.st.failHeader = 1, 1
	io.f.st.mu.Unlock()
	if m, out := io.f.open(testPIN, rPW); m != nil || out.Code != OpenRetry {
		t.Fatalf("open stopped after step 2: %+v", out)
	}
	if h := io.f.storedHeader(); h.Next == nil || h.Next.Reason != ReplaceRecovery {
		t.Fatal("not a completion stopped after step 2")
	}
	io.rw.mu.Lock()
	io.rw.register = []error{relayErr(503, "")}
	io.rw.mu.Unlock()
	io.unlockMakesNoAttempt(t, nil)
	if h := io.f.storedHeader(); h.Next != nil {
		t.Fatal("step 3 not stored")
	}
}

// The same for the recovered phone's unlock that drops a stored `next`
// part naming a new app key (§11.14.2: the current secret unlocked first;
// the parent is told to clear app_key_next).
func TestRelayRotRecoveredUnlockDroppingTheNextAppKeyMakesNoAttempt(t *testing.T) {
	io := goneMailboxLocked(t)
	p := HeaderParams{Options: io.f.opts, VaultID: io.f.vid, UserGUID: "u1"}
	if err := headerTx(context.Background(), p, func(h *Header, _ time.Time) (bool, error) {
		h.Next = &HeaderNext{Reason: ReplaceTransfer, DEKVersion: h.DEKVersion + 1, AppKey: []byte("next-app-key"), AppKeySeq: h.AppKeySeq + 1,
			HeaderSeq: h.HeaderSeq + 1}
		return false, nil
	}); err != nil {
		t.Fatal(err)
	}
	io.unlockMakesNoAttempt(t, nil)
}

// §3.4 "Retrying with the same key": the recovered phone's unlock with
// the current mailbox gone makes its attempt before the bundle; a key
// left in the refused state after it does not answer retry (no wait would
// end it): the unlock goes on, as before, with the refused key pending.
func TestRelayRotRecoveredUnlockRefusedKeyGoesOn(t *testing.T) {
	io := newInheritedOpen(t, func(rw *rotWorld, k, _ string) {
		delete(rw.live, k)
		rw.register = []error{relayErr(400, "bad_request"), relayErr(400, "bad_request")}
	})
	if rs := ownRelayState(io.m); rs.Pending == nil || rs.Pending.Refused == "" || rs.Collect.Stopped.IsZero() {
		t.Fatalf("after the open: relay %+v", rs)
	}
	if err := io.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	io.rw.mu.Lock()
	io.rw.register = []error{relayErr(400, "bad_request")}
	io.rw.mu.Unlock()
	_, reg0 := io.rw.log()
	m, uo := io.f.phoneUnlockOut()
	if m == nil || !uo.OK || len(uo.VaultBundle) == 0 {
		t.Fatalf("unlock %+v", uo)
	}
	defer m.Crash()
	if _, reg := io.rw.log(); len(reg) != len(reg0)+1 {
		t.Fatalf("registers at the unlock %v", reg[len(reg0):])
	}
	if rs := ownRelayState(m); rs.Pending == nil || rs.Pending.Refused == "" || m.pendingMailbox() != io.p {
		t.Fatalf("relay %+v", rs)
	}
}

// §3.4, §11.14.6 "A lost ok": a recovered phone's unlock whose key waits
// for its mailbox made afresh (the answer's time stored with the key, the
// vault locked and unlocked since, so only the stored time tells) makes
// no attempt and answers retry with the time left of freshMailboxWait.
func TestRelayRotRecoveredUnlockFreshWaitAfterALockRetriesWithTheTimeLeft(t *testing.T) {
	io := goneMailboxLocked(t)
	io.rw.mu.Lock()
	io.rw.register = nil // the relay answers: the mailbox made afresh
	io.rw.mu.Unlock()
	io.f.clock = io.f.clock.Add(time.Hour)
	answered := io.f.clock
	if m, uo := io.f.phoneUnlockOut(); m != nil || uo.Code != CodeRetry || uo.RetryAfter != freshMailboxWait {
		t.Fatalf("unlock 1: %+v", uo)
	}
	const later = 100 * time.Second
	io.f.clock = answered.Add(later)
	rot0, reg0 := io.rw.log()
	m, uo := io.f.phoneUnlockOut()
	if m != nil || uo.OK || uo.Code != CodeRetry || len(uo.VaultBundle) != 0 {
		t.Fatalf("unlock 2: %+v", uo)
	}
	if want := answered.Add(freshMailboxWait).Sub(io.f.clock); uo.RetryAfter != want {
		t.Fatalf("unlock 2: retry after %v, want %v", uo.RetryAfter, want)
	}
	if rot, reg := io.rw.log(); len(rot) != len(rot0) || len(reg) != len(reg0) {
		t.Fatalf("relay calls within the wait: rotates %v, registers %v", rot[len(rot0):], reg[len(reg0):])
	}
}
