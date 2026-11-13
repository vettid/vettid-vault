package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/strictjson"
)

// The recovered phone's wait (recoveryWaits, a reading of this release):
// only the recovery's own relay key waits for the phone's first handshake,
// and only while the current mailbox lives; an inherited key never waits
// (§3.4 "A recovery's inherited key", "Retrying with the same key":
// mailbox_unknown while a key is pending starts the same path).

// phoneUnlockOut is the recovered phone's own unlock (a lost ok before its
// first handshake carries the vault's bundle again, resumeLostOK).
func (f *openFixture) phoneUnlockOut() (*Manager, *AltUnlockOutcome) { return f.phoneUnlockFloor(0) }

// phoneUnlockFloor is phoneUnlockOut with the phone's header_seq floor.
func (f *openFixture) phoneUnlockFloor(minHeaderSeq uint64) (*Manager, *AltUnlockOutcome) {
	own := ReleaseEntry{PCR0: testRelease.PCR0, Number: testRelease.Number, Status: "active"}
	return UnlockAlt(context.Background(), AltUnlockParams{Options: f.opts, VaultID: f.vid, UserGUID: "u1", MinHeaderSeq: minHeaderSeq,
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
// that unlock before the bundle. A first unlock while the relay still
// fails is answered retry, as is one whose registration is answered (the
// key then waits freshMailboxWait, its mailbox perhaps made afresh), with
// the time left and the floors of what it wrote; no recovery attempt is
// spent and no try of the phone's. The unlock after the wait completes
// the key (and the next key owed): its bundle names the new mailbox.
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

	// The relay still fails: retry, with the sooner retries' wait.
	io.rw.mu.Lock()
	io.rw.register = []error{relayErr(503, "")}
	io.rw.mu.Unlock()
	if m, uo := io.f.phoneUnlockOut(); m != nil || uo.OK || uo.Code != CodeRetry || len(uo.VaultBundle) != 0 ||
		uo.RetryAfter < 0 || uo.RetryAfter > time.Minute {
		t.Fatalf("unlock with the relay failing: %+v", uo)
	}
	// Lost-ok unlock 1: the relay answers the registration; the key waits
	// freshMailboxWait. Retry, with the time left and the header_seq the
	// answer's write stored.
	io.f.clock = io.f.clock.Add(time.Hour)
	m, uo := io.f.phoneUnlockOut()
	if m != nil || uo.OK || uo.Code != CodeRetry || uo.RetryAfter != freshMailboxWait || len(uo.VaultBundle) != 0 {
		t.Fatalf("unlock 1: %+v", uo)
	}
	if h := io.f.storedHeader(); uo.HeaderSeq != h.HeaderSeq || uo.StateSeq != h.StateSeq {
		t.Fatalf("unlock 1 carries seqs %d/%d, stored %d/%d", uo.StateSeq, uo.HeaderSeq, h.StateSeq, h.HeaderSeq)
	}
	// Lost-ok unlock 2, after the wait: the key is made current; the next
	// key owed, stored by its second write, gets a 503. The attempt is
	// made before the bundle, which names the new current mailbox: the
	// phone's second try (the open's bundle was its first) pairs.
	io.rw.mu.Lock()
	io.rw.rotate = []error{nil, relayErr(503, "")}
	io.rw.mu.Unlock()
	io.f.clock = io.f.clock.Add(freshMailboxWait)
	m, uo = io.f.phoneUnlock(t)
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
	checkPhoneBundle(t, m, uo)
	// (pairRecoveredPhone stands in for the phone's first handshake: it
	// writes the device record directly; the bundle and the token the
	// phone would pair with are checked against the vault above.)
	pairRecoveredPhone(t, m, io.f.phone)
}

// checkPhoneBundle checks a lost-ok unlock's bundle and token against the
// vault's current relay key and mailbox: the address the phone's first
// hs.init goes to, and the token it deposits with.
func checkPhoneBundle(t *testing.T, m *Manager, uo *AltUnlockOutcome) {
	t.Helper()
	bo, err := strictjson.ParseObject(uo.VaultBundle)
	if err != nil {
		t.Fatal(err)
	}
	pr, err := handshake.ParsePrincipal(bo)
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, pub := m.st.Relay.Mailbox, pubOf(m.keys.relay)
	if pr.Relay.Mailbox != cur || !bytes.Equal(pr.Relay.PK, pub) || pr.Relay.URL != m.st.Relay.URL {
		t.Fatalf("bundle relay %+v, vault's %s", pr.Relay, cur)
	}
	c, err := relayauth.ParseToken(uo.Token, pub)
	if err != nil || c.Iss != cur || c.Aud != m.relayBase() {
		t.Fatalf("token for %q (aud %q): %v; vault's mailbox %s", c.Iss, c.Aud, err, cur)
	}
}

// A lost-ok unlock that confirms a release move makes no relay-key
// attempt before its bundle: only its ok completes the move (the old
// header deleted), so it is answered ok, with the vault's address as it
// stands; Start's attempt follows.
func TestRelayRotPhoneUnlockConfirmingAMoveIsAnsweredOK(t *testing.T) {
	io := newInheritedOpen(t, func(rw *rotWorld, k, _ string) {
		delete(rw.live, k)
		rw.register = []error{relayErr(503, "")}
	})
	io.m.mu.Lock()
	io.m.st.ReleaseMove = &ReleaseMove{To: testRelease.PCR0, ToRelease: testRelease.Number, From: "earlier-release", ApprovedBy: "dev1"}
	io.m.dirty = true
	if err := io.m.persist(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	io.m.mu.Unlock()
	if err := io.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	io.rw.mu.Lock()
	io.rw.register = []error{relayErr(503, "")}
	io.rw.mu.Unlock()
	rot0, reg0 := io.rw.log()
	m, uo := io.f.phoneUnlock(t)
	defer m.Crash()
	if rot, reg := io.rw.log(); len(rot) != len(rot0) || len(reg) != len(reg0) {
		t.Fatalf("an attempt before the bundle: %v %v", rot[len(rot0):], reg[len(reg0):])
	}
	m.mu.Lock()
	move := m.st.ReleaseMove
	m.mu.Unlock()
	if move != nil || !bundleNames(uo.VaultBundle, io.k) {
		t.Fatalf("move %+v", move)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rot, _ := io.rw.log(); len(rot) == len(rot0) {
		t.Fatal("Start made no attempt")
	}
}

// A lost-ok unlock whose attempt gets a 429 is answered retry, with the
// retry_after (stored with the key by the attempt's write); an unlock
// while it runs makes no attempt and is answered retry with what is left.
func TestRelayRotPhoneUnlockRetryCarriesTheRetryAfter(t *testing.T) {
	io := newInheritedOpen(t, func(rw *rotWorld, k, _ string) {
		delete(rw.live, k)
		rw.register = []error{relayErr(503, "")}
	})
	if err := io.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	io.rw.mu.Lock()
	io.rw.register = []error{&relayclient.Error{Status: 429, Code: "rate_limited", RetryAfter: 600}}
	io.rw.mu.Unlock()
	if m, uo := io.f.phoneUnlockOut(); m != nil || uo.Code != CodeRetry || uo.RetryAfter != 600*time.Second {
		t.Fatalf("unlock answered 429: %+v", uo)
	}
	_, reg0 := io.rw.log()
	io.f.clock = io.f.clock.Add(time.Minute)
	if m, uo := io.f.phoneUnlockOut(); m != nil || uo.Code != CodeRetry || uo.RetryAfter != 540*time.Second {
		t.Fatalf("unlock while the retry_after runs: %+v", uo)
	}
	if _, reg := io.rw.log(); len(reg) != len(reg0) {
		t.Fatal("an attempt while the retry_after runs")
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
	io.f.clock = io.f.clock.Add(freshMailboxWait) // registered: the wait of a mailbox made afresh
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
	// The sooner retry, once its wait has run, then the wait of a mailbox
	// made afresh.
	for _, d := range []time.Duration{2 * time.Minute, freshMailboxWait} {
		f.clock = f.clock.Add(d)
		if err := m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
			t.Fatal(err)
		}
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

// The attempt before the bundle stores the state and then its header put
// fails: the retry reports the header_seq last stored, not the one the
// failed put used, so the phone's floor never passes the stored header
// and its next unlock is not refused as a rollback.
func TestRelayRotPhoneUnlockRetryReportsTheStoredHeaderSeq(t *testing.T) {
	io := newInheritedOpen(t, func(rw *rotWorld, k, _ string) {
		delete(rw.live, k)
		rw.register = []error{relayErr(503, "")}
	})
	if err := io.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	stored := io.f.storedHeader().HeaderSeq
	io.f.st.mu.Lock()
	// The unlock's count passes (§11.8); the attempt's header put fails (its
	// state put succeeds); the count's reset after it passes.
	io.f.st.passHeader, io.f.st.failHeader = 1, 1
	io.f.st.mu.Unlock()
	m, uo := io.f.phoneUnlockOut()
	if m != nil || uo.Code != CodeRetry || uo.RetryAfter != freshMailboxWait {
		t.Fatalf("unlock 1: %+v", uo)
	}
	if h := io.f.storedHeader(); uo.HeaderSeq != h.HeaderSeq || h.HeaderSeq <= stored || h.Backoff != (Backoff{}) {
		t.Fatalf("retry reports header_seq %d; stored %d (before %d), backoff %+v", uo.HeaderSeq, h.HeaderSeq, stored, h.Backoff)
	}
	io.f.clock = io.f.clock.Add(freshMailboxWait)
	m, uo = io.f.phoneUnlockFloor(uo.HeaderSeq)
	if m == nil || !uo.OK {
		t.Fatalf("the next unlock with the phone's floor: %+v", uo)
	}
	m.Crash()
}
