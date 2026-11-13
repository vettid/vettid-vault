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
	// phone's first try pairs.
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
