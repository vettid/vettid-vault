package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vault/counter"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/suite"
)

// The recovery open of release R (VAULT-MESSAGING 0.33.0 §11.14.6) in the
// vault: counted before it is tested, the same wrong pair once, the waits,
// the quiet period, the counter cut, busy, not_armed, stored_mismatch, and
// a completion that replaces the DEK for the new phone's secret.

func (b *rBackupFeature) RecoverFromBackup(_ *Session, pw []byte) error {
	if string(pw) != rPW {
		return errors.New("bad password")
	}
	return nil
}

type openFixture struct {
	*rFixture
	clock   time.Time // the enclave's clock
	code    string
	phone   ed25519.PrivateKey
	phoneUS []byte
}

func newOpenFixture(t *testing.T) *openFixture { return newOpenFixtureWith(t, nil) }

// newOpenFixtureWith runs before (if set) on the armed, running vault
// before it is locked and the recovery requested.
func newOpenFixtureWith(t *testing.T, before func(*openFixture)) *openFixture {
	f := &openFixture{rFixture: newRFixture(t), clock: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}
	f.opts.Now = func() time.Time { return f.clock }
	f.m.opt.Now, f.m.now = f.opts.Now, f.opts.Now
	if st := f.arm(); st != RecoveryArmed {
		t.Fatal(st)
	}
	f.m.mu.Lock()
	f.m.markPresent(context.Background(), f.clock)
	f.m.mu.Unlock()
	f.flush()
	if before != nil {
		before(f)
	}
	if err := f.m.Lock(context.Background()); err != nil && before == nil {
		t.Fatal(err)
	}
	f.bucket.Advance(73 * time.Hour)
	f.clock = f.clock.Add(73 * time.Hour)
	p := HeaderParams{Options: f.opts, VaultID: f.vid, UserGUID: "u1"}
	if err := headerTx(context.Background(), p, func(h *Header, _ time.Time) (bool, error) {
		h.HasCredential = true
		yes := true
		h.CredentialBackup = &yes
		return false, nil
	}); err != nil {
		t.Fatal(err)
	}
	code, rec, earliest, err := RecoveryRequest(context.Background(), p, recID, RecoveryDelay)
	if err != nil || earliest || !rec.NotBefore.Equal(f.clock.Add(24*time.Hour)) {
		t.Fatalf("request: %v %v %v", err, earliest, rec.NotBefore)
	}
	f.code = code
	f.clock = f.clock.Add(25 * time.Hour)
	f.bucket.Advance(25 * time.Hour)
	f.phone = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, 32))
	app := RecoveryApp{IK: f.phone.Public().(ed25519.PublicKey), KEM: bytes.Repeat([]byte{1}, 32), RelayPK: bytes.Repeat([]byte{2}, 32),
		APIKey: []byte("phone-app-key")}
	if err := RecoveryRegister(context.Background(), p, recID, code, app, ok); err != nil {
		t.Fatal(err)
	}
	f.phoneUS = bytes.Repeat([]byte{0x77}, 32)
	return f
}

func (f *openFixture) open(pin, pw string) (*Manager, *RecoveryOpenOutcome) {
	return RecoveryOpen(context.Background(), RecoveryOpenParams{Options: f.opts, VaultID: f.vid, UserGUID: "u1", RecoveryID: recID,
		DeviceIK: f.phone.Public().(ed25519.PublicKey), PIN: pin, Password: []byte(pw), UnlockSecret: f.phoneUS,
		VerifyDevice: func(*RecoveryApp) (json.RawMessage, error) { return json.RawMessage(`{}`), nil },
		Manifest: func(uint64) (*ManifestView, error) {
			return &ManifestView{Serial: 1, Own: ReleaseEntry{PCR0: testRelease.PCR0, Number: testRelease.Number}}, nil
		}})
}

func TestRecoveryOpenSchedule(t *testing.T) {
	f := newOpenFixture(t)
	m, out := f.open(testPIN, "wrong password one")
	if m != nil || out.Code != OpenWrong || !out.Counted || out.Used != 1 {
		t.Fatalf("first wrong: %+v", out)
	}
	m, out = f.open(testPIN, "wrong password one")
	if m != nil || out.Code != OpenWrongAgain || out.Counted {
		t.Fatalf("same wrong pair: %+v", out)
	}
	m, out = f.open("000000", rPW)
	if m != nil || out.Code != OpenWrong || out.Used != 2 || out.RetryAt.IsZero() || out.Expires.IsZero() {
		t.Fatalf("second wrong: %+v", out)
	}
	m, out = f.open(testPIN, rPW)
	if m != nil || out.Code != OpenWait || out.Counted {
		t.Fatalf("during the wait: %+v", out)
	}
	f.bucket.Advance(10 * time.Minute)
	m, out = f.open(testPIN, rPW)
	if m == nil || !out.OK || !out.Counted || out.Used != 3 {
		t.Fatalf("right pair: %+v", out)
	}
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := f.storedHeader()
	if h.Recovery != nil || h.Next != nil || h.DEKVersion != 2 || h.Rec.Generation != 1 || h.Rec.Wrap == nil || h.Rec.Wrap.OpenerDEKVersion != 2 {
		t.Fatalf("after the completion: %+v %+v", h.Recovery, h.Rec)
	}
	if string(h.AppKey) != "phone-app-key" {
		t.Fatal("the phone's app key is not the vault's")
	}
	// The ten are for the life of the pair: the success gives none back.
	v, _ := f.m.counter().Status(context.Background(), 1)
	if v.Used != 3 || !v.Attempts[2].Success {
		t.Fatalf("counter: %+v", v)
	}
	// The old app's secret opens nothing; the phone's does.
	f.mustRefuse(testPIN, testSecret, CodeDeviceSecret)
	f.mustUnlock(testPIN, f.phoneUS).Crash()
}

func TestRecoveryOpenRefusals(t *testing.T) {
	f := newOpenFixture(t)
	f.permit = false
	if m, out := f.open(testPIN, rPW); m != nil || out.Code != OpenBusy || out.Counted {
		t.Fatalf("busy: %+v", out)
	}
	f.permit = true
	f.bucket.SetDown(true)
	if m, out := f.open(testPIN, rPW); m != nil || out.Code != OpenCounterDown || out.Counted {
		t.Fatalf("counter down: %+v", out)
	}
	f.bucket.SetDown(false)
	// The member was present within 72 hours: quiet, nothing used.
	n, _ := f.storedHeader(), 0
	_ = n
	f.mPresent()
	if m, out := f.open(testPIN, rPW); m != nil || out.Code != OpenQuiet || out.Counted || out.RetryAt.IsZero() {
		t.Fatalf("quiet: %+v", out)
	}
	if v, _ := f.m.counter().Status(context.Background(), 1); v.Used != 0 {
		t.Fatal("a refusal used an attempt")
	}
}

// mPresent records a presence through the vault's counter now.
func (f *openFixture) mPresent() {
	if _, err := f.m.counter().MarkPresent(context.Background()); err != nil {
		f.t.Fatal(err)
	}
}

func TestRecoveryOpenStoredMismatchAndNotArmed(t *testing.T) {
	f := newOpenFixture(t)
	ctx := context.Background()
	// A state written under another DEK than the header's opener: the
	// stored state and header do not belong together; nothing is used.
	sk := store.StateKey(f.vid)
	sb, sv, _ := f.st.Get(ctx, sk)
	bad := bytes.Clone(sb)
	bad[16]++ // dek_version + 1 in the clear prefix
	if _, err := f.st.Put(ctx, sk, bad, sv); err != nil {
		t.Fatal(err)
	}
	if m, out := f.open(testPIN, rPW); m != nil || out.Code != OpenStoredMismatch || out.Counted {
		t.Fatalf("mismatch: %+v", out)
	}
	_, sv, _ = f.st.Get(ctx, sk)
	if _, err := f.st.Put(ctx, sk, sb, sv); err != nil {
		t.Fatal(err)
	}
	// Not armed: no wrap for the generation.
	p := HeaderParams{Options: f.opts, VaultID: f.vid, UserGUID: "u1"}
	if err := headerTx(ctx, p, func(h *Header, _ time.Time) (bool, error) {
		h.Rec.Wrap = nil
		return false, nil
	}); err != nil {
		t.Fatal(err)
	}
	if m, out := f.open(testPIN, rPW); m != nil || out.Code != OpenNotArmed {
		t.Fatalf("not armed: %+v", out)
	}
	_ = suite.Wipe
}

// A replacement stopped after its step 2 (here a renew whose step 3 was
// lost; a transfer whose new phone was then lost is the same shape): the
// `next` part's opener of the same generation opens the stored state
// (§11.14.6 step 2).
func TestRecoveryOpenThroughNextOpener(t *testing.T) {
	f := newOpenFixtureWith(t, func(f *openFixture) {
		if err := f.change(SecretChange{Reason: ReplaceRenew, PIN: testPIN, Password: []byte(rPW), NewUnlockSecret: testSecret2}); err != nil {
			t.Fatal(err)
		}
		f.st.failHeader = 1
		f.m.mu.Lock()
		_ = f.m.persist(context.Background(), false)
		f.m.mu.Unlock()
		f.m.Crash()
	})
	h := f.storedHeader()
	if h.Next == nil || f.storedStateVersion() != h.Next.DEKVersion || h.Rec.Wrap.OpenerDEKVersion == f.storedStateVersion() {
		t.Fatal("not a replacement stopped after step 2")
	}
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("open: %+v", out)
	}
	_ = m.Lock(context.Background())
	if h := f.storedHeader(); h.Next != nil || h.DEKVersion != 3 || h.Rec.Wrap.OpenerDEKVersion != 3 {
		t.Fatalf("after: next %v dek %d", h.Next, h.DEKVersion)
	}
}

// A right open whose completion fails at its state write (step 2): the
// attempt is used; the open again goes through the `next` wrap with no
// new attempt (§11.14.2, §11.14.6).
func TestRecoveryOpenResumesAfterStep1(t *testing.T) {
	f := newOpenFixture(t)
	f.st.failState = 1
	m, out := f.open(testPIN, rPW)
	if m != nil || out.OK || out.Code != OpenRetry || !out.Counted || out.Used != 1 {
		t.Fatalf("failed completion: %+v", out)
	}
	if h := f.storedHeader(); h.Next == nil || h.Next.Reason != ReplaceRecovery {
		t.Fatal("step 1 not stored")
	}
	m, out = f.open(testPIN, rPW)
	if m == nil || !out.OK || out.Counted {
		t.Fatalf("resume: %+v", out)
	}
	_ = m.Lock(context.Background())
	if v, _ := f.m.counter().Status(context.Background(), 1); v.Used != 1 {
		t.Fatalf("the resume used an attempt: %d", v.Used)
	}
	if h := f.storedHeader(); h.Next != nil || h.Recovery != nil {
		t.Fatal("not completed")
	}
}

// A presence recorded between the status and the spend (an owner check, or
// a status answer held back): the attempt is used and the wrap is never
// tried (quiet, not wrong).
func TestRecoveryOpenPresenceBetweenStatusAndSpend(t *testing.T) {
	f := newOpenFixture(t)
	done := false
	f.bucket.SetHook(func(op, key string) {
		if op == "put_create" && !done {
			done = true
			f.mPresent()
		}
	})
	m, out := f.open(testPIN, "a wrong password here")
	if m != nil || out.Code != OpenQuiet || !out.Counted {
		t.Fatalf("open: %+v", out)
	}
}

// VAULT-MESSAGING 0.33.2 §11.14.4: the recovery open's counter locks its
// tokens for Options.RecoveryCounterLock (the measured channel's period),
// and for 100 years when it is zero.
func TestRecoveryOpenUsesTheCounterLock(t *testing.T) {
	f := newOpenFixture(t)
	ctx := context.Background()
	lock := func(n int) time.Duration {
		t.Helper()
		name := f.m.counter().Names().Token(1, n)
		l, err := f.bucket.List(ctx, name)
		if err != nil || len(l.Entries) != 1 {
			t.Fatalf("token %d: %v %+v", n, err, l)
		}
		r, err := f.bucket.GetRetention(ctx, name, l.Entries[0].VersionID)
		if err != nil {
			t.Fatal(err)
		}
		return r.Until.Sub(l.Entries[0].LastModified)
	}
	if _, out := f.open(testPIN, "wrong password one"); !out.Counted || out.Used != 1 {
		t.Fatalf("first: %+v", out)
	}
	if got := lock(1); got != counter.LongLock {
		t.Fatalf("no option: token locked for %v", got)
	}
	f.opts.RecoveryCounterLock = 24 * time.Hour
	if _, out := f.open("000000", rPW); !out.Counted || out.Used != 2 {
		t.Fatalf("second: %+v", out)
	}
	// Attempt 2's wait is one unit (10 minutes): the day, or the wait plus
	// a day if longer.
	if got, want := lock(2), 10*time.Minute+counter.TokenWaitMargin; got != want {
		t.Fatalf("staging period: token locked for %v, want %v", got, want)
	}
}

// VAULT-MESSAGING §3.6.1 "What else starts the clock": the successful
// recovery open (§11.14.6) starts the owner check's clock at the scaled
// interval and ends a hold, written with the completion's state; a wrong
// pair or a completion whose state write fails starts nothing, and the
// repeat through the `next` wrap that completes starts it then.

// heldBefore leaves the running vault held: its deadline passed a day ago.
func heldBefore(f *openFixture) {
	f.m.mu.Lock()
	rec := f.m.ownerCheckRecord()
	rec.LastAt, rec.Deadline, rec.Gate = f.clock.Add(-48*time.Hour), f.clock.Add(-24*time.Hour), OwnerCheckHeld
	f.m.dirty = true
	f.m.mu.Unlock()
	f.flush()
}

// storedOwnerCheck is the owner check record of the stored state, read
// with dek.
func (f *openFixture) storedOwnerCheck(dek []byte) *OwnerCheck {
	f.t.Helper()
	b, _, err := f.st.Get(context.Background(), store.StateKey(f.vid))
	if err != nil {
		f.t.Fatal(err)
	}
	pt, _, err := decryptState(dek, f.vid, b)
	if err != nil {
		f.t.Fatal(err)
	}
	var st State
	if err := json.Unmarshal(pt, &st); err != nil {
		f.t.Fatal(err)
	}
	return st.OwnerCheck
}

func TestRecoveryOpenStartsTheOwnerCheckClock(t *testing.T) {
	var old time.Time
	f := newOpenFixtureWith(t, func(f *openFixture) { heldBefore(f); old = f.m.st.OwnerCheck.Deadline })
	f.opts.TimeScale = 24
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("open: %+v", out)
	}
	at := f.clock.UTC().Truncate(time.Millisecond)
	want := at.Add(DefaultOwnerCheckInterval / 24)
	if rec := m.st.OwnerCheck; rec == nil || !rec.Deadline.Equal(want) || !rec.LastAt.Equal(at) || rec.Gate != "" || rec.Failures != 0 {
		t.Fatalf("after the open: %+v, want deadline %v (old %v)", rec, want, old)
	}
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Stored: the recovered phone's unlock finds the new deadline, not held.
	f.clock = f.clock.Add(time.Minute)
	m2 := f.mustUnlock(testPIN, f.phoneUS)
	defer m2.Crash()
	if rec := m2.st.OwnerCheck; rec == nil || !rec.Deadline.Equal(want) || rec.Gate != "" {
		t.Fatalf("stored: %+v, want deadline %v", rec, want)
	}
}

func TestRecoveryOpenFailureKeepsTheOwnerCheckClock(t *testing.T) {
	var old time.Time
	var dek []byte
	f := newOpenFixtureWith(t, func(f *openFixture) {
		heldBefore(f)
		old, dek = f.m.st.OwnerCheck.Deadline, bytes.Clone(f.m.dek)
	})
	// A wrong pair: nothing written to the state.
	if m, out := f.open(testPIN, "wrong password one"); m != nil || out.Code != OpenWrong {
		t.Fatalf("wrong: %+v", out)
	}
	if rec := f.storedOwnerCheck(dek); !rec.Deadline.Equal(old) || rec.Gate != OwnerCheckHeld {
		t.Fatalf("after a wrong pair: %+v", rec)
	}
	// A right pair whose completion fails at its state write (step 2):
	// the state, still under the old DEK, keeps the old deadline and the hold.
	f.st.failState = 1
	m, out := f.open(testPIN, rPW)
	if m != nil || out.Code != OpenRetry || !out.Counted {
		t.Fatalf("failed completion: %+v", out)
	}
	if rec := f.storedOwnerCheck(dek); !rec.Deadline.Equal(old) || rec.Gate != OwnerCheckHeld {
		t.Fatalf("after a failed completion: %+v", rec)
	}
	// The repeat through the `next` wrap completes and starts the clock.
	f.clock = f.clock.Add(time.Hour)
	m, out = f.open(testPIN, rPW)
	if m == nil || !out.OK || out.Counted {
		t.Fatalf("resume: %+v", out)
	}
	defer m.Crash()
	want := f.clock.UTC().Truncate(time.Millisecond).Add(DefaultOwnerCheckInterval)
	if rec := m.st.OwnerCheck; !rec.Deadline.Equal(want) || rec.Gate != "" {
		t.Fatalf("after the resume: %+v, want %v", rec, want)
	}
}
