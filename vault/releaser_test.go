package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/countertest"
	"github.com/vettid/vettid-vault/vault/counter"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/recovery"
)

// Release R in a running vault (VAULT-MESSAGING 0.33.0 §11.14.1-§11.14.3,
// §11.14.5, §11.14.9): the phone's secret at unlock, the three writes of a
// DEK replacement and every place a run can end, arming, new generations,
// presence. The recovery wrap's derivation needs vettid_testcost.

const (
	rPW    = "violet-Kestrel-91-moss"
	rNewPW = "glacier mango tuesday piano"
	rPIN2  = "246802"
)

var testSecret2 = bytes.Repeat([]byte{0x45}, 32)

func requireTestCost(t *testing.T) {
	t.Helper()
	if !recovery.TestCost {
		t.Skip("the recovery wrap at 1 GiB: run with -tags vettid_testcost")
	}
}

// rBackupFeature stands in for the credential feature's backup copy.
type rBackupFeature struct{ on bool }

func (b *rBackupFeature) Name() string                   { return "backuptest" }
func (b *rBackupFeature) Types() []TypeSpec              { return nil }
func (b *rBackupFeature) Load(json.RawMessage) error     { return nil }
func (b *rBackupFeature) Save() (json.RawMessage, error) { return json.RawMessage(`{}`), nil }
func (b *rBackupFeature) HasBackupCopy() bool            { return b.on }
func (b *rBackupFeature) Handle(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) {
	return nil, nil
}

// faultStore loses or fails writes of the header on request.
type faultStore struct {
	store.Store
	mu sync.Mutex
	// failHeader fails the next n header writes before storing; loseHeader
	// answers the next n header writes "written" without keeping them.
	failHeader, loseHeader int
	// failState fails the next n state writes before storing.
	failState int
	// passHeader lets the next n header writes through before failHeader
	// and loseHeader apply.
	passHeader int
}

func (f *faultStore) Put(ctx context.Context, key string, data []byte, ifMatch store.Version) (store.Version, error) {
	f.mu.Lock()
	hdr := strings.Contains(key, "/header/")
	if hdr && f.passHeader > 0 {
		f.passHeader--
		f.mu.Unlock()
		return f.Store.Put(ctx, key, data, ifMatch)
	}
	fail, lose := hdr && f.failHeader > 0, hdr && f.loseHeader > 0
	if !hdr && strings.HasSuffix(key, "/state") && f.failState > 0 {
		f.failState--
		fail = true
	}
	if fail {
		f.failHeader--
	}
	if lose {
		f.loseHeader--
	}
	f.mu.Unlock()
	if fail {
		return "", errors.New("faultstore: write failed")
	}
	if lose {
		_, v, err := f.Store.Get(ctx, key)
		if err != nil {
			return "", err
		}
		return v + "-lost", nil
	}
	return f.Store.Put(ctx, key, data, ifMatch)
}

type rFixture struct {
	t      *testing.T
	st     *faultStore
	bucket *countertest.Bucket
	opts   Options
	m      *Manager
	vid    string
	backup *rBackupFeature
	permit bool
}

func newRFixture(t *testing.T) *rFixture {
	t.Helper()
	requireTestCost(t)
	f := &rFixture{t: t, st: &faultStore{Store: store.NewMemory()}, bucket: countertest.New(time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)),
		backup: &rBackupFeature{on: true}, permit: true}
	f.opts = Options{Store: f.st, Sealer: testSealer{key: bytes.Repeat([]byte{7}, 32)}, Release: testRelease,
		Relay:   func(base string, key ed25519.PrivateKey) Relay { return &stubRelay{base: base, key: key} },
		Counter: f.bucket, Features: []Feature{f.backup}, RecoveryWaitUnit: 10 * time.Minute,
		HeavyPermit: func(context.Context) (func(), bool) { return func() {}, f.permit }}
	k, _ := MinKDF()
	m, err := Create(context.Background(), CreateParams{Options: f.opts, UserGUID: "u1", PIN: testPIN, UnlockSecret: testSecret, KDF: k, RelayURL: "https://relay.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	f.m, f.vid = m, m.VaultID()
	return f
}

func (f *rFixture) unlock(pin string, secret []byte) (*Manager, *AltUnlockOutcome) {
	return UnlockAlt(context.Background(), AltUnlockParams{Options: f.opts, VaultID: f.vid, PIN: pin, UnlockSecret: secret, pinOnly: true})
}

func (f *rFixture) flush() {
	f.t.Helper()
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	if err := f.m.persist(context.Background(), false); err != nil {
		f.t.Fatal(err)
	}
}

func (f *rFixture) arm() string {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	return f.m.arm(context.Background(), testPIN, []byte(rPW), 0, f.backup.on, f.m.now())
}

func (f *rFixture) change(c SecretChange) error {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	c.BackupCopy = f.backup.on
	return f.m.changeSecrets(context.Background(), c, f.m.now())
}

func (f *rFixture) storedHeader() *Header {
	f.t.Helper()
	ctx := context.Background()
	b, _, err := f.st.Get(ctx, store.HeaderKey(f.vid, testRelease.PCR0))
	if err != nil {
		f.t.Fatal(err)
	}
	h, err := unsealHeader(ctx, f.opts.Sealer, b, f.vid, testRelease.PCR0)
	if err != nil {
		f.t.Fatal(err)
	}
	return h
}

func (f *rFixture) storedStateVersion() uint64 {
	b, _, _ := f.st.Get(context.Background(), store.StateKey(f.vid))
	v, _ := StateDEKVersion(b)
	return v
}

func TestUnlockNeedsThePhoneSecret(t *testing.T) {
	f := newFixture(t)
	if err := f.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	try := func(secret []byte) *AltUnlockOutcome {
		m, out := UnlockAlt(context.Background(), AltUnlockParams{Options: f.opts, VaultID: f.vid, PIN: testPIN, UnlockSecret: secret, pinOnly: true})
		if m != nil {
			_ = m.Lock(context.Background())
		}
		return out
	}
	if out := try(nil); out.Code != CodeBadRequest {
		t.Fatalf("no secret: %s", out.Code)
	}
	if out := try(testSecret[:31]); out.Code != CodeBadRequest {
		t.Fatalf("31 bytes: %s", out.Code)
	}
	for i := 0; i < 5; i++ {
		if out := try(testSecret2); out.Code != CodeDeviceSecret {
			t.Fatalf("wrong secret: %s", out.Code)
		}
	}
	if h := f.storedHeader(); h.Backoff.Failures != 0 {
		t.Fatal("device_secret counted as a PIN failure")
	}
	if _, _, err := f.unlock("654321", 0, 0); !errors.Is(err, ErrBadPIN) {
		t.Fatal("wrong PIN not bad_pin")
	}
	if out := try(testSecret); !out.OK {
		t.Fatalf("right secret: %s", out.Code)
	}
}

func (f *fixture) storedHeader() *Header {
	b, _, _ := f.store.Get(context.Background(), store.HeaderKey(f.vid, testRelease.PCR0))
	h, _ := unsealHeader(context.Background(), f.opts.Sealer, b, f.vid, testRelease.PCR0)
	return h
}

func TestArming(t *testing.T) {
	f := newRFixture(t)
	if st := f.arm(); st != RecoveryArmed || f.m.hdr.Rec.Generation != 1 || f.m.hdr.Rec.Wrap == nil {
		t.Fatalf("arm: %s %+v", st, f.m.hdr.Rec)
	}
	w := f.m.hdr.Rec.Wrap
	// The wrap opens with the pair, not with either alone; its opener
	// gives the DEK.
	rk, err := f.m.openWrap(w, testPIN, []byte(rPW))
	if err != nil {
		t.Fatal(err)
	}
	d, err := recovery.OpenOpener(rk, w.Opener, f.vid, 1, f.m.hdr.DEKVersion)
	if err != nil || !bytes.Equal(d, f.m.dek) {
		t.Fatal("opener")
	}
	if _, err := f.m.openWrap(w, "000000", []byte(rPW)); err == nil {
		t.Fatal("opened with a wrong PIN")
	}
	if _, err := f.m.openWrap(w, testPIN, []byte(rNewPW)); err == nil {
		t.Fatal("opened with a wrong password")
	}
	if f.arm() != RecoveryArmed || f.m.hdr.Rec.Generation != 1 {
		t.Fatal("armed twice")
	}
	f.flush()
	if h := f.storedHeader(); h.Rec.Wrap == nil || h.Rec.Wrap.KDF.MemoryKiB < 8*1024 {
		t.Fatal("wrap not stored")
	}
}

func TestArmingRefusals(t *testing.T) {
	// No permit: needs_check, nothing changed.
	f := newRFixture(t)
	f.permit = false
	if st := f.arm(); st != RecoveryNeedsCheck || f.m.hdr.Rec.Wrap != nil {
		t.Fatalf("busy: %s", st)
	}
	// Counter unreachable: needs_check.
	f.permit = true
	f.bucket.SetDown(true)
	if st := f.arm(); st != RecoveryNeedsCheck {
		t.Fatalf("counter down: %s", st)
	}
	f.bucket.SetDown(false)
	// A weak password is never armed: change_required.
	f.m.mu.Lock()
	st := f.m.arm(context.Background(), testPIN, []byte("password1234"), 0, true, f.m.now())
	f.m.mu.Unlock()
	if st != RecoveryChangeRequired {
		t.Fatalf("weak password: %s", st)
	}
	// Backup off: off.
	g := newRFixture(t)
	g.backup.on = false
	if st := g.arm(); st != RecoveryOff {
		t.Fatalf("backup off: %s", st)
	}
}

// pinChange runs a PIN change from an armed vault up to step 1.
func (f *rFixture) pinChange() {
	f.t.Helper()
	if st := f.arm(); st != RecoveryArmed {
		f.t.Fatal(st)
	}
	f.flush()
	if err := f.change(SecretChange{Reason: ReplacePIN, PIN: testPIN, NewPIN: rPIN2, Password: []byte(rPW), NewUnlockSecret: testSecret2}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *rFixture) mustUnlock(pin string, secret []byte) *Manager {
	f.t.Helper()
	m, out := f.unlock(pin, secret)
	if !out.OK {
		f.t.Fatalf("unlock %s: %s", pin, out.Code)
	}
	return m
}

func (f *rFixture) mustRefuse(pin string, secret []byte, code string) {
	f.t.Helper()
	m, out := f.unlock(pin, secret)
	if m != nil {
		m.Crash()
	}
	if out.OK || out.Code != code {
		f.t.Fatalf("unlock %s: ok %v code %s, want %s", pin, out.OK, out.Code, code)
	}
}

func TestPINChangeCompletes(t *testing.T) {
	f := newRFixture(t)
	f.pinChange()
	h := f.storedHeader()
	if h.Next == nil || h.Next.Reason != ReplacePIN || h.Next.DEKVersion != 2 || h.Next.Wrap == nil || h.Next.Wrap.Generation != 2 {
		t.Fatalf("step 1 header %+v", h.Next)
	}
	// The old generation is closed at the counter before step 1.
	v, err := f.m.counter().Status(context.Background(), 1)
	if err != nil || !v.Closed {
		t.Fatal("generation 1 not closed")
	}
	f.flush() // steps 2 and 3
	h = f.storedHeader()
	if h.Next != nil || h.DEKVersion != 2 || h.Rec.Generation != 2 || h.Rec.Wrap == nil || f.storedStateVersion() != 2 {
		t.Fatalf("after step 3: %+v", h)
	}
	f.m.Crash()
	f.mustRefuse(testPIN, testSecret, CodeDeviceSecret) // the old pair opens no current wrap
	f.mustRefuse(testPIN, testSecret2, CodeBadPIN)
	m := f.mustUnlock(rPIN2, testSecret2)
	m.Crash()
}

// The run ends after step 1 (§11.14.2, row 2): the old phone and PIN open
// DEK_0 and drop the `next` part; the new PIN and secret reach DEK_0
// through the `next` wrap and the change completes.
func TestPINChangeEndsAfterStep1(t *testing.T) {
	for _, who := range []string{"old", "new"} {
		t.Run(who, func(t *testing.T) {
			f := newRFixture(t)
			f.pinChange()
			f.m.Crash()
			if f.storedStateVersion() != 1 || f.storedHeader().Next == nil {
				t.Fatal("not the state of row 2")
			}
			if who == "old" {
				m := f.mustUnlock(testPIN, testSecret)
				m.mu.Lock()
				_ = m.persist(context.Background(), false)
				m.mu.Unlock()
				m.Crash()
				if h := f.storedHeader(); h.Next != nil || h.DEKVersion != 1 {
					t.Fatal("the next part was not dropped")
				}
				// A generation closed by a change that did not complete.
				if h := f.storedHeader(); !h.Rec.ClosedUnchanged || h.Rec.Wrap != nil {
					t.Fatalf("%+v", h.Rec)
				}
				return
			}
			m := f.mustUnlock(rPIN2, testSecret2)
			m.mu.Lock()
			_ = m.persist(context.Background(), false)
			m.mu.Unlock()
			m.Crash()
			if h := f.storedHeader(); h.Next != nil || h.DEKVersion != 2 || f.storedStateVersion() != 2 {
				t.Fatal("the change was not completed")
			}
			f.mustRefuse(testPIN, testSecret, CodeDeviceSecret)
		})
	}
}

// The run ends after step 2, before step 3 (row 3): only the new PIN and
// secret open; step 3 is done at that unlock.
func TestPINChangeEndsAfterStep2(t *testing.T) {
	f := newRFixture(t)
	f.pinChange()
	f.st.failHeader = 1
	f.m.mu.Lock()
	err := f.m.persist(context.Background(), false)
	f.m.mu.Unlock()
	if err == nil {
		t.Fatal("step 3 did not fail")
	}
	f.m.Crash()
	if f.storedStateVersion() != 2 || f.storedHeader().Next == nil {
		t.Fatal("not the state of row 3")
	}
	f.mustRefuse(testPIN, testSecret, CodeDeviceSecret)
	m := f.mustUnlock(rPIN2, testSecret2)
	m.mu.Lock()
	_ = m.persist(context.Background(), false)
	m.mu.Unlock()
	m.Crash()
	if h := f.storedHeader(); h.Next != nil || h.DEKVersion != 2 {
		t.Fatal("step 3 not done at the unlock")
	}
}

// Step 1 dropped: a failed write, and a store that answers "written" but
// does not keep it, both answer retry with nothing changed.
func TestStep1Dropped(t *testing.T) {
	for _, mode := range []string{"fail", "lose"} {
		t.Run(mode, func(t *testing.T) {
			f := newRFixture(t)
			f.arm()
			f.flush()
			if mode == "fail" {
				f.st.failHeader = 1
			} else {
				f.st.loseHeader = 1
			}
			err := f.change(SecretChange{Reason: ReplaceRenew, PIN: testPIN, Password: []byte(rPW), NewUnlockSecret: testSecret2})
			var he *HandlerError
			if !errors.As(err, &he) || he.Code != "retry" {
				t.Fatalf("%v", err)
			}
			if f.m.repl != nil || f.m.hdr.Next != nil || f.m.hdr.Rec.Generation != 1 {
				t.Fatal("something changed")
			}
		})
	}
}

// An older header served after the change opens nothing newer (§11.14.2,
// "The host serves the old header again later").
func TestOldHeaderOpensNothingNewer(t *testing.T) {
	f := newRFixture(t)
	f.arm()
	f.flush()
	ctx := context.Background()
	hk := store.HeaderKey(f.vid, testRelease.PCR0)
	oldHdr, _, _ := f.st.Get(ctx, hk)
	if err := f.change(SecretChange{Reason: ReplaceRenew, PIN: testPIN, Password: []byte(rPW), NewUnlockSecret: testSecret2}); err != nil {
		t.Fatal(err)
	}
	f.flush()
	f.m.Crash()
	_, v, _ := f.st.Get(ctx, hk)
	if _, err := f.st.Store.Put(ctx, hk, oldHdr, v); err != nil {
		t.Fatal(err)
	}
	f.mustRefuse(testPIN, testSecret, CodeRollback)
	f.mustRefuse(testPIN, testSecret2, CodeDeviceSecret)
}

func TestChangeRefusals(t *testing.T) {
	f := newRFixture(t)
	f.arm()
	f.flush()
	f.permit = false
	err := f.change(SecretChange{Reason: ReplacePassword, PIN: testPIN, Password: []byte(rPW), NewPassword: []byte(rNewPW)})
	if he, ok := err.(*HandlerError); !ok || he.Code != "busy" {
		t.Fatalf("busy: %v", err)
	}
	f.permit = true
	f.bucket.SetDown(true)
	err = f.change(SecretChange{Reason: ReplacePassword, PIN: testPIN, Password: []byte(rPW), NewPassword: []byte(rNewPW)})
	if he, ok := err.(*HandlerError); !ok || he.Code != "counter_unavailable" {
		t.Fatalf("counter: %v", err)
	}
	if f.m.hdr.Rec.Generation != 1 || f.m.hdr.Rec.Wrap == nil || f.m.repl != nil {
		t.Fatal("a refused change changed something")
	}
	f.bucket.SetDown(false)
	if err := f.change(SecretChange{Reason: ReplacePassword, PIN: testPIN, Password: []byte(rPW), NewPassword: []byte(rNewPW)}); err != nil {
		t.Fatal(err)
	}
	f.flush()
	w := f.m.hdr.Rec.Wrap
	if w == nil || w.Generation != 2 {
		t.Fatal("password change did not arm the next generation")
	}
	if _, err := f.m.openWrap(w, testPIN, []byte(rNewPW)); err != nil {
		t.Fatal("the new wrap is not for the new pair")
	}
	// The PIN and the secret are unchanged by a password change.
	f.m.Crash()
	f.mustUnlock(testPIN, testSecret).Crash()
}

func TestBackupOffClosesTheGeneration(t *testing.T) {
	f := newRFixture(t)
	f.arm()
	f.bucket.SetDown(true)
	f.m.mu.Lock()
	err := f.m.closeForBackupOff(context.Background(), f.m.now())
	f.m.mu.Unlock()
	if err == nil {
		t.Fatal("closed with the counter down")
	}
	f.bucket.SetDown(false)
	f.m.mu.Lock()
	err = f.m.closeForBackupOff(context.Background(), f.m.now())
	f.m.mu.Unlock()
	if err != nil || f.m.hdr.Rec.Wrap != nil || f.m.hdr.Rec.Generation != 2 || !f.m.hdr.Rec.ClosedUnchanged {
		t.Fatalf("%v %+v", err, f.m.hdr.Rec)
	}
	// Turned on again with unchanged secrets: armed only if the closed
	// generation has no used attempt.
	if st := f.arm(); st != RecoveryArmed {
		t.Fatalf("re-arm: %s", st)
	}
}

func TestPresence(t *testing.T) {
	f := newRFixture(t)
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	now := f.m.now()
	if !f.m.markPresent(context.Background(), now) || f.m.rec.presentAt.IsZero() {
		t.Fatal("presence not recorded")
	}
	f.bucket.SetDown(true)
	if f.m.markPresent(context.Background(), now) || f.m.rec.presentRetryUntil.IsZero() {
		t.Fatal("no retry after a failed presence")
	}
	f.bucket.SetDown(false)
	f.m.recoveryHousekeeping(context.Background(), now.Add(2*time.Minute))
	if !f.m.rec.presentRetryUntil.IsZero() {
		t.Fatal("the retry did not record the presence")
	}
}

// F1: a host serves a header from before the arming; a change then still
// closes generation 1 (armed in the later header against the old pair)
// and never reuses its number.
func TestChangeClosesTheArmedGenerationOfALaterHeader(t *testing.T) {
	f := newRFixture(t)
	ctx := context.Background()
	f.flush()
	hk := store.HeaderKey(f.vid, testRelease.PCR0)
	pre, _, _ := f.st.Get(ctx, hk)
	if f.arm() != RecoveryArmed {
		t.Fatal("not armed")
	}
	f.flush()
	f.m.Crash()
	_, v, _ := f.st.Get(ctx, hk)
	if _, err := f.st.Store.Put(ctx, hk, pre, v); err != nil {
		t.Fatal(err)
	}
	f.m = f.mustUnlock(testPIN, testSecret)
	if f.m.hdr.Rec.Generation != 0 {
		t.Fatal("not the pre-arming header")
	}
	if err := f.change(SecretChange{Reason: ReplacePassword, PIN: testPIN, Password: []byte(rPW), NewPassword: []byte(rNewPW)}); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.m.counter().Status(ctx, 1); !st.Closed {
		t.Fatal("generation 1 left open")
	}
	f.flush()
	if w := f.m.hdr.Rec.Wrap; w == nil || w.Generation != 2 {
		t.Fatalf("new wrap %+v", w)
	}
	// Backup off closes the current generation even without a wrap.
	f.m.mu.Lock()
	f.m.hdr.Rec.Wrap = nil
	err := f.m.closeForBackupOff(ctx, f.m.now())
	f.m.mu.Unlock()
	if st, _ := f.m.counter().Status(ctx, 2); err != nil || !st.Closed || f.m.hdr.Rec.Generation != 3 {
		t.Fatalf("backup off: %v", err)
	}
}

// F9: arming moves past a generation the counter shows closed.
func TestArmMovesPastAClosedGeneration(t *testing.T) {
	f := newRFixture(t)
	if err := f.m.counter().Close(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if st := f.arm(); st != RecoveryArmed || f.m.hdr.Rec.Generation != 2 {
		t.Fatalf("arm: %s, generation %d", st, f.m.hdr.Rec.Generation)
	}
}

// The write-order table (§11.14.2) for a password change: after step 1 the
// unchanged PIN and secret open DEK_0 and drop `next` (the closed
// generation stays closed); after step 2 they open DEK_1 and promote.
func TestPasswordChangeWriteOrder(t *testing.T) {
	for _, after := range []int{1, 2} {
		f := newRFixture(t)
		f.arm()
		f.flush()
		if err := f.change(SecretChange{Reason: ReplacePassword, PIN: testPIN, Password: []byte(rPW), NewPassword: []byte(rNewPW)}); err != nil {
			t.Fatal(err)
		}
		if after == 2 {
			f.st.failHeader = 1
			f.m.mu.Lock()
			_ = f.m.persist(context.Background(), false)
			f.m.mu.Unlock()
		}
		f.m.Crash()
		m := f.mustUnlock(testPIN, testSecret)
		m.mu.Lock()
		_ = m.persist(context.Background(), false)
		m.mu.Unlock()
		m.Crash()
		h := f.storedHeader()
		switch after {
		case 1:
			if h.Next != nil || h.DEKVersion != 1 || h.Rec.Wrap != nil || !h.Rec.ClosedUnchanged {
				t.Fatalf("after step 1: %+v", h.Rec)
			}
		case 2:
			if h.Next != nil || h.DEKVersion != 2 || h.Rec.Wrap == nil || h.Rec.Wrap.Generation != 2 {
				t.Fatalf("after step 2: %+v", h.Rec)
			}
		}
	}
}

// F1: a next generation the counter already knows (another timeline) is
// never used: both are closed, the change answers retry, and the next
// change arms after them.
func TestChangeMovesPastAKnownGeneration(t *testing.T) {
	f := newRFixture(t)
	ctx := context.Background()
	f.arm()
	f.flush()
	if err := f.m.counter().Close(ctx, 2); err != nil {
		t.Fatal(err)
	}
	err := f.change(SecretChange{Reason: ReplacePassword, PIN: testPIN, Password: []byte(rPW), NewPassword: []byte(rNewPW)})
	if he, ok := err.(*HandlerError); !ok || he.Code != "retry" {
		t.Fatalf("%v", err)
	}
	if st, _ := f.m.counter().Status(ctx, 1); !st.Closed || f.m.hdr.Rec.Generation != 3 || f.m.hdr.Rec.Wrap != nil {
		t.Fatalf("generation %d", f.m.hdr.Rec.Generation)
	}
	if err := f.change(SecretChange{Reason: ReplacePassword, PIN: testPIN, Password: []byte(rPW), NewPassword: []byte(rNewPW)}); err != nil {
		t.Fatal(err)
	}
	f.flush()
	if w := f.m.hdr.Rec.Wrap; w == nil || w.Generation != 4 {
		t.Fatalf("wrap %+v", w)
	}
}

// VAULT-MESSAGING 0.33.2 §11.14.4: the vault's counter locks token,
// success and close records for Options.RecoveryCounterLock, the measured
// channel's period (staging a day), and for 100 years when it is zero.
func TestCounterRecordLockFromOptions(t *testing.T) {
	f := newRFixture(t)
	ctx := context.Background()
	for i, tc := range []struct {
		opt, want time.Duration
	}{{0, counter.LongLock}, {24 * time.Hour, 24 * time.Hour}, {counter.LongLock, counter.LongLock}} {
		f.m.mu.Lock()
		f.m.opt.RecoveryCounterLock, f.m.rec.ctr = tc.opt, nil
		c := f.m.counter()
		f.m.mu.Unlock()
		if c.RecordLock() != tc.want {
			t.Fatalf("option %v: record lock %v", tc.opt, c.RecordLock())
		}
		g := uint64(100 + i)
		if err := c.Close(ctx, g); err != nil {
			t.Fatal(err)
		}
		name := c.Names().Close(g)
		l, err := f.bucket.List(ctx, name)
		if err != nil || len(l.Entries) != 1 {
			t.Fatalf("%v %+v", err, l)
		}
		r, err := f.bucket.GetRetention(ctx, name, l.Entries[0].VersionID)
		if err != nil || !r.Until.Equal(l.Entries[0].LastModified.Add(tc.want)) {
			t.Fatalf("option %v: close locked until %v (written %v)", tc.opt, r.Until, l.Entries[0].LastModified)
		}
	}
}
