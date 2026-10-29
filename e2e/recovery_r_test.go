//go:build devenclave && e2e

package e2e

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/features/all"
	"github.com/vettid/vettid-vault/internal/countertest"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/altchan"
)

// Recovery from release R (VAULT-MESSAGING 0.33.0 §11.14) end to end: the
// real relay, the enclave instance with its vault, the reference client as
// both phones, and the stand-in S3 counter (whose clock is the only
// recovery clock the test moves besides the enclave's delay clock).

const recPW = credPW

// recKeyRand, if set by a test before the world starts, draws the seeds of
// the vault's key rotations (a draw that fails is a rotation that cannot
// be made).
var recKeyRand func(n int) ([]byte, error)

type recR struct {
	*acWorld
	bucket *countertest.Bucket
	off    *atomic.Int64 // the enclave's recovery clock offset
}

func newRecR(t *testing.T) *recR { return newRecRWith(t, 0) }

// newRecRWith starts the world; quiet, if set, replaces the release's
// quiet period (tests of the code and the register, not of the period).
func newRecRWith(t *testing.T, quiet time.Duration) *recR { return newRecRStore(t, quiet, nil) }

// newRecRStore is newRecRWith whose enclave stores through wrap(store),
// if wrap is set (fault injection).
func newRecRStore(t *testing.T, quiet time.Duration, wrap func(store.Store) store.Store) *recR {
	t.Helper()
	r := relaytest.Start(t, nil)
	w := enclavetest.NewWorld(time.Now, r.URL)
	if wrap != nil {
		w.Store = wrap(w.Store)
	}
	aw := &acWorld{t: t, w: w, relay: r.URL, trust: w.Trust()}
	b := countertest.NewLive()
	w.VaultOptions = vault.Options{PollWait: time.Second, Counter: b, KeyRand: recKeyRand,
		Relay: func(base string, key ed25519.PrivateKey) vault.Relay {
			return vault.NewClientRelay(base, key, nil, time.Now)
		}}
	w.Features = all.Dev
	w.AddRelease(rel3)
	off := &atomic.Int64{}
	if _, err := w.StartWith(3, func(c *enclave.Config) {
		c.RecoveryNow = func() time.Time { return time.Now().Add(time.Duration(off.Load())) }
		if quiet > 0 {
			c.Recovery.Quiet = quiet
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	return &recR{acWorld: aw, bucket: b, off: off}
}

func (rr *recR) advance(d time.Duration) {
	rr.bucket.Advance(d)
	rr.off.Add(int64(d))
}

func (rr *recR) request(a *acApp) (*altchan.RecoveryCode, *enclave.Response) {
	t := rr.t
	bk, err := ecdh.P256().GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rid, resp := rr.w.Recovery(ctxT(t, 60*time.Second), rr.w.Instance(3), a.vid, a.guid, bk.PublicKey().Bytes())
	c, err := altchan.OpenRecoveryCode(bk, resp.Envelope, a.vid, rid)
	if err != nil {
		t.Fatalf("open code: %v", err)
	}
	if c.Error != "" {
		return c, resp
	}
	qr, err := altchan.ParseRecoveryQR(altchan.RecoveryQR(c))
	if err != nil {
		t.Fatal(err)
	}
	qr.NotBefore, qr.Expires = c.NotBefore, c.Expires
	return qr, resp
}

func (rr *recR) register(b *acApp, qr *altchan.RecoveryCode) {
	t := rr.t
	e, in := rr.enclave(b, "", false)
	req, err := b.dev.BuildRecoveryRegister(b.guid, qr, e, b.att)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rr.w.Post(ctxT(t, 60*time.Second), in, enclave.OpRecoveryRegister, b.vid, b.guid, req)
	if err != nil {
		t.Fatal(err)
	}
	r, err := b.dev.OpenRecoveryResult(resp.Envelope)
	if err != nil || !r.OK || resp.Code != enclave.CodeRecoveryRegistered {
		t.Fatalf("register: %v %+v %s", err, r, resp.Code)
	}
}

func (rr *recR) open(b *acApp, pin, pw string) (*altchan.RecoveryOpenResult, *enclave.Response) {
	t := rr.t
	t.Helper()
	e, in := rr.enclave(b, "", false)
	_, m, err := b.dev.VerifyManifest(rr.w.Served(), rr.trust)
	if err != nil {
		t.Fatal(err)
	}
	req, err := b.dev.BuildRecoveryOpen(b.guid, pin, pw, e, m, b.att)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rr.w.Post(ctxT(t, 60*time.Second), in, enclave.OpRecoveryOpen, b.vid, b.guid, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Envelope) != altchan.ResultEnvelopeSize {
		t.Fatalf("result size %d", len(resp.Envelope))
	}
	r, err := b.dev.OpenRecoveryOpenResult(resp.Envelope)
	if err != nil {
		t.Fatalf("open result: %v", err)
	}
	return r, resp
}

// The new phone of member a, registered for a recovery whose code is
// valid.
func (rr *recR) setup(guid string) (a, b *acApp) {
	t := rr.t
	a = rr.newApp(guid, enclavetest.NewAndroidAttester(0x61, enclavetest.AndroidOptions{}))
	if r := rr.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	// The member was present at credential.create; three days pass.
	rr.advance(73 * time.Hour)
	qr, resp := rr.request(a)
	if resp.Clear.NotBefore.IsZero() || resp.Clear.Earliest {
		t.Fatalf("clear not_before: %+v", resp.Clear)
	}
	waitEvent(t, a.dev, "vault.locking", has("reason", "recovery"))
	rr.advance(25 * time.Hour)
	b = rr.newApp(guid, enclavetest.NewAndroidAttester(0x62, enclavetest.AndroidOptions{}))
	b.vid = a.vid
	rr.register(b, qr)
	return a, b
}

func TestRecoveryR(t *testing.T) {
	rr := newRecR(t)
	a, b := rr.setup("member-rr")
	r, resp := rr.open(b, acPIN, "a wrong password here")
	if r.OK || r.Code != vault.OpenWrong || !r.Counted || !r.AttemptUsed || r.Used != 1 || resp.Code != enclave.CodeRecoveryAttempt {
		t.Fatalf("wrong: %+v %s", r, resp.Code)
	}
	if r, resp = rr.open(b, acPIN, "a wrong password here"); r.Code != vault.OpenWrongAgain || r.AttemptUsed || resp.Code != "" {
		t.Fatalf("same wrong pair: %+v %s", r, resp.Code)
	}
	r, resp = rr.open(b, "000000", recPW)
	if r.Code != vault.OpenWrong || !r.AttemptUsed || r.Used != 2 || r.RetryAt.IsZero() || resp.Clear.RetryAt.IsZero() || resp.Clear.Expires.IsZero() {
		t.Fatalf("second wrong: %+v %+v", r, resp.Clear)
	}
	if r, _ = rr.open(b, acPIN, recPW); r.Code != vault.OpenWait || r.AttemptUsed || !r.Counted || r.Used != 2 {
		t.Fatalf("during the wait: %+v", r)
	}
	rr.advance(10 * time.Minute) // the test release's wait unit
	r, resp = rr.open(b, acPIN, recPW)
	if !r.OK || !r.AttemptUsed || r.Used != 3 || resp.Code != enclave.CodeRecoveryAttempt {
		t.Fatalf("right pair: %+v %s", r, resp.Code)
	}
	// 0.29.0, release L (owner decision 2026-10-23, VAULT-LOCK Q1): a
	// recovery open is an opening of the vault and names it.
	if !altchan.ValidUnlockID(r.UnlockID) || r.UnlockID != b.dev.UnlockID() {
		t.Fatalf("recovery open unlock_id %q (device %q)", r.UnlockID, b.dev.UnlockID())
	}
	ctx := ctxT(t, 20*time.Second)
	if err := b.dev.CompleteRecoveryHandshake(ctx); err != nil {
		if m := rr.instanceOf(a).Manager(a.vid); m != nil {
			for _, e := range m.Audit() {
				t.Logf("audit %s %s", e.Event, e.PeerID)
			}
		} else {
			t.Log("no running vault")
		}
		t.Fatalf("handshake: %v", err)
	}
	if err := b.dev.CredentialFetch(ctx); err != nil {
		t.Fatalf("credential.get as the holder: %v", err)
	}
	// From storage: the new phone unlocks with its own secret; the old
	// phone's keys open nothing.
	rr.lock(b)
	if u := rr.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !u.OK {
		t.Fatalf("the recovered phone's unlock: %+v", u)
	}
	rr.lock(b)
	if u, err := rr.unlock(a, acPIN, client.UnlockOptions{}, ""); err == nil && u.OK {
		t.Fatal("the old phone unlocked after the recovery")
	}
}

func TestRecoveryRQuietAndCounter(t *testing.T) {
	rr := newRecR(t)
	a := rr.newApp("member-rq", enclavetest.NewAndroidAttester(0x63, enclavetest.AndroidOptions{}))
	if r := rr.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	// Present at credential.create: not_before is 72 hours away.
	qr, resp := rr.request(a)
	if d := time.Until(resp.Clear.NotBefore); d < 71*time.Hour {
		t.Fatalf("not_before in %v, want about 72 h", d)
	}
	_ = qr
	rr.advance(25 * time.Hour)
	b := rr.newApp("member-rq", enclavetest.NewAndroidAttester(0x64, enclavetest.AndroidOptions{}))
	b.vid = a.vid
	if _, err := b.dev.BuildRecoveryRegister(b.guid, qr, mustEnclave(rr, b), b.att); err != nil {
		t.Fatal(err)
	}
	// The code is not valid before not_before (the quiet period).
	rr.advance(48 * time.Hour)
	rr.register(b, qr)
	// The counter cut: counter_unavailable, nothing used.
	rr.bucket.SetDown(true)
	if r, resp := rr.open(b, acPIN, recPW); r.Code != vault.OpenCounterDown || r.AttemptUsed || resp.Code != "" {
		t.Fatalf("counter down: %+v", r)
	}
	rr.bucket.SetDown(false)
	if r, _ := rr.open(b, acPIN, recPW); !r.OK || !r.AttemptUsed || r.Used != 1 {
		t.Fatalf("after the cut: %+v", r)
	}
}

func mustEnclave(rr *recR, b *acApp) *client.Enclave {
	e, _ := rr.enclave(b, "", false)
	return e
}

// The helpers of the tests that predate release R: a world whose quiet
// period does not delay the code (so the code is valid 24 h after the
// request), the portal's request, the register, and the open.

func newRecWorld(t *testing.T) (*acWorld, *atomic.Int64) {
	rr := newRecRWith(t, time.Nanosecond)
	return rr.acWorld, rr.off
}

func requestRecovery(t *testing.T, aw *acWorld, a *acApp) *altchan.RecoveryCode {
	t.Helper()
	qr, _ := (&recR{acWorld: aw}).request(a)
	return qr
}

func register(t *testing.T, aw *acWorld, b *acApp, qr *altchan.RecoveryCode) *altchan.RecoveryResult {
	t.Helper()
	e, in := aw.enclave(b, "", false)
	req, err := b.dev.BuildRecoveryRegister(b.guid, qr, e, b.att)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := aw.w.Post(ctxT(t, 60*time.Second), in, enclave.OpRecoveryRegister, b.vid, b.guid, req)
	if err != nil {
		t.Fatal(err)
	}
	r, err := b.dev.OpenRecoveryResult(resp.Envelope)
	if err != nil {
		t.Fatalf("recovery result: %v", err)
	}
	if want := map[bool]string{true: enclave.CodeRecoveryRegistered}[r.OK]; resp.Code != want {
		t.Fatalf("register answer code %q for %+v", resp.Code, r)
	}
	return r
}

func openRecovery(t *testing.T, aw *acWorld, b *acApp, pin, pw string) *altchan.RecoveryOpenResult {
	t.Helper()
	r, _ := (&recR{acWorld: aw}).open(b, pin, pw)
	return r
}

// A lost ok (owner decision of 2026-10-16, VAULT-MESSAGING 0.34.0
// §11.14.6): the phone never reads vault.recovery.open.result, so it has
// neither the bundle nor a token. Its own unlock (its secret and the PIN)
// carries the bundle again, also a second time (the first answer lost too),
// with no attempt used; the old phone's does not; after the phone's first
// handshake no unlock carries it.
func TestRecoveryRLostOK(t *testing.T) {
	rr := newRecR(t)
	a, b := rr.setup("member-lost")
	// The right pair; the answer is dropped on the way.
	e, in := rr.enclave(b, "", false)
	_, m, err := b.dev.VerifyManifest(rr.w.Served(), rr.trust)
	if err != nil {
		t.Fatal(err)
	}
	req, err := b.dev.BuildRecoveryOpen(b.guid, acPIN, recPW, e, m, b.att)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rr.w.Post(ctxT(t, 60*time.Second), in, enclave.OpRecoveryOpen, b.vid, b.guid, req)
	if err != nil || resp.Code != enclave.CodeRecoveryAttempt {
		t.Fatalf("open: %v %+v", err, resp)
	}
	if err := b.dev.CompleteRecoveryHandshake(ctxT(t, 5*time.Second)); err == nil {
		t.Fatal("a handshake without the bundle")
	}
	creates := rr.bucket.Calls(countertest.OpPutCreate)
	// The phone's unlock gets the bundle; the first answer is lost too, the
	// second carries it again.
	if u := rr.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !u.OK || len(u.VaultBundle) == 0 || u.Token == "" {
		t.Fatalf("first unlock after a lost ok: %+v", u)
	}
	rr.lock(b)
	u := rr.mustUnlock(b, acPIN, client.UnlockOptions{}, "")
	if !u.OK || len(u.VaultBundle) == 0 || u.Token == "" {
		t.Fatalf("second unlock after a lost ok: %+v", u)
	}
	// The old phone gets nothing.
	rr.lock(b)
	if ua, err := rr.unlock(a, acPIN, client.UnlockOptions{}, ""); err == nil && (ua.OK || len(ua.VaultBundle) > 0) {
		t.Fatalf("the old phone after the recovery: %+v", ua)
	}
	// No attempt used by the unlocks: the counter still shows one.
	if u := rr.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !u.OK {
		t.Fatalf("unlock: %+v", u)
	}
	ctx := ctxT(t, 20*time.Second)
	if err := b.dev.CompleteRecoveryHandshake(ctx); err != nil {
		t.Fatalf("handshake after the resumed ok: %v", err)
	}
	if err := b.dev.CredentialFetch(ctx); err != nil {
		t.Fatalf("credential.get as the holder: %v", err)
	}
	rr.lock(b)
	if u := rr.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !u.OK || len(u.VaultBundle) > 0 {
		t.Fatalf("an unlock after the pairing: %+v", u)
	}
	if n := rr.bucket.Calls(countertest.OpPutCreate); n != creates {
		t.Fatalf("the unlocks wrote %d counter records", n-creates)
	}
}
