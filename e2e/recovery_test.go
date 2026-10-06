//go:build devenclave && e2e

package e2e

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/features/all"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/altchan"
)

// recWorld is an alternate-channel world whose recovery clock can be
// moved past the 24 h delay (enclave.Config.RecoveryNow).
func newRecWorld(t *testing.T) (*acWorld, *atomic.Int64) {
	t.Helper()
	r := relaytest.Start(t, nil)
	w := enclavetest.NewWorld(time.Now, r.URL)
	aw := &acWorld{t: t, w: w, relay: r.URL, trust: w.Trust()}
	w.VaultOptions = vault.Options{PollWait: time.Second,
		Relay: func(base string, key ed25519.PrivateKey) vault.Relay {
			return vault.NewClientRelay(base, key, nil, time.Now)
		}}
	w.Features = all.Dev
	w.AddRelease(rel3)
	off := &atomic.Int64{}
	if _, err := w.StartWith(3, func(c *enclave.Config) {
		c.RecoveryNow = func() time.Time { return time.Now().Add(time.Duration(off.Load())) }
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	return aw, off
}

// requestRecovery plays the portal: a browser key, the request, and the
// sealed code from the response slot.
func requestRecovery(t *testing.T, aw *acWorld, a *acApp) *altchan.RecoveryCode {
	t.Helper()
	bk, err := ecdh.P256().GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rid, resp := aw.w.Recovery(ctxT(t, 60*time.Second), aw.w.Instance(3), a.vid, a.guid, bk.PublicKey().Bytes())
	if len(resp.Envelope) != altchan.ResultEnvelopeSize {
		t.Fatalf("sealed code size %d", len(resp.Envelope))
	}
	c, err := altchan.OpenRecoveryCode(bk, resp.Envelope, a.vid, rid)
	if err != nil {
		t.Fatalf("open code: %v", err)
	}
	if d := time.Until(c.NotBefore); d < 23*time.Hour || d > 25*time.Hour {
		t.Fatalf("not_before in %v", d)
	}
	qr, err := altchan.ParseRecoveryQR(altchan.RecoveryQR(c))
	if err != nil {
		t.Fatal(err)
	}
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
	// §11.5, §11.11.3 (0.10.6): the clear marker exactly on {"ok": true}.
	if want := map[bool]string{true: enclave.CodeRecoveryRegistered}[r.OK]; resp.Code != want {
		t.Fatalf("register answer code %q for %+v", resp.Code, r)
	}
	return r
}

const recPW = credPW

// §11.11: request → the running vault locks (vault.locking{recovery}) →
// other devices are refused with recovery_pending → cancel (portal/email,
// then from an owner device with its PIN) → the code is dead.
func TestRecoveryCancel(t *testing.T) {
	aw, _ := newRecWorld(t)
	a := aw.newApp("member-rc", enclavetest.NewAndroidAttester(0x61, enclavetest.AndroidOptions{}))
	if r := aw.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	qr := requestRecovery(t, aw, a)
	waitEvent(t, a.dev, "vault.locking", has("reason", "recovery"))
	if aw.instanceOf(a).Manager(a.vid) != nil {
		t.Fatal("vault still running after the recovery request")
	}
	if r := aw.mustUnlock(a, acPIN, client.UnlockOptions{}, ""); r.OK || r.Code != vault.CodeRecoveryPending {
		t.Fatalf("unlock during recovery: %+v", r)
	}
	// Cancel from the portal or the email link.
	aw.w.RecoveryCancel(ctxT(t, 30*time.Second), aw.w.Instance(3), a.vid, a.guid)
	if r := aw.mustUnlock(a, acPIN, client.UnlockOptions{}, ""); !r.OK || r.CredentialBackup != nil || len(r.VaultBundle) != 0 {
		t.Fatalf("unlock after cancel: %+v", r)
	}
	aw.lock(a)
	// A second request, cancelled by the owner device with its PIN.
	requestRecovery(t, aw, a)
	r := aw.mustUnlock(a, acPIN, client.UnlockOptions{CancelRecovery: true}, "")
	if !r.OK || !r.RecoveryCancelled {
		t.Fatalf("cancel by unlock: %+v", r)
	}
	aw.status(a)
	aw.lock(a)
	// Neither code works any more.
	b := aw.newApp(a.guid, enclavetest.NewIOSAttester(0x71, enclavetest.IOSOptions{}))
	b.vid = a.vid
	if res := register(t, aw, b, qr); res.OK || res.Code != vault.CodeRecoveryNone {
		t.Fatalf("cancelled code: %+v", res)
	}
}

// §11.11: the whole recovery: request (vault locked) → too early → 24 h →
// wrong code → register (device attestation) → code reuse refused → wrong
// PIN (enclave backoff) → PIN unlock → restricted until the credential
// password (wrong first) → the credential is handed over, re-sealed.
func TestRecoveryFlow(t *testing.T) {
	aw, off := newRecWorld(t)
	a := aw.newApp("member-rf", enclavetest.NewAndroidAttester(0x62, enclavetest.AndroidOptions{}))
	if r := aw.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	ctx := ctxT(t, 120*time.Second)
	sid, _, err := a.dev.ItemPutCritical(ctx, recPW, "", 0, nil, client.ItemContent{Name: "seed",
		Fields: []client.ItemField{{Label: "Words", Kind: "multiline", Value: "abandon abandon about"}}})
	if err != nil {
		t.Fatal(err)
	}
	qr := requestRecovery(t, aw, a)

	b := aw.newApp(a.guid, enclavetest.NewIOSAttester(0x72, enclavetest.IOSOptions{}))
	b.vid = a.vid
	if res := register(t, aw, b, qr); res.Code != vault.CodeRecoveryEarly {
		t.Fatalf("before the delay: %+v", res)
	}
	off.Store(int64(24*time.Hour + time.Minute))
	bad := *qr
	bad.Code = strings.Repeat("0", 32)
	if res := register(t, aw, b, &bad); res.Code != vault.CodeRecoveryCode {
		t.Fatalf("wrong code: %+v", res)
	}
	if res := register(t, aw, b, qr); !res.OK {
		t.Fatalf("register: %+v", res)
	}
	c := aw.newApp(a.guid, enclavetest.NewAndroidAttester(0x63, enclavetest.AndroidOptions{}))
	c.vid = a.vid
	if res := register(t, aw, c, qr); res.Code != vault.CodeRecoveryUsed {
		t.Fatalf("code reused: %+v", res)
	}
	// The PIN, under the enclave's backoff.
	if r := aw.mustUnlock(b, "999999", client.UnlockOptions{}, ""); r.OK || r.Code != vault.CodeBadPIN {
		t.Fatalf("wrong PIN: %+v", r)
	}
	r := aw.mustUnlock(b, acPIN, client.UnlockOptions{}, "")
	if !r.OK || len(r.VaultBundle) == 0 {
		t.Fatalf("recovered unlock: %+v", r)
	}
	if err := b.dev.CompleteRecoveryHandshake(ctx); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	// Restricted until the password.
	if rr, err := b.dev.Request(ctx, "item.list", []byte(`{}`)); err != nil || rr.ErrorCode() != "forbidden" {
		t.Fatalf("recovering app listed items: %v %s", err, rr.ErrorCode())
	}
	if err := b.dev.CredentialRecover(ctx, "not the password"); client.Code(err) != "bad_password" {
		t.Fatalf("wrong password: %v", err)
	}
	if err := b.dev.CredentialRecover(ctx, recPW); err != nil {
		t.Fatalf("recover: %v", err)
	}
	v, err := b.dev.ItemRevealCritical(ctx, recPW, sid)
	if err != nil || !strings.Contains(string(v), "abandon abandon about") {
		t.Fatalf("critical item after recovery: %v", err)
	}
	if rr, err := b.dev.Request(ctx, "item.list", []byte(`{}`)); err != nil || !rr.OK() {
		t.Fatal("recovered app still restricted")
	}
	// The recovered app replaces the old one (0.9.0): one app.
	dl, err := b.dev.Request(ctx, "device.list", []byte(`{}`))
	if err != nil || strings.Count(string(dl.Body()), `"kind":"app"`) != 1 {
		t.Fatalf("devices: %s", dl.Body())
	}
	au, err := b.dev.AuditList(ctx, map[string]any{"kinds": []string{"recovery"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"recovery.requested", "recovery.bad_code", "recovery.registered", "recovery.completed"} {
		if !strings.Contains(string(au["entries"]), `"`+k+`"`) {
			t.Errorf("audit lacks %s: %s", k, au["entries"])
		}
	}
}

// §11.11.2: a code expires 24 h after it becomes usable.
func TestRecoveryExpiry(t *testing.T) {
	aw, off := newRecWorld(t)
	a := aw.newApp("member-rx", enclavetest.NewAndroidAttester(0x64, enclavetest.AndroidOptions{}))
	if r := aw.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	qr := requestRecovery(t, aw, a)
	off.Store(int64(48*time.Hour + time.Minute))
	b := aw.newApp(a.guid, enclavetest.NewAndroidAttester(0x66, enclavetest.AndroidOptions{}))
	b.vid = a.vid
	if res := register(t, aw, b, qr); res.Code != vault.CodeRecoveryExpired {
		t.Fatalf("expired code: %+v", res)
	}
	// The expired recovery is gone: the owner device unlocks again.
	if r := aw.mustUnlock(a, acPIN, client.UnlockOptions{}, ""); !r.OK {
		t.Fatalf("unlock after expiry: %+v", r)
	}
}

// TestRecoveryBackupOffRefused (oneapp_test.go) covers the refusal of a recovery
// with credential.backup off (0.16.0).

// §3.5.7: a vault without a credential is restricted (and stays
// provisional) and cannot be recovered (§11.11.1).
func TestNoCredentialNoRecovery(t *testing.T) {
	aw, _ := newRecWorld(t)
	a := aw.newApp("member-nc", enclavetest.NewAndroidAttester(0x69, enclavetest.AndroidOptions{}))
	ctx := ctxT(t, 60*time.Second)
	e, in := aw.enclave(a, "", true)
	_, m, _ := a.dev.VerifyManifest(aw.w.Served(), aw.trust)
	req, err := a.dev.BuildEnroll(a.guid, acPIN, e, m, a.att)
	if err != nil {
		t.Fatal(err)
	}
	a.vid = randomID()
	if _, err := aw.w.Post(ctx, in, enclave.OpEnroll, a.vid, a.guid, req); err != nil {
		t.Fatal(err)
	}
	if err := a.dev.AwaitEnrolled(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.dev.CompleteEnrollment(ctx); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"vault.enroll.confirm", "device.pair.create", "connection.invite.create", "item.list"} {
		if rr, err := a.dev.Request(ctx, typ, []byte(`{"role":"desktop","ttl_seconds":600}`)); err != nil || rr.ErrorCode() != "credential_required" {
			t.Fatalf("%s without a credential: %v %q", typ, err, rr.ErrorCode())
		}
	}
	if rr, err := a.dev.Request(ctx, "vault.status", []byte(`{}`)); err != nil || !rr.OK() || !strings.Contains(string(rr.Body()), `"provisional":true`) {
		t.Fatal("vault.status")
	}
	aw.lock(a)
	bk, _ := ecdh.P256().GenerateKey(nil)
	rid, resp := aw.w.Recovery(ctx, aw.w.Instance(3), a.vid, a.guid, bk.PublicKey().Bytes())
	c, err := altchan.OpenRecoveryCode(bk, resp.Envelope, a.vid, rid)
	if err != nil || c.Error != "no_credential" || c.Code != "" || resp.Code != enclave.CodeRecoveryUnavailable {
		t.Fatalf("recovery of a vault without a credential: %v %+v %q", err, c, resp.Code)
	}
}
