//go:build devenclave && e2e

package e2e

import (
	"context"
	"crypto/ecdh"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/altchan"
)

// The Android package is the channel's release constant (VAULT-MESSAGING
// 0.26.0 §11.7, §11.10.8 "Android package"): it is checked where an
// attestation is verified (enrollment, a transfer's hs.init, a recovery's
// register) and nowhere else. This is the move of the staging vaults at
// S10: a vault enrolled under the old package keeps unlocking and can
// approve release moves on an image that pins only the new one, while the
// old build can no longer enroll, receive a transfer or register for a
// recovery there.

const (
	oldPackage = enclavetest.AndroidPackage // what the test policy pins, as S1 to S9 pinned com.vettid.app
	newPackage = "com.vettid.app.staging"   // what the later releases of this test pin, as S10 does
)

// startWithPackage starts release r with a device policy that accepts
// only pkg, and the world's movable recovery clock.
func startWithPackage(t *testing.T, aw *acWorld, r enclavetest.ReleaseSpec, pkg string, recNow func() time.Time) {
	t.Helper()
	aw.w.AddRelease(r)
	if _, err := aw.w.StartWith(r.Number, func(c *enclave.Config) {
		p := *c.DeviceAttest
		p.AndroidPackage = pkg
		c.DeviceAttest = &p
		c.RecoveryNow = recNow
	}); err != nil {
		t.Fatal(err)
	}
}

func moveTo(t *testing.T, aw *acWorld, a *acApp, r enclavetest.ReleaseSpec) {
	t.Helper()
	aw.lock(a)
	res := aw.mustUnlock(a, acPIN, client.UnlockOptions{Approve: &client.Approval{To: r.PCR0Hex(), ToRelease: r.Number}}, "")
	if !res.OK || res.Update == nil || res.Update.Result != "moved" {
		t.Fatalf("move to %d: %+v %+v", r.Number, res, res.Update)
	}
	if res = aw.mustUnlock(a, acPIN, client.UnlockOptions{}, ""); !res.OK || res.Release != r.PCR0Hex() {
		t.Fatalf("unlock under %d: %+v", r.Number, res)
	}
	aw.status(a)
}

// requestRecoveryAt is requestRecovery on the instance the vault is
// sealed to.
func requestRecoveryAt(t *testing.T, aw *acWorld, a *acApp) *altchan.RecoveryCode {
	t.Helper()
	bk, err := ecdh.P256().GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rid, resp := aw.w.Recovery(ctxT(t, 60*time.Second), aw.instanceOf(a), a.vid, a.guid, bk.PublicKey().Bytes())
	c, err := altchan.OpenRecoveryCode(bk, resp.Envelope, a.vid, rid)
	if err != nil {
		t.Fatalf("open code: %v", err)
	}
	qr, err := altchan.ParseRecoveryQR(altchan.RecoveryQR(c))
	if err != nil {
		t.Fatal(err)
	}
	return qr
}

func TestAndroidPackagePerChannel(t *testing.T) {
	aw, off := newRecWorld(t) // release 3 pins the old package
	recNow := func() time.Time { return time.Now().Add(time.Duration(off.Load())) }
	ctx := ctxT(t, 300*time.Second)
	oldBuild := func(seed byte) client.Attester {
		return enclavetest.NewAndroidAttester(seed, enclavetest.AndroidOptions{Package: oldPackage})
	}
	newBuild := func(seed byte) client.Attester {
		return enclavetest.NewAndroidAttester(seed, enclavetest.AndroidOptions{Package: newPackage})
	}
	a := aw.newApp("member-pkg", oldBuild(0xa1))
	if r := aw.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	// Release 3 never accepts the new build: it can attach to nothing
	// that is still sealed to the old release.
	early := aw.newApp("member-early", newBuild(0xa2))
	if r := aw.enroll(early, acPIN); r.OK || r.Code != "attestation" {
		t.Fatalf("the new package on the old release: %+v", r)
	}

	// Release 4 pins only the new package. The old build approves the
	// move (verified by release 3) and keeps unlocking there: an unlock
	// checks the stored key's signature, not the package again.
	startWithPackage(t, aw, rel4, newPackage, recNow)
	moveTo(t, aw, a, rel4)
	// A release approval verified by an image that pins another package
	// than the binding was made under: the move from 4 to 5.
	startWithPackage(t, aw, rel5, newPackage, recNow)
	moveTo(t, aw, a, rel5)
	aw.lock(a)
	if r := aw.mustUnlock(a, acPIN, client.UnlockOptions{}, ""); !r.OK {
		t.Fatalf("the old build's unlock on a release that pins the new package: %+v", r)
	}
	aw.status(a)

	// Enrollment: the other channel's package is refused, the channel's
	// own accepted.
	x := aw.newApp("member-x", oldBuild(0xa3))
	if r := aw.enroll(x, acPIN); r.OK || r.Code != "attestation" {
		t.Fatalf("enrollment under the old package: %+v", r)
	}
	y := aw.newApp("member-y", newBuild(0xa4))
	if r := aw.enroll(y, acPIN); !r.OK {
		t.Fatalf("enrollment under the new package: %+v", r)
	}

	// A transfer: the old build as the new app is dropped at hs.init
	// (nothing reaches the holder), the new build is accepted.
	id, link, err := a.dev.TransferCreate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c := aw.newApp("phone-old-build", oldBuild(0xa5))
	quiet, cancel := context.WithTimeout(ctx, 4*time.Second)
	if _, err := c.dev.PairAttested(quiet, link, c.att); err == nil {
		t.Fatal("the vault answered a transfer hs.init from an app of the other package")
	}
	cancel()
	quiet, cancel = context.WithTimeout(ctx, time.Second)
	if _, err := a.dev.WaitEvent(quiet, "device.transfer.pending", nil); err == nil {
		t.Fatal("a transfer to an app of the other package reached the holder")
	}
	cancel()
	au, err := a.dev.AuditList(ctx, map[string]any{"kinds": []string{"device"}}, false)
	if err != nil || !strings.Contains(string(au["entries"]), `"device.transfer.attestation_failed"`) {
		t.Fatalf("no device.transfer.attestation_failed in the audit log: %v", err)
	}
	// The link's claim is spent; the holder ends that transfer and
	// starts another for the new build.
	if err := a.dev.TransferReject(ctx, id); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if id, link, err = a.dev.TransferCreate(ctx); err != nil {
		t.Fatal(err)
	}
	b := aw.newApp("phone-new-build", newBuild(0xa6))
	if _, err := b.dev.PairAttested(ctx, link, b.att); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, a.dev, "device.transfer.pending", has("transfer_id", id))
	if err := a.dev.TransferApprove(ctx, id, acPIN, credPW); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := b.dev.AwaitPaired(ctx); err != nil {
		t.Fatalf("new app: %v", err)
	}
	b.guid, b.vid = b.dev.UserGUID(), a.vid
	if err := b.dev.CredentialFetch(ctx); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	aw.lock(b)
	if r := aw.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !r.OK {
		t.Fatalf("the new build's unlock: %+v", r)
	}
	aw.status(b)
	aw.lock(b)

	// A recovery's register: the old build is refused, the new accepted.
	qr := requestRecoveryAt(t, aw, b)
	off.Store(int64(24*time.Hour + time.Minute))
	d := aw.newApp(b.guid, oldBuild(0xa7))
	d.vid = b.vid
	if res := register(t, aw, d, qr); res.OK || res.Code != "attestation" {
		t.Fatalf("register under the old package: %+v", res)
	}
	e := aw.newApp(b.guid, newBuild(0xa8))
	e.vid = b.vid
	if res := register(t, aw, e, qr); !res.OK {
		t.Fatalf("register under the new package: %+v", res)
	}
	if r := aw.mustUnlock(e, acPIN, client.UnlockOptions{}, ""); !r.OK {
		t.Fatalf("the recovering app's unlock: %+v", r)
	}
}
