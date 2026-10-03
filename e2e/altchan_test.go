//go:build devenclave && e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/features/all"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/suite"
)

// The V3a exit tests: the alternate channel in process, against the real
// relay binary, with the fake NSM, fake KMS and test attestation roots.

var (
	rel3 = enclavetest.ReleaseSpec{Number: 3, PCR0: 0xa3, PCR1: 0x13, PCR2: 0x23, Status: "active"}
	rel4 = enclavetest.ReleaseSpec{Number: 4, PCR0: 0xa4, PCR1: 0x14, PCR2: 0x24, Status: "active"}
	rel5 = enclavetest.ReleaseSpec{Number: 5, PCR0: 0xa5, PCR1: 0x15, PCR2: 0x25, Status: "active"}
)

type acWorld struct {
	t     *testing.T
	w     *enclavetest.World
	relay string
	trust client.Trust
}

func newACWorld(t *testing.T) *acWorld {
	t.Helper()
	r := relaytest.Start(t, nil)
	w := enclavetest.NewWorld(time.Now, r.URL)
	aw := &acWorld{t: t, w: w, relay: r.URL, trust: w.Trust()}
	w.VaultOptions = vault.Options{PollWait: time.Second,
		Relay: func(base string, key ed25519.PrivateKey) vault.Relay {
			return vault.NewClientRelay(base, key, nil, time.Now)
		}}
	w.Features = all.Dev
	w.Stopped = func(id string, err error) { t.Logf("vault %s stopped: %v", id[:6], err) }
	w.AddRelease(rel3)
	if _, err := w.Start(3); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	return aw
}

type acApp struct {
	dev  *client.Device
	att  client.Attester
	guid string
	vid  string
}

func (aw *acWorld) newApp(guid string, att client.Attester) *acApp {
	aw.t.Helper()
	d, err := client.New(ctxT(aw.t, 30*time.Second), client.Config{Role: vault.KindApp, Name: guid, RelayURL: aw.relay,
		PollWait: time.Second, Trust: &aw.trust})
	if err != nil {
		aw.t.Fatal(err)
	}
	return &acApp{dev: d, att: att, guid: guid}
}

func (aw *acWorld) enclave(a *acApp, release string, enroll bool) (*client.Enclave, *enclave.Instance) {
	aw.t.Helper()
	desc, att, in, err := aw.w.Enclave(a.vid, release)
	if err != nil {
		aw.t.Fatal(err)
	}
	_, m, err := a.dev.VerifyManifest(aw.w.Served(), aw.trust)
	if err != nil {
		aw.t.Fatal(err)
	}
	e, err := client.VerifyEnclave(desc, att, m, enroll, aw.trust, time.Now())
	if err != nil {
		aw.t.Fatalf("verify enclave: %v", err)
	}
	return e, in
}

func randomID() string {
	b, _ := suite.RandomBytes(16)
	return strings.ToLower(hexs(b))
}

func hexs(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, d[c>>4], d[c&15])
	}
	return string(out)
}

// enroll runs §11.3 completely: request, vault.enrolled with its
// attestation, the first app's handshake and vault.enroll.confirm.
func (aw *acWorld) enroll(a *acApp, pin string) *altchan.EnrollResult {
	t := aw.t
	t.Helper()
	ctx := ctxT(t, 60*time.Second)
	e, in := aw.enclave(a, "", true)
	served, _, _ := a.dev.VerifyManifest(aw.w.Served(), aw.trust)
	req, err := a.dev.BuildEnroll(a.guid, pin, e, served, a.att)
	if err != nil {
		t.Fatal(err)
	}
	vid := a.vid
	if vid == "" {
		vid = randomID()
	}
	resp, err := aw.w.Post(ctx, in, enclave.OpEnroll, vid, a.guid, req)
	if err != nil {
		t.Fatal(err)
	}
	r, err := a.dev.OpenEnrollResult(resp.Envelope, req.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK {
		return r
	}
	a.vid = vid
	if err := a.dev.AwaitEnrolled(ctx); err != nil {
		t.Fatalf("vault.enrolled: %v", err)
	}
	if err := a.dev.CompleteEnrollment(ctx); err != nil {
		t.Fatalf("first-app handshake: %v", err)
	}
	if rr, err := a.dev.Request(ctx, "vault.enroll.confirm", []byte(`{}`)); err != nil || !rr.OK() {
		t.Fatalf("confirm: %v", err)
	}
	return r
}

func (aw *acWorld) unlock(a *acApp, pin string, o client.UnlockOptions, release string) (*altchan.UnlockResult, error) {
	aw.t.Helper()
	e, in := aw.enclave(a, release, false)
	served, m, err := a.dev.VerifyManifest(aw.w.Served(), aw.trust)
	if err != nil {
		return nil, err
	}
	req, err := a.dev.BuildUnlock(a.guid, pin, e, served, m, a.att, o)
	if err != nil {
		return nil, err
	}
	resp, err := aw.w.Post(ctxT(aw.t, 60*time.Second), in, enclave.OpUnlock, a.vid, a.guid, req)
	if err != nil {
		aw.t.Fatal(err)
	}
	if len(resp.Envelope) != altchan.ResultEnvelopeSize {
		aw.t.Fatalf("result size %d", len(resp.Envelope))
	}
	return a.dev.OpenUnlockResult(resp.Envelope)
}

func (aw *acWorld) mustUnlock(a *acApp, pin string, o client.UnlockOptions, release string) *altchan.UnlockResult {
	aw.t.Helper()
	r, err := aw.unlock(a, pin, o, release)
	if err != nil {
		aw.t.Fatal(err)
	}
	return r
}

func (aw *acWorld) instanceOf(a *acApp) *enclave.Instance {
	for _, n := range []uint64{3, 4, 5} {
		if in := aw.w.Instance(n); in != nil && in.Release().PCR0 == aw.w.SealedRelease(a.vid) {
			return in
		}
	}
	return aw.w.Instance(3)
}

func (aw *acWorld) lock(a *acApp) {
	aw.w.Lock(context.Background(), aw.instanceOf(a), a.vid, a.guid)
}

// status asks the running vault over the session (the vault resumed with
// its state intact).
func (aw *acWorld) status(a *acApp) {
	aw.t.Helper()
	r, err := a.dev.Request(ctxT(aw.t, 30*time.Second), "vault.status", []byte(`{}`))
	if err != nil || !r.OK() || !strings.Contains(string(r.Body()), a.vid) {
		in := aw.instanceOf(a)
		if m := in.Manager(a.vid); m != nil {
			for _, e := range m.Audit() {
				aw.t.Logf("audit: %s %s", e.Event, e.PeerID)
			}
			aw.t.Logf("running at %s locked=%v", in.Release().PCR0[:4], m.Locked())
		} else {
			aw.t.Logf("not running at %s", in.Release().PCR0[:4])
		}
		aw.t.Fatalf("vault.status: %v", err)
	}
}

const acPIN = "246810"

// Enroll an Android-style and an iOS-style app, unlock, lock, unlock
// again; a replayed unlock, a rolled-back state, a bad device attestation
// and a stale manifest are refused.
func TestAltchanEnrollUnlock(t *testing.T) {
	aw := newACWorld(t)
	var confirmedAndroid string
	for _, att := range []client.Attester{enclavetest.NewAndroidAttester(0x61, enclavetest.AndroidOptions{}),
		enclavetest.NewIOSAttester(0x71, enclavetest.IOSOptions{})} {
		a := aw.newApp("member-"+att.Platform(), att)
		if r := aw.enroll(a, acPIN); !r.OK {
			t.Fatalf("%s enroll: %s", att.Platform(), r.Code)
		}
		if att.Platform() == "android" {
			confirmedAndroid = a.vid
		}
		aw.status(a)
		aw.lock(a)
		r := aw.mustUnlock(a, acPIN, client.UnlockOptions{}, "")
		if !r.OK || r.Release != rel3.PCR0Hex() {
			t.Fatalf("%s unlock: %+v", att.Platform(), r)
		}
		aw.status(a)
		aw.lock(a)

		// Replay: the same sealed request twice.
		e, in := aw.enclave(a, "", false)
		served, m, _ := a.dev.VerifyManifest(aw.w.Served(), aw.trust)
		req, _ := a.dev.BuildUnlock(a.guid, acPIN, e, served, m, a.att, client.UnlockOptions{})
		ctx := ctxT(t, 60*time.Second)
		first, _ := aw.w.Post(ctx, in, enclave.OpUnlock, a.vid, a.guid, req)
		if r, err := a.dev.OpenUnlockResult(first.Envelope); err != nil || !r.OK {
			t.Fatalf("first: %v", err)
		}
		aw.lock(a)
		_, _ = a.dev.BuildUnlock(a.guid, acPIN, e, served, m, a.att, client.UnlockOptions{})
		again, _ := aw.w.Post(ctx, in, enclave.OpUnlock, a.vid, a.guid, req)
		if _, err := a.dev.OpenUnlockResult(again.Envelope); err != client.ErrResult {
			t.Fatalf("replayed unlock accepted: %v", err)
		}
	}

	// A second app pairs with device attestation (§6.7) and unlocks.
	{
		a := aw.newApp("member-pair", enclavetest.NewAndroidAttester(0x65, enclavetest.AndroidOptions{}))
		aw.enroll(a, acPIN)
		ctx := ctxT(t, 60*time.Second)
		pc, err := a.dev.Request(ctx, "device.pair.create", []byte(`{"role":"app"}`))
		if err != nil || !pc.OK() {
			t.Fatalf("pair.create: %v", err)
		}
		link := field(t, pc.Body(), "link")
		pid := field(t, pc.Body(), "pairing_id")
		b := aw.newApp("member-pair", enclavetest.NewIOSAttester(0x75, enclavetest.IOSOptions{}))
		if _, err := b.dev.PairAttested(ctx, link, b.att); err != nil {
			t.Fatal(err)
		}
		waitEvent(t, a.dev, "device.pair.pending", has("pairing_id", pid))
		if r, err := a.dev.Request(ctx, "device.pair.approve", []byte(`{"pairing_id":"`+pid+`"}`)); err != nil || !r.OK() {
			t.Fatalf("approve: %v", err)
		}
		if err := b.dev.AwaitPaired(ctx); err != nil {
			t.Fatal(err)
		}
		b.vid = a.vid
		aw.lock(a)
		if r := aw.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); !r.OK {
			t.Fatalf("paired app unlock: %+v", r)
		}
		aw.status(b)
		aw.lock(b)
		// A pairing app without attestation is not admitted.
		if r := aw.mustUnlock(a, acPIN, client.UnlockOptions{}, ""); !r.OK {
			t.Fatal(r)
		}
		pc, _ = a.dev.Request(ctx, "device.pair.create", []byte(`{"role":"app"}`))
		c := aw.newApp("member-pair", nil)
		if _, err := c.dev.Pair(ctx, field(t, pc.Body(), "link")); err != nil {
			t.Fatal(err)
		}
		ctx2, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := a.dev.WaitEvent(ctx2, "device.pair.pending", nil); err == nil {
			t.Fatal("unattested app reached approval")
		}
		aw.lock(a)
	}

	// A confirmed vault is never replaced (§11.3), whether the API reuses
	// the member's vault_id or not.
	for _, reuse := range []bool{true, false} {
		dup := aw.newApp("member-android", enclavetest.NewAndroidAttester(0x66, enclavetest.AndroidOptions{}))
		if reuse {
			dup.vid = confirmedAndroid
		}
		if r := aw.enroll(dup, acPIN); r.OK || r.Code != "vault_exists" {
			t.Fatalf("second enrollment of a member (reuse %v): %+v", reuse, r)
		}
	}

	// Rolled-back state object.
	a := aw.newApp("member-rollback", enclavetest.NewAndroidAttester(0x62, enclavetest.AndroidOptions{}))
	aw.enroll(a, acPIN)
	aw.lock(a)
	old, _, _ := aw.w.Store.Get(context.Background(), store.StateKey(a.vid))
	aw.mustUnlock(a, acPIN, client.UnlockOptions{}, "")
	aw.status(a)
	aw.lock(a)
	_, v, _ := aw.w.Store.Get(context.Background(), store.StateKey(a.vid))
	if _, err := aw.w.Store.Put(context.Background(), store.StateKey(a.vid), old, v); err != nil {
		t.Fatal(err)
	}
	if r := aw.mustUnlock(a, acPIN, client.UnlockOptions{}, ""); r.OK || r.Code != "state_rollback" {
		t.Fatalf("rolled-back state: %+v", r)
	}

	// Bad device attestation at enrollment and at unlock.
	bad := aw.newApp("member-bad", enclavetest.NewAndroidAttester(0x63, enclavetest.AndroidOptions{Unlocked: true}))
	if r := aw.enroll(bad, acPIN); r.OK || r.Code != "attestation" {
		t.Fatalf("bad attestation: %+v", r)
	}
	b := aw.newApp("member-b", enclavetest.NewIOSAttester(0x72, enclavetest.IOSOptions{}))
	aw.enroll(b, acPIN)
	aw.lock(b)
	b.att = enclavetest.NewIOSAttester(0x73, enclavetest.IOSOptions{})
	if r := aw.mustUnlock(b, acPIN, client.UnlockOptions{}, ""); r.OK || r.Code != "attestation" {
		t.Fatalf("assertion by another key: %+v", r)
	}
}

// A release move N -> N+1 approved by the member; the vault unlocks under
// N+1 with its state; a downgrade and a key failing the policy check are
// refused; an unconfirmed move can be abandoned.
func TestAltchanReleaseUpdates(t *testing.T) {
	aw := newACWorld(t)
	a := aw.newApp("member-move", enclavetest.NewAndroidAttester(0x64, enclavetest.AndroidOptions{}))
	aw.enroll(a, acPIN)
	aw.lock(a)
	aw.w.AddRelease(rel4)
	if _, err := aw.w.Start(4); err != nil {
		t.Fatal(err)
	}
	r := aw.mustUnlock(a, acPIN, client.UnlockOptions{Approve: &client.Approval{To: rel4.PCR0Hex(), ToRelease: 4}}, "")
	if !r.OK || r.Update == nil || r.Update.Result != "moved" {
		t.Fatalf("move: %+v", r)
	}
	r = aw.mustUnlock(a, acPIN, client.UnlockOptions{}, "")
	if !r.OK || r.Release != rel4.PCR0Hex() {
		t.Fatalf("unlock under N+1: %+v", r)
	}
	aw.status(a) // the session and state survived the move
	aw.lock(a)

	// Downgrade (release 3 is still active): refused, the unlock succeeds.
	r = aw.mustUnlock(a, acPIN, client.UnlockOptions{Approve: &client.Approval{To: rel3.PCR0Hex(), ToRelease: 3}}, "")
	if !r.OK || r.Update == nil || r.Update.Code != "downgrade" {
		t.Fatalf("downgrade: %+v", r)
	}
	aw.lock(a)

	// A target key failing the policy check (an administrator statement).
	aw.w.AddRelease(rel5)
	if _, err := aw.w.Start(5); err != nil {
		t.Fatal(err)
	}
	good := enclavetest.GoodPolicy(rel5.PCR0Hex(), []string{rel3.PCR0Hex(), rel4.PCR0Hex(), rel5.PCR0Hex()})
	aw.w.KMS.SetPolicy(enclavetest.KeyARN(5), strings.Replace(good, `"Statement":[`,
		`"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"kms:*","Resource":"*"},`, 1))
	r = aw.mustUnlock(a, acPIN, client.UnlockOptions{Approve: &client.Approval{To: rel5.PCR0Hex(), ToRelease: 5}}, "")
	if !r.OK || r.Update == nil || r.Update.Code != "seal_key" {
		t.Fatalf("failing key: %+v %+v", r, r.Update)
	}
	aw.status(a)
	aw.lock(a)

	// Move to 5 with a fixed key, then abandon before 5 runs the vault.
	aw.w.KMS.SetPolicy(enclavetest.KeyARN(5), good)
	r = aw.mustUnlock(a, acPIN, client.UnlockOptions{Approve: &client.Approval{To: rel5.PCR0Hex(), ToRelease: 5}}, "")
	if !r.OK || r.Update == nil || r.Update.Result != "moved" {
		t.Fatalf("move to 5: %+v", r)
	}
	r = aw.mustUnlock(a, acPIN, client.UnlockOptions{Abandon: true}, rel4.PCR0Hex())
	if !r.OK || r.Update == nil || r.Update.Result != "abandoned" || r.Release != rel4.PCR0Hex() {
		t.Fatalf("abandon: %+v %+v", r, r.Update)
	}
	aw.status(a)
}
