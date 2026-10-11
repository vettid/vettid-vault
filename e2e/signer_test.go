//go:build devenclave && e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
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
	"github.com/vettid/vettid-vault/vms/devattest"
)

// Per-vault signer binding (VAULT-MESSAGING 0.27.0 §11.7.1) through the
// enclave, the real relay and the reference client: enrollment binds;
// unlock and a release approval need the recorded signer to be pinned by
// the running release (signer_refused); the binding changes only by a
// transfer, confirmed when the signer changes, or a completed recovery;
// vaults enrolled before the rule bind from their key's chain.

var (
	vettidDigest = hex.EncodeToString(enclavetest.AndroidSigner[:])
	playDigest   = hex.EncodeToString(enclavetest.AndroidSignerPlay[:])
)

func vettidApp(seed byte) client.Attester {
	return enclavetest.NewAndroidAttester(seed, enclavetest.AndroidOptions{})
}

func playApp(seed byte) client.Attester {
	return enclavetest.NewAndroidAttester(seed, enclavetest.AndroidOptions{Signers: [][]byte{enclavetest.AndroidSignerPlay[:]}})
}

func ownChain(a *acApp) [][]byte {
	c, _ := a.dev.AttestChain()
	return c
}

// signerWorld is an alternate-channel world whose releases pin two
// signers (the test policy's, class vettid, and a second of class
// google_play), with a movable recovery clock. tweak adjusts release 3.
type signerWorld struct {
	*acWorld
	off   *atomic.Int64
	added map[uint64]bool
}

func bothPinned(c *enclave.Config) {
	c.DeviceAttest = enclavetest.PinSigner(c.DeviceAttest, enclavetest.AndroidSignerPlay, devattest.ClassGooglePlay)
}

func newSignerWorld(t *testing.T, tweak func(*enclave.Config)) *signerWorld {
	t.Helper()
	r := relaytest.Start(t, nil)
	w := enclavetest.NewWorld(time.Now, r.URL)
	aw := &acWorld{t: t, w: w, relay: r.URL, trust: w.Trust()}
	w.VaultOptions = vault.Options{PollWait: time.Second,
		Relay: func(base string, key ed25519.PrivateKey) vault.Relay {
			return vault.NewClientRelay(base, key, nil, time.Now)
		}}
	w.Features = all.Dev
	sw := &signerWorld{acWorld: aw, off: &atomic.Int64{}, added: map[uint64]bool{}}
	sw.startRelease(rel3, tweak)
	t.Cleanup(w.Close)
	return sw
}

// startRelease starts (or restarts) a release's instance with both
// signers pinned, then tweak.
func (sw *signerWorld) startRelease(r enclavetest.ReleaseSpec, tweak func(*enclave.Config)) {
	sw.t.Helper()
	if !sw.added[r.Number] {
		sw.added[r.Number] = true
		sw.w.AddRelease(r)
	}
	if _, err := sw.w.StartWith(r.Number, func(c *enclave.Config) {
		bothPinned(c)
		c.RecoveryNow = func() time.Time { return time.Now().Add(time.Duration(sw.off.Load())) }
		if tweak != nil {
			tweak(c)
		}
	}); err != nil {
		sw.t.Fatal(err)
	}
}

// audited returns the audit log's device entries of one kind.
func audited(t *testing.T, d *client.Device, kind string) []map[string]any {
	t.Helper()
	au, err := d.AuditList(ctxT(t, 30*time.Second), map[string]any{"kinds": []string{"device"}}, false)
	if err != nil {
		t.Fatalf("audit.list: %v", err)
	}
	var entries []map[string]any
	if err := json.Unmarshal(au["entries"], &entries); err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, e := range entries {
		if e["kind"] == kind {
			out = append(out, e)
		}
	}
	for _, digest := range []string{vettidDigest, playDigest} {
		if strings.Contains(string(au["entries"]), digest) {
			t.Fatalf("the audit log carries a signer digest: %s", au["entries"])
		}
	}
	return out
}

func feedItems(t *testing.T, d *client.Device, kind string) []map[string]any {
	t.Helper()
	fl, err := d.FeedList(ctxT(t, 30*time.Second), nil)
	if err != nil {
		t.Fatalf("feed.list: %v", err)
	}
	var items []map[string]any
	if err := json.Unmarshal(fl["items"], &items); err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, it := range items {
		if it["kind"] == kind {
			out = append(out, it)
		}
	}
	for _, digest := range []string{vettidDigest, playDigest} {
		if strings.Contains(string(fl["items"]), digest) {
			t.Fatalf("the feed carries a signer digest: %s", fl["items"])
		}
	}
	return out
}

func mustSigner(t *testing.T, d *client.Device, class, digest string) {
	t.Helper()
	sg, err := d.Signer(ctxT(t, 30*time.Second))
	if err != nil {
		t.Fatalf("device.list: %v", err)
	}
	if class == "" {
		if sg != nil {
			t.Fatalf("signer %+v, want none", sg)
		}
		return
	}
	if sg == nil || sg.Class != class || sg.Digest != digest {
		t.Fatalf("signer %+v, want %s %s", sg, class, digest)
	}
}

// Enrollment binds and audits device.signer_bound; device.list shows
// signer{class, digest} on the app's entry only; each configured signer
// has its class; an iOS app has none. Unlock and a release approval with
// a bound signer the running release pins are unchanged.
func TestSignerBoundAtEnrollment(t *testing.T) {
	sw := newSignerWorld(t, nil)
	a := sw.newApp("member-sb", vettidApp(0xb1))
	if r := sw.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	mustSigner(t, a.dev, "vettid", vettidDigest)
	if e := audited(t, a.dev, "device.signer_bound"); len(e) != 1 || e[0]["ref"] != "vettid" {
		t.Fatalf("device.signer_bound: %v", e)
	}
	if len(audited(t, a.dev, "device.signer_changed")) != 0 || len(feedItems(t, a.dev, "device.signer_changed")) != 0 {
		t.Fatal("an enrollment recorded a change of signer")
	}
	// On the app's entry only: the desktop's has none, and the desktop
	// reads the same member.
	desk := acPairDesktop(t, sw.acWorld, a)
	n, body := appCount(t, desk)
	if n != 1 || strings.Count(body, `"signer":`) != 1 || !strings.Contains(body, `"signer":{"class":"vettid","digest":"`+vettidDigest+`"}`) {
		t.Fatalf("device.list as the desktop sees it: %s", body)
	}
	// Unlock and a release-update approval: unchanged.
	sw.lock(a)
	if r := sw.mustUnlock(a, acPIN, client.UnlockOptions{NoChain: true}, ""); !r.OK {
		t.Fatalf("unlock: %+v", r)
	}
	sw.status(a)
	sw.startRelease(rel4, nil)
	moveTo(t, sw.acWorld, a, rel4)
	mustSigner(t, a.dev, "vettid", vettidDigest)
	if e := audited(t, a.dev, "device.signer_bound"); len(e) != 1 {
		t.Fatalf("bound again by an unlock or a move: %v", e)
	}
	if len(audited(t, a.dev, "device.signer_refused")) != 0 {
		t.Fatal("a refusal was audited")
	}
	// The other configured signer has its class.
	p := sw.newApp("member-sb-play", playApp(0xb2))
	if r := sw.enroll(p, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	mustSigner(t, p.dev, "google_play", playDigest)
	if e := audited(t, p.dev, "device.signer_bound"); len(e) != 1 || e[0]["ref"] != "google_play" {
		t.Fatalf("device.signer_bound: %v", e)
	}
	// iOS: no signer, nothing audited.
	i := sw.newApp("member-sb-ios", enclavetest.NewIOSAttester(0xb3, enclavetest.IOSOptions{}))
	if r := sw.enroll(i, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	mustSigner(t, i.dev, "", "")
	if len(audited(t, i.dev, "device.signer_bound")) != 0 {
		t.Fatal("an iOS enrollment bound a signer")
	}
	// An unpinned signer, and two pinned digests in one attestation:
	// the attestation fails, as before 0.27.0 for the first.
	for name, att := range map[string]client.Attester{
		"unpinned": enclavetest.NewAndroidAttester(0xb4, enclavetest.AndroidOptions{Signers: [][]byte{enclavetest.AndroidSignerDev[:]}}),
		"two":      enclavetest.NewAndroidAttester(0xb5, enclavetest.AndroidOptions{Signers: [][]byte{enclavetest.AndroidSigner[:], enclavetest.AndroidSignerPlay[:]}}),
	} {
		x := sw.newApp("member-sb-"+name, att)
		if r := sw.enroll(x, acPIN); r.OK || r.Code != "attestation" {
			t.Fatalf("%s: %+v", name, r)
		}
	}
}

// The same vault moved to an image whose configuration omits its signer:
// signer_refused, sealed and sized as any result (acWorld.unlock checks
// the size), at the confirming unlock of the move; the backoff counters
// are unchanged whatever PIN came with it; no alarm, nothing reported to
// the host; one header-log entry per 24 hours; device.signer_refused in
// the audit log after a later successful unlock. A wrong assertion never
// yields signer_refused.
func TestSignerRefused(t *testing.T) {
	sw := newSignerWorld(t, nil)
	a := sw.newApp("member-sr", vettidApp(0xc1))
	if r := sw.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	// Release 4 pins only the Play signer.
	dropped := func(c *enclave.Config) {
		c.DeviceAttest = enclavetest.UnpinSigner(c.DeviceAttest, enclavetest.AndroidSigner)
	}
	sw.startRelease(rel4, dropped)
	sw.lock(a)
	// The move is approved on release 3, which pins the signer.
	res := sw.mustUnlock(a, acPIN, client.UnlockOptions{Approve: &client.Approval{To: rel4.PCR0Hex(), ToRelease: 4}}, "")
	if !res.OK || res.Update == nil || res.Update.Result != "moved" {
		t.Fatalf("move: %+v %+v", res, res.Update)
	}
	events := len(sw.w.Events())
	// Refused at release 4, with the right PIN and with wrong ones (more
	// of them than the backoff allows for free).
	var seq uint64
	for i, pin := range []string{acPIN, "000000", "111111", "222222", "333333", "444444", acPIN} {
		r := sw.mustUnlock(a, pin, client.UnlockOptions{}, "")
		if r.OK || r.Code != vault.CodeSignerRefused || r.RetryAfter != 0 || r.Token != "" {
			t.Fatalf("attempt %d: %+v", i, r)
		}
		if i == 0 {
			seq = r.HeaderSeq
		} else if r.HeaderSeq != seq {
			t.Fatalf("attempt %d wrote the header again (header_seq %d, was %d): one log entry per 24 hours", i, r.HeaderSeq, seq)
		}
	}
	if sw.w.Instance(4).Manager(a.vid) != nil {
		t.Fatal("the vault runs")
	}
	for _, ev := range sw.w.Events()[events:] {
		t.Fatalf("a refusal reported %q to the host", ev.Event)
	}
	// With the chain it is still refused: a bound key ignores `chain`.
	if r := sw.mustUnlock(a, acPIN, client.UnlockOptions{Chain: ownChain(a)}, ""); r.Code != vault.CodeSignerRefused {
		t.Fatalf("with a chain: %+v", r)
	}
	// A wrong assertion (another device key) is `attestation`, never
	// signer_refused.
	real := a.att
	a.att = vettidApp(0xc2)
	if r := sw.mustUnlock(a, acPIN, client.UnlockOptions{}, ""); r.OK || r.Code != "attestation" {
		t.Fatalf("another device key: %+v", r)
	}
	a.att = real
	// A release approval is refused the same way: the unlock that
	// carries it is refused before anything else.
	sw.startRelease(rel5, dropped)
	if r := sw.mustUnlock(a, acPIN, client.UnlockOptions{Approve: &client.Approval{To: rel5.PCR0Hex(), ToRelease: 5}}, ""); r.OK ||
		r.Code != vault.CodeSignerRefused || r.Update != nil {
		t.Fatalf("an approval by a refused key: %+v %+v", r, r.Update)
	}
	// The same release pinning the signer again: the right PIN unlocks at
	// once (no backoff was counted), and the refusal is in the audit log,
	// once, without a device.
	sw.startRelease(rel4, nil)
	r := sw.mustUnlock(a, acPIN, client.UnlockOptions{}, "")
	if !r.OK {
		t.Fatalf("unlock once the signer is pinned again: %+v", r)
	}
	sw.status(a)
	e := audited(t, a.dev, "device.signer_refused")
	if len(e) != 1 || e[0]["ref"] != "unpinned" {
		t.Fatalf("device.signer_refused: %v", e)
	}
	if id, has := e[0]["device_id"]; has && id != "" {
		t.Fatalf("device.signer_refused names a device: %v", e[0])
	}
	if len(feedItems(t, a.dev, "device.signer_refused")) != 0 {
		t.Fatal("a refusal is in the feed")
	}
	if id, st := alarmOf(t, a.dev); id != "" || st != "" {
		t.Fatalf("an alarm was opened: %q %q", id, st)
	}
	mustSigner(t, a.dev, "vettid", vettidDigest)
}

// transferPending waits for the holder's device.transfer.pending and
// returns its signer members.
func transferPending(t *testing.T, holder *client.Device, id string) (signer string, changed, present bool) {
	t.Helper()
	ev := waitEvent(t, holder, "device.transfer.pending", has("transfer_id", id))
	var o map[string]json.RawMessage
	if err := json.Unmarshal(ev.Body, &o); err != nil {
		t.Fatal(err)
	}
	if _, ok := o["signer"]; !ok {
		if _, ok := o["signer_changed"]; ok {
			t.Fatalf("signer_changed without signer: %s", ev.Body)
		}
		return "", false, false
	}
	if json.Unmarshal(o["signer"], &signer) != nil || json.Unmarshal(o["signer_changed"], &changed) != nil {
		t.Fatalf("pending %s", ev.Body)
	}
	if strings.Contains(string(ev.Body), vettidDigest) || strings.Contains(string(ev.Body), playDigest) {
		t.Fatalf("the pending carries a digest: %s", ev.Body)
	}
	return signer, changed, true
}

// A transfer to the same signer needs no `signer` and audits no change.
// To another pinned signer: signer_changed is true; an approval without
// `signer`, or with the wrong class, is signer_unconfirmed with the UTK
// unspent and the PIN backoff untouched; with it the transfer completes,
// the binding is the new signer, and device.signer_changed is audited
// with both classes and in the feed. To an unpinned signer: dropped.
func TestTransferSigner(t *testing.T) {
	sw := newSignerWorld(t, nil)
	a := sw.newApp("member-ts", vettidApp(0xd1))
	if r := sw.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	ctx := ctxT(t, 300*time.Second)

	// To the same signer.
	id, link, err := a.dev.TransferCreate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b := sw.newApp("phone-2", vettidApp(0xd2))
	if _, err := b.dev.PairAttested(ctx, link, b.att); err != nil {
		t.Fatal(err)
	}
	if s, changed, ok := transferPending(t, a.dev, id); !ok || s != "vettid" || changed {
		t.Fatalf("pending to the same signer: %q %v %v", s, changed, ok)
	}
	if err := a.dev.TransferApprove(ctx, id, acPIN, credPW); err != nil {
		t.Fatalf("approve without signer: %v", err)
	}
	if err := b.dev.AwaitPaired(ctx); err != nil {
		t.Fatal(err)
	}
	b.guid, b.vid = b.dev.UserGUID(), a.vid
	if err := b.dev.CredentialFetch(ctx); err != nil {
		t.Fatal(err)
	}
	mustSigner(t, b.dev, "vettid", vettidDigest)
	if len(audited(t, b.dev, "device.signer_changed")) != 0 || len(feedItems(t, b.dev, "device.signer_changed")) != 0 {
		t.Fatal("a transfer to the same signer recorded a change")
	}

	// To an unpinned signer: dropped as before (the attestation fails).
	id, link, err = b.dev.TransferCreate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	x := sw.newApp("phone-x", enclavetest.NewAndroidAttester(0xd3, enclavetest.AndroidOptions{Signers: [][]byte{enclavetest.AndroidSignerDev[:]}}))
	quiet, cancel := context.WithTimeout(ctx, 4*time.Second)
	if _, err := x.dev.PairAttested(quiet, link, x.att); err == nil {
		t.Fatal("a transfer to an unpinned signer was answered")
	}
	cancel()
	if len(audited(t, b.dev, "device.transfer.attestation_failed")) != 1 {
		t.Fatal("no device.transfer.attestation_failed")
	}
	if err := b.dev.TransferReject(ctx, id); err != nil {
		t.Fatal(err)
	}

	// To another pinned signer.
	id, link, err = b.dev.TransferCreate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c := sw.newApp("phone-3", playApp(0xd4))
	if _, err := c.dev.PairAttested(ctx, link, c.att); err != nil {
		t.Fatal(err)
	}
	if s, changed, ok := transferPending(t, b.dev, id); !ok || s != "google_play" || !changed {
		t.Fatalf("pending to another signer: %q %v %v", s, changed, ok)
	}
	// Unconfirmed, with one and the same UTK each time: it is never
	// spent. A wrong PIN comes with it: the answer is still
	// signer_unconfirmed, and no PIN failure is counted.
	utk := takeUTK(t, b.dev)
	approve := func(pin string, extra map[string]any) error {
		extra["transfer_id"] = id
		_, err := b.dev.CredentialRawExtra(ctx, "device.transfer.approve", utk, b.dev.CredentialBlob(), map[string]any{"password": credPW, "pin": pin}, extra)
		return err
	}
	for name, extra := range map[string]map[string]any{"no signer": {}, "the old class": {"signer": "vettid"}, "another class": {"signer": "development"}} {
		for _, pin := range []string{"999999", acPIN} {
			if err := approve(pin, extra); client.Code(err) != "signer_unconfirmed" {
				t.Fatalf("%s: %v", name, err)
			}
		}
	}
	if len(audited(t, b.dev, "vault.pin_failed")) != 0 {
		t.Fatal("a refused approval counted a PIN failure")
	}
	mustSigner(t, b.dev, "vettid", vettidDigest) // the binding has not moved
	// Confirmed, with the UTK the refusals did not spend: completes.
	if err := approve(acPIN, map[string]any{"signer": "google_play"}); err != nil {
		t.Fatalf("confirmed approval with the unspent UTK and no backoff: %v", err)
	}
	if err := c.dev.AwaitPaired(ctx); err != nil {
		t.Fatal(err)
	}
	c.guid, c.vid = c.dev.UserGUID(), a.vid
	if err := c.dev.CredentialFetch(ctx); err != nil {
		t.Fatal(err)
	}
	mustSigner(t, c.dev, "google_play", playDigest)
	e := audited(t, c.dev, "device.signer_changed")
	if len(e) != 1 || e[0]["ref"] != "vettid:google_play" || e[0]["device_id"] != c.dev.DeviceID() {
		t.Fatalf("device.signer_changed: %v", e)
	}
	f := feedItems(t, c.dev, "device.signer_changed")
	if len(f) != 1 || f[0]["priority"] != "high" || f[0]["ref"] != "vettid:google_play" {
		t.Fatalf("feed item: %v", f)
	}
	// The new app unlocks; the old one does not.
	sw.lock(c)
	if r, err := sw.unlock(b, acPIN, client.UnlockOptions{}, ""); err == nil && r.OK {
		t.Fatal("the old app still unlocks")
	}
	if r := sw.mustUnlock(c, acPIN, client.UnlockOptions{}, ""); !r.OK {
		t.Fatalf("new app unlock: %+v", r)
	}
	sw.status(c)
}

// Recovery to another pinned signer: the binding is unchanged after
// register, after a cancel and after an expiry; changed, audited and in
// the feed after credential.recover; the old app's key no longer unlocks.
func TestRecoverySigner(t *testing.T) {
	sw := newSignerWorld(t, nil)
	a := sw.newApp("member-rs", vettidApp(0xe1))
	if r := sw.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	ctx := ctxT(t, 300*time.Second)
	unchanged := func(when string) {
		t.Helper()
		if r := sw.mustUnlock(a, acPIN, client.UnlockOptions{}, ""); !r.OK {
			t.Fatalf("%s: the old app's unlock: %+v", when, r)
		}
		sw.status(a)
		mustSigner(t, a.dev, "vettid", vettidDigest)
		if len(audited(t, a.dev, "device.signer_changed")) != 0 || len(feedItems(t, a.dev, "device.signer_changed")) != 0 {
			t.Fatalf("%s: a change of signer was recorded", when)
		}
		sw.lock(a)
	}
	sw.lock(a)

	// Registered, then cancelled.
	qr := requestRecoveryAt(t, sw.acWorld, a)
	sw.off.Add(int64(24*time.Hour + time.Minute))
	b := sw.newApp(a.guid, playApp(0xe2))
	b.vid = a.vid
	if res := register(t, sw.acWorld, b, qr); !res.OK {
		t.Fatalf("register: %+v", res)
	}
	sw.w.RecoveryCancel(ctxT(t, 30*time.Second), sw.instanceOf(a), a.vid, a.guid)
	unchanged("after register and a cancel")

	// Requested, then expired before anything registered: the code is
	// refused and the recovery is gone. (A registered recovery has no
	// expiry of its own inside the vault; it ends by a cancel or by
	// credential.recover.)
	qr = requestRecoveryAt(t, sw.acWorld, a)
	sw.off.Add(int64(48*time.Hour + time.Minute))
	b2 := sw.newApp(a.guid, playApp(0xe3))
	b2.vid = a.vid
	if res := register(t, sw.acWorld, b2, qr); res.OK || res.Code != vault.CodeRecoveryExpired {
		t.Fatalf("register after the expiry: %+v", res)
	}
	unchanged("after an expiry")

	// Completed.
	qr = requestRecoveryAt(t, sw.acWorld, a)
	sw.off.Add(int64(24*time.Hour + time.Minute))
	c := sw.newApp(a.guid, playApp(0xe4))
	c.vid = a.vid
	if res := register(t, sw.acWorld, c, qr); !res.OK {
		t.Fatalf("register: %+v", res)
	}
	if r := sw.mustUnlock(c, acPIN, client.UnlockOptions{}, ""); !r.OK {
		t.Fatalf("the registered app's unlock: %+v", r)
	}
	if err := c.dev.CompleteRecoveryHandshake(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.dev.CredentialRecover(ctx, credPW); err != nil {
		t.Fatalf("recover: %v", err)
	}
	mustSigner(t, c.dev, "google_play", playDigest)
	e := audited(t, c.dev, "device.signer_changed")
	if len(e) != 1 || e[0]["ref"] != "vettid:google_play" || e[0]["device_id"] != c.dev.DeviceID() {
		t.Fatalf("device.signer_changed: %v", e)
	}
	if f := feedItems(t, c.dev, "device.signer_changed"); len(f) != 1 || f[0]["priority"] != "high" {
		t.Fatalf("feed item: %v", f)
	}
	sw.lock(c)
	if r, err := sw.unlock(a, acPIN, client.UnlockOptions{}, ""); err == nil && r.OK {
		t.Fatal("the replaced app still unlocks")
	}
	if r := sw.mustUnlock(c, acPIN, client.UnlockOptions{}, ""); !r.OK {
		t.Fatalf("the new app's unlock: %+v", r)
	}
}

// before027 makes a release's instance behave as releases before 0.27.0
// did: bindings without a signer, no signer rule, `chain` ignored.
func before027(c *enclave.Config) { c.Before027 = true }

// A header written before 0.27.0, on a production-channel build (which
// never accepts an unbound key): without a chain signer_refused; with a
// chain for another key, with other serials or naming another package,
// `attestation`; with its own chain, bound and audited; a bound key
// ignores `chain`.
func TestUnboundVaultBindsByChain(t *testing.T) {
	sw := newSignerWorld(t, before027) // release 3 plays the previous release
	a := sw.newApp("member-ub", vettidApp(0xf1))
	if r := sw.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	mustSigner(t, a.dev, "", "") // enrolled before the rule: no signer
	chain := ownChain(a)
	if len(chain) != 3 {
		t.Fatalf("the app kept a chain of %d certificates", len(chain))
	}
	// The previous release ignores `chain` (unknown members are ignored).
	sw.lock(a)
	if r := sw.mustUnlock(a, acPIN, client.UnlockOptions{}, ""); !r.OK {
		t.Fatalf("the previous release with a chain: %+v", r)
	}
	mustSigner(t, a.dev, "", "")
	// Release 4 has the rule and does not accept unbound keys.
	sw.startRelease(rel4, nil)
	sw.lock(a)
	res := sw.mustUnlock(a, acPIN, client.UnlockOptions{NoChain: true, Approve: &client.Approval{To: rel4.PCR0Hex(), ToRelease: 4}}, "")
	if !res.OK || res.Update == nil || res.Update.Result != "moved" {
		t.Fatalf("move: %+v %+v", res, res.Update)
	}
	if r := sw.mustUnlock(a, acPIN, client.UnlockOptions{NoChain: true}, ""); r.OK || r.Code != vault.CodeSignerRefused {
		t.Fatalf("without a chain: %+v", r)
	}
	// A chain for another key (the same app on another device key).
	other := vettidApp(0xf2)
	oda, _ := other.Attest([32]byte{1})
	if r := sw.mustUnlock(a, acPIN, client.UnlockOptions{Chain: oda.Chain}, ""); r.OK || r.Code != "attestation" {
		t.Fatalf("another key's chain: %+v", r)
	}
	// The same key attested again: other serials.
	again, _ := a.att.Attest([32]byte{2})
	if r := sw.mustUnlock(a, acPIN, client.UnlockOptions{Chain: again.Chain}, ""); r.OK || r.Code != "attestation" {
		t.Fatalf("other serials: %+v", r)
	}
	// A truncated chain.
	if r := sw.mustUnlock(a, acPIN, client.UnlockOptions{Chain: chain[:2]}, ""); r.OK || r.Code != "attestation" {
		t.Fatalf("a chain without its root: %+v", r)
	}
	// A release whose package is another than the chain's (the staging
	// move to com.vettid.app.staging): `attestation`.
	sw.startRelease(rel4, func(c *enclave.Config) {
		p := *c.DeviceAttest
		p.AndroidPackage = newPackage
		c.DeviceAttest = &p
	})
	if r := sw.mustUnlock(a, acPIN, client.UnlockOptions{Chain: chain}, ""); r.OK || r.Code != "attestation" {
		t.Fatalf("a chain naming another package: %+v", r)
	}
	sw.startRelease(rel4, nil)
	// Its own chain (what the app sends by default): bound and audited,
	// with the refusal that came before.
	if r := sw.mustUnlock(a, acPIN, client.UnlockOptions{}, ""); !r.OK {
		t.Fatalf("with its chain: %+v", r)
	}
	sw.status(a)
	mustSigner(t, a.dev, "vettid", vettidDigest)
	if e := audited(t, a.dev, "device.signer_bound"); len(e) != 1 || e[0]["ref"] != "vettid" {
		t.Fatalf("device.signer_bound: %v", e)
	}
	if e := audited(t, a.dev, "device.signer_refused"); len(e) != 1 || e[0]["ref"] != "unbound" {
		t.Fatalf("device.signer_refused: %v", e)
	}
	// Bound: it unlocks without a chain, and a chain of any kind is
	// ignored (the app has seen its signer and stops sending one).
	sw.lock(a)
	if r := sw.mustUnlock(a, acPIN, client.UnlockOptions{NoChain: true}, ""); !r.OK {
		t.Fatalf("bound, without a chain: %+v", r)
	}
	sw.lock(a)
	if r := sw.mustUnlock(a, acPIN, client.UnlockOptions{Chain: oda.Chain}, ""); !r.OK {
		t.Fatalf("a bound key did not ignore a chain: %+v", r)
	}
	sw.status(a)
	if e := audited(t, a.dev, "device.signer_bound"); len(e) != 1 {
		t.Fatalf("bound again: %v", e)
	}
	if _, seen := a.dev.AttestChain(); !seen {
		t.Fatal("the app did not note its signer")
	}
}

// On a staging-channel build at S10 (which accepts unbound keys): a
// header written before 0.27.0 unlocks unbound without a chain, also
// under a package other than the one it enrolled with (the old staging
// build on S10); a transfer from the unbound vault shows signer_changed
// false, needs no `signer`, binds and audits device.signer_bound.
func TestUnboundVaultOnStaging(t *testing.T) {
	sw := newSignerWorld(t, before027)
	a := sw.newApp("member-us", vettidApp(0xf5))
	if r := sw.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	ctx := ctxT(t, 300*time.Second)
	// "S10": the rule, the new package, unbound keys accepted.
	sw.startRelease(rel4, func(c *enclave.Config) {
		p := *c.DeviceAttest
		p.AndroidPackage, p.AndroidAcceptUnbound = newPackage, true
		c.DeviceAttest = &p
	})
	sw.lock(a)
	res := sw.mustUnlock(a, acPIN, client.UnlockOptions{NoChain: true, Approve: &client.Approval{To: rel4.PCR0Hex(), ToRelease: 4}}, "")
	if !res.OK || res.Update == nil || res.Update.Result != "moved" {
		t.Fatalf("move: %+v %+v", res, res.Update)
	}
	// The old build sends no chain (it predates 0.27.0): unbound unlock.
	if r := sw.mustUnlock(a, acPIN, client.UnlockOptions{NoChain: true}, ""); !r.OK {
		t.Fatalf("an unbound unlock on staging: %+v", r)
	}
	sw.status(a)
	mustSigner(t, a.dev, "", "")
	if len(audited(t, a.dev, "device.signer_bound")) != 0 || len(audited(t, a.dev, "device.signer_refused")) != 0 {
		t.Fatal("an unbound unlock was audited as a binding or a refusal")
	}
	// The transfer to the new build (new package, attested afresh).
	id, link, err := a.dev.TransferCreate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b := sw.newApp("new-build", enclavetest.NewAndroidAttester(0xf6, enclavetest.AndroidOptions{Package: newPackage}))
	if _, err := b.dev.PairAttested(ctx, link, b.att); err != nil {
		t.Fatal(err)
	}
	if s, changed, ok := transferPending(t, a.dev, id); !ok || s != "vettid" || changed {
		t.Fatalf("pending from an unbound vault: %q %v %v", s, changed, ok)
	}
	if err := a.dev.TransferApprove(ctx, id, acPIN, credPW); err != nil {
		t.Fatalf("approve without signer: %v", err)
	}
	if err := b.dev.AwaitPaired(ctx); err != nil {
		t.Fatal(err)
	}
	b.guid, b.vid = b.dev.UserGUID(), a.vid
	if err := b.dev.CredentialFetch(ctx); err != nil {
		t.Fatal(err)
	}
	mustSigner(t, b.dev, "vettid", vettidDigest)
	if e := audited(t, b.dev, "device.signer_bound"); len(e) != 1 || e[0]["ref"] != "vettid" || e[0]["device_id"] != b.dev.DeviceID() {
		t.Fatalf("device.signer_bound: %v", e)
	}
	if len(audited(t, b.dev, "device.signer_changed")) != 0 {
		t.Fatal("binding an unbound vault was audited as a change")
	}
	// The staging release after S10 refuses a vault that is still
	// unbound; this one is bound and unlocks there.
	sw.startRelease(rel5, func(c *enclave.Config) {
		p := *c.DeviceAttest
		p.AndroidPackage = newPackage
		c.DeviceAttest = &p
	})
	moveTo(t, sw.acWorld, b, rel5)
	mustSigner(t, b.dev, "vettid", vettidDigest)
}
