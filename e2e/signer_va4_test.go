//go:build devenclave && e2e

package e2e

import (
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/enclavetest"
)

// IOS-PLAN VA4, VAULT-MESSAGING §11.7.1 "Across an iOS app" (decided
// 2026-10-11): through the enclave, the relay and the reference client,
// the vault keeps the last recorded Android signer across an iOS app, so
// a return to an Android app of another signer is signer_changed,
// confirmed and audited as between two Android apps; the kept signer
// survives a lock and an unlock; an iOS-first vault binds its first
// Android app as before.

func iosApp(seed byte) client.Attester {
	return enclavetest.NewIOSAttester(seed, enclavetest.IOSOptions{})
}

// transferTo transfers the vault from holder to a new app and returns it:
// the pending's signer members are checked against wantSigner and
// wantChanged (wantSigner "" = no members), and the approval names
// confirm ("" = none).
func (sw *signerWorld) transferTo(holder *acApp, name string, att client.Attester, wantSigner string, wantChanged bool, confirm string) *acApp {
	t := sw.t
	t.Helper()
	ctx := ctxT(t, 300*time.Second)
	id, link, err := holder.dev.TransferCreate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n := sw.newApp(name, att)
	if _, err := n.dev.PairAttested(ctx, link, n.att); err != nil {
		t.Fatal(err)
	}
	s, changed, ok := transferPending(t, holder.dev, id)
	if ok != (wantSigner != "") || s != wantSigner || changed != wantChanged {
		t.Fatalf("pending to %s: %q %v %v, want %q %v", name, s, changed, ok, wantSigner, wantChanged)
	}
	if wantChanged {
		// Without the confirmation, or with the wrong class:
		// signer_unconfirmed, no PIN failure, the binding unmoved.
		for _, wrong := range []string{"", "development"} {
			if err := holder.dev.TransferApproveSigner(ctx, id, acPIN, credPW, wrong); client.Code(err) != "signer_unconfirmed" {
				t.Fatalf("unconfirmed (%q): %v", wrong, err)
			}
		}
		if len(audited(t, holder.dev, "vault.pin_failed")) != 0 {
			t.Fatal("a refused approval counted a PIN failure")
		}
	}
	if err := holder.dev.TransferApproveSigner(ctx, id, acPIN, credPW, confirm); err != nil {
		t.Fatalf("approve %s (%q): %v", name, confirm, err)
	}
	if err := n.dev.AwaitPaired(ctx); err != nil {
		t.Fatal(err)
	}
	n.guid, n.vid = n.dev.UserGUID(), holder.vid
	if err := n.dev.CredentialFetch(ctx); err != nil {
		t.Fatal(err)
	}
	return n
}

// relock locks the vault and unlocks it from a: the kept signer is in
// the stored state, not only in memory.
func (sw *signerWorld) relock(a *acApp) {
	sw.t.Helper()
	sw.lock(a)
	if r := sw.mustUnlock(a, acPIN, client.UnlockOptions{}, ""); !r.OK {
		sw.t.Fatalf("unlock: %+v", r)
	}
	sw.status(a)
}

func signerEntries(t *testing.T, d *client.Device) (bound, changed []map[string]any) {
	t.Helper()
	return audited(t, d, "device.signer_bound"), audited(t, d, "device.signer_changed")
}

// Android (vettid) → iOS → iOS → Android (google_play): no signer on the
// iOS apps' entries and nothing audited at the moves to them; the return
// is signer_changed, refused without the confirmation, then audited
// vettid:google_play and in the feed. Then google_play → iOS → vettid:
// google_play:vettid.
func TestSignerAcrossIOSChanged(t *testing.T) {
	sw := newSignerWorld(t, nil)
	a := sw.newApp("member-ios-c", vettidApp(0x91))
	if r := sw.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	i1 := sw.transferTo(a, "ios-1", iosApp(0x92), "", false, "")
	mustSigner(t, i1.dev, "", "")
	sw.relock(i1)
	i2 := sw.transferTo(i1, "ios-2", iosApp(0x93), "", false, "")
	mustSigner(t, i2.dev, "", "")
	if b, c := signerEntries(t, i2.dev); len(b) != 1 || len(c) != 0 {
		t.Fatalf("the moves to iOS were audited: %v %v", b, c)
	}
	sw.relock(i2)
	p := sw.transferTo(i2, "play-1", playApp(0x94), "google_play", true, "google_play")
	mustSigner(t, p.dev, "google_play", playDigest)
	b, c := signerEntries(t, p.dev)
	if len(b) != 1 || len(c) != 1 || c[0]["ref"] != "vettid:google_play" || c[0]["device_id"] != p.dev.DeviceID() {
		t.Fatalf("after the return: bound %v changed %v", b, c)
	}
	if f := feedItems(t, p.dev, "device.signer_changed"); len(f) != 1 || f[0]["priority"] != "high" || f[0]["ref"] != "vettid:google_play" {
		t.Fatalf("feed item: %v", f)
	}
	sw.relock(p)
	// And back again through iOS to the other signer.
	i3 := sw.transferTo(p, "ios-3", iosApp(0x95), "", false, "")
	v := sw.transferTo(i3, "vettid-2", vettidApp(0x96), "vettid", true, "vettid")
	mustSigner(t, v.dev, "vettid", vettidDigest)
	// The audit list is newest first.
	if _, c := signerEntries(t, v.dev); len(c) != 2 || c[0]["ref"] != "google_play:vettid" || c[0]["device_id"] != v.dev.DeviceID() {
		t.Fatalf("second return: %v", c)
	}
	sw.relock(v)
}

// Android (vettid) → iOS → Android (vettid): signer_changed false, no
// confirmation asked, no device.signer_changed; the return binds
// (device.signer_bound with the new app's id).
func TestSignerAcrossIOSSame(t *testing.T) {
	sw := newSignerWorld(t, nil)
	a := sw.newApp("member-ios-s", vettidApp(0x81))
	if r := sw.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	i := sw.transferTo(a, "ios-1", iosApp(0x82), "", false, "")
	sw.relock(i)
	v := sw.transferTo(i, "vettid-2", vettidApp(0x83), "vettid", false, "")
	mustSigner(t, v.dev, "vettid", vettidDigest)
	b, c := signerEntries(t, v.dev)
	if len(c) != 0 || len(feedItems(t, v.dev, "device.signer_changed")) != 0 {
		t.Fatalf("a return to the same signer was audited as a change: %v", c)
	}
	if len(b) != 2 || b[0]["ref"] != "vettid" || b[0]["device_id"] != v.dev.DeviceID() {
		t.Fatalf("device.signer_bound: %v", b)
	}
	sw.relock(v)
}

// An iOS-first vault (no Android signer ever recorded): the first Android
// app binds, signer_bound, as before VA4.
func TestSignerIOSFirst(t *testing.T) {
	sw := newSignerWorld(t, nil)
	i := sw.newApp("member-ios-f", iosApp(0x71))
	if r := sw.enroll(i, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	if b, _ := signerEntries(t, i.dev); len(b) != 0 {
		t.Fatalf("an iOS enrollment bound: %v", b)
	}
	p := sw.transferTo(i, "play-1", playApp(0x72), "google_play", false, "")
	mustSigner(t, p.dev, "google_play", playDigest)
	b, c := signerEntries(t, p.dev)
	if len(c) != 0 || len(b) != 1 || b[0]["ref"] != "google_play" || b[0]["device_id"] != p.dev.DeviceID() {
		t.Fatalf("bound %v changed %v", b, c)
	}
}

// Recovery on each path (release R: the open, then the recovered phone's
// first handshake): from an iOS app keeping vettid to google_play,
// signer_changed; to vettid, signer_bound; from an iOS-first vault to
// google_play, signer_bound; and a recovery to an iOS app keeps vettid,
// so a later transfer to google_play is signer_changed.
func TestRecoverySignerAcrossIOS(t *testing.T) {
	sw := newSignerWorld(t, nil)
	recoverTo := func(holder *acApp, att client.Attester) *acApp {
		t.Helper()
		sw.lock(holder)
		qr := requestRecoveryAt(t, sw.acWorld, holder)
		sw.off.Add(int64(24*time.Hour + time.Minute))
		n := sw.newApp(holder.guid, att)
		n.vid = holder.vid
		if res := register(t, sw.acWorld, n, qr); !res.OK {
			t.Fatalf("register: %+v", res)
		}
		if r := openRecovery(t, sw.acWorld, n, acPIN, credPW); !r.OK {
			t.Fatalf("the registered phone's open: %+v", r)
		}
		if err := n.dev.CompleteRecoveryHandshake(ctxT(t, 120*time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := n.dev.CredentialFetch(ctxT(t, 60*time.Second)); err != nil {
			t.Fatal(err)
		}
		return n
	}
	viaIOS := func(guid string, seed byte) *acApp {
		t.Helper()
		a := sw.newApp(guid, vettidApp(seed))
		if r := sw.enroll(a, acPIN); !r.OK {
			t.Fatal(r.Code)
		}
		return sw.transferTo(a, guid+"-ios", iosApp(seed+1), "", false, "")
	}

	{ // another signer
		n := recoverTo(viaIOS("member-rc", 0x61), playApp(0x63))
		mustSigner(t, n.dev, "google_play", playDigest)
		b, c := signerEntries(t, n.dev)
		if len(b) != 1 || len(c) != 1 || c[0]["ref"] != "vettid:google_play" || c[0]["device_id"] != n.dev.DeviceID() {
			t.Fatalf("bound %v changed %v", b, c)
		}
		if f := feedItems(t, n.dev, "device.signer_changed"); len(f) != 1 || f[0]["priority"] != "high" {
			t.Fatalf("feed item: %v", f)
		}
	}
	{ // the kept signer
		n := recoverTo(viaIOS("member-rs", 0x65), vettidApp(0x67))
		mustSigner(t, n.dev, "vettid", vettidDigest)
		b, c := signerEntries(t, n.dev)
		if len(c) != 0 || len(b) != 2 || b[0]["ref"] != "vettid" || b[0]["device_id"] != n.dev.DeviceID() {
			t.Fatalf("bound %v changed %v", b, c)
		}
	}
	{ // iOS first
		i := sw.newApp("member-rf", iosApp(0x69))
		if r := sw.enroll(i, acPIN); !r.OK {
			t.Fatal(r.Code)
		}
		n := recoverTo(i, playApp(0x6a))
		b, c := signerEntries(t, n.dev)
		if len(c) != 0 || len(b) != 1 || b[0]["ref"] != "google_play" {
			t.Fatalf("bound %v changed %v", b, c)
		}
	}
	{ // to iOS
		a := sw.newApp("member-ri", vettidApp(0x6b))
		if r := sw.enroll(a, acPIN); !r.OK {
			t.Fatal(r.Code)
		}
		i := recoverTo(a, iosApp(0x6c))
		mustSigner(t, i.dev, "", "")
		if b, c := signerEntries(t, i.dev); len(b) != 1 || len(c) != 0 {
			t.Fatalf("a recovery to iOS was audited: %v %v", b, c)
		}
		sw.relock(i)
		p := sw.transferTo(i, "member-ri-play", playApp(0x6d), "google_play", true, "google_play")
		if _, c := signerEntries(t, p.dev); len(c) != 1 || c[0]["ref"] != "vettid:google_play" {
			t.Fatalf("changed %v", c)
		}
	}
}
