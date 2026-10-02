package enclave_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/devattest"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

const pin = "424242"

func (f *fx) lock(a *app) {
	in := f.w.Instance(3)
	if r := f.w.SealedRelease(a.vid); r != "" {
		for _, n := range []uint64{3, 4, 5} {
			if i := f.w.Instance(n); i != nil && i.Release().PCR0 == r {
				in = i
			}
		}
	}
	f.w.Lock(f.ctx, in, a.vid, a.guid)
}

// §11.3, §11.4: an Android app and an iOS app enroll; each unlocks after
// a lock, and the results carry the release fields.
func TestEnrollUnlock(t *testing.T) {
	f := newFx(t)
	for i, att := range []client.Attester{android(0x61), ios(0x71)} {
		a := f.newApp("user-"+att.Platform(), att)
		if r := f.enroll(a, pin); !r.OK || r.VaultID != a.vid {
			t.Fatalf("%s enroll: %+v", att.Platform(), r)
		}
		if f.w.Instance(3).Manager(a.vid) == nil {
			t.Fatal("vault not running after enrollment")
		}
		st := a.dev.Alt()
		if st.Release != r3.PCR0Hex() || st.ReleaseNumber != 3 || st.StateSeq == 0 {
			t.Fatalf("app state %+v", st)
		}
		f.lock(a)
		if f.w.Instance(3).Manager(a.vid) != nil {
			t.Fatal("still running after lock")
		}
		r := f.mustUnlock(a, pin, client.UnlockOptions{}, "")
		if !r.OK || r.Release != r3.PCR0Hex() || r.ReleaseNumber != 3 || r.ReleaseStatus != "active" ||
			r.ManifestSerial == 0 || r.Token == "" || r.Update != nil {
			t.Fatalf("%d unlock: %+v", i, r)
		}
		if f.w.Instance(3).Manager(a.vid) == nil {
			t.Fatal("not running after unlock")
		}
		// A second unlock of a running vault locks and reopens it.
		r2 := f.mustUnlock(a, pin, client.UnlockOptions{}, "")
		if !r2.OK || r2.StateSeq <= r.StateSeq || r2.HeaderSeq <= r.HeaderSeq {
			t.Fatalf("re-unlock: %+v after %+v", r2, r)
		}
	}
	var enrolled, unlocked, locked int
	for _, ev := range f.w.Events() {
		switch ev.Event {
		case "enrolled":
			enrolled++
		case "unlocked":
			unlocked++
		case "locked":
			locked++
		}
		if ev.VaultVersion != r3.PCR0Hex() || ev.StateVersion != 1 {
			t.Fatalf("event %+v", ev)
		}
	}
	if enrolled != 2 || unlocked < 6 || locked < 4 {
		t.Fatalf("events: %d enrolled, %d unlocked, %d locked", enrolled, unlocked, locked)
	}
}

// §11.6: a replayed unlock is refused (dropped: the API sees a result of
// the same size, the app cannot read it).
func TestReplayRefused(t *testing.T) {
	f := newFx(t)
	a := f.newApp("user-1", android(0x61))
	f.enroll(a, pin)
	f.lock(a)
	e, in := f.enclaveFor(a, "", false)
	served, m, _ := a.dev.VerifyManifest(f.w.Served(), f.trust)
	req, err := a.dev.BuildUnlock(a.guid, pin, e, served, m, a.att, client.UnlockOptions{})
	if err != nil {
		t.Fatal(err)
	}
	first, _ := f.w.Post(f.ctx, in, enclave.OpUnlock, a.vid, a.guid, req)
	r, err := a.dev.OpenUnlockResult(first.Envelope)
	if err != nil || !r.OK {
		t.Fatalf("first: %v %+v", err, r)
	}
	// The same request again (and to another vault id: redirected).
	if _, err := a.dev.BuildUnlock(a.guid, pin, e, served, m, a.att, client.UnlockOptions{}); err != nil {
		t.Fatal(err)
	}
	again, _ := f.w.Post(f.ctx, in, enclave.OpUnlock, a.vid, a.guid, req)
	if len(again.Envelope) != len(first.Envelope) {
		t.Fatal("replay answered with a different size")
	}
	if _, err := a.dev.OpenUnlockResult(again.Envelope); !errors.Is(err, client.ErrResult) {
		t.Fatalf("replay: %v", err)
	}
}

// §11.6: requests older than 5 minutes are refused; an unknown ETK is
// reported; the previous ETK stays valid for an hour after rotation.
func TestETKLifecycle(t *testing.T) {
	f := newFx(t)
	a := f.newApp("user-1", android(0x61))
	f.enroll(a, pin)
	f.lock(a)
	e, in := f.enclaveFor(a, "", false)
	served, m, _ := a.dev.VerifyManifest(f.w.Served(), f.trust)
	req, _ := a.dev.BuildUnlock(a.guid, pin, e, served, m, a.att, client.UnlockOptions{})
	f.clk.Add(6 * time.Minute)
	resp, _ := f.w.Post(f.ctx, in, enclave.OpUnlock, a.vid, a.guid, req)
	if _, err := a.dev.OpenUnlockResult(resp.Envelope); !errors.Is(err, client.ErrResult) {
		t.Fatal("stale request answered")
	}
	// Rotate: the old ETK still works for an hour.
	req, _ = a.dev.BuildUnlock(a.guid, pin, e, served, m, a.att, client.UnlockOptions{})
	if err := in.RotateETK(); err != nil {
		t.Fatal(err)
	}
	resp, _ = f.w.Post(f.ctx, in, enclave.OpUnlock, a.vid, a.guid, req)
	if r, err := a.dev.OpenUnlockResult(resp.Envelope); err != nil || !r.OK {
		t.Fatalf("previous ETK within grace: %v", err)
	}
	f.lock(a)
	f.clk.Add(61 * time.Minute)
	if err := in.Maintain(); err != nil {
		t.Fatal(err)
	}
	req, _ = a.dev.BuildUnlock(a.guid, pin, e, served, m, a.att, client.UnlockOptions{})
	resp, _ = f.w.Post(f.ctx, in, enclave.OpUnlock, a.vid, a.guid, req)
	if resp.Status != enclave.StatusETKUnknown || resp.Envelope != nil {
		t.Fatalf("destroyed ETK: %s", resp.Status)
	}
	// The new descriptor verifies; ETKs rotate before 24 h.
	e2, _ := f.enclaveFor(a, "", false)
	if e2.Descriptor.Kid.Equal(e.Descriptor.Kid) {
		t.Fatal("not rotated")
	}
	f.clk.Add(23 * time.Hour)
	_ = in.Maintain()
	e3, _ := f.enclaveFor(a, "", false)
	if e3.Descriptor.Kid.Equal(e2.Descriptor.Kid) {
		t.Fatal("not rotated after 23 h")
	}
}

// §11.4, §11.8: bad PINs are counted (header_seq grows), back off after
// three, never wipe; a correct PIN after the delay unlocks and resets.
func TestBadPINAndBackoff(t *testing.T) {
	f := newFx(t)
	a := f.newApp("user-1", ios(0x71))
	f.enroll(a, pin)
	f.lock(a)
	var last uint64
	for i := 0; i < 3; i++ {
		r := f.mustUnlock(a, "000000", client.UnlockOptions{}, "")
		if r.OK || r.Code != "bad_pin" || r.HeaderSeq <= last {
			t.Fatalf("attempt %d: %+v", i, r)
		}
		last = r.HeaderSeq
	}
	r := f.mustUnlock(a, pin, client.UnlockOptions{}, "")
	if r.OK || r.Code != "backoff" || r.RetryAfter == 0 || r.RetryAfter > 30 {
		t.Fatalf("backoff: %+v", r)
	}
	f.clk.Add(31 * time.Second)
	if r := f.mustUnlock(a, pin, client.UnlockOptions{}, ""); !r.OK {
		t.Fatalf("after backoff: %+v", r)
	}
	f.lock(a)
	if r := f.mustUnlock(a, "000000", client.UnlockOptions{}, ""); r.Code != "bad_pin" || r.RetryAfter != 0 {
		t.Fatalf("backoff not reset: %+v", r)
	}
}

// §13.2: a rolled-back state object or header is refused with
// state_rollback; the app's minimums anchor the check.
func TestRollbackRefused(t *testing.T) {
	f := newFx(t)
	a := f.newApp("user-1", android(0x61))
	f.enroll(a, pin)
	f.lock(a)
	old, _, _ := f.w.Store.Get(f.ctx, store.StateKey(a.vid))
	oldHdr, _, _ := f.w.Store.Get(f.ctx, store.HeaderKey(a.vid, r3.PCR0Hex()))
	f.mustUnlock(a, pin, client.UnlockOptions{}, "")
	f.lock(a)
	// Serve the older state with the current header.
	_, v, _ := f.w.Store.Get(f.ctx, store.StateKey(a.vid))
	if _, err := f.w.Store.Put(f.ctx, store.StateKey(a.vid), old, v); err != nil {
		t.Fatal(err)
	}
	if r := f.mustUnlock(a, pin, client.UnlockOptions{}, ""); r.OK || r.Code != "state_rollback" {
		t.Fatalf("old state: %+v", r)
	}
	// Serve both older objects consistently: the app's minimums catch it.
	_, hv, _ := f.w.Store.Get(f.ctx, store.HeaderKey(a.vid, r3.PCR0Hex()))
	if _, err := f.w.Store.Put(f.ctx, store.HeaderKey(a.vid, r3.PCR0Hex()), oldHdr, hv); err != nil {
		t.Fatal(err)
	}
	if r := f.mustUnlock(a, pin, client.UnlockOptions{}, ""); r.OK || r.Code != "state_rollback" {
		t.Fatalf("old header and state: %+v", r)
	}
}

// §11.7: enrollment with a software key, an unlocked bootloader or a
// stale status list, and an unlock assertion by another key, are refused.
func TestDeviceAttestationRefused(t *testing.T) {
	f := newFx(t)
	for name, att := range map[string]client.Attester{
		"software":   enclavetest.NewAndroidAttester(0x61, enclavetest.AndroidOptions{SoftwareLevel: true}),
		"unlocked":   enclavetest.NewAndroidAttester(0x62, enclavetest.AndroidOptions{Unlocked: true}),
		"other-app":  enclavetest.NewAndroidAttester(0x63, enclavetest.AndroidOptions{Package: "com.evil"}),
		"ios-devenv": enclavetest.NewIOSAttester(0x71, enclavetest.IOSOptions{Develop: true}),
	} {
		a := f.newApp("user-"+name, att)
		if r := f.enroll(a, pin); r.OK || r.Code != "attestation" {
			t.Errorf("%s: %+v", name, r)
		}
	}
	f.w.SetStatusList(enclavetest.EmptyStatusList(f.clk.Now().Add(-25 * time.Hour)))
	a := f.newApp("user-stale", android(0x64))
	if r := f.enroll(a, pin); r.OK || r.Code != "attestation" {
		t.Errorf("stale list: %+v", r)
	}
	f.w.SetStatusList(enclavetest.EmptyStatusList(f.clk.Now()))
	// A valid enrollment; then unlock assertions by another device key.
	a = f.newApp("user-ok", android(0x65))
	if r := f.enroll(a, pin); !r.OK {
		t.Fatal(r)
	}
	f.lock(a)
	a.att = android(0x66)
	if r := f.mustUnlock(a, pin, client.UnlockOptions{}, ""); r.OK || r.Code != "attestation" {
		t.Fatalf("other key: %+v", r)
	}
	// A revoked chain fails at unlock (the stored serials are rechecked).
	a.att = android(0x65)
	rev, _ := devattest.ParseStatusList([]byte(`{"entries":{"2":{"status":"REVOKED"}}}`), f.clk.Now())
	f.w.SetStatusList(rev)
	if r := f.mustUnlock(a, pin, client.UnlockOptions{}, ""); r.OK || r.Code != "attestation" {
		t.Fatalf("revoked: %+v", r)
	}
	f.w.SetStatusList(enclavetest.EmptyStatusList(f.clk.Now()))
	if r := f.mustUnlock(a, pin, client.UnlockOptions{}, ""); !r.OK {
		t.Fatalf("after: %+v", r)
	}
}

// An unlock from an app that is not an unlock key of the vault is
// dropped: no device to answer, a same-size unreadable response.
func TestUnknownDeviceDropped(t *testing.T) {
	f := newFx(t)
	a := f.newApp("user-1", android(0x61))
	f.enroll(a, pin)
	f.lock(a)
	b := f.newApp("user-1", android(0x62))
	f.enroll(b, pin) // another vault of the same member is refused...
	// ...so bind b to a's vault id by hand (as a malicious app would).
	b2 := f.retarget(b, a.vid)
	if _, err := f.unlock(b2, pin, client.UnlockOptions{}, ""); !errors.Is(err, client.ErrResult) {
		t.Fatalf("unbound device: %v", err)
	}
}

// retarget returns a copy of a's device pointed at another vault id.
func (f *fx) retarget(a *app, vid string) *app {
	f.t.Helper()
	saved, err := a.dev.Save()
	if err != nil {
		f.t.Fatal(err)
	}
	var st map[string]any
	_ = json.Unmarshal(saved, &st)
	st["vault_id"] = vid
	if st["vault"] == nil {
		st["vault"] = map[string]any{"ik": make([]byte, 32), "kem": make([]byte, 1216), "relay_url": relayURL,
			"mailbox": "x", "relay_pk": make([]byte, 32), "sessions": map[string]any{}, "suite": 2}
	}
	b, _ := json.Marshal(st)
	d, err := client.Load(client.Config{Now: f.clk.Now, Trust: &f.trust}, b)
	if err != nil {
		f.t.Fatal(err)
	}
	return &app{dev: d, att: a.att, guid: a.guid, vid: vid}
}

// §11.10.4 step 1: a manifest with a serial below the one recorded in the
// header, or not signed by a pinned key, gives code manifest and is not
// counted as a PIN failure.
func TestManifestRefused(t *testing.T) {
	f := newFx(t)
	a := f.newApp("user-1", android(0x61))
	f.enroll(a, pin)
	f.lock(a)
	stale, _ := a.dev.Save() // a copy of the device that saw only serial 1
	oldServed := f.w.Served()
	f.w.Publish() // serial 2
	f.mustUnlock(a, pin, client.UnlockOptions{}, "")
	f.lock(a)
	f.served = oldServed
	_ = stale
	if r := f.mustUnlock(staleApp(f, stale, a), pin, client.UnlockOptions{}, ""); r.OK || r.Code != "manifest" {
		t.Fatalf("old manifest: %+v", r)
	}
	f.lock(a)
	// Signed by an unpinned key.
	in2, err := f.w.StartWith(3, func(c *enclave.Config) { c.ManifestKeys = nil })
	if err != nil {
		t.Fatal(err)
	}
	_ = in2
	if r := f.mustUnlock(a, pin, client.UnlockOptions{}, ""); r.OK || r.Code != "manifest" {
		t.Fatalf("unpinned: %+v", r)
	}
	if _, err := f.w.StartWith(3, nil); err != nil {
		t.Fatal(err)
	}
	if r := f.mustUnlock(a, pin, client.UnlockOptions{}, ""); !r.OK {
		t.Fatalf("manifest failures counted as PIN failures: %+v", r)
	}
}

// staleApp loads a saved device state (a device that missed updates).
func staleApp(f *fx, saved []byte, a *app) *app {
	d, err := client.Load(client.Config{Now: f.clk.Now, Trust: &f.trust}, saved)
	if err != nil {
		f.t.Fatal(err)
	}
	return &app{dev: d, att: a.att, guid: a.guid, vid: a.vid}
}

// Uniform results: every outcome has the same envelope size (§11.4).
func TestUniformSizes(t *testing.T) {
	f := newFx(t)
	a := f.newApp("user-1", android(0x61))
	f.enroll(a, pin)
	f.lock(a)
	e, in := f.enclaveFor(a, "", false)
	served, m, _ := a.dev.VerifyManifest(f.w.Served(), f.trust)
	sizes := map[int]bool{}
	for _, p := range []string{pin, "000000"} {
		req, err := a.dev.BuildUnlock(a.guid, p, e, served, m, a.att, client.UnlockOptions{})
		if err != nil {
			t.Fatal(err)
		}
		resp, _ := f.w.Post(f.ctx, in, enclave.OpUnlock, a.vid, a.guid, req)
		sizes[len(resp.Envelope)] = true
		f.lock(a)
	}
	junk, _ := suite.RandomBytes(altchan.RequestEnvelopeSize)
	rid, _ := envelope.NewULID(f.clk.Now())
	resp, _ := f.w.Post(f.ctx, in, enclave.OpUnlock, a.vid, a.guid, &client.Request{RequestID: rid, ETKKid: e.Descriptor.Kid.String(), Envelope: junk})
	sizes[len(resp.Envelope)] = true
	if len(sizes) != 1 || !sizes[altchan.ResultEnvelopeSize] {
		t.Fatalf("sizes %v", sizes)
	}
}

// §11.3: the app accepts vault.enrolled only with an attestation whose
// nonce is its own, user_data covers the bundle, and PCRs are the
// enclave's it sealed to.
func TestEnrolledAttestationChecked(t *testing.T) {
	f := newFx(t)
	a := f.newApp("user-1", android(0x61))
	e, in := f.enclaveFor(a, "", true)
	served, _, _ := a.dev.VerifyManifest(f.w.Served(), f.trust)
	req, err := a.dev.BuildEnroll(a.guid, pin, e, served, a.att)
	if err != nil {
		t.Fatal(err)
	}
	vid := newVaultID()
	if _, err := f.w.Post(f.ctx, in, enclave.OpEnroll, vid, a.guid, req); err != nil {
		t.Fatal(err)
	}
	// A device whose pending enrollment has another nonce rejects it.
	saved, _ := a.dev.Save()
	var st map[string]any
	_ = json.Unmarshal(saved, &st)
	st["alt"].(map[string]any)["enroll_nonce"] = make([]byte, 32)
	b, _ := json.Marshal(st)
	other, err := client.Load(client.Config{Now: f.clk.Now, Trust: &f.trust}, b)
	if err != nil {
		t.Fatal(err)
	}
	f.deliver(&app{dev: other})
	if other.VaultID() != "" {
		t.Fatal("vault.enrolled with a foreign nonce accepted")
	}
	f.deliver(a)
	if a.dev.VaultID() != vid {
		t.Fatal("vault.enrolled rejected")
	}
}

// §11.3 "Provisional vaults": a member's provisional vault blocks a new
// enrollment for 24 h and may be replaced afterwards.
func TestProvisionalReplacement(t *testing.T) {
	f := newFx(t)
	a := f.newApp("user-1", android(0x61))
	if r := f.enroll(a, pin); !r.OK {
		t.Fatal(r)
	}
	b := f.newApp("user-1", android(0x62))
	if r := f.enroll(b, pin); r.OK || r.Code != "vault_exists" {
		t.Fatalf("within 24 h: %+v", r)
	}
	f.clk.Add(25 * time.Hour)
	f.w.SetStatusList(enclavetest.EmptyStatusList(f.clk.Now()))
	if err := f.w.Instance(3).Maintain(); err != nil {
		t.Fatal(err)
	}
	f.w.Publish()
	if r := f.enroll(b, pin); !r.OK {
		t.Fatalf("after 24 h: %+v", r)
	}
}
