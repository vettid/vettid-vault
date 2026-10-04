package enclave_test

import (
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/manifest"
)

// §11.5, §11.10.4 step 1 (0.10.0, M1): the request names its manifest by
// hash and serial and the host supplies the document. A withheld
// document, another (valid, signed) manifest, or a corrupted document is
// refused with code manifest, never counted as a PIN failure; the
// supplied document is used once the host gives the right one.
func TestManifestByHash(t *testing.T) {
	f := newFx(t)
	a := f.newApp("user-1", android(0x61))
	f.enroll(a, pin)
	f.lock(a)
	older := f.w.Served()
	f.w.Publish() // the app now fetches serial 2
	for name, set := range map[string]func(){
		"withheld":       func() { f.w.Withhold = true },
		"another":        func() { f.w.Substitute = older },
		"corrupt":        func() { f.w.Substitute = []byte(strings.Replace(string(older), `"sig":"`, `"sig":"A`, 1)) },
		"not a document": func() { f.w.Substitute = []byte(`{}`) },
		"too large":      func() { f.w.Substitute = append([]byte(`{"x":"`+strings.Repeat("a", manifest.MaxServed)), '"', '}') },
	} {
		set()
		for i := 0; i < 4; i++ { // more than the 3 free failures before backoff
			if r := f.mustUnlock(a, pin, client.UnlockOptions{}, ""); r.OK || r.Code != "manifest" {
				t.Fatalf("%s: %+v", name, r)
			}
		}
		f.w.Withhold, f.w.Substitute = false, nil
	}
	if r := f.mustUnlock(a, pin, client.UnlockOptions{}, ""); !r.OK || r.ManifestSerial != 2 {
		t.Fatalf("after: %+v", r)
	}
	f.lock(a)
	// Enrollment, too.
	b := f.newApp("user-2", android(0x62))
	f.w.Withhold = true
	if r := f.enroll(b, pin); r.OK || r.Code != "manifest" {
		t.Fatalf("enroll withheld: %+v", r)
	}
	f.w.Withhold = false
	if r := f.enroll(b, pin); !r.OK {
		t.Fatalf("enroll: %+v", r)
	}
}

// §11.10.1, §11.10.5 (0.10.0): a release whose own entry is removed still
// unlocks if it is running (a rescue during the KMS window), reports the
// status, and moves the vault on (the move-only contract); a removed
// release is never a move target, and apps never enroll into one.
func TestRemovedRelease(t *testing.T) {
	f := newFx(t)
	a := f.newApp("user-1", android(0x61))
	f.enroll(a, pin)
	f.lock(a)
	// Release 4 is listed as removed: no move into it.
	f.startRelease(r4)
	f.w.SetStatus(4, manifest.StatusRemoved)
	res := f.mustUnlock(a, pin, client.UnlockOptions{Approve: &client.Approval{To: r4.PCR0Hex(), ToRelease: 4}}, "")
	if !res.OK || res.Update == nil || res.Update.Result != "refused" || res.Update.Code != "target" {
		t.Fatalf("move into removed: %+v %+v", res, res.Update)
	}
	f.lock(a)
	// Release 3 removed, 4 active again: the rescue unlock under 3 works,
	// reports removed, and the member moves to 4.
	f.w.SetStatus(4, manifest.StatusActive)
	f.w.SetStatus(3, manifest.StatusRemoved)
	if r := f.mustUnlock(a, pin, client.UnlockOptions{}, ""); !r.OK || r.ReleaseStatus != manifest.StatusRemoved {
		t.Fatalf("rescue unlock: %+v", r)
	}
	f.lock(a)
	f.moveTo(a, r4)
	if r := f.mustUnlock(a, pin, client.UnlockOptions{}, ""); !r.OK || r.ReleaseNumber != 4 {
		t.Fatalf("after the rescue move: %+v", r)
	}
	f.lock(a)
	// The app refuses to enroll into a release that is not active.
	desc, att, _, err := f.w.Enclave("", r3.PCR0Hex())
	if err != nil {
		t.Fatal(err)
	}
	_, m, _ := a.dev.VerifyManifest(f.w.Served(), f.trust)
	if _, err := client.VerifyEnclave(desc, att, m, true, f.trust, f.clk.Now()); err == nil {
		t.Fatal("enrollment into a removed release accepted")
	}
	if _, err := client.VerifyEnclave(desc, att, m, false, f.trust, f.clk.Now()); err != nil {
		t.Fatalf("unlock of a removed release refused by the app: %v", err)
	}
}

// §11.10.7 (0.10.0): the release keys carry the retirement statements;
// an image that pins the retirement role and window accepts them (every
// test above), and one that pins another window, or none, refuses the key
// at enrollment (release_key).
func TestRetirementPinnedInImage(t *testing.T) {
	for name, tweak := range map[string]func(*enclave.Config){
		"no retirement pinned": func(c *enclave.Config) { c.RetirementPrincipal, c.RetirementWindowDays = "", 0 },
		"another window":       func(c *enclave.Config) { c.RetirementWindowDays = 30 },
		"another role": func(c *enclave.Config) {
			c.RetirementPrincipal = "arn:aws:iam::" + enclavetest.KMSAccount + ":role/someone-else"
		},
	} {
		f := newFx(t)
		if _, err := f.w.StartWith(3, tweak); err != nil {
			t.Fatal(err)
		}
		a := f.newApp("user-1", android(0x61))
		if r := f.enroll(a, pin); r.OK || r.Code != "release_key" {
			t.Fatalf("%s: %+v", name, r)
		}
	}
}
