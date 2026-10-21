package enclave_test

import (
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/nitro"
)

// 0.53.0, §11.2 "Lifetime and clock allowance": the enclave sets
// not_after to at most 24 h - 60 s after its own clock, truncated to the
// second and never rounded up.
func TestETKNotAfterMargin(t *testing.T) {
	if enclave.ETKLifetime != 24*time.Hour-60*time.Second {
		t.Fatalf("ETKLifetime %v", enclave.ETKLifetime)
	}
	f := newFx(t)
	in := f.w.Instance(3)
	// A clock just short of a whole second: truncation, not rounding.
	now := f.clk.Now()
	f.clk.Add(now.Truncate(time.Second).Add(time.Second + 999*time.Millisecond).Sub(now))
	now = f.clk.Now()
	if err := in.RotateETK(); err != nil {
		t.Fatal(err)
	}
	desc, att := in.Descriptor()
	ds, err := altchan.ParseDescriptor(desc)
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Truncate(time.Second).Add(24*time.Hour - 60*time.Second); !ds.NotAfter.Equal(want) {
		t.Fatalf("not_after %v, want %v", ds.NotAfter, want)
	}
	if ds.NotAfter.After(now.Add(24*time.Hour - 60*time.Second)) {
		t.Fatalf("not_after %v past the clock + 24 h - 60 s", ds.NotAfter)
	}
	doc, err := nitro.Verify(att, f.trust.NitroRoots)
	if err != nil {
		t.Fatal(err)
	}
	if d := ds.NotAfter.Sub(doc.Timestamp); d > 24*time.Hour-60*time.Second || d > client.MaxDescriptorLifetime {
		t.Fatalf("not_after %v after the attestation", d)
	}
}

// §11.2: the ETK rotates at 23 h, so the new descriptor is out close to an
// hour before the previous one's not_after; the previous ETK's 1 h grace
// is cut at its not_after (24 h - 60 s), not at 24 h.
func TestETKRotationBeforeNotAfter(t *testing.T) {
	f := newFx(t)
	a := f.newApp("user-1", android(0x62))
	f.enroll(a, pin)
	f.lock(a)
	e, in := f.enclaveFor(a, "", false)
	f.clk.Add(enclave.ETKRotate)
	if err := in.Maintain(); err != nil {
		t.Fatal(err)
	}
	e2, _ := f.enclaveFor(a, "", false)
	if e2.Descriptor.Kid.Equal(e.Descriptor.Kid) {
		t.Fatal("not rotated at 23 h")
	}
	if left := e.Descriptor.NotAfter.Sub(f.clk.Now()); left < 58*time.Minute || left > time.Hour {
		t.Fatalf("new descriptor %v before the previous not_after", left)
	}
	_, m, _ := a.dev.VerifyManifest(f.w.Served(), f.trust)
	unlock := func() *enclave.Response {
		t.Helper()
		req, err := a.dev.BuildUnlock(a.guid, pin, e, m, a.att, client.UnlockOptions{})
		if err != nil {
			t.Fatal(err)
		}
		resp, _ := f.w.Post(f.ctx, in, enclave.OpUnlock, a.vid, a.guid, req)
		return resp
	}
	// At the previous not_after, within the grace: still usable.
	f.clk.Add(e.Descriptor.NotAfter.Sub(f.clk.Now()))
	if err := in.Maintain(); err != nil {
		t.Fatal(err)
	}
	if r, err := a.dev.OpenUnlockResult(unlock().Envelope); err != nil || !r.OK {
		t.Fatalf("previous ETK at its not_after: %v %+v", err, r)
	}
	f.lock(a)
	// A second later, still inside the hour of grace: destroyed.
	f.clk.Add(time.Second)
	if err := in.Maintain(); err != nil {
		t.Fatal(err)
	}
	if resp := unlock(); resp.Status != enclave.StatusETKUnknown || resp.Envelope != nil {
		t.Fatalf("previous ETK past its not_after: %s", resp.Status)
	}
}
