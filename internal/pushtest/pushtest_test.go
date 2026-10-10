package pushtest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/pushwire"
)

func setup(t *testing.T) (*Server, *pushwire.Client, *enclavetest.FakeNSM) {
	spec := enclavetest.Spec(3, "")
	nsm := enclavetest.NewFakeNSM(spec.PCR0, spec.PCR1, spec.PCR2, time.Now)
	s := New(Config{Roots: enclavetest.TestNitroCA().Roots(), PCR0s: []string{spec.PCR0Hex()}})
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	c := &pushwire.Client{BaseURL: srv.URL, HTTP: srv.Client(),
		Attest: func(pub ed25519.PublicKey, d [32]byte) ([]byte, error) { return nsm.Attest(d[:], nil, pub) }}
	return s, c, nsm
}

func key(t *testing.T) ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var reg = pushwire.Registration{Platform: "fcm", Token: "tok-1", AppID: "com.vettid.app"}

func code(err error) string {
	var e *pushwire.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestRegisterAndWake(t *testing.T) {
	s, c, _ := setup(t)
	ctx := context.Background()
	k := key(t)
	blob, err := c.Register(ctx, k, reg)
	if err != nil || !pushwire.ValidBlob(blob) {
		t.Fatal(blob, err)
	}
	if r, err := c.Wake(ctx, k, blob); err != nil || r != "" {
		t.Fatal(r, err)
	}
	w := s.Wakes()
	if len(w) != 1 || w[0].Platform != "fcm" || w[0].AppID != "com.vettid.app" || w[0].Class != "notify" || len(w[0].TokenSHA256) != 64 {
		t.Fatalf("%+v", w)
	}
	// Another key than the registration's, or a tampered blob: blob_invalid.
	if _, err := c.Wake(ctx, key(t), blob); code(err) != pushwire.CodeBlobInvalid {
		t.Fatal(err)
	}
	b := []byte(blob)
	b[len(b)-3] ^= 1
	if _, err := c.Wake(ctx, k, string(b)); code(err) != pushwire.CodeBlobInvalid {
		t.Fatal(err)
	}
	// Injected answers, then a reseal that works.
	s.FailNext(Failure{Status: 410, Code: pushwire.CodeTokenGone})
	if _, err := c.Wake(ctx, k, blob); code(err) != pushwire.CodeTokenGone {
		t.Fatal(err)
	}
	s.FailNext(Failure{Status: 429, Code: pushwire.CodeRateLimited, RetryAfter: 12})
	var e *pushwire.Error
	if _, err := c.Wake(ctx, k, blob); !errors.As(err, &e) || e.Status != 429 || e.RetryAfter != 12 {
		t.Fatal(err)
	}
	s.ResealNext(1)
	r, err := c.Wake(ctx, k, blob)
	if err != nil || r == "" || r == blob {
		t.Fatal(r, err)
	}
	if _, err := c.Wake(ctx, k, r); err != nil {
		t.Fatal(err)
	}
	if len(s.Wakes()) != 3 || s.Registrations() != 1 {
		t.Fatalf("%d wakes %d regs", len(s.Wakes()), s.Registrations())
	}
	// APNs with its environment.
	if _, err := c.Register(ctx, key(t), pushwire.Registration{Platform: "apns", Environment: "sandbox", AppID: "com.vettid.app",
		Token: "0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a"[:64]}); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterRefusals(t *testing.T) {
	s, c, nsm := setup(t)
	ctx := context.Background()
	// No attestation.
	bare := *c
	bare.Attest = nil
	if _, err := bare.Register(ctx, key(t), reg); code(err) != pushwire.CodeAttestationInvalid {
		t.Fatal(err)
	}
	// An attestation of another key or another digest.
	other := *c
	other.Attest = func(_ ed25519.PublicKey, d [32]byte) ([]byte, error) {
		return nsm.Attest(d[:], nil, key(t).Public().(ed25519.PublicKey))
	}
	if _, err := other.Register(ctx, key(t), reg); code(err) != pushwire.CodeAttestationInvalid {
		t.Fatal(err)
	}
	other.Attest = func(pub ed25519.PublicKey, d [32]byte) ([]byte, error) {
		d[0] ^= 1
		return nsm.Attest(d[:], nil, pub)
	}
	if _, err := other.Register(ctx, key(t), reg); code(err) != pushwire.CodeAttestationInvalid {
		t.Fatal(err)
	}
	// Another release.
	spec := enclavetest.Spec(4, "")
	n4 := enclavetest.NewFakeNSM(spec.PCR0, spec.PCR1, spec.PCR2, time.Now)
	other.Attest = func(pub ed25519.PublicKey, d [32]byte) ([]byte, error) { return n4.Attest(d[:], nil, pub) }
	if _, err := other.Register(ctx, key(t), reg); code(err) != pushwire.CodeAttestationInvalid {
		t.Fatal(err)
	}
	// Bodies.
	for _, c2 := range []struct {
		r    pushwire.Registration
		want string
	}{
		{pushwire.Registration{Platform: "webpush", Token: "x", AppID: "a"}, pushwire.CodePlatformInvalid},
		{pushwire.Registration{Platform: "fcm", Token: "x", AppID: "/"}, pushwire.CodeAppInvalid},
		{pushwire.Registration{Platform: "apns", Token: "XYZ", AppID: "a", Environment: "sandbox"}, pushwire.CodeTokenInvalid},
	} {
		if _, err := c.Register(ctx, key(t), c2.r); code(err) != c2.want {
			t.Fatalf("%+v: %v", c2.r, err)
		}
	}
	s.cfg.AppIDs = map[string][]string{"fcm": {"com.vettid.app.dev"}}
	if _, err := c.Register(ctx, key(t), reg); code(err) != pushwire.CodeAppInvalid {
		t.Fatal(err)
	}
	if s.Registrations() != 0 || s.Refusals()["register:attestation_invalid"] != 4 {
		t.Fatalf("%d %v", s.Registrations(), s.Refusals())
	}
}

// A stale or unsigned request is refused before anything else.
func TestSignature(t *testing.T) {
	s, c, _ := setup(t)
	old := *c
	old.Now = func() time.Time { return time.Now().Add(-10 * time.Minute) }
	if _, err := old.Register(context.Background(), key(t), reg); code(err) != pushwire.CodeTimestampStale {
		t.Fatal(err)
	}
	if s.Refusals()["register:timestamp_stale"] != 1 {
		t.Fatal(s.Refusals())
	}
}
