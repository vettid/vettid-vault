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

// register registers r in both steps (PUSH-GATEWAY 0.5.0 §5.1), playing
// the app: the challenge's recorded code confirms the pending registration.
func register(t *testing.T, s *Server, c *pushwire.Client, k ed25519.PrivateKey, r pushwire.Registration) string {
	t.Helper()
	ctx := context.Background()
	p, err := c.Register(ctx, k, r)
	if err != nil || !pushwire.ValidPending(p) {
		t.Fatal(p, err)
	}
	blob, err := c.Confirm(ctx, k, p, s.LastCode())
	if err != nil || !pushwire.ValidBlob(blob) {
		t.Fatal(blob, err)
	}
	return blob
}

func TestRegisterAndWake(t *testing.T) {
	s, c, _ := setup(t)
	ctx := context.Background()
	k := key(t)
	blob := register(t, s, c, k, reg)
	if ch := s.Challenges(); len(ch) != 1 || ch[0].Platform != "fcm" || ch[0].AppID != "com.vettid.app" || len(ch[0].TokenSHA256) != 64 ||
		!pushwire.ValidChallengeCode(ch[0].Code) || len(ch[0].Code) != 22 {
		t.Fatalf("challenges %+v", ch)
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
	register(t, s, c, key(t), pushwire.Registration{Platform: "apns", Environment: "sandbox", AppID: "com.vettid.app",
		Token: "0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a"[:64]})
}

// PUSH-GATEWAY 0.5.0 §5.1: only the code sent to the token, with the
// pending registration's own key, within 10 minutes, gets a blob; every
// refusal is the same 403 challenge_invalid.
func TestConfirm(t *testing.T) {
	s, c, _ := setup(t)
	ctx := context.Background()
	k := key(t)
	p, err := c.Register(ctx, k, reg)
	if err != nil {
		t.Fatal(err)
	}
	good := s.LastCode()
	if s.Registrations() != 0 {
		t.Fatal("a pending registration counted as registered")
	}
	// A pending registration is not a wake blob.
	if _, err := c.Wake(ctx, k, p); code(err) != pushwire.CodeBlobInvalid {
		t.Fatalf("pending woke: %v", err)
	}
	wrong := "AAAAAAAAAAAAAAAAAAAAAA"
	if wrong == good {
		wrong = "BBBBBBBBBBBBBBBBBBBBBB"
	}
	for name, f := range map[string]func() error{
		"wrong code":  func() error { _, err := c.Confirm(ctx, k, p, wrong); return err },
		"another key": func() error { _, err := c.Confirm(ctx, key(t), p, good); return err },
		"tampered": func() error {
			b := []byte(p)
			b[len(b)-3] ^= 1
			_, err := c.Confirm(ctx, k, string(b), good)
			return err
		},
	} {
		if err := f(); code(err) != pushwire.CodeChallengeInvalid {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// A strict body.
	if _, err := c.Confirm(ctx, k, p, ""); code(err) != pushwire.CodeBadRequest {
		t.Fatalf("empty code: %v", err)
	}
	blob, err := c.Confirm(ctx, k, p, good)
	if err != nil || s.Registrations() != 1 {
		t.Fatalf("confirm: %v (%d)", err, s.Registrations())
	}
	// A wake blob is not a pending registration.
	if _, err := c.Confirm(ctx, k, blob, good); code(err) != pushwire.CodeChallengeInvalid {
		t.Fatalf("blob as pending: %v", err)
	}
	// A replaced challenge: the older code does not confirm the newer
	// pending registration.
	p1, _ := c.Register(ctx, k, reg)
	c1 := s.LastCode()
	p2, _ := c.Register(ctx, k, reg)
	c2 := s.LastCode()
	if _, err := c.Confirm(ctx, k, p2, c1); code(err) != pushwire.CodeChallengeInvalid {
		t.Fatalf("older code: %v", err)
	}
	if _, err := c.Confirm(ctx, k, p2, c2); err != nil {
		t.Fatal(err)
	}
	// After 10 minutes: refused.
	later := func() time.Time { return time.Now().Add(ChallengeLife + time.Minute) }
	s.cfg.Now = later
	lc := *c
	lc.Now = later
	if _, err := lc.Confirm(ctx, k, p1, c1); code(err) != pushwire.CodeChallengeInvalid {
		t.Fatalf("expired: %v", err)
	}
	if n := s.Refusals()["confirm:challenge_invalid"]; n != 6 {
		t.Fatalf("refusals %v", s.Refusals())
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
	// A pending registration for an app id the gateway no longer accepts
	// is not confirmed.
	k := key(t)
	p, err := c.Register(ctx, k, reg)
	if err != nil {
		t.Fatal(err)
	}
	s.cfg.AppIDs = map[string][]string{"fcm": {"com.vettid.app.dev"}}
	if _, err := c.Confirm(ctx, k, p, s.LastCode()); code(err) != pushwire.CodeChallengeInvalid {
		t.Fatal(err)
	}
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
