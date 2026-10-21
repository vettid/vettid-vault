package client_test

import (
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/manifest"
	"github.com/vettid/vettid-vault/vms/suite"
)

func world(t *testing.T, now *time.Time) *enclavetest.World {
	t.Helper()
	w := enclavetest.NewWorld(func() time.Time { return *now }, "https://relay.test")
	w.AddRelease(enclavetest.Spec(3, "active"))
	if _, err := w.Start(3); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	return w
}

// §11.2: the app's checks on a descriptor and its attestation.
func TestVerifyEnclave(t *testing.T) {
	now := time.Now().UTC()
	w := world(t, &now)
	tr := w.Trust()
	desc, att, _, err := w.Enclave("", "")
	if err != nil {
		t.Fatal(err)
	}
	s, _ := manifest.ParseServed(w.Served())
	m, err := manifest.Verify(s, tr.ManifestKeys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.VerifyEnclave(desc, att, m, true, tr, now); err != nil {
		t.Fatal(err)
	}
	// user_data covers the exact descriptor bytes.
	bad := append([]byte(nil), desc...)
	bad = append(bad[:len(bad)-1], ' ', '}')
	if _, err := client.VerifyEnclave(bad, att, m, true, tr, now); !errors.Is(err, client.ErrEnclave) {
		t.Error("descriptor bytes changed")
	}
	// The attestation must be fresh (< 26 h) and the descriptor unexpired.
	if _, err := client.VerifyEnclave(desc, att, m, false, tr, now.Add(25*time.Hour)); !errors.Is(err, client.ErrEnclave) {
		t.Error("descriptor past not_after")
	}
	// Another release's PCRs are not in this manifest.
	other := enclavetest.NewWorld(func() time.Time { return now }, "https://relay.test")
	other.AddRelease(enclavetest.Spec(4, "active"))
	os, _ := manifest.ParseServed(other.Served())
	om, _ := manifest.Verify(os, tr.ManifestKeys)
	if _, err := client.VerifyEnclave(desc, att, om, false, tr, now); !errors.Is(err, client.ErrEnclave) {
		t.Error("PCRs not in the manifest")
	}
	// Enrollment needs an active release; unlock accepts any listed one.
	w.SetStatus(3, "deprecated")
	s, _ = manifest.ParseServed(w.Served())
	m, _ = manifest.Verify(s, tr.ManifestKeys)
	if _, err := client.VerifyEnclave(desc, att, m, true, tr, now); !errors.Is(err, client.ErrEnclave) {
		t.Error("enrollment into a deprecated release")
	}
	if _, err := client.VerifyEnclave(desc, att, m, false, tr, now); err != nil {
		t.Errorf("unlock of a deprecated release: %v", err)
	}
	// An attestation by a debug enclave (all-zero PCRs) for the same
	// descriptor, and one not chaining to the trusted root.
	dbg := enclavetest.NewFakeNSM(0, 0, 0, func() time.Time { return now })
	ud := altchan.ETKUserData(desc)
	datt, _ := dbg.Attest(ud[:], nil, nil)
	if _, err := client.VerifyEnclave(desc, datt, m, false, tr, now); !errors.Is(err, client.ErrEnclave) {
		t.Error("debug PCRs")
	}
	if _, err := client.VerifyEnclave(desc, att, m, false, client.Trust{NitroRoots: x509.NewCertPool(), ManifestKeys: tr.ManifestKeys}, now); !errors.Is(err, client.ErrEnclave) {
		t.Error("untrusted root")
	}
}

// §11.10.1, §11.10.6: the app refuses a manifest older than one it saw.
func TestVerifyManifestSerial(t *testing.T) {
	now := time.Now().UTC()
	w := world(t, &now)
	tr := w.Trust()
	d, err := client.Generate(client.Config{Role: "app", RelayURL: "https://relay.test", Trust: &tr})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.VerifyManifest(w.Served(), tr); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.VerifyManifest(w.Served(), client.Trust{}); err == nil {
		t.Fatal("unpinned manifest key accepted")
	}
}

// 0.53.0, §11.2 "Lifetime and clock allowance": not_after must be after
// the app's time and at most 24 h + 5 min after the attestation document's
// timestamp, inclusive; the 5 min is the only allowance between the two.
func TestVerifyEnclaveLifetimeAllowance(t *testing.T) {
	now := time.Now().UTC()
	w := world(t, &now)
	tr := w.Trust()
	s, _ := manifest.ParseServed(w.Served())
	m, err := manifest.Verify(s, tr.ManifestKeys)
	if err != nil {
		t.Fatal(err)
	}
	k, err := suite.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer k.Destroy()
	spec := enclavetest.Spec(3, "active")
	// The attestation's timestamp is a whole second; not_after is
	// written to the second.
	attT := now.Truncate(time.Second)
	// check verifies a descriptor with not_after = attT + lifetime, attested
	// at attT + attOff, as the app at time at.
	check := func(lifetime, attOff time.Duration, at time.Time) error {
		desc := altchan.MarshalDescriptor("i-test-0001", k.Public(), spec.PCR0Hex(), attT.Add(lifetime), altchan.ReleaseCapabilities(true), 1)
		ts := attT.Add(attOff)
		nsm := enclavetest.NewFakeNSM(spec.PCR0, spec.PCR1, spec.PCR2, func() time.Time { return ts })
		ud := altchan.ETKUserData(desc)
		att, err := nsm.Attest(ud[:], nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.VerifyEnclave(desc, att, m, false, tr, at)
		return err
	}
	if client.MaxDescriptorLifetime != 24*time.Hour+5*time.Minute {
		t.Fatalf("allowance %v", client.MaxDescriptorLifetime)
	}
	for _, c := range []struct {
		name     string
		lifetime time.Duration
		attOff   time.Duration
		at       time.Time
		ok       bool
	}{
		{"release 21: 24 h - 60 s", 24*time.Hour - 60*time.Second, 0, attT, true},
		{"earlier releases: 24 h", 24 * time.Hour, 0, attT, true},
		{"24 h, attestation 61 s behind the enclave's clock", 24 * time.Hour, -61 * time.Second, attT, true},
		{"exactly 24 h + 5 min", 24*time.Hour + 5*time.Minute, 0, attT, true},
		{"24 h + 5 min + 1 ms", 24*time.Hour + 5*time.Minute, -time.Millisecond, attT, false},
		{"24 h + 5 min + 1 s", 24*time.Hour + 5*time.Minute + time.Second, 0, attT, false},
		{"25 h", 25 * time.Hour, 0, attT, false},
		{"not_after just ahead of the app", 24*time.Hour - 60*time.Second, 0, attT.Add(24*time.Hour - 60*time.Second - time.Millisecond), true},
		{"not_after = the app's time", 24*time.Hour - 60*time.Second, 0, attT.Add(24*time.Hour - 60*time.Second), false},
		{"not_after before the app's time", 24*time.Hour - 60*time.Second, 0, attT.Add(24 * time.Hour), false},
	} {
		err := check(c.lifetime, c.attOff, c.at)
		if c.ok && err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
		}
		if !c.ok && !errors.Is(err, client.ErrEnclave) {
			t.Errorf("%s: accepted (%v)", c.name, err)
		}
	}
}
