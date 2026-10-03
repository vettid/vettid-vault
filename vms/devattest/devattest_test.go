package devattest_test

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/devattest"
	"github.com/vettid/vettid-vault/vms/pins"
)

var now = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func challenge(s string) [32]byte { return sha256.Sum256([]byte(s)) }

func fresh() *devattest.StatusList { return enclavetest.EmptyStatusList(now.Add(-time.Hour)) }

func TestAndroidHappyPath(t *testing.T) {
	p := enclavetest.Policy()
	ch := challenge("enroll")
	a := enclavetest.NewAndroidAttester(0x61, enclavetest.AndroidOptions{})
	da, _ := a.Attest(ch)
	b, err := devattest.VerifyAttest(p, da, ch, now, fresh())
	if err != nil {
		t.Fatal(err)
	}
	if b.Platform != "android" || len(b.Serials) != 3 {
		t.Fatalf("%+v", b)
	}
	uch := challenge("unlock")
	as, _ := a.Assert(devattest.ForChallenge(uch))
	if _, err := devattest.VerifyAssertion(p, b, as, devattest.ForChallenge(uch), b.Counter, now, enclavetest.EmptyStatusList(now.Add(-6*24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	// Wrong message.
	if _, err := devattest.VerifyAssertion(p, b, as, devattest.ForChallenge(challenge("other")), 0, now, fresh()); !errors.Is(err, devattest.ErrSignature) {
		t.Fatalf("other challenge: %v", err)
	}
	// A list older than 7 days fails unlock; older than 24 h fails enrollment.
	if _, err := devattest.VerifyAssertion(p, b, as, devattest.ForChallenge(uch), 0, now, enclavetest.EmptyStatusList(now.Add(-8*24*time.Hour))); !errors.Is(err, devattest.ErrRevocationList) {
		t.Fatalf("stale unlock list: %v", err)
	}
	if _, err := devattest.VerifyAttest(p, da, ch, now, enclavetest.EmptyStatusList(now.Add(-25*time.Hour))); !errors.Is(err, devattest.ErrRevocationList) {
		t.Fatalf("stale enroll list: %v", err)
	}
	if _, err := devattest.VerifyAttest(p, da, ch, now, nil); !errors.Is(err, devattest.ErrRevocationList) {
		t.Fatal("no list")
	}
	// A revoked intermediate (serial 2) fails both.
	rev, err := devattest.ParseStatusList([]byte(`{"entries":{"2":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}`), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := devattest.VerifyAttest(p, da, ch, now, rev); !errors.Is(err, devattest.ErrRevoked) {
		t.Fatalf("revoked: %v", err)
	}
	if _, err := devattest.VerifyAssertion(p, b, as, devattest.ForChallenge(uch), 0, now, rev); !errors.Is(err, devattest.ErrRevoked) {
		t.Fatalf("revoked at unlock: %v", err)
	}
}

func TestAndroidRejects(t *testing.T) {
	p := enclavetest.Policy()
	ch := challenge("enroll")
	other := sha256.Sum256([]byte("another app"))
	gos := enclavetest.TestGrapheneOSBootKey[:]
	for name, tc := range map[string]struct {
		o   enclavetest.AndroidOptions
		err error
	}{
		"software level":      {enclavetest.AndroidOptions{SoftwareLevel: true}, devattest.ErrSecurityLevel},
		"old version":         {enclavetest.AndroidOptions{Version: 2}, devattest.ErrSecurityLevel},
		"wrong challenge":     {enclavetest.AndroidOptions{Challenge: challenge("x")}, devattest.ErrChallenge},
		"unlocked bootloader": {enclavetest.AndroidOptions{Unlocked: true}, devattest.ErrRootOfTrust},
		"self-signed boot":    {enclavetest.AndroidOptions{BootState: 1}, devattest.ErrRootOfTrust},
		"unverified boot":     {enclavetest.AndroidOptions{BootState: 2}, devattest.ErrRootOfTrust},
		// GrapheneOS (§11.7, 0.9.0): SelfSigned only with a pinned OS key,
		// still locked; Unverified and Failed never.
		"grapheneos self-signed":          {enclavetest.AndroidOptions{BootState: 1, BootKey: gos}, nil},
		"self-signed, other key":          {enclavetest.AndroidOptions{BootState: 1, BootKey: other[:]}, devattest.ErrRootOfTrust},
		"self-signed, short key":          {enclavetest.AndroidOptions{BootState: 1, BootKey: gos[:31]}, devattest.ErrRootOfTrust},
		"grapheneos key, unlocked":        {enclavetest.AndroidOptions{BootState: 1, BootKey: gos, Unlocked: true}, devattest.ErrRootOfTrust},
		"grapheneos key, unverified boot": {enclavetest.AndroidOptions{BootState: 2, BootKey: gos}, devattest.ErrRootOfTrust},
		"grapheneos key, failed boot":     {enclavetest.AndroidOptions{BootState: 3, BootKey: gos}, devattest.ErrRootOfTrust},
		"verified with any key is fine":   {enclavetest.AndroidOptions{BootKey: other[:]}, nil},
		"no root of trust":                {enclavetest.AndroidOptions{NoRootOfTrust: true}, devattest.ErrRootOfTrust},
		"other package":                   {enclavetest.AndroidOptions{Package: "com.evil.app"}, devattest.ErrApplication},
		"extra package":                   {enclavetest.AndroidOptions{ExtraPackage: "com.evil.app"}, devattest.ErrApplication},
		"other signer":                    {enclavetest.AndroidOptions{Signers: [][]byte{other[:]}}, devattest.ErrApplication},
		"extra signer":                    {enclavetest.AndroidOptions{Signers: [][]byte{enclavetest.AndroidSigner[:], other[:]}}, devattest.ErrApplication},
		"no signer":                       {enclavetest.AndroidOptions{Signers: [][]byte{}}, devattest.ErrApplication},
		"decrypt purpose":                 {enclavetest.AndroidOptions{Purposes: []int64{2, 1}}, devattest.ErrKeyProperties},
		"agree purpose":                   {enclavetest.AndroidOptions{Purposes: []int64{2, 6}}, devattest.ErrKeyProperties},
		"verify only":                     {enclavetest.AndroidOptions{Purposes: []int64{3}}, devattest.ErrKeyProperties},
		"rsa":                             {enclavetest.AndroidOptions{Algorithm: 1}, devattest.ErrKeyProperties},
		"p-384 curve":                     {enclavetest.AndroidOptions{Curve: 2}, devattest.ErrKeyProperties},
		"imported key":                    {enclavetest.AndroidOptions{Origin: 2}, devattest.ErrKeyProperties},
		"software-only props":             {enclavetest.AndroidOptions{SoftwarePurposes: true}, devattest.ErrKeyProperties},
		"app id in hw is fine":            {enclavetest.AndroidOptions{AppIDInHardware: true}, nil},
		"sign and verify fine":            {enclavetest.AndroidOptions{Purposes: []int64{2, 3}}, nil},
		"TEE level is fine":               {enclavetest.AndroidOptions{AttestSecurity: 1, KeymintSecurity: 1}, nil},
	} {
		a := enclavetest.NewAndroidAttester(0x62, tc.o)
		da, _ := a.Attest(ch)
		_, err := devattest.VerifyAttest(p, da, ch, now, fresh())
		if tc.err == nil && err != nil || tc.err != nil && !errors.Is(err, tc.err) {
			t.Errorf("%s: got %v, want %v", name, err, tc.err)
		}
	}
	// Chain problems.
	a := enclavetest.NewAndroidAttester(0x63, enclavetest.AndroidOptions{})
	da, _ := a.Attest(ch)
	short := &altchan.DeviceAttest{Platform: "android", Chain: da.Chain[:2]} // root missing
	if _, err := devattest.VerifyAttest(p, short, ch, now, fresh()); !errors.Is(err, devattest.ErrRoot) {
		t.Errorf("no root: %v", err)
	}
	swapped := &altchan.DeviceAttest{Platform: "android", Chain: [][]byte{da.Chain[0], da.Chain[2], da.Chain[1]}}
	if _, err := devattest.VerifyAttest(p, swapped, ch, now, fresh()); !errors.Is(err, devattest.ErrChain) {
		t.Errorf("swapped: %v", err)
	}
	real := *p
	real.AndroidRoots = pins.GoogleAttestationRoots()
	if _, err := devattest.VerifyAttest(&real, da, ch, now, fresh()); !errors.Is(err, devattest.ErrRoot) {
		t.Errorf("google roots accepted the test chain: %v", err)
	}
	if _, err := devattest.VerifyAttest(p, da, ch, time.Date(2070, 1, 1, 0, 0, 0, 0, time.UTC), enclavetest.EmptyStatusList(time.Date(2070, 1, 1, 0, 0, 0, 0, time.UTC))); !errors.Is(err, devattest.ErrChain) {
		t.Errorf("expired: %v", err)
	}
	// The release's real allowlist: a real GrapheneOS key (Pixel 8 Pro) is
	// accepted, and the test policy does not accept it.
	pixel := pins.GrapheneOSVerifiedBootKeys()[11]
	ga := enclavetest.NewAndroidAttester(0x64, enclavetest.AndroidOptions{BootState: 1, BootKey: pixel})
	gda, _ := ga.Attest(ch)
	if _, err := devattest.VerifyAttest(p, gda, ch, now, fresh()); !errors.Is(err, devattest.ErrRootOfTrust) {
		t.Errorf("test policy accepted a key it does not pin: %v", err)
	}
	rel := *p
	rel.AndroidSelfSignedBootKeys = pins.GrapheneOSVerifiedBootKeys()
	if _, err := devattest.VerifyAttest(&rel, gda, ch, now, fresh()); err != nil {
		t.Errorf("pinned GrapheneOS key refused: %v", err)
	}
	none := *p
	none.AndroidSelfSignedBootKeys = nil
	if _, err := devattest.VerifyAttest(&none, gda, ch, now, fresh()); !errors.Is(err, devattest.ErrRootOfTrust) {
		t.Errorf("SelfSigned without an allowlist: %v", err)
	}
	disabled := *p
	disabled.AndroidPackage = ""
	if _, err := devattest.VerifyAttest(&disabled, da, ch, now, fresh()); !errors.Is(err, devattest.ErrPlatform) {
		t.Errorf("unconfigured policy: %v", err)
	}
	if _, err := devattest.VerifyAttest(p, &altchan.DeviceAttest{Platform: "web"}, ch, now, fresh()); !errors.Is(err, devattest.ErrPlatform) {
		t.Error("platform")
	}
}

func TestIOS(t *testing.T) {
	p := enclavetest.Policy()
	ch := challenge("enroll")
	a := enclavetest.NewIOSAttester(0x71, enclavetest.IOSOptions{})
	da, _ := a.Attest(ch)
	b, err := devattest.VerifyAttest(p, da, ch, now, nil) // iOS needs no status list
	if err != nil {
		t.Fatal(err)
	}
	if b.Platform != "ios" || len(b.PublicKey) != 65 || b.Counter != 0 {
		t.Fatalf("%+v", b)
	}
	// Assertions: counters must increase.
	s := devattest.ForChallenge(challenge("unlock"))
	as1, _ := a.Assert(s)
	b1, err := devattest.VerifyAssertion(p, b, as1, s, b.Counter, now, nil)
	if err != nil || b1.Counter != 1 {
		t.Fatalf("%v %+v", err, b1)
	}
	if _, err := devattest.VerifyAssertion(p, b1, as1, s, b1.Counter, now, nil); !errors.Is(err, devattest.ErrCounter) {
		t.Fatalf("replayed counter: %v", err)
	}
	as2, _ := a.Assert(devattest.ForString("approval"))
	if _, err := devattest.VerifyAssertion(p, b1, as2, s, b1.Counter, now, nil); !errors.Is(err, devattest.ErrSignature) {
		t.Fatalf("wrong client data: %v", err)
	}
	if _, err := devattest.VerifyAssertion(p, b1, as2, devattest.ForString("approval"), b1.Counter, now, nil); err != nil {
		t.Fatal(err)
	}
	// Attestation rejects.
	for name, tc := range map[string]struct {
		o   enclavetest.IOSOptions
		err error
	}{
		"development": {enclavetest.IOSOptions{Develop: true}, devattest.ErrEnvironment},
		"other app":   {enclavetest.IOSOptions{AppID: "OTHERTEAM0.com.vettid.app"}, devattest.ErrApplication},
		"counter":     {enclavetest.IOSOptions{Counter: 1}, devattest.ErrCounter},
		"nonce":       {enclavetest.IOSOptions{WrongNonce: true}, devattest.ErrChallenge},
	} {
		x := enclavetest.NewIOSAttester(0x72, tc.o)
		d, _ := x.Attest(ch)
		if _, err := devattest.VerifyAttest(p, d, ch, now, nil); !errors.Is(err, tc.err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := devattest.VerifyAttest(p, da, challenge("other"), now, nil); !errors.Is(err, devattest.ErrChallenge) {
		t.Error("challenge")
	}
	wrongKey := *da
	wrongKey.KeyID = append([]byte(nil), da.KeyID...)
	wrongKey.KeyID[0] ^= 1
	if _, err := devattest.VerifyAttest(p, &wrongKey, ch, now, nil); !errors.Is(err, devattest.ErrKeyID) {
		t.Error("key id")
	}
	real := *p
	real.IOSRoots = x509.NewCertPool()
	real.IOSRoots.AddCert(pins.AppleAppAttestRoot())
	if _, err := devattest.VerifyAttest(&real, da, ch, now, nil); !errors.Is(err, devattest.ErrChain) {
		t.Error("apple root accepted the test chain")
	}
}

func TestStatusList(t *testing.T) {
	for name, s := range map[string]string{
		"upper hex":  `{"entries":{"ABC":{"status":"REVOKED"}}}`,
		"no status":  `{"entries":{"abc":{"reason":"KEY_COMPROMISE"}}}`,
		"duplicate":  `{"entries":{"abc":{"status":"REVOKED"},"abc":{"status":"REVOKED"}}}`,
		"no entries": `{}`,
		"array":      `{"entries":[]}`,
	} {
		if _, err := devattest.ParseStatusList([]byte(s), now); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	l, err := devattest.ParseStatusList([]byte(`{"entries":{"abc":{"status":"SUSPENDED","reason":"x"}}}`), now)
	if err != nil || l.Len() != 1 {
		t.Fatal(err)
	}
	if !errors.Is(l.Check([]string{"abc"}, now, time.Hour), devattest.ErrRevoked) {
		t.Fatal("suspended counts as revoked")
	}
}

func FuzzVerifyAttest(f *testing.F) {
	p := enclavetest.Policy()
	ch := challenge("enroll")
	da, _ := enclavetest.NewAndroidAttester(0x61, enclavetest.AndroidOptions{}).Attest(ch)
	ia, _ := enclavetest.NewIOSAttester(0x71, enclavetest.IOSOptions{}).Attest(ch)
	f.Add(da.Chain[0], []byte{}, false)
	f.Add(ia.Attestation, ia.KeyID, true)
	list := fresh()
	f.Fuzz(func(t *testing.T, blob, keyID []byte, ios bool) {
		if ios {
			_, _ = devattest.VerifyAttest(p, &altchan.DeviceAttest{Platform: "ios", KeyID: keyID, Attestation: blob}, ch, now, list)
			return
		}
		_, _ = devattest.VerifyAttest(p, &altchan.DeviceAttest{Platform: "android", Chain: [][]byte{blob, da.Chain[1], da.Chain[2]}}, ch, now, list)
	})
}

func FuzzVerifyAssertion(f *testing.F) {
	p := enclavetest.Policy()
	a := enclavetest.NewIOSAttester(0x71, enclavetest.IOSOptions{})
	da, _ := a.Attest(challenge("e"))
	b, _ := devattest.VerifyAttest(p, da, challenge("e"), now, nil)
	s := devattest.ForChallenge(challenge("u"))
	as, _ := a.Assert(s)
	f.Add(as.Assertion)
	f.Fuzz(func(t *testing.T, blob []byte) {
		_, _ = devattest.VerifyAssertion(p, b, &altchan.DeviceAssertion{Platform: "ios", Assertion: blob}, s, 0, now, nil)
	})
}

func FuzzStatusList(f *testing.F) {
	f.Add([]byte(`{"entries":{"abc":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = devattest.ParseStatusList(b, now)
	})
}

func FuzzKeyDescription(f *testing.F) {
	for _, o := range []enclavetest.AndroidOptions{{}, {BootState: 1, BootKey: enclavetest.TestGrapheneOSBootKey[:]}} {
		da, _ := enclavetest.NewAndroidAttester(0x61, o).Attest(challenge("e"))
		leaf, _ := x509.ParseCertificate(da.Chain[0])
		for _, e := range leaf.Extensions {
			if e.Id.Equal(devattest.OIDKeyDescription) {
				f.Add(e.Value)
			}
		}
	}
	p := enclavetest.Policy()
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = devattest.CheckKeyDescription(p, b)
	})
}
