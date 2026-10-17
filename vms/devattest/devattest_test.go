package devattest_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
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

// AndroidDevPackages (the dev enclave's device policy file) accepts the
// listed packages besides AndroidPackage, and nothing else.
func TestAndroidDevPackages(t *testing.T) {
	ch := challenge("enroll")
	dev := enclavetest.NewAndroidAttester(0x62, enclavetest.AndroidOptions{Package: "com.vettid.app.devstack"})
	da, _ := dev.Attest(ch)
	p := enclavetest.Policy()
	if _, err := devattest.VerifyAttest(p, da, ch, now, fresh()); !errors.Is(err, devattest.ErrApplication) {
		t.Fatalf("dev package without the dev policy: %v", err)
	}
	p.AndroidDevPackages = []string{"", "com.vettid.app.dev", "com.vettid.app.devstack"}
	if _, err := devattest.VerifyAttest(p, da, ch, now, fresh()); err != nil {
		t.Fatalf("dev package: %v", err)
	}
	// The release package still passes; others and prefixes do not.
	rel := enclavetest.NewAndroidAttester(0x63, enclavetest.AndroidOptions{ExtraPackage: "com.vettid.app.dev"})
	da, _ = rel.Attest(ch)
	if _, err := devattest.VerifyAttest(p, da, ch, now, fresh()); err != nil {
		t.Fatalf("release + dev package: %v", err)
	}
	for _, pkg := range []string{"com.vettid.app.devstack2", "com.vettid.app.de", "com.evil.app"} {
		a := enclavetest.NewAndroidAttester(0x64, enclavetest.AndroidOptions{Package: pkg})
		da, _ := a.Attest(ch)
		if _, err := devattest.VerifyAttest(p, da, ch, now, fresh()); !errors.Is(err, devattest.ErrApplication) {
			t.Fatalf("%s: %v", pkg, err)
		}
	}
	// An empty AndroidPackage still disables Android.
	p.AndroidPackage = ""
	if _, err := devattest.VerifyAttest(p, da, ch, now, fresh()); !errors.Is(err, devattest.ErrPlatform) {
		t.Fatalf("no package: %v", err)
	}
}

// VAULT-MESSAGING 0.27.0 §11.7.1, "The signer of an attestation": exactly
// one signing digest, pinned by the release, recorded in the binding with
// the class the release gives it. Two digests are refused even when both
// are pinned; an unpinned digest is refused; each configured signer has
// its class.
func TestAndroidSigner(t *testing.T) {
	ch := challenge("enroll")
	p := enclavetest.PinSigner(enclavetest.PinSigner(enclavetest.Policy(), enclavetest.AndroidSignerPlay, devattest.ClassGooglePlay),
		enclavetest.AndroidSignerDev, devattest.ClassDevelopment)
	for name, tc := range map[string]struct {
		signer [32]byte
		class  string
	}{
		"vettid":      {enclavetest.AndroidSigner, devattest.ClassVettID},
		"google_play": {enclavetest.AndroidSignerPlay, devattest.ClassGooglePlay},
		"development": {enclavetest.AndroidSignerDev, devattest.ClassDevelopment},
	} {
		a := enclavetest.NewAndroidAttester(0x61, enclavetest.AndroidOptions{Signers: [][]byte{tc.signer[:]}})
		da, _ := a.Attest(ch)
		b, err := devattest.VerifyAttest(p, da, ch, now, fresh())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if b.Signer != hex.EncodeToString(tc.signer[:]) || b.SignerClass != tc.class {
			t.Fatalf("%s: recorded %q %q", name, b.Signer, b.SignerClass)
		}
		if c, pinned := p.SignerClass(b.Signer); !pinned || c != tc.class {
			t.Fatalf("%s: class %q pinned %v", name, c, pinned)
		}
		if r := devattest.CheckSigner(p, b); r != "" {
			t.Fatalf("%s: a pinned signer refused: %s", name, r)
		}
		// The same key on a release that does not pin its signer.
		if r := devattest.CheckSigner(enclavetest.UnpinSigner(p, tc.signer), b); r != devattest.RefusedUnpinned {
			t.Fatalf("%s: unpinned signer: %q", name, r)
		}
	}
	// Two digests, both pinned: refused (before 0.27.0: accepted).
	two := enclavetest.NewAndroidAttester(0x62, enclavetest.AndroidOptions{Signers: [][]byte{enclavetest.AndroidSigner[:], enclavetest.AndroidSignerPlay[:]}})
	da, _ := two.Attest(ch)
	if _, err := devattest.VerifyAttest(p, da, ch, now, fresh()); !errors.Is(err, devattest.ErrApplication) {
		t.Fatalf("two pinned digests: %v", err)
	}
	same := enclavetest.NewAndroidAttester(0x62, enclavetest.AndroidOptions{Signers: [][]byte{enclavetest.AndroidSigner[:], enclavetest.AndroidSigner[:]}})
	da, _ = same.Attest(ch)
	if _, err := devattest.VerifyAttest(p, da, ch, now, fresh()); !errors.Is(err, devattest.ErrApplication) {
		t.Fatalf("one pinned digest twice: %v", err)
	}
	// An unpinned digest: refused (the test policy alone pins one).
	play := enclavetest.NewAndroidAttester(0x63, enclavetest.AndroidOptions{Signers: [][]byte{enclavetest.AndroidSignerPlay[:]}})
	da, _ = play.Attest(ch)
	if _, err := devattest.VerifyAttest(enclavetest.Policy(), da, ch, now, fresh()); !errors.Is(err, devattest.ErrApplication) {
		t.Fatalf("unpinned digest: %v", err)
	}
	// Class helpers.
	for _, c := range []string{"vettid", "google_play", "development"} {
		if !devattest.ValidClass(c) {
			t.Errorf("%s not a class", c)
		}
	}
	for _, c := range []string{"", "play", "Vettid", "unknown"} {
		if devattest.ValidClass(c) {
			t.Errorf("%q accepted as a class", c)
		}
	}
	if _, pinned := p.SignerClass("zz"); pinned {
		t.Fatal("a malformed digest is pinned")
	}
	// iOS has no signer and always passes the rule.
	ia := enclavetest.NewIOSAttester(0x71, enclavetest.IOSOptions{})
	ida, _ := ia.Attest(ch)
	ib, err := devattest.VerifyAttest(p, ida, ch, now, fresh())
	if err != nil || ib.Signer != "" || devattest.CheckSigner(p, ib) != "" {
		t.Fatalf("ios: %+v %v", ib, err)
	}
}

// §11.7.1, "Vaults enrolled before 0.27.0": a key with no recorded signer
// is bound from the chain it was attested with. The chain is verified as
// at attestation except that the leaf must be the bound key and the
// serials the stored ones, and that the challenge and the validity
// periods are not checked again.
func TestBindSigner(t *testing.T) {
	p := enclavetest.Policy()
	ch := challenge("enrolled long ago")
	a := enclavetest.NewAndroidAttester(0x65, enclavetest.AndroidOptions{})
	da, _ := a.Attest(ch)
	full, err := devattest.VerifyAttest(p, da, ch, now, fresh())
	if err != nil {
		t.Fatal(err)
	}
	old := *full // a binding as releases before 0.27.0 wrote it
	old.Signer, old.SignerClass = "", ""
	// Unbound: refused, except where the release accepts unbound keys.
	if r := devattest.CheckSigner(p, &old); r != devattest.RefusedUnbound {
		t.Fatalf("unbound: %q", r)
	}
	staging := *p
	staging.AndroidAcceptUnbound = true
	if r := devattest.CheckSigner(&staging, &old); r != "" {
		t.Fatalf("unbound on staging S10: %q", r)
	}
	// With the chain: bound, long after the attestation (no challenge, no
	// validity check), the rest of the binding unchanged.
	later := *p
	b, err := devattest.BindSigner(&later, &old, da.Chain)
	if err != nil {
		t.Fatal(err)
	}
	if b.Signer != full.Signer || b.SignerClass != devattest.ClassVettID || string(b.PublicKey) != string(old.PublicKey) ||
		len(b.Serials) != len(old.Serials) || devattest.CheckSigner(p, b) != "" {
		t.Fatalf("bound %+v", b)
	}
	// Bound once: BindSigner refuses a key that has a signer (the caller
	// ignores `chain` for it).
	if _, err := devattest.BindSigner(p, b, da.Chain); err == nil {
		t.Fatal("a bound key was bound again")
	}
	// A chain for another key (same app, another device key).
	other := enclavetest.NewAndroidAttester(0x66, enclavetest.AndroidOptions{})
	oda, _ := other.Attest(ch)
	if _, err := devattest.BindSigner(p, &old, oda.Chain); !errors.Is(err, devattest.ErrChain) {
		t.Fatalf("another key's chain: %v", err)
	}
	// The same key attested again: other serials.
	again, _ := a.Attest(ch)
	if _, err := devattest.BindSigner(p, &old, again.Chain); !errors.Is(err, devattest.ErrChain) {
		t.Fatalf("other serials: %v", err)
	}
	// A chain naming another package than the policy's (the staging
	// move: a vault enrolled under the old package cannot bind by chain).
	moved := *p
	moved.AndroidPackage = "com.vettid.app.staging"
	if _, err := devattest.BindSigner(&moved, &old, da.Chain); !errors.Is(err, devattest.ErrApplication) {
		t.Fatalf("another package: %v", err)
	}
	// Two digests, and an unpinned digest, in the chain of the bound key.
	for name, signers := range map[string][][]byte{
		"two digests": {enclavetest.AndroidSigner[:], enclavetest.AndroidSignerPlay[:]},
		"unpinned":    {enclavetest.AndroidSignerPlay[:]},
	} {
		x := enclavetest.NewAndroidAttester(0x67, enclavetest.AndroidOptions{Signers: signers})
		xda, _ := x.Attest(ch)
		// What a release before 0.27.0 with both pinned would have stored.
		both := enclavetest.PinSigner(p, enclavetest.AndroidSignerPlay, devattest.ClassGooglePlay)
		xb := bindingOf(t, both, xda.Chain)
		pol := p
		if name == "two digests" {
			pol = both
		}
		if _, err := devattest.BindSigner(pol, xb, xda.Chain); !errors.Is(err, devattest.ErrApplication) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// A broken chain, a missing root, no chain.
	if _, err := devattest.BindSigner(p, &old, da.Chain[:2]); !errors.Is(err, devattest.ErrRoot) {
		t.Fatalf("no root: %v", err)
	}
	if _, err := devattest.BindSigner(p, &old, nil); err == nil {
		t.Fatal("no chain")
	}
	if _, err := devattest.BindSigner(p, &old, [][]byte{{0x30, 0x00}}); err == nil {
		t.Fatal("garbage chain")
	}
	// The other attestation checks still apply to the re-sent chain: a
	// software-level key is not bound.
	sw := enclavetest.NewAndroidAttester(0x68, enclavetest.AndroidOptions{SoftwareLevel: true})
	swda, _ := sw.Attest(ch)
	if _, err := devattest.BindSigner(p, bindingOf(t, nil, swda.Chain), swda.Chain); !errors.Is(err, devattest.ErrSecurityLevel) {
		t.Fatalf("software level: %v", err)
	}
}

// bindingOf builds the signer-less binding of a chain's key without
// verifying it (pol nil), or after checking that pol would have accepted
// something like it before 0.27.0: the public key and the serials.
func bindingOf(t *testing.T, _ *devattest.Policy, chain [][]byte) *devattest.Binding {
	t.Helper()
	b := &devattest.Binding{Platform: "android"}
	for i, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			b.PublicKey = c.RawSubjectPublicKeyInfo
		}
		b.Serials = append(b.Serials, c.SerialNumber.Text(16))
	}
	return b
}

// The development members of the iOS policy (the dev enclave's device
// policy file): further App IDs, at attestation and at each assertion,
// and the development environment. A policy without them (every release
// configuration) accepts only IOSAppID and production, and an empty
// IOSAppID accepts nothing even with development App IDs.
func TestIOSDevelopmentMembers(t *testing.T) {
	const devApp = "3X25CJ86MV.com.vettid.app.dev"
	ch := challenge("enroll")
	base := enclavetest.Policy()
	dev := *base
	dev.IOSDevAppIDs = []string{devApp}
	dev.IOSDevelopmentEnvironment = true

	for _, tc := range []struct {
		name    string
		o       enclavetest.IOSOptions
		baseErr error
	}{
		{"dev App ID", enclavetest.IOSOptions{AppID: devApp}, devattest.ErrApplication},
		{"development environment", enclavetest.IOSOptions{Develop: true}, devattest.ErrEnvironment},
		{"both", enclavetest.IOSOptions{AppID: devApp, Develop: true}, devattest.ErrApplication},
	} {
		a := enclavetest.NewIOSAttester(0x74, tc.o)
		d, _ := a.Attest(ch)
		if _, err := devattest.VerifyAttest(base, d, ch, now, nil); !errors.Is(err, tc.baseErr) {
			t.Errorf("%s under the TEST policy: %v", tc.name, err)
		}
		b, err := devattest.VerifyAttest(&dev, d, ch, now, nil)
		if err != nil {
			t.Fatalf("%s under the dev members: %v", tc.name, err)
		}
		s := devattest.ForChallenge(challenge("unlock"))
		as, _ := a.Assert(s)
		if _, err := devattest.VerifyAssertion(&dev, b, as, s, b.Counter, now, nil); err != nil {
			t.Fatalf("%s: assertion under the dev members: %v", tc.name, err)
		}
		if tc.o.AppID != "" {
			if _, err := devattest.VerifyAssertion(base, b, as, s, b.Counter, now, nil); !errors.Is(err, devattest.ErrApplication) {
				t.Errorf("%s: assertion of a dev App ID under the TEST policy: %v", tc.name, err)
			}
		}
	}
	// Development only adds: the TEST App ID still passes, another App ID
	// still fails, and an unknown aaguid is still refused.
	d, _ := enclavetest.NewIOSAttester(0x75, enclavetest.IOSOptions{}).Attest(ch)
	if _, err := devattest.VerifyAttest(&dev, d, ch, now, nil); err != nil {
		t.Fatalf("TEST App ID under the dev members: %v", err)
	}
	d, _ = enclavetest.NewIOSAttester(0x76, enclavetest.IOSOptions{AppID: "OTHERTEAM0.com.vettid.app.dev"}).Attest(ch)
	if _, err := devattest.VerifyAttest(&dev, d, ch, now, nil); !errors.Is(err, devattest.ErrApplication) {
		t.Fatalf("other App ID under the dev members: %v", err)
	}
	// Without IOSAppID nothing is accepted, development App IDs or not.
	none := dev
	none.IOSAppID = ""
	d, _ = enclavetest.NewIOSAttester(0x77, enclavetest.IOSOptions{AppID: devApp}).Attest(ch)
	if _, err := devattest.VerifyAttest(&none, d, ch, now, nil); !errors.Is(err, devattest.ErrPlatform) {
		t.Fatalf("no IOSAppID: %v", err)
	}
	if string(devattest.AAGUIDDevelopment[:]) != "appattestdevelop" || string(devattest.AAGUIDProduction[:9]) != "appattest" {
		t.Fatal("aaguids")
	}
}
