package enclavetest_test

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/devattest"
	"github.com/vettid/vettid-vault/vms/pins"
)

var debugSigner = sha256.Sum256([]byte("TEST debug keystore certificate"))

// otherCA is a second Android attestation PKI, standing in for Google's.
func otherCA() *enclavetest.AndroidCA {
	root := enclavetest.NewRootCA("TEST other attestation root", enclavetest.TestKey(elliptic.P384(), 0x51))
	return &enclavetest.AndroidCA{Root: root, Inter: root.SubCA("TEST other attestation intermediate", 2, enclavetest.TestKey(elliptic.P256(), 0x52))}
}

func pemOf(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func policyJSON(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fullPolicy(t *testing.T) []byte {
	colon := strings.ToUpper(hex.EncodeToString(debugSigner[:]))
	var pairs []string
	for i := 0; i < len(colon); i += 2 {
		pairs = append(pairs, colon[i:i+2])
	}
	return policyJSON(t, map[string]any{
		"google_attestation_roots": true,
		"android_roots_pem":        []string{pemOf(otherCA().Root.Cert)},
		"android_packages":         []string{"com.vettid.app.dev", "com.vettid.app.devstack"},
		"android_signers_sha256":   []string{strings.Join(pairs, ":")},
		"grapheneos_boot_keys":     true,
	})
}

func TestDevDevicePolicyApply(t *testing.T) {
	p, err := enclavetest.ParseDevDevicePolicy(fullPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Signers[0], debugSigner[:]) || len(p.Packages) != 2 || len(p.ExtraRoots) != 1 || !p.GoogleRoots || !p.GrapheneOS {
		t.Fatalf("%+v", p)
	}
	base := enclavetest.Policy()
	ext := p.Apply(base)
	// The base policy is unchanged and still included.
	if len(base.AndroidRoots) != 1 || len(base.AndroidSigners) != 1 || len(base.AndroidDevPackages) != 0 || len(base.AndroidSelfSignedBootKeys) != 1 {
		t.Fatalf("base modified: %+v", base)
	}
	google := pins.GoogleAttestationRoots()
	if len(ext.AndroidRoots) != 1+len(google)+1 || ext.AndroidRoots[0] != base.AndroidRoots[0] {
		t.Fatalf("roots: %d", len(ext.AndroidRoots))
	}
	ca1 := false
	for _, r := range ext.AndroidRoots {
		if strings.Contains(r.Subject.String(), "Key Attestation CA1") {
			ca1 = true
		}
	}
	if !ca1 {
		t.Fatal("Google Key Attestation CA1 missing")
	}
	if ext.AndroidPackage != enclavetest.AndroidPackage || len(ext.AndroidSigners) != 2 ||
		len(ext.AndroidSelfSignedBootKeys) != 1+len(pins.GrapheneOSVerifiedBootKeys()) {
		t.Fatalf("%+v", ext)
	}
	if p2 := (*enclavetest.DevDevicePolicy)(nil); p2.Apply(base) != base {
		t.Fatal("nil policy")
	}
	sum := p.Summary()
	if sum["android_packages"].([]string)[1] != "com.vettid.app.devstack" || sum["android_signers_sha256"].([]string)[0] != hex.EncodeToString(debugSigner[:]) {
		t.Fatalf("%v", sum)
	}
}

// A dev-stack build on a GrapheneOS phone: dev package, debug signer,
// SelfSigned boot with a real GrapheneOS key, chain to an added root.
func TestDevDevicePolicyVerifies(t *testing.T) {
	now := time.Now()
	list := enclavetest.EmptyStatusList(now.Add(-time.Hour))
	ch := sha256.Sum256([]byte("enroll"))
	bootKey := pins.GrapheneOSVerifiedBootKeys()[0] // a real, pinned GrapheneOS key
	o := enclavetest.AndroidOptions{Challenge: ch, Package: "com.vettid.app.devstack", Signers: [][]byte{debugSigner[:]},
		BootState: 1, BootKey: bootKey}
	key := enclavetest.TestKey(elliptic.P256(), 0x71)
	chain := otherCA().Attest(key, o)

	verify := func(pol *devattest.Policy) error {
		_, err := devattest.VerifyAttest(pol, &altchan.DeviceAttest{Platform: altchan.PlatformAndroid, Chain: chain}, ch, now, list)
		return err
	}
	base := enclavetest.Policy()
	if err := verify(base); !errors.Is(err, devattest.ErrRoot) {
		t.Fatalf("TEST policy: %v", err)
	}
	p, err := enclavetest.ParseDevDevicePolicy(fullPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(p.Apply(base)); err != nil {
		t.Fatalf("dev policy: %v", err)
	}
	// Each part is needed.
	for name, m := range map[string]map[string]any{
		"no root":       {"android_packages": []string{"com.vettid.app.devstack"}, "android_signers_sha256": []string{hex.EncodeToString(debugSigner[:])}, "grapheneos_boot_keys": true},
		"no package":    {"android_roots_pem": []string{pemOf(otherCA().Root.Cert)}, "android_signers_sha256": []string{hex.EncodeToString(debugSigner[:])}, "grapheneos_boot_keys": true},
		"no signer":     {"android_roots_pem": []string{pemOf(otherCA().Root.Cert)}, "android_packages": []string{"com.vettid.app.devstack"}, "grapheneos_boot_keys": true},
		"no grapheneos": {"android_roots_pem": []string{pemOf(otherCA().Root.Cert)}, "android_packages": []string{"com.vettid.app.devstack"}, "android_signers_sha256": []string{hex.EncodeToString(debugSigner[:])}},
	} {
		p, err := enclavetest.ParseDevDevicePolicy(policyJSON(t, m))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := verify(p.Apply(base)); err == nil {
			t.Fatalf("%s: verified", name)
		}
	}
	// The TEST attester still passes the extended policy.
	a := enclavetest.NewAndroidAttester(0x72, enclavetest.AndroidOptions{})
	da, _ := a.Attest(ch)
	if _, err := devattest.VerifyAttest(p.Apply(base), da, ch, now, list); err != nil {
		t.Fatalf("TEST attester: %v", err)
	}
}

func TestDevDevicePolicyRejects(t *testing.T) {
	other := otherCA()
	inter := pemOf(other.Inter.Cert) // not self-signed
	leaf := other.Inter.Issue(&x509.Certificate{SerialNumber: big.NewInt(9)}, enclavetest.TestKey(elliptic.P256(), 0x73).Public())
	root := pemOf(other.Root.Cert)
	hex64 := hex.EncodeToString(debugSigner[:])
	for name, in := range map[string]string{
		"empty":            ``,
		"not object":       `[]`,
		"empty object":     `{}`,
		"adds nothing":     `{"google_attestation_roots":false,"grapheneos_boot_keys":false,"android_packages":[]}`,
		"unknown member":   `{"google_attestation_roots":true,"android_package":"com.x.y"}`,
		"case variant":     `{"Google_attestation_roots":true}`,
		"duplicate member": `{"google_attestation_roots":true,"google_attestation_roots":true}`,
		"trailing data":    `{"google_attestation_roots":true} {}`,
		"bool as string":   `{"google_attestation_roots":"true"}`,
		"packages string":  `{"android_packages":"com.vettid.app.dev"}`,
		"package number":   `{"android_packages":[1]}`,
		"package one part": `{"android_packages":["vettid"]}`,
		"package digit":    `{"android_packages":["com.1vettid.app"]}`,
		"package dash":     `{"android_packages":["com.vettid-app.dev"]}`,
		"package trailing": `{"android_packages":["com.vettid.app."]}`,
		"package space":    `{"android_packages":["com.vettid.app "]}`,
		"package dup":      `{"android_packages":["com.vettid.app.dev","com.vettid.app.dev"]}`,
		"packages many":    `{"android_packages":["a.a","a.b","a.c","a.d","a.e","a.f","a.g","a.h","a.i","a.j","a.k","a.l","a.m","a.n","a.o","a.p","a.q"]}`,
		"signer short":     `{"android_signers_sha256":["` + hex64[:62] + `"]}`,
		"signer long":      `{"android_signers_sha256":["` + hex64 + `00"]}`,
		"signer non-hex":   `{"android_signers_sha256":["` + strings.Repeat("g", 64) + `"]}`,
		"signer colons":    `{"android_signers_sha256":["` + strings.Repeat("ab:", 31) + `a:b"]}`,
		"signer dup":       `{"android_signers_sha256":["` + hex64 + `","` + strings.ToUpper(hex64) + `"]}`,
		"root garbage":     `{"android_roots_pem":["hello"]}`,
		"root not root":    string(policyJSON(t, map[string]any{"android_roots_pem": []string{inter}})),
		"root not CA":      string(policyJSON(t, map[string]any{"android_roots_pem": []string{pemOf(leaf)}})),
		"root two blocks":  string(policyJSON(t, map[string]any{"android_roots_pem": []string{root + root}})),
		"root prefix":      string(policyJSON(t, map[string]any{"android_roots_pem": []string{"x\n" + root}})),
		"root wrong type":  string(policyJSON(t, map[string]any{"android_roots_pem": []string{strings.ReplaceAll(root, "CERTIFICATE", "PUBLIC KEY")}})),
		"root dup":         string(policyJSON(t, map[string]any{"android_roots_pem": []string{root, root}})),
		"not utf-8":        "{\"android_packages\":[\"com.vettid.\xff\"]}",
		"too large":        `{"android_packages":["com.vettid.app.dev"],"x":"` + strings.Repeat("a", enclavetest.MaxDevDevicePolicySize) + `"}`,
	} {
		if _, err := enclavetest.ParseDevDevicePolicy([]byte(in)); !errors.Is(err, enclavetest.ErrDevPolicy) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Whitespace around the PEM block is allowed.
	if _, err := enclavetest.ParseDevDevicePolicy(policyJSON(t, map[string]any{"android_roots_pem": []string{"\n\n" + root + "\n"}})); err != nil {
		t.Fatal(err)
	}
}

// The vault processes get the policy through DevVaultPolicyArgs.
func TestDevVaultPolicyArgs(t *testing.T) {
	in := fullPolicy(t)
	p, err := enclavetest.ParseDevDevicePolicy(in)
	if err != nil {
		t.Fatal(err)
	}
	if enclavetest.DevVaultPolicyArgs(nil) != nil {
		t.Fatal("nil policy has arguments")
	}
	args := append(enclavetest.DevVaultArgs(3, "https://relay.vettid.test"), enclavetest.DevVaultPolicyArgs(p)...)
	pl, err := enclavetest.DevVaultPlatform(args)
	if err != nil {
		t.Fatal(err)
	}
	if got := pl.Config("v").DeviceAttest.AndroidDevPackages; len(got) != 2 {
		t.Fatalf("vault process policy: %v", got)
	}
	pl, err = enclavetest.DevVaultPlatform(enclavetest.DevVaultArgs(3, "https://relay.vettid.test"))
	if err != nil || len(pl.Config("v").DeviceAttest.AndroidDevPackages) != 0 {
		t.Fatalf("no policy: %v", err)
	}
	for _, bad := range [][]string{
		append(enclavetest.DevVaultArgs(3, "https://relay.vettid.test"), "-device-policy", "!!"),
		append(enclavetest.DevVaultArgs(3, "https://relay.vettid.test"), "-device-policy", "e30="), // {}
		append(enclavetest.DevVaultArgs(3, "https://relay.vettid.test"), "extra"),
	} {
		if _, err := enclavetest.DevVaultPlatform(bad); err == nil {
			t.Fatalf("%v accepted", bad)
		}
	}
	if !bytes.Equal(p.Raw(), in) {
		t.Fatal("raw")
	}
}

func FuzzParseDevDevicePolicy(f *testing.F) {
	f.Add([]byte(`{"google_attestation_roots":true,"android_packages":["com.vettid.app.dev"],"grapheneos_boot_keys":true}`))
	f.Add([]byte(`{"android_signers_sha256":["` + hex.EncodeToString(debugSigner[:]) + `"]}`))
	f.Add([]byte(`{"android_roots_pem":["-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"]}`))
	f.Add([]byte(`{"android_packages":["a.b","a.b"]}`))
	f.Add([]byte(`{}`))
	base := enclavetest.Policy()
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := enclavetest.ParseDevDevicePolicy(b)
		if err != nil {
			if !errors.Is(err, enclavetest.ErrDevPolicy) {
				t.Fatalf("error not ErrDevPolicy: %v", err)
			}
			return
		}
		ext := p.Apply(base)
		if len(ext.AndroidRoots) < len(base.AndroidRoots) || len(ext.AndroidSigners) < len(base.AndroidSigners) || ext.AndroidPackage != base.AndroidPackage {
			t.Fatal("the dev policy removed something")
		}
		p2, err := enclavetest.ParseDevDevicePolicy(p.Raw())
		if err != nil || len(p2.Packages) != len(p.Packages) || len(p2.Signers) != len(p.Signers) || len(p2.ExtraRoots) != len(p.ExtraRoots) {
			t.Fatalf("raw does not reparse: %v", err)
		}
		_ = p.Summary()
	})
}
