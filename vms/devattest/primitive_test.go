package devattest_test

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/devattest"
)

// keyDescriptionOf returns the key attestation extension of a test leaf.
func keyDescriptionOf(t *testing.T, o enclavetest.AndroidOptions) []byte {
	t.Helper()
	da, err := enclavetest.NewAndroidAttester(0x61, o).Attest(challenge("e"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(da.Chain[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range leaf.Extensions {
		if e.Id.Equal(devattest.OIDKeyDescription) {
			return e.Value
		}
	}
	t.Fatal("no key description")
	return nil
}

// A SEQUENCE or SET encoded as primitive (the FuzzKeyDescription crasher
// shape) is refused, without a panic, wherever it appears in the Android
// key description: the outer KeyDescription, both AuthorizationLists, the
// purpose and digest SETs, RootOfTrust, and the AttestationApplicationId
// with its package infos and signature digests.
func TestAndroidPrimitiveConstructed(t *testing.T) {
	p := enclavetest.Policy()
	p.AndroidDevPackages = []string{"com.vettid.app.dev"}
	for _, o := range []enclavetest.AndroidOptions{{}, {AppIDInHardware: true}, {ExtraPackage: "com.vettid.app.dev"}} {
		kd := keyDescriptionOf(t, o)
		if err := devattest.CheckKeyDescriptionStrict(p, kd); err != nil {
			t.Fatalf("valid key description: %v", err)
		}
		vs := enclavetest.PrimitiveConstructedVariants(kd)
		if len(vs) < 8 {
			t.Fatalf("only %d SEQUENCE/SET positions", len(vs))
		}
		for i, v := range vs {
			if err := devattest.CheckKeyDescriptionStrict(p, v); err == nil {
				t.Errorf("%+v variant %d accepted", o, i)
			}
			// Through the full entry point: a validly signed chain whose
			// leaf carries the malformed extension.
			ch := challenge("enroll")
			o2 := o
			o2.Challenge = ch
			o2.MutateKeyDescription = func([]byte) []byte { return v }
			da, err := enclavetest.NewAndroidAttester(0x65, o2).Attest(ch)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := devattest.VerifyAttest(p, da, ch, now, fresh()); err == nil {
				t.Errorf("%+v variant %d: VerifyAttest accepted", o, i)
			}
		}
	}
	// The crasher shape itself: hardware purpose [1] holding a primitive SET.
	crash, _ := hex.DecodeString("3019020103" + "0a0101" + "020103" + "0a0101" + "0400" + "0400" + "3000" + "3005a103110102")
	if err := devattest.CheckKeyDescriptionStrict(p, crash); err == nil {
		t.Error("primitive SET purpose accepted")
	}
	if err := devattest.CheckKeyDescription(p, crash); err == nil {
		t.Error("primitive SET purpose accepted")
	}
}

// The same for the App Attest nonce extension, directly and through
// VerifyAttest.
func TestIOSPrimitiveConstructed(t *testing.T) {
	ext, _ := hex.DecodeString("3024a1220420" + "0101010101010101010101010101010101010101010101010101010101010101")
	if n, err := devattest.ParseNonceExt(ext); err != nil || len(n) != 32 {
		t.Fatalf("valid nonce extension: %v", err)
	}
	for _, s := range []string{
		"1024a1220420" + "0101010101010101010101010101010101010101010101010101010101010101", // primitive SEQUENCE
		"3024812204200101010101010101010101010101010101010101010101010101010101010101",      // primitive [1]
	} {
		b, _ := hex.DecodeString(s)
		if _, err := devattest.ParseNonceExt(b); !errors.Is(err, devattest.ErrFormat) {
			t.Errorf("%s: %v", s[:12], err)
		}
	}
	p := enclavetest.Policy()
	ch := challenge("enroll")
	for k := 0; ; k++ {
		hit := false
		a := enclavetest.NewIOSAttester(0x73, enclavetest.IOSOptions{MutateNonceExt: func(e []byte) []byte {
			vs := enclavetest.PrimitiveConstructedVariants(e)
			if k >= len(vs) {
				return e
			}
			hit = true
			return vs[k]
		}})
		da, err := a.Attest(ch)
		if err != nil {
			t.Fatal(err)
		}
		if !hit {
			if k == 0 {
				t.Fatal("no SEQUENCE in the nonce extension")
			}
			break
		}
		if _, err := devattest.VerifyAttest(p, da, ch, now, nil); err == nil {
			t.Errorf("variant %d accepted", k)
		}
	}
}
