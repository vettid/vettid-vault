package devattest_test

import (
	"bytes"
	"crypto/elliptic"
	"errors"
	"testing"

	"github.com/vettid/vettid-vault/internal/cbor"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/devattest"
)

// authDataOf returns the authenticator data inside an App Attest
// attestation ("authData") or assertion ("authenticatorData") object.
func authDataOf(t *testing.T, obj []byte, key string) []byte {
	t.Helper()
	v, err := cbor.Decode(obj)
	if err != nil {
		t.Fatal(err)
	}
	b, err := v.BytesAt(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// App Attest authenticator data with the ED flag (0x80) and Apple's
// extensions map, as iOS 27 sends it (vettid/vettid.org#334): flags 0xc0
// in the attestation (226 bytes: the extensions follow the COSE key) and
// in every assertion (99 bytes: the extensions follow the counter, with
// AT set and no attested credential data).
func TestIOSExtensions(t *testing.T) {
	p := enclavetest.Policy()
	ch := challenge("enroll")
	o := enclavetest.IOSAppleExtensions(enclavetest.IOSOptions{})
	if n := len(enclavetest.AppleExtensions()); n != 62 {
		t.Fatalf("TEST extensions map is %d bytes, iOS 27 sends 62", n)
	}
	a := enclavetest.NewIOSAttester(0x71, o)
	da, _ := a.Attest(ch)
	ad := authDataOf(t, da.Attestation, "authData")
	if len(ad) != 226 || ad[32] != 0xc0 || !bytes.HasSuffix(ad, enclavetest.AppleExtensions()) {
		t.Fatalf("TEST attestation authData: %d bytes, flags %#x", len(ad), ad[32])
	}
	b, err := devattest.VerifyAttest(p, da, ch, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The binding is the one the same key gets without extensions.
	plain, _ := enclavetest.NewIOSAttester(0x71, enclavetest.IOSOptions{}).Attest(ch)
	pb, err := devattest.VerifyAttest(p, plain, ch, now, nil)
	if err != nil || !bytes.Equal(b.PublicKey, pb.PublicKey) || !bytes.Equal(b.KeyID, pb.KeyID) || b.Counter != 0 {
		t.Fatalf("%v %+v %+v", err, b, pb)
	}
	// Assertions with counters 1 then 2.
	s := devattest.ForChallenge(challenge("unlock"))
	as1, _ := a.Assert(s)
	sd := authDataOf(t, as1.Assertion, "authenticatorData")
	if len(sd) != 99 || sd[32] != 0xc0 {
		t.Fatalf("TEST assertion authData: %d bytes, flags %#x", len(sd), sd[32])
	}
	b1, err := devattest.VerifyAssertion(p, b, as1, s, b.Counter, now, nil)
	if err != nil || b1.Counter != 1 {
		t.Fatalf("%v %+v", err, b1)
	}
	as2, _ := a.Assert(s)
	b2, err := devattest.VerifyAssertion(p, b1, as2, s, b1.Counter, now, nil)
	if err != nil || b2.Counter != 2 {
		t.Fatalf("%v %+v", err, b2)
	}
	if _, err := devattest.VerifyAssertion(p, b2, as2, s, b2.Counter, now, nil); !errors.Is(err, devattest.ErrCounter) {
		t.Fatalf("replayed counter: %v", err)
	}
	// The extensions are ignored, not allow-listed: other content in the
	// map is accepted when the nonce and signature cover it.
	other := func() []byte {
		var e cbor.Encoder
		e.Map(1).Int(7).ByteString([]byte("anything"))
		return e.Bytes()
	}()
	ox := enclavetest.IOSOptions{ED: true, ExtensionData: other}
	od, _ := enclavetest.NewIOSAttester(0x71, ox).Attest(ch)
	if _, err := devattest.VerifyAttest(p, od, ch, now, nil); err != nil {
		t.Fatalf("other extensions: %v", err)
	}
	key := enclavetest.TestKey(elliptic.P256(), 0x71)
	assert := func(o enclavetest.IOSOptions, counter uint32) error {
		as := &altchan.DeviceAssertion{Platform: "ios", Assertion: enclavetest.IOSAssertWith(key, o, counter, s.ClientDataHash)}
		_, err := devattest.VerifyAssertion(p, b, as, s, 0, now, nil)
		return err
	}
	if err := assert(ox, 5); err != nil {
		t.Fatalf("other extensions in an assertion: %v", err)
	}
	// The old forms (no ED, nothing after the COSE key or the counter)
	// are still accepted, with both environments' aaguids.
	if err := assert(enclavetest.IOSOptions{}, 5); err != nil {
		t.Fatalf("plain assertion: %v", err)
	}
	dev := *p
	dev.IOSDevelopmentEnvironment = true
	for _, x := range []enclavetest.IOSOptions{{}, {Develop: true}, enclavetest.IOSAppleExtensions(enclavetest.IOSOptions{Develop: true})} {
		d, _ := enclavetest.NewIOSAttester(0x71, x).Attest(ch)
		if _, err := devattest.VerifyAttest(&dev, d, ch, now, nil); err != nil {
			t.Fatalf("%+v: %v", x, err)
		}
	}

	apple := enclavetest.AppleExtensions()
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	indefinite := cat([]byte{0xbf}, apple[1:], []byte{0xff})
	big := func() []byte {
		var e cbor.Encoder
		e.Map(1).Int(1).ByteString(make([]byte, 1100))
		return e.Bytes()
	}()
	tamper := func(ad []byte) []byte {
		ad = append([]byte(nil), ad...)
		ad[len(ad)-1] ^= 0x01 // "01" -> "00": still a valid map
		return ad
	}
	for name, tc := range map[string]struct {
		o           enclavetest.IOSOptions
		attest, ast error
	}{
		"ED without a map":       {enclavetest.IOSOptions{ED: true}, devattest.ErrFormat, devattest.ErrFormat},
		"trailing after the map": {enclavetest.IOSOptions{ED: true, ExtensionData: cat(apple, []byte{0})}, devattest.ErrFormat, devattest.ErrFormat},
		"two maps":               {enclavetest.IOSOptions{ED: true, ExtensionData: cat(apple, apple)}, devattest.ErrFormat, devattest.ErrFormat},
		"map without ED":         {enclavetest.IOSOptions{ExtensionData: apple}, devattest.ErrFormat, devattest.ErrFormat},
		"text as extensions":     {enclavetest.IOSOptions{ED: true, ExtensionData: []byte{0x63, 'd', 'e', 'v'}}, devattest.ErrFormat, devattest.ErrFormat},
		"array as extensions":    {enclavetest.IOSOptions{ED: true, ExtensionData: []byte{0x81, 0x00}}, devattest.ErrFormat, devattest.ErrFormat},
		"bytes as extensions":    {enclavetest.IOSOptions{ED: true, ExtensionData: []byte{0x41, 0x00}}, devattest.ErrFormat, devattest.ErrFormat},
		"uint as extensions":     {enclavetest.IOSOptions{ED: true, ExtensionData: []byte{0x00}}, devattest.ErrFormat, devattest.ErrFormat},
		"truncated map":          {enclavetest.IOSOptions{ED: true, ExtensionData: apple[:len(apple)-1]}, devattest.ErrFormat, devattest.ErrFormat},
		"indefinite map":         {enclavetest.IOSOptions{ED: true, ExtensionData: indefinite}, devattest.ErrFormat, devattest.ErrFormat},
		"oversized map":          {enclavetest.IOSOptions{ED: true, ExtensionData: big}, devattest.ErrFormat, devattest.ErrFormat},
		"duplicate key":          {enclavetest.IOSOptions{ED: true, ExtensionData: []byte{0xa2, 0x01, 0x00, 0x01, 0x00}}, devattest.ErrFormat, devattest.ErrFormat},
		// Tampered extension bytes are covered by the nonce and the
		// assertion signature.
		"tampered extensions": {enclavetest.IOSOptions{ED: true, ExtensionData: apple, MutateAuthData: tamper}, devattest.ErrChallenge, devattest.ErrSignature},
		"extensions added": {enclavetest.IOSOptions{MutateAuthData: func(ad []byte) []byte {
			ad = cat(ad, apple)
			ad[32] |= 0x80
			return ad
		}}, devattest.ErrChallenge, devattest.ErrSignature},
		"extensions removed": {enclavetest.IOSOptions{ED: true, ExtensionData: apple, MutateAuthData: func(ad []byte) []byte {
			ad = cat(ad[:len(ad)-len(apple)])
			ad[32] &^= 0x80
			return ad
		}}, devattest.ErrChallenge, devattest.ErrSignature},
	} {
		d, _ := enclavetest.NewIOSAttester(0x71, tc.o).Attest(ch)
		if _, err := devattest.VerifyAttest(p, d, ch, now, nil); !errors.Is(err, tc.attest) {
			t.Errorf("%s: attestation: %v", name, err)
		}
		if err := assert(tc.o, 5); !errors.Is(err, tc.ast) {
			t.Errorf("%s: assertion: %v", name, err)
		}
	}
	// An assertion carrying attested credential data (AT set) is refused
	// with or without ED: an assertion has none.
	acd := cat(devattest.AAGUIDProduction[:], []byte{0, 32}, enclavetest.IOSKeyID(key))
	for _, x := range []enclavetest.IOSOptions{{ED: true, ExtensionData: cat(acd, apple)}, {ExtensionData: acd}} {
		if err := assert(x, 5); !errors.Is(err, devattest.ErrFormat) {
			t.Errorf("assertion with attested credential data (ED %v): %v", x.ED, err)
		}
	}
}
