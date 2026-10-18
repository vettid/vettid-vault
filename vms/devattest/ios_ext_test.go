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

// mapOfSize returns a definite-length CBOR map {1: h'00..'} of exactly n
// bytes (n >= 261: a two-byte byte-string length).
func mapOfSize(t *testing.T, n int) []byte {
	t.Helper()
	var e cbor.Encoder
	e.Map(1).Int(1).ByteString(make([]byte, n-5))
	if b := e.Bytes(); len(b) == n {
		return b
	}
	t.Fatalf("map of %d bytes", n)
	return nil
}

// The AT flag in an assertion, the extensions size bound, empty and nested
// maps.
func TestIOSExtensionsEdges(t *testing.T) {
	p := enclavetest.Policy()
	ch := challenge("enroll")
	key := enclavetest.TestKey(elliptic.P256(), 0x71)
	plain, _ := enclavetest.NewIOSAttester(0x71, enclavetest.IOSOptions{}).Attest(ch)
	b, err := devattest.VerifyAttest(p, plain, ch, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := devattest.ForChallenge(challenge("unlock"))
	assert := func(o enclavetest.IOSOptions) error {
		as := &altchan.DeviceAssertion{Platform: "ios", Assertion: enclavetest.IOSAssertWith(key, o, 5, s.ClientDataHash)}
		_, err := devattest.VerifyAssertion(p, b, as, s, 0, now, nil)
		return err
	}
	attest := func(o enclavetest.IOSOptions) error {
		d, _ := enclavetest.NewIOSAttester(0x71, o).Attest(ch)
		_, err := devattest.VerifyAttest(p, d, ch, now, nil)
		return err
	}

	// An AT-only assertion (flags 0x40, nothing after the counter) is
	// accepted: AT is not read in an assertion.
	if err := assert(enclavetest.IOSOptions{Flags: 0x40}); err != nil {
		t.Fatalf("AT-only assertion: %v", err)
	}
	// Well-formed attested credential data after an assertion's counter,
	// with AT set, is refused by the parser whether or not ED is set. The
	// bytes are an attestation's own (aaguid, credId, COSE key and, with ED,
	// the extensions map), so they would parse as attested credential data:
	// the refusal is because an assertion has none, not because the bytes
	// are malformed. AT is set after signing, so a parser that accepted the
	// bytes would fail ErrSignature instead of ErrFormat.
	for _, ed := range []bool{false, true} {
		o := enclavetest.IOSOptions{}
		if ed {
			o = enclavetest.IOSAppleExtensions(o)
		}
		d, _ := enclavetest.NewIOSAttester(0x71, o).Attest(ch)
		ad := authDataOf(t, d.Attestation, "authData")
		if err := devattest.ParseAuthData(ad, true); err != nil {
			t.Fatalf("ED %v: attestation authData does not parse: %v", ed, err)
		}
		x := enclavetest.IOSOptions{ED: ed, ExtensionData: ad[37:], MutateAuthData: func(b []byte) []byte {
			b = append([]byte(nil), b...)
			b[32] |= 0x40
			return b
		}}
		if err := assert(x); !errors.Is(err, devattest.ErrFormat) {
			t.Errorf("assertion with AT and attested credential data (ED %v): %v", ed, err)
		}
		// The same bytes with AT set as an assertion's authData.
		as := append([]byte(nil), ad...)
		if err := devattest.ParseAuthData(as, false); !errors.Is(err, devattest.ErrFormat) {
			t.Errorf("attestation authData parsed as an assertion's (ED %v): %v", ed, err)
		}
	}

	// The size bound: a 1024-byte map is accepted, 1025 refused, in both.
	for n, want := range map[int]error{1024: nil, 1025: devattest.ErrFormat} {
		o := enclavetest.IOSOptions{ED: true, ExtensionData: mapOfSize(t, n)}
		if err := attest(o); !errors.Is(err, want) {
			t.Errorf("%d-byte map: attestation: %v", n, err)
		}
		if err := assert(o); !errors.Is(err, want) {
			t.Errorf("%d-byte map: assertion: %v", n, err)
		}
	}
	// More than the bound after the header is refused even when it is not
	// a map at all (refused before decoding).
	if err := devattest.ParseAuthData(append(append(make([]byte, 32), 0x80, 0, 0, 0, 1), make([]byte, 1025)...), false); !errors.Is(err, devattest.ErrFormat) {
		t.Errorf("oversized rest: %v", err)
	}

	// An empty map with ED is accepted.
	empty := enclavetest.IOSOptions{ED: true, ExtensionData: []byte{0xa0}}
	if err := attest(empty); err != nil {
		t.Errorf("empty map: attestation: %v", err)
	}
	if err := assert(empty); err != nil {
		t.Errorf("empty map: assertion: %v", err)
	}

	// Nested definite-length items are accepted; an indefinite-length array
	// or map anywhere inside the map is refused.
	for name, tc := range map[string]struct {
		ext  []byte
		want error
	}{
		"nested definite":         {[]byte{0xa1, 0x01, 0xa1, 0x02, 0x82, 0x00, 0xc1, 0x00}, nil},
		"indefinite array value":  {[]byte{0xa1, 0x01, 0x9f, 0x00, 0xff}, devattest.ErrFormat},
		"indefinite map value":    {[]byte{0xa1, 0x01, 0xbf, 0x02, 0x00, 0xff}, devattest.ErrFormat},
		"indefinite deeper":       {[]byte{0xa1, 0x01, 0x81, 0xa1, 0x02, 0x9f, 0xff}, devattest.ErrFormat},
		"indefinite under a tag":  {[]byte{0xa1, 0x01, 0xc1, 0x9f, 0xff}, devattest.ErrFormat},
		"indefinite outer map":    {[]byte{0xbf, 0x01, 0x00, 0xff}, devattest.ErrFormat},
		"indefinite array as key": {[]byte{0xa1, 0x9f, 0xff, 0x00}, devattest.ErrFormat},
	} {
		o := enclavetest.IOSOptions{ED: true, ExtensionData: tc.ext}
		if err := attest(o); !errors.Is(err, tc.want) {
			t.Errorf("%s: attestation: %v", name, err)
		}
		if err := assert(o); !errors.Is(err, tc.want) {
			t.Errorf("%s: assertion: %v", name, err)
		}
	}
}
