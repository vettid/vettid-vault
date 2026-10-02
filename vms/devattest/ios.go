package devattest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"time"

	"github.com/vettid/vettid-vault/internal/cbor"
	"github.com/vettid/vettid-vault/internal/der"
	"github.com/vettid/vettid-vault/vms/suite"
)

// OIDAppAttestNonce is the App Attest credential certificate's nonce
// extension (1.2.840.113635.100.8.2).
var OIDAppAttestNonce = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

// AAGUIDProduction is the authenticator data aaguid of the production App
// Attest environment ("appattest" followed by seven zero bytes); the
// development environment uses "appattestdevelop".
var AAGUIDProduction = [16]byte{'a', 'p', 'p', 'a', 't', 't', 'e', 's', 't'}

const flagAttested = 0x40

// authData is the parsed authenticator data.
type authData struct {
	rpIDHash []byte
	flags    byte
	counter  uint32
	aaguid   []byte
	credID   []byte
	coseKey  []byte
}

func parseAuthData(b []byte, attested bool) (*authData, error) {
	if len(b) < 37 {
		return nil, ErrFormat
	}
	a := &authData{rpIDHash: b[:32], flags: b[32], counter: binary.BigEndian.Uint32(b[33:37])}
	rest := b[37:]
	if !attested {
		if len(rest) != 0 {
			return nil, ErrFormat
		}
		return a, nil
	}
	if a.flags&flagAttested == 0 || len(rest) < 18 {
		return nil, ErrFormat
	}
	a.aaguid = rest[:16]
	n := int(binary.BigEndian.Uint16(rest[16:18]))
	rest = rest[18:]
	if n == 0 || n > 64 || len(rest) < n {
		return nil, ErrFormat
	}
	a.credID, a.coseKey = rest[:n], rest[n:]
	return a, nil
}

func appIDHash(p *Policy) []byte {
	h := sha256.Sum256([]byte(p.IOSAppID))
	return h[:]
}

func verifyIOS(p *Policy, keyID, att []byte, cdh [32]byte, now time.Time) (*Binding, error) {
	if p.IOSAppID == "" || p.IOSRoots == nil {
		return nil, ErrPlatform
	}
	if len(keyID) != 32 {
		return nil, ErrKeyID
	}
	v, err := cbor.Decode(att)
	if err != nil || v.Kind != cbor.KindMap || len(v.Map) != 3 {
		return nil, ErrFormat
	}
	if f, err := v.TextAt("fmt"); err != nil || f != "apple-appattest" {
		return nil, ErrFormat
	}
	ad, err := v.BytesAt("authData")
	if err != nil {
		return nil, ErrFormat
	}
	st, ok := v.Lookup("attStmt")
	if !ok || st.Kind != cbor.KindMap {
		return nil, ErrFormat
	}
	x5c, ok := st.Lookup("x5c")
	if !ok || x5c.Kind != cbor.KindArray || len(x5c.Array) < 2 || len(x5c.Array) > 5 {
		return nil, ErrFormat
	}
	var chain []*x509.Certificate
	for _, c := range x5c.Array {
		if c.Kind != cbor.KindBytes {
			return nil, ErrFormat
		}
		cert, err := x509.ParseCertificate(c.Bytes)
		if err != nil {
			return nil, ErrFormat
		}
		chain = append(chain, cert)
	}
	if _, err := st.BytesAt("receipt"); err != nil {
		return nil, ErrFormat
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	leaf := chain[0]
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: p.IOSRoots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, ErrChain
	}
	// nonce = SHA-256(authData || clientDataHash) must equal the leaf's
	// extension value: SEQUENCE { [1] EXPLICIT OCTET STRING nonce }.
	h := sha256.New()
	h.Write(ad)
	h.Write(cdh[:])
	nonce := h.Sum(nil)
	var extNonce []byte
	for _, e := range leaf.Extensions {
		if e.Id.Equal(OIDAppAttestNonce) {
			if extNonce != nil {
				return nil, ErrFormat
			}
			if extNonce, err = parseNonceExt(e.Value); err != nil {
				return nil, err
			}
		}
	}
	if extNonce == nil || !suite.Equal(extNonce, nonce) {
		return nil, ErrChallenge
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, ErrKeyProperties
	}
	point, err := pub.Bytes()
	if err != nil {
		return nil, ErrKeyProperties
	}
	kh := sha256.Sum256(point)
	if !suite.Equal(kh[:], keyID) {
		return nil, ErrKeyID
	}
	a, err := parseAuthData(ad, true)
	if err != nil {
		return nil, err
	}
	if !suite.Equal(a.rpIDHash, appIDHash(p)) {
		return nil, ErrApplication
	}
	if a.counter != 0 {
		return nil, ErrCounter
	}
	if !suite.Equal(a.aaguid, AAGUIDProduction[:]) {
		return nil, ErrEnvironment
	}
	if !suite.Equal(a.credID, keyID) {
		return nil, ErrKeyID
	}
	if err := checkCOSEKey(a.coseKey, point); err != nil {
		return nil, err
	}
	return &Binding{Platform: "ios", PublicKey: point, KeyID: append([]byte(nil), keyID...)}, nil
}

func parseNonceExt(b []byte) ([]byte, error) {
	r := der.NewReader(b)
	seq, err := r.Expect(der.ClassUniversal, der.TagSequence, true)
	if err != nil || !r.Empty() {
		return nil, ErrFormat
	}
	c, _ := seq.Children()
	t, err := c.Expect(der.ClassContext, 1, true)
	if err != nil || !c.Empty() {
		return nil, ErrFormat
	}
	in, _ := t.Children()
	o, err := in.Next()
	if err != nil || !in.Empty() {
		return nil, ErrFormat
	}
	return der.OctetString(o)
}

// checkCOSEKey requires the credential public key in authData to be the
// certificate's key: an EC2 P-256 COSE_Key.
func checkCOSEKey(b, point []byte) error {
	v, err := cbor.Decode(b)
	if err != nil || v.Kind != cbor.KindMap {
		return ErrFormat
	}
	get := func(k int64) *cbor.Value {
		e, ok := v.LookupInt(k)
		if !ok {
			return nil
		}
		return e
	}
	kty, crv, x, y := get(1), get(-1), get(-2), get(-3)
	if kty == nil || kty.Kind != cbor.KindUint || kty.Uint != 2 || crv == nil || crv.Kind != cbor.KindUint || crv.Uint != 1 ||
		x == nil || x.Kind != cbor.KindBytes || len(x.Bytes) != 32 || y == nil || y.Kind != cbor.KindBytes || len(y.Bytes) != 32 {
		return ErrFormat
	}
	if !suite.Equal(append(append([]byte{4}, x.Bytes...), y.Bytes...), point) {
		return ErrKeyID
	}
	return nil
}

// verifyIOSAssertion verifies an App Attest assertion and returns its
// counter. The signature is ECDSA P-256 with SHA-256 over
// nonce = SHA-256(authenticatorData || clientDataHash).
func verifyIOSAssertion(p *Policy, b *Binding, assertion []byte, cdh [32]byte, minCounter uint32) (uint32, error) {
	v, err := cbor.Decode(assertion)
	if err != nil || v.Kind != cbor.KindMap || len(v.Map) != 2 {
		return 0, ErrFormat
	}
	sig, err := v.BytesAt("signature")
	if err != nil {
		return 0, ErrFormat
	}
	ad, err := v.BytesAt("authenticatorData")
	if err != nil {
		return 0, ErrFormat
	}
	a, err := parseAuthData(ad, false)
	if err != nil {
		return 0, err
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), b.PublicKey)
	if err != nil {
		return 0, ErrFormat
	}
	h := sha256.New()
	h.Write(ad)
	h.Write(cdh[:])
	nonce := h.Sum(nil)
	digest := sha256.Sum256(nonce)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return 0, ErrSignature
	}
	if !suite.Equal(a.rpIDHash, appIDHash(p)) {
		return 0, ErrApplication
	}
	if a.counter <= minCounter {
		return 0, ErrCounter
	}
	return a.counter, nil
}
