// Package autoattest is the staging automation attester (VAULT-RELEASES
// §3.1; owner decision 2026-10-26): an app device without a phone, whose
// Android key attestation chain is issued by the staging automation
// attestation CA instead of a phone's Keystore. Staging images accept
// that CA beside Google's roots (releasecfg.Config.AutomationRoots);
// production images never do.
//
// The chain is [leaf, CA certificate]. The leaf carries the key
// attestation extension (VAULT-MESSAGING §11.7) for a software P-256 key
// that the automation holds, with every value a staging image checks:
// the channel's package, the automation signer digest (class automation,
// VAULT-MESSAGING 0.66.0 §11.7.1), the version code, TEE security levels, a locked device with
// verifiedBootState Verified, and a generated EC P-256 signing key. The
// CA asserts the hardware levels; nothing about them is true, which is
// why only staging accepts it: whoever can sign with the CA key can act
// as a staging device.
//
// The CA key is an AWS KMS key in the staging account in use
// (cmd/vaultctl); this package takes any crypto.Signer, and its tests use
// a local key.
package autoattest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/devattest"
)

// CAName is the subject common name of the staging automation CA.
const CAName = "VettID staging automation attestation CA"

// BootKey is the verifiedBootKey the leaf reports: a fixed marker, not a
// device's key. A Verified boot state does not check it (§11.7).
var BootKey = sha256.Sum256([]byte("VettID staging automation: no device, no verified boot key"))

// NewCA returns a self-signed CA certificate (DER) for key, valid from
// notBefore to the end of the day until (UTC) minus one second, as the
// staging file's automation_attestation requires (no root outlives its
// end date). key must be ECDSA P-256 (an AWS KMS ECC_NIST_P256 key).
func NewCA(key crypto.Signer, notBefore, until time.Time) ([]byte, error) {
	pub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("autoattest: the CA key is not ECDSA P-256")
	}
	end := time.Date(until.Year(), until.Month(), until.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1).Add(-time.Second)
	if !notBefore.Before(end) {
		return nil, errors.New("autoattest: the end date is not after notBefore")
	}
	serial, err := randSerial(rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: CAName, Organization: []string{"VettID staging"}},
		NotBefore:    notBefore.UTC().Truncate(time.Second), NotAfter: end,
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
}

// Attester is an automation app device (client.Attester): Key is the
// device attestation key the vault records; CA and CAKey issue its
// attestation chain (CAKey may be nil for a device that only asserts,
// such as at unlock).
type Attester struct {
	Key   *ecdsa.PrivateKey
	CA    *x509.Certificate
	CAKey crypto.Signer
	// Package, Signer and VersionCode are the attestationApplicationId
	// the leaf reports: the staging package, the automation signer digest
	// (a staging image refuses an automation chain with any other), and
	// a version code no lower than its android_min_version_code.
	Package     string
	Signer      []byte
	VersionCode int64
	// Now is the clock for the leaf's validity (default time.Now).
	Now func() time.Time
}

// Platform implements client.Attester.
func (a *Attester) Platform() string { return altchan.PlatformAndroid }

// Attest implements client.Attester: device_attest with a chain the CA
// issues for this challenge.
func (a *Attester) Attest(challenge [32]byte) (*altchan.DeviceAttest, error) {
	chain, err := a.Chain(challenge)
	if err != nil {
		return nil, err
	}
	return &altchan.DeviceAttest{Platform: altchan.PlatformAndroid, Chain: chain}, nil
}

// Assert implements client.Attester: ECDSA-SHA256 (DER) over the message,
// as Android Keystore signs.
func (a *Attester) Assert(s devattest.Signed) (*altchan.DeviceAssertion, error) {
	h := sha256.Sum256(s.Message)
	sig, err := ecdsa.SignASN1(rand.Reader, a.Key, h[:])
	if err != nil {
		return nil, err
	}
	return &altchan.DeviceAssertion{Platform: altchan.PlatformAndroid, Sig: sig}, nil
}

// Chain returns the attestation chain (leaf first, DER) for challenge.
func (a *Attester) Chain(challenge [32]byte) ([][]byte, error) {
	if a.Key == nil || a.CA == nil || a.CAKey == nil {
		return nil, errors.New("autoattest: no device key or CA signer")
	}
	if a.Package == "" || len(a.Signer) != sha256.Size || a.VersionCode < 1 {
		return nil, errors.New("autoattest: package, signer digest and version code are required")
	}
	if a.Key.Curve != elliptic.P256() {
		return nil, errors.New("autoattest: the device key is not P-256")
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	if !now.Before(a.CA.NotAfter) {
		return nil, fmt.Errorf("autoattest: the CA certificate expired %s", a.CA.NotAfter.Format(time.DateOnly))
	}
	serial, err := randSerial(rand.Reader)
	if err != nil {
		return nil, err
	}
	kd := KeyDescription(challenge, a.Package, a.VersionCode, a.Signer, now)
	nb := now.Add(-time.Hour)
	if nb.Before(a.CA.NotBefore) {
		nb = a.CA.NotBefore
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Android Keystore Key"},
		NotBefore:    nb, NotAfter: a.CA.NotAfter,
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: devattest.OIDKeyDescription, Value: kd}},
	}
	leaf, err := x509.CreateCertificate(rand.Reader, tmpl, a.CA, &a.Key.PublicKey, a.CAKey)
	if err != nil {
		return nil, fmt.Errorf("autoattest: issuing the leaf: %w", err)
	}
	return [][]byte{leaf, a.CA.Raw}, nil
}

// randSerial is a positive 127-bit serial number.
func randSerial(r io.Reader) (*big.Int, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	b[0] &= 0x7f
	b[0] |= 0x40
	return new(big.Int).SetBytes(b), nil
}

// KeyMint values of the key description (Android KeyMint
// KeyDescription, attestation version 300).
const (
	kmVersion       = 300
	secTEE          = 1
	purposeSign     = 2
	algEC           = 3
	digestSHA256    = 4
	curveP256       = 1
	originGenerated = 0
	bootVerified    = 0
)

// KeyDescription returns the DER of the key attestation extension
// (OID 1.3.6.1.4.1.11129.2.1.17) for a generated, hardware-enforced EC
// P-256 signing key at TEE level, on a locked device with verified boot,
// of the app pkg at versionCode signed by signer.
func KeyDescription(challenge [32]byte, pkg string, versionCode int64, signer []byte, created time.Time) []byte {
	appID := seq(set(seq(oct([]byte(pkg)), integer(versionCode))), set(oct(signer)))
	sw := seq(
		explicit(701, integer(created.UnixMilli())), // creationDateTime
		explicit(709, oct(appID)),                   // attestationApplicationId
	)
	hw := seq(
		explicit(1, set(integer(purposeSign))),  // purpose
		explicit(2, integer(algEC)),             // algorithm
		explicit(3, integer(256)),               // keySize
		explicit(5, set(integer(digestSHA256))), // digest
		explicit(10, integer(curveP256)),        // ecCurve
		explicit(503, []byte{0x05, 0x00}),       // noAuthRequired
		explicit(702, integer(originGenerated)), // origin
		explicit(704, seq(oct(BootKey[:]), boolean(true), enumerated(bootVerified), oct(make([]byte, 32)))), // rootOfTrust
		explicit(705, integer(150000)), // osVersion
		explicit(706, integer(202610)), // osPatchLevel
	)
	return seq(integer(kmVersion), enumerated(secTEE), integer(kmVersion), enumerated(secTEE),
		oct(challenge[:]), oct(nil), sw, hw)
}

// --- a minimal DER writer ---

func tlv(tag []byte, content ...[]byte) []byte {
	var c []byte
	for _, x := range content {
		c = append(c, x...)
	}
	out := append([]byte(nil), tag...)
	switch n := len(c); {
	case n < 0x80:
		out = append(out, byte(n))
	case n <= 0xff:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, c...)
}

func seq(c ...[]byte) []byte { return tlv([]byte{0x30}, c...) }
func set(c ...[]byte) []byte { return tlv([]byte{0x31}, c...) }
func oct(b []byte) []byte    { return tlv([]byte{0x04}, b) }
func boolean(v bool) []byte {
	if v {
		return []byte{0x01, 0x01, 0xff}
	}
	return []byte{0x01, 0x01, 0x00}
}

func integer(v int64) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func enumerated(v int64) []byte {
	b := integer(v)
	b[0] = 0x0a
	return b
}

// explicit writes [tag] EXPLICIT (context-specific, constructed), in the
// high-tag-number form from 31.
func explicit(tag int, inner []byte) []byte {
	if tag < 31 {
		return tlv([]byte{0xa0 | byte(tag)}, inner)
	}
	var num []byte
	for t := tag; t > 0; t >>= 7 {
		num = append([]byte{byte(t & 0x7f)}, num...)
	}
	for i := 0; i < len(num)-1; i++ {
		num[i] |= 0x80
	}
	return tlv(append([]byte{0xbf}, num...), inner)
}
