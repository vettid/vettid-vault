// Package nitro verifies AWS Nitro Enclaves attestation documents
// (VAULT-MESSAGING §11.2, §11.3): a COSE_Sign1 (RFC 9052) structure signed
// with ES384 by a certificate that chains to the AWS Nitro root, whose
// payload carries the enclave's PCRs, a timestamp, and the optional
// public_key, user_data and nonce fields.
//
// The same code verifies ETK descriptors and vault.enrolled attestations in
// the reference client, which the apps mirror. Release builds pass the
// pinned AWS root (package pins); tests pass a test root.
package nitro

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"time"

	"github.com/vettid/vettid-vault/internal/cbor"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Limits.
const (
	MaxDocument   = 32 * 1024
	PCRSize       = 48 // SHA-384
	maxCABundle   = 8
	maxField      = 1024 // public_key, user_data, nonce (NSM limits)
	maxPublicKey  = 2048 // a DER RSA-2048 key for KMS recipients fits
	coseAlgES384  = -35
	coseHeaderAlg = 1
)

// Errors.
var (
	ErrFormat    = errors.New("nitro: malformed attestation document")
	ErrSignature = errors.New("nitro: attestation signature invalid")
	ErrChain     = errors.New("nitro: certificate chain invalid")
	ErrNoRoots   = errors.New("nitro: no trust roots")
	ErrPCR       = errors.New("nitro: PCR mismatch")
	ErrDebug     = errors.New("nitro: debug (all-zero) PCRs")
	ErrStale     = errors.New("nitro: attestation too old or from the future")
	ErrUserData  = errors.New("nitro: user_data mismatch")
	ErrNonce     = errors.New("nitro: nonce mismatch")
)

// Document is a verified attestation document.
type Document struct {
	ModuleID  string
	Timestamp time.Time
	PCRs      map[uint64][]byte
	PublicKey []byte // nil if absent or null
	UserData  []byte
	Nonce     []byte
	// Payload is the signed payload bytes.
	Payload []byte
}

// PCRHex returns PCR i as lowercase hex ("" if absent).
func (d *Document) PCRHex(i uint64) string {
	p, ok := d.PCRs[i]
	if !ok {
		return ""
	}
	return hex.EncodeToString(p)
}

// Verify parses doc and verifies its signature and certificate chain to
// one of roots. The chain is evaluated at the document's own timestamp:
// Nitro signing certificates are short-lived, while descriptors are served
// for up to 24 h; the caller bounds the document's age separately
// (CheckFresh).
func Verify(doc []byte, roots *x509.CertPool) (*Document, error) {
	if roots == nil {
		return nil, ErrNoRoots
	}
	if len(doc) == 0 || len(doc) > MaxDocument {
		return nil, ErrFormat
	}
	v, err := cbor.Decode(doc)
	if err != nil {
		return nil, ErrFormat
	}
	v = v.Untag(18) // COSE_Sign1 tag, optional
	if v.Kind != cbor.KindArray || len(v.Array) != 4 {
		return nil, ErrFormat
	}
	prot, unprot, payload, sig := &v.Array[0], &v.Array[1], &v.Array[2], &v.Array[3]
	if prot.Kind != cbor.KindBytes || unprot.Kind != cbor.KindMap || payload.Kind != cbor.KindBytes ||
		sig.Kind != cbor.KindBytes || len(sig.Bytes) != 96 {
		return nil, ErrFormat
	}
	ph, err := cbor.Decode(prot.Bytes)
	if err != nil || ph.Kind != cbor.KindMap || len(ph.Map) != 1 {
		return nil, ErrFormat
	}
	if a, ok := ph.LookupInt(coseHeaderAlg); !ok || a.Kind != cbor.KindNeg || a.Uint != uint64(-1-coseAlgES384) {
		return nil, ErrFormat
	}
	d, leaf, bundle, err := parsePayload(payload.Bytes)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, c := range bundle {
		pool.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: pool, CurrentTime: d.Timestamp,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, ErrChain
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P384() {
		return nil, ErrChain
	}
	// Sig_structure = ["Signature1", protected, external_aad = h'', payload]
	var e cbor.Encoder
	e.Array(4).Text("Signature1").ByteString(prot.Bytes).ByteString(nil).ByteString(payload.Bytes)
	digest := sha512.Sum384(e.Bytes())
	r := new(big.Int).SetBytes(sig.Bytes[:48])
	s := new(big.Int).SetBytes(sig.Bytes[48:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, ErrSignature
	}
	return d, nil
}

func optBytes(m *cbor.Value, key string, max int) ([]byte, error) {
	e, ok := m.Lookup(key)
	if !ok || e.Kind == cbor.KindNull {
		return nil, nil
	}
	if e.Kind != cbor.KindBytes || len(e.Bytes) > max {
		return nil, ErrFormat
	}
	return append([]byte(nil), e.Bytes...), nil
}

func parsePayload(b []byte) (*Document, *x509.Certificate, []*x509.Certificate, error) {
	m, err := cbor.Decode(b)
	if err != nil || m.Kind != cbor.KindMap {
		return nil, nil, nil, ErrFormat
	}
	d := &Document{Payload: append([]byte(nil), b...), PCRs: map[uint64][]byte{}}
	if d.ModuleID, err = m.TextAt("module_id"); err != nil || d.ModuleID == "" {
		return nil, nil, nil, ErrFormat
	}
	if dg, err := m.TextAt("digest"); err != nil || dg != "SHA384" {
		return nil, nil, nil, ErrFormat
	}
	ts, err := m.UintAt("timestamp")
	if err != nil || ts == 0 || ts > 1<<53 {
		return nil, nil, nil, ErrFormat
	}
	d.Timestamp = time.UnixMilli(int64(ts)).UTC()
	pcrs, ok := m.Lookup("pcrs")
	if !ok || pcrs.Kind != cbor.KindMap || len(pcrs.Map) == 0 || len(pcrs.Map) > 32 {
		return nil, nil, nil, ErrFormat
	}
	for _, p := range pcrs.Map {
		if p.Key.Kind != cbor.KindUint || p.Key.Uint > 31 || p.Value.Kind != cbor.KindBytes ||
			(len(p.Value.Bytes) != PCRSize && len(p.Value.Bytes) != 32 && len(p.Value.Bytes) != 64) {
			return nil, nil, nil, ErrFormat
		}
		d.PCRs[p.Key.Uint] = append([]byte(nil), p.Value.Bytes...)
	}
	for _, i := range []uint64{0, 1, 2} {
		if len(d.PCRs[i]) != PCRSize {
			return nil, nil, nil, ErrFormat
		}
	}
	cb, err := m.BytesAt("certificate")
	if err != nil {
		return nil, nil, nil, ErrFormat
	}
	leaf, err := x509.ParseCertificate(cb)
	if err != nil {
		return nil, nil, nil, ErrFormat
	}
	bun, ok := m.Lookup("cabundle")
	if !ok || bun.Kind != cbor.KindArray || len(bun.Array) == 0 || len(bun.Array) > maxCABundle {
		return nil, nil, nil, ErrFormat
	}
	var bundle []*x509.Certificate
	for _, c := range bun.Array {
		if c.Kind != cbor.KindBytes {
			return nil, nil, nil, ErrFormat
		}
		cert, err := x509.ParseCertificate(c.Bytes)
		if err != nil {
			return nil, nil, nil, ErrFormat
		}
		bundle = append(bundle, cert)
	}
	if d.PublicKey, err = optBytes(m, "public_key", maxPublicKey); err != nil {
		return nil, nil, nil, err
	}
	if d.UserData, err = optBytes(m, "user_data", maxField); err != nil {
		return nil, nil, nil, err
	}
	if d.Nonce, err = optBytes(m, "nonce", maxField); err != nil {
		return nil, nil, nil, err
	}
	return d, leaf, bundle, nil
}

// Measurements are the PCRs an app checks against the release manifest
// (§11.2 step 2), as lowercase hex.
type Measurements struct {
	PCR0, PCR1, PCR2 string
}

// Measurements returns PCR0-2 as hex.
func (d *Document) Measurements() Measurements {
	return Measurements{PCR0: d.PCRHex(0), PCR1: d.PCRHex(1), PCR2: d.PCRHex(2)}
}

// IsDebug reports whether any of PCR0-2 is all zero (a debug-mode enclave).
func (m Measurements) IsDebug() bool {
	for _, p := range []string{m.PCR0, m.PCR1, m.PCR2} {
		zero := true
		for i := 0; i < len(p); i++ {
			if p[i] != '0' {
				zero = false
			}
		}
		if zero {
			return true
		}
	}
	return false
}

// Equal compares measurements in constant time.
func (m Measurements) Equal(o Measurements) bool {
	return suite.Equal([]byte(m.PCR0+m.PCR1+m.PCR2), []byte(o.PCR0+o.PCR1+o.PCR2))
}

// CheckFresh requires the document to be at most maxAge old and not more
// than skew in the future.
func (d *Document) CheckFresh(now time.Time, maxAge, skew time.Duration) error {
	if d.Timestamp.After(now.Add(skew)) || now.Sub(d.Timestamp) > maxAge {
		return ErrStale
	}
	return nil
}

// CheckUserData compares user_data in constant time.
func (d *Document) CheckUserData(want []byte) error {
	if !suite.Equal(d.UserData, want) {
		return ErrUserData
	}
	return nil
}

// CheckNonce compares the nonce in constant time.
func (d *Document) CheckNonce(want []byte) error {
	if !suite.Equal(d.Nonce, want) {
		return ErrNonce
	}
	return nil
}

// Pool returns a pool holding the given roots.
func Pool(roots ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, r := range roots {
		p.AddCert(r)
	}
	return p
}
