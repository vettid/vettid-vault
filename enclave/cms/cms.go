// Package cms unwraps the CMS EnvelopedData (RFC 5652) that AWS KMS returns
// in CiphertextForRecipient when a request carries a Nitro attestation
// document as Recipient: one key-transport recipient whose key is
// encrypted with RSAES-OAEP (SHA-256, MGF1-SHA-256) to the enclave's
// ephemeral RSA key, and AES-256-CBC content.
//
// Only that profile is accepted. In particular there is no RSA PKCS#1 v1.5
// fallback (vettid.dev had one), and the OAEP parameters must name SHA-256
// explicitly: the default parameters (SHA-1) are refused.
package cms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"

	"github.com/vettid/vettid-vault/internal/der"
)

// Errors.
var (
	ErrFormat  = errors.New("cms: malformed or unsupported EnvelopedData")
	ErrDecrypt = errors.New("cms: decryption failed")
)

// MaxSize bounds the input.
const MaxSize = 16 * 1024

func oid(o asn1.ObjectIdentifier) []byte {
	b, err := asn1.Marshal(o)
	if err != nil {
		panic(err)
	}
	return b[2:]
}

// Object identifiers.
var (
	OIDEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	OIDData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDRSAESOAEP     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	OIDMGF1          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	OIDSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDAES256CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

var (
	oidEnveloped = oid(OIDEnvelopedData)
	oidData      = oid(OIDData)
	oidOAEP      = oid(OIDRSAESOAEP)
	oidMGF1      = oid(OIDMGF1)
	oidSHA256    = oid(OIDSHA256)
	oidAES256CBC = oid(OIDAES256CBC)
)

func sameOID(e der.Element, want []byte) bool {
	got, err := der.OID(e)
	if err != nil || len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func seq(r *der.Reader) (*der.Reader, error) {
	e, err := r.Expect(der.ClassUniversal, der.TagSequence, true)
	if err != nil {
		return nil, ErrFormat
	}
	c, err := e.Children()
	if err != nil {
		return nil, ErrFormat
	}
	return c, nil
}

// algID reads AlgorithmIdentifier { OID, params? } and returns the params
// reader (nil if absent).
func algID(r *der.Reader, want []byte) (*der.Reader, *der.Element, error) {
	c, err := seq(r)
	if err != nil {
		return nil, nil, ErrFormat
	}
	o, err := c.Next()
	if err != nil || !sameOID(o, want) {
		return nil, nil, ErrFormat
	}
	if c.Empty() {
		return c, nil, nil
	}
	p, err := c.Next()
	if err != nil || !c.Empty() {
		return nil, nil, ErrFormat
	}
	return c, &p, nil
}

// sha256AlgID accepts AlgorithmIdentifier sha256 with absent or NULL
// parameters.
func sha256AlgID(r *der.Reader) error {
	_, p, err := algID(r, oidSHA256)
	if err != nil {
		return err
	}
	if p != nil && der.Null(*p) != nil {
		return ErrFormat
	}
	return nil
}

func checkOAEPParams(p *der.Element) error {
	if p == nil {
		return ErrFormat // absent parameters mean SHA-1: refused
	}
	r, err := p.ChildrenOf(der.ClassUniversal, der.TagSequence)
	if err != nil {
		return ErrFormat
	}
	h, err := r.Expect(der.ClassContext, 0, true)
	if err != nil {
		return ErrFormat
	}
	hr, err := h.Children()
	if err != nil {
		return ErrFormat
	}
	if err := sha256AlgID(hr); err != nil || !hr.Empty() {
		return ErrFormat
	}
	m, err := r.Expect(der.ClassContext, 1, true)
	if err != nil {
		return ErrFormat
	}
	mr, err := m.Children()
	if err != nil {
		return ErrFormat
	}
	_, mp, err := algID(mr, oidMGF1)
	if err != nil || mp == nil || !mr.Empty() {
		return ErrFormat
	}
	mpr := der.NewBERReader(mp.Raw)
	if err := sha256AlgID(mpr); err != nil || !mpr.Empty() {
		return ErrFormat
	}
	if !r.Empty() {
		return ErrFormat // a pSourceAlgorithm (label) is not used by KMS
	}
	return nil
}

// Unwrap decrypts the EnvelopedData with the recipient's RSA key and
// returns the content (the KMS data key or plaintext).
func Unwrap(b []byte, key *rsa.PrivateKey) ([]byte, error) {
	if len(b) == 0 || len(b) > MaxSize || key == nil {
		return nil, ErrFormat
	}
	top := der.NewBERReader(b)
	ci, err := seq(top)
	if err != nil || !top.Empty() {
		return nil, ErrFormat
	}
	ct, err := ci.Next()
	if err != nil || !sameOID(ct, oidEnveloped) {
		return nil, ErrFormat
	}
	wrap, err := ci.Expect(der.ClassContext, 0, true)
	if err != nil || !ci.Empty() {
		return nil, ErrFormat
	}
	wr, err := wrap.Children()
	if err != nil {
		return nil, ErrFormat
	}
	ed, err := seq(wr)
	if err != nil || !wr.Empty() {
		return nil, ErrFormat
	}
	ve, err := ed.Next()
	if err != nil {
		return nil, ErrFormat
	}
	if v, err := der.Int(ve); err != nil || v != 0 && v != 2 {
		return nil, ErrFormat
	}
	if t, ok := ed.Peek(); ok && t.Is(der.ClassContext, 0) { // originatorInfo: not used by KMS
		return nil, ErrFormat
	}
	ris, err := ed.Expect(der.ClassUniversal, der.TagSet, true)
	if err != nil {
		return nil, ErrFormat
	}
	rr, err := ris.Children()
	if err != nil {
		return nil, ErrFormat
	}
	ri, err := seq(rr)
	if err != nil || !rr.Empty() { // exactly one recipient
		return nil, ErrFormat
	}
	rv, err := ri.Next()
	if err != nil {
		return nil, ErrFormat
	}
	if v, err := der.Int(rv); err != nil || v != 0 && v != 2 {
		return nil, ErrFormat
	}
	if _, err := ri.Next(); err != nil { // rid: issuerAndSerialNumber or [0] subjectKeyIdentifier
		return nil, ErrFormat
	}
	_, params, err := algID(ri, oidOAEP)
	if err != nil {
		return nil, err
	}
	if err := checkOAEPParams(params); err != nil {
		return nil, err
	}
	eke, err := ri.Next()
	if err != nil || !ri.Empty() {
		return nil, ErrFormat
	}
	ek, err := der.OctetString(eke)
	if err != nil {
		return nil, ErrFormat
	}
	eci, err := seq(ed)
	if err != nil {
		return nil, ErrFormat
	}
	if t, ok := ed.Peek(); ok && !t.Is(der.ClassContext, 1) { // only unprotectedAttrs may follow
		return nil, ErrFormat
	}
	cty, err := eci.Next()
	if err != nil || !sameOID(cty, oidData) {
		return nil, ErrFormat
	}
	_, ivp, err := algID(eci, oidAES256CBC)
	if err != nil || ivp == nil {
		return nil, ErrFormat
	}
	iv, err := der.OctetString(*ivp)
	if err != nil || len(iv) != aes.BlockSize {
		return nil, ErrFormat
	}
	ece, err := eci.Next()
	if err != nil || !eci.Empty() || !ece.Is(der.ClassContext, 0) {
		return nil, ErrFormat
	}
	ctext, err := der.OctetContent(ece)
	if err != nil || len(ctext) == 0 || len(ctext)%aes.BlockSize != 0 {
		return nil, ErrFormat
	}
	cek, err := rsa.DecryptOAEP(sha256.New(), nil, key, ek, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	defer wipe(cek)
	if len(cek) != 32 {
		return nil, ErrDecrypt
	}
	blk, err := aes.NewCipher(cek)
	if err != nil {
		return nil, ErrDecrypt
	}
	pt := make([]byte, len(ctext))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(pt, ctext)
	n := int(pt[len(pt)-1])
	if n == 0 || n > aes.BlockSize {
		wipe(pt)
		return nil, ErrDecrypt
	}
	for _, c := range pt[len(pt)-n:] {
		if int(c) != n {
			wipe(pt)
			return nil, ErrDecrypt
		}
	}
	out := append([]byte(nil), pt[:len(pt)-n]...)
	wipe(pt)
	return out, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
