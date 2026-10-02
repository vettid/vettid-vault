package enclavetest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

var (
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidRSAESOAEP     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	oidMGF1          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidAES256CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

func explicit(tag int, inner []byte) asn1.RawValue {
	return asn1.RawValue{Class: 2, Tag: tag, IsCompound: true, Bytes: inner}
}

func mustMarshal(v any, params ...string) []byte {
	var b []byte
	var err error
	if len(params) > 0 {
		b, err = asn1.MarshalWithParams(v, params[0])
	} else {
		b, err = asn1.Marshal(v)
	}
	if err != nil {
		panic(err)
	}
	return b
}

// CMSOptions alter the envelope for negative tests.
type CMSOptions struct {
	DefaultOAEPParams bool // omit OAEP parameters (SHA-1)
	PKCS1v15          bool // encrypt the key with PKCS#1 v1.5
	Indefinite        bool // BER indefinite lengths on the outer layers
}

// WrapCMS builds an EnvelopedData as AWS KMS does for a Nitro recipient
// (TEST ONLY): RSAES-OAEP-SHA256 key transport, AES-256-CBC content.
func WrapCMS(pub *rsa.PublicKey, content []byte, o CMSOptions) []byte {
	cek := make([]byte, 32)
	iv := make([]byte, 16)
	_, _ = rand.Read(cek)
	_, _ = rand.Read(iv)
	var ek []byte
	var err error
	if o.PKCS1v15 {
		//lint:ignore SA1019 negative test input: the enclave must refuse PKCS#1 v1.5 key transport
		ek, err = rsa.EncryptPKCS1v15(rand.Reader, pub, cek)
	} else {
		ek, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, cek, nil)
	}
	if err != nil {
		panic(err)
	}
	pad := 16 - len(content)%16
	pt := append(append([]byte(nil), content...), make([]byte, pad)...)
	for i := len(content); i < len(pt); i++ {
		pt[i] = byte(pad)
	}
	blk, _ := aes.NewCipher(cek)
	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, pt)

	sha := mustMarshal(algorithmIdentifier{Algorithm: oidSHA256})
	mgf := mustMarshal(struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue
	}{oidMGF1, asn1.RawValue{FullBytes: sha}})
	oaepParams := mustMarshal(struct {
		Hash asn1.RawValue
		MGF  asn1.RawValue
	}{explicit(0, sha), explicit(1, mgf)})
	kea := algorithmIdentifier{Algorithm: oidRSAESOAEP, Parameters: asn1.RawValue{FullBytes: oaepParams}}
	if o.DefaultOAEPParams {
		kea = algorithmIdentifier{Algorithm: oidRSAESOAEP}
	}
	type issuerAndSerial struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}
	ri := mustMarshal(struct {
		Version int
		RID     issuerAndSerial
		KEA     algorithmIdentifier
		EK      []byte
	}{0, issuerAndSerial{asn1.RawValue{FullBytes: mustMarshal(asn1.RawValue{Tag: 16, IsCompound: true, Class: 0})}, big.NewInt(1)}, kea, ek})
	ivb := mustMarshal(iv)
	eci := mustMarshal(struct {
		CT  asn1.ObjectIdentifier
		Alg algorithmIdentifier
		EC  asn1.RawValue
	}{oidData, algorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: ivb}},
		asn1.RawValue{Class: 2, Tag: 0, Bytes: ct}})
	ed := mustMarshal(struct {
		Version int
		RIs     asn1.RawValue
		ECI     asn1.RawValue
	}{2, asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: ri}, asn1.RawValue{FullBytes: eci}})
	ci := mustMarshal(struct {
		CT asn1.ObjectIdentifier
		C  asn1.RawValue
	}{oidEnvelopedData, explicit(0, ed)})
	if !o.Indefinite {
		return ci
	}
	// Re-encode the two outer layers with indefinite lengths.
	oidCT := mustMarshal(oidEnvelopedData)
	out := append([]byte{0x30, 0x80}, oidCT...)
	out = append(out, 0xa0, 0x80)
	out = append(out, ed...)
	return append(out, 0, 0, 0, 0)
}
