// Package enclavetest provides TEST-ONLY stand-ins for the enclave's
// hardware and vendor dependencies (VAULT-PLAN §6): a fake Nitro Security
// Module that signs real COSE_Sign1 attestation documents under a test CA,
// a fake AWS KMS that enforces key policies and attestation conditions,
// test Android key-attestation and App Attest authorities, and a test
// release-manifest key.
//
// Every key here is derived from a fixed, public seed and is labeled test
// only. Release packages must never link this package: `make check-tcb`
// fails the build if one does.
package enclavetest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// TestKey returns a TEST-ONLY ECDSA key whose private scalar is size bytes
// of seed (seed must be non-zero and small enough for the curve).
func TestKey(c elliptic.Curve, seed byte) *ecdsa.PrivateKey {
	n := (c.Params().BitSize + 7) / 8
	b := make([]byte, n)
	for i := range b {
		b[i] = seed
	}
	k, err := ecdsa.ParseRawPrivateKey(c, b)
	if err != nil {
		panic("enclavetest: bad test key seed")
	}
	return k
}

// CA is a test certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

var epoch = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// NewRootCA creates a self-signed TEST root.
func NewRootCA(name string, key crypto.Signer) *CA {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name, Organization: []string{"VettID TEST ONLY"}},
		NotBefore: epoch, NotAfter: epoch.AddDate(40, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		panic(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &CA{Cert: c, Key: key}
}

// Issue issues a certificate for pub under the CA.
func (ca *CA) Issue(tmpl *x509.Certificate, pub crypto.PublicKey) *x509.Certificate {
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = epoch
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = epoch.AddDate(30, 0, 0)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return c
}

// SubCA issues an intermediate CA.
func (ca *CA) SubCA(name string, serial int64, key crypto.Signer) *CA {
	c := ca.Issue(&x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name, Organization: []string{"VettID TEST ONLY"}},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, key.Public())
	return &CA{Cert: c, Key: key}
}
