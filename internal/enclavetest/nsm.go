package enclavetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/internal/cbor"
	"github.com/vettid/vettid-vault/vms/nitro"
)

// NitroCA is a TEST-ONLY stand-in for the AWS Nitro attestation PKI: a
// root, one intermediate and a signing leaf, all P-384.
type NitroCA struct {
	Root, Inter *CA
	Leaf        *x509.Certificate
	LeafKey     *ecdsa.PrivateKey
}

var (
	nitroOnce sync.Once
	nitroCA   *NitroCA
)

// TestNitroCA returns the shared test Nitro PKI (keys from fixed seeds).
func TestNitroCA() *NitroCA {
	nitroOnce.Do(func() {
		root := NewRootCA("TEST aws.nitro-enclaves", TestKey(elliptic.P384(), 0x31))
		inter := root.SubCA("TEST nitro intermediate", 2, TestKey(elliptic.P384(), 0x32))
		lk := TestKey(elliptic.P384(), 0x33)
		leaf := inter.Issue(&x509.Certificate{SerialNumber: big.NewInt(3),
			Subject:  pkix.Name{CommonName: "TEST i-0000000000000000-enc0000000000000000"},
			KeyUsage: x509.KeyUsageDigitalSignature}, lk.Public())
		nitroCA = &NitroCA{Root: root, Inter: inter, Leaf: leaf, LeafKey: lk}
	})
	return nitroCA
}

// Roots returns a pool with the test Nitro root.
func (n *NitroCA) Roots() *x509.CertPool { return nitro.Pool(n.Root.Cert) }

// PCR returns a 48-byte test PCR value, all bytes b.
func PCR(b byte) []byte {
	p := make([]byte, 48)
	for i := range p {
		p[i] = b
	}
	return p
}

// PCRHex is PCR as hex.
func PCRHex(b byte) string { return hex.EncodeToString(PCR(b)) }

// FakeNSM is a TEST-ONLY Nitro Security Module: it reports fixed PCRs and
// signs attestation documents with the test Nitro PKI.
type FakeNSM struct {
	CA   *NitroCA
	PCRs map[uint64][]byte
	Now  func() time.Time
	// Fail, if set, makes Attest fail (fault injection).
	Fail bool
}

// NewFakeNSM returns a fake NSM for a release whose PCR0, PCR1 and PCR2 are
// 48 bytes of p0, p1 and p2.
func NewFakeNSM(p0, p1, p2 byte, now func() time.Time) *FakeNSM {
	if now == nil {
		now = time.Now
	}
	pcrs := map[uint64][]byte{0: PCR(p0), 1: PCR(p1), 2: PCR(p2)}
	for i := uint64(3); i < 16; i++ {
		pcrs[i] = PCR(0)
	}
	return &FakeNSM{CA: TestNitroCA(), PCRs: pcrs, Now: now}
}

// Measurements implements the enclave's NSM interface.
func (f *FakeNSM) Measurements() (nitro.Measurements, error) {
	return nitro.Measurements{PCR0: hex.EncodeToString(f.PCRs[0]), PCR1: hex.EncodeToString(f.PCRs[1]),
		PCR2: hex.EncodeToString(f.PCRs[2])}, nil
}

// Attest implements the enclave's NSM interface.
func (f *FakeNSM) Attest(userData, nonce, publicKey []byte) ([]byte, error) {
	if f.Fail {
		return nil, errors.New("enclavetest: NSM failure")
	}
	return BuildDocument(f.CA, f.PCRs, f.Now(), userData, nonce, publicKey), nil
}

// BuildDocument signs an attestation document as the NSM would.
func BuildDocument(ca *NitroCA, pcrs map[uint64][]byte, ts time.Time, userData, nonce, publicKey []byte) []byte {
	var p cbor.Encoder
	p.Map(9).Text("module_id").Text("i-0000000000000000-enc0000000000000000").
		Text("digest").Text("SHA384").
		Text("timestamp").Uint(uint64(ts.UnixMilli()))
	p.Text("pcrs").Map(len(pcrs))
	for i := uint64(0); i < 32; i++ {
		if v, ok := pcrs[i]; ok {
			p.Uint(i).ByteString(v)
		}
	}
	p.Text("certificate").ByteString(ca.Leaf.Raw)
	p.Text("cabundle").Array(2).ByteString(ca.Root.Cert.Raw).ByteString(ca.Inter.Cert.Raw)
	opt := func(k string, v []byte) {
		p.Text(k)
		if v == nil {
			p.Null()
		} else {
			p.ByteString(v)
		}
	}
	opt("public_key", publicKey)
	opt("user_data", userData)
	opt("nonce", nonce)
	payload := p.Bytes()
	var ph cbor.Encoder
	ph.Map(1).Int(1).Int(-35)
	prot := ph.Bytes()
	var ss cbor.Encoder
	ss.Array(4).Text("Signature1").ByteString(prot).ByteString(nil).ByteString(payload)
	d := sha512.Sum384(ss.Bytes())
	r, s, err := ecdsa.Sign(rand.Reader, ca.LeafKey, d[:])
	if err != nil {
		panic(err)
	}
	sig := make([]byte, 96)
	r.FillBytes(sig[:48])
	s.FillBytes(sig[48:])
	var doc cbor.Encoder
	doc.Array(4).ByteString(prot).Map(0).ByteString(payload).ByteString(sig)
	return doc.Bytes()
}
