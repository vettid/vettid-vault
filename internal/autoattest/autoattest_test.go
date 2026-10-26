package autoattest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"
)

func TestNewCA(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	until := time.Date(2027, 6, 30, 0, 0, 0, 0, time.UTC)
	der, err := NewCA(k, from, until)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsCA || !c.BasicConstraintsValid || c.KeyUsage != x509.KeyUsageCertSign || c.Subject.CommonName != CAName ||
		!c.NotAfter.Equal(time.Date(2027, 6, 30, 23, 59, 59, 0, time.UTC)) || !c.NotBefore.Equal(from) || c.CheckSignatureFrom(c) != nil {
		t.Fatalf("%+v", c)
	}
	if _, err := NewCA(k, until.AddDate(0, 0, 1), until); err == nil {
		t.Fatal("notBefore after the end date")
	}
	k384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := NewCA(k384, from, until); err == nil {
		t.Fatal("a P-384 CA key (the KMS signer signs SHA-256 digests only)")
	}
	// The leaf: the challenge and the identity in the key description.
	a := &Attester{Key: k, CA: c, CAKey: k, Package: "com.vettid.app.staging", Signer: bytes.Repeat([]byte{7}, 32), VersionCode: 101,
		Now: func() time.Time { return from.Add(time.Hour) }}
	var ch [32]byte
	ch[5] = 5
	chain, err := a.Chain(ch)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil || leaf.CheckSignatureFrom(c) != nil || !bytes.Equal(chain[1], c.Raw) || leaf.IsCA {
		t.Fatal(err)
	}
	if !leaf.NotBefore.Equal(c.NotBefore) || !leaf.NotAfter.Equal(c.NotAfter) {
		t.Fatalf("leaf validity %v %v", leaf.NotBefore, leaf.NotAfter)
	}
	for _, bad := range []func(*Attester){
		func(a *Attester) { a.Package = "" },
		func(a *Attester) { a.Signer = nil },
		func(a *Attester) { a.VersionCode = 0 },
		func(a *Attester) { a.CAKey = nil },
		func(a *Attester) { a.Now = func() time.Time { return c.NotAfter } },
	} {
		b := *a
		bad(&b)
		if _, err := b.Chain(ch); err == nil {
			t.Error("issued")
		}
	}
}
