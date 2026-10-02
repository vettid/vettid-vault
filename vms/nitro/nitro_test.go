package nitro_test

import (
	"strings"
	"os"
	"encoding/base64"
	"crypto/elliptic"
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/cbor"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/nitro"
	"github.com/vettid/vettid-vault/vms/pins"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func TestVerifyRoundTrip(t *testing.T) {
	nsm := enclavetest.NewFakeNSM(0xab, 0x11, 0x22, func() time.Time { return t0 })
	doc, err := nsm.Attest([]byte("ud"), []byte("nonce"), []byte("pk"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := nitro.Verify(doc, nsm.CA.Roots())
	if err != nil {
		t.Fatal(err)
	}
	if !d.Timestamp.Equal(t0) || string(d.UserData) != "ud" || string(d.Nonce) != "nonce" || string(d.PublicKey) != "pk" {
		t.Fatalf("%+v", d)
	}
	m := d.Measurements()
	if m.PCR0 != enclavetest.PCRHex(0xab) || m.IsDebug() {
		t.Fatal("pcrs")
	}
	if d.CheckUserData([]byte("ud")) != nil || d.CheckUserData([]byte("x")) == nil || d.CheckNonce([]byte("nonce")) != nil {
		t.Fatal("checks")
	}
	if d.CheckFresh(t0.Add(25*time.Hour), 26*time.Hour, time.Minute) != nil ||
		!errors.Is(d.CheckFresh(t0.Add(27*time.Hour), 26*time.Hour, time.Minute), nitro.ErrStale) ||
		!errors.Is(d.CheckFresh(t0.Add(-2*time.Minute), 26*time.Hour, time.Minute), nitro.ErrStale) {
		t.Fatal("freshness")
	}
	// Null optional fields.
	doc, _ = nsm.Attest(nil, nil, nil)
	if d, err := nitro.Verify(doc, nsm.CA.Roots()); err != nil || d.UserData != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejects(t *testing.T) {
	nsm := enclavetest.NewFakeNSM(0xab, 0x11, 0x22, func() time.Time { return t0 })
	doc, _ := nsm.Attest([]byte("ud"), nil, nil)
	// The real AWS root does not anchor the test chain.
	if _, err := nitro.Verify(doc, nitro.Pool(pins.NitroRoot())); !errors.Is(err, nitro.ErrChain) {
		t.Fatalf("aws root: %v", err)
	}
	if _, err := nitro.Verify(doc, nil); !errors.Is(err, nitro.ErrNoRoots) {
		t.Fatal("nil roots")
	}
	// Flip one payload byte: signature fails (or the payload no longer parses).
	for i := 40; i < len(doc)-100; i += 97 {
		bad := append([]byte(nil), doc...)
		bad[i] ^= 1
		if _, err := nitro.Verify(bad, nsm.CA.Roots()); err == nil {
			t.Fatalf("flip at %d accepted", i)
		}
	}
	// A document signed by a key outside the chain.
	other := *nsm.CA
	other.LeafKey = enclavetest.TestKey(elliptic.P384(), 0x34)
	forged := enclavetest.BuildDocument(&other, nsm.PCRs, t0, nil, nil, nil)
	if _, err := nitro.Verify(forged, nsm.CA.Roots()); !errors.Is(err, nitro.ErrSignature) {
		t.Fatalf("forged: %v", err)
	}
	// Debug PCRs are detected.
	dbg := enclavetest.NewFakeNSM(0, 0, 0, func() time.Time { return t0 })
	ddoc, _ := dbg.Attest(nil, nil, nil)
	d, err := nitro.Verify(ddoc, dbg.CA.Roots())
	if err != nil || !d.Measurements().IsDebug() {
		t.Fatal("debug")
	}
	// Wrong algorithm in the protected header.
	v, _ := cbor.Decode(doc)
	var ph cbor.Encoder
	ph.Map(1).Int(1).Int(-7)
	var e cbor.Encoder
	e.Array(4).ByteString(ph.Bytes()).Map(0).ByteString(v.Array[2].Bytes).ByteString(v.Array[3].Bytes)
	if _, err := nitro.Verify(e.Bytes(), nsm.CA.Roots()); !errors.Is(err, nitro.ErrFormat) {
		t.Fatal("alg")
	}
}

func FuzzVerify(f *testing.F) {
	nsm := enclavetest.NewFakeNSM(0xab, 0x11, 0x22, func() time.Time { return t0 })
	doc, _ := nsm.Attest([]byte("ud"), []byte("n"), nil)
	f.Add(doc)
	if b, err := os.ReadFile("testdata/aws-attestation-2025-09-16.b64"); err == nil {
		if real, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b))); err == nil {
			f.Add(real) // the NSM's own encoding
		}
	}
	roots := nsm.CA.Roots()
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = nitro.Verify(b, roots)
	})
}
