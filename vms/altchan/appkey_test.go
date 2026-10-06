package altchan

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
)

// testAppKey is a fixed P-256 app key (scalar 32 x b), TEST ONLY.
func testAppKey(t testing.TB, b byte) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k, der
}

// §11.12.2: the app key is the canonical SPKI DER of a P-256 key; akid is
// the first 16 bytes of its SHA-256 in hex; anything else is refused.
func TestParseAppKey(t *testing.T) {
	_, der := testAppKey(t, 0x41)
	pub, got, err := ParseAppKey(base64.StdEncoding.EncodeToString(der))
	if err != nil || !bytes.Equal(got, der) || pub == nil {
		t.Fatal(err)
	}
	if id := AppKeyID(der); len(id) != 32 || strings.ToLower(id) != id {
		t.Fatal(id)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), nil)
	d384, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	for _, s := range []string{"", "!!", base64.RawStdEncoding.EncodeToString(der), base64.StdEncoding.EncodeToString(d384),
		base64.StdEncoding.EncodeToString(append(der, 0)), base64.StdEncoding.EncodeToString(der[:len(der)-1]),
		strings.Repeat("A", MaxAppKeyB64+4)} {
		if _, _, err := ParseAppKey(s); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}

// §11.12.2: the signing string, the header, and verification.
func TestAppRequestSigning(t *testing.T) {
	k, der := testAppKey(t, 0x41)
	r := &AppRequest{Method: "POST", Path: "/api/vault/unlock", Query: "", VaultID: "0123456789abcdef0123456789abcdef",
		KID: AppKeyID(der), TS: 1791374400, Nonce: "AAECAwQFBgcICQoLDA0ODw", Body: []byte(`{"a":1}`)}
	want := "vettid/member-api/app/1\nPOST\n/api/vault/unlock\n\n0123456789abcdef0123456789abcdef\n" + AppKeyID(der) +
		"\n1791374400\nAAECAwQFBgcICQoLDA0ODw\n015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"
	if s := r.SigningString(); s != want {
		t.Fatalf("signing string\n%s\nwant\n%s", s, want)
	}
	h, err := r.Sign(k)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "v=1; vault=0123456789abcdef0123456789abcdef; kid="+AppKeyID(der)+"; ts=1791374400; nonce=AAECAwQFBgcICQoLDA0ODw; sig=") {
		t.Fatal(h)
	}
	p, sig, err := ParseAppHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	p.Method, p.Path, p.Query, p.Body = r.Method, r.Path, r.Query, r.Body
	pub, _, _ := ParseAppKey(base64.StdEncoding.EncodeToString(der))
	if !p.Verify(pub, der, sig) {
		t.Fatal("does not verify")
	}
	p.Body = []byte(`{"a":2}`)
	if p.Verify(pub, der, sig) {
		t.Fatal("verifies another body")
	}
	_, other := testAppKey(t, 0x42)
	p.Body = r.Body
	if p.Verify(pub, other, sig) {
		t.Fatal("verifies under another akid")
	}
	for _, bad := range []string{
		strings.Replace(h, "v=1", "v=2", 1),
		strings.Replace(h, "; ", ";", 1),
		strings.Replace(h, "ts=1791374400", "ts=01791374400", 1),
		strings.Replace(h, "nonce=AAECAwQFBgcICQoLDA0ODw", "nonce=AAECAwQFBgcICQoLDA0O", 1),
		strings.Replace(h, "kid=", "kid=A", 1),
		h + "; x=1",
	} {
		if _, _, err := ParseAppHeader(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	// A redeem's empty vault.
	if _, _, err := ParseAppHeader(strings.Replace(h, "vault=0123456789abcdef0123456789abcdef", "vault=", 1)); err != nil {
		t.Fatal(err)
	}
}

// §11.12.1: the code alphabet, rejection sampling, normalization.
func TestSetupCode(t *testing.T) {
	if len(CodeAlphabet) != 31 || strings.ContainsAny(CodeAlphabet, "01ILO") {
		t.Fatal("alphabet")
	}
	c, n, err := CodeFromBytes([]byte{248, 255, 0, 30, 31, 247, 1, 2, 3, 4, 5})
	if err != nil || c != "2Z2Z345678"[:8] || n != 10 {
		t.Fatalf("%q %d %v", c, n, err)
	}
	if _, _, err := CodeFromBytes([]byte{250, 1}); err == nil {
		t.Fatal("short stream")
	}
	seen := map[byte]int{}
	for i := 0; i < 200; i++ {
		c, err := NewCode()
		if err != nil || len(c) != CodeLength {
			t.Fatal(err)
		}
		for j := 0; j < len(c); j++ {
			seen[c[j]]++
		}
	}
	if len(seen) != 31 {
		t.Fatalf("symbols seen %d", len(seen))
	}
	for in, want := range map[string]string{"abcd-efgh": "ABCDEFGH", " 2345 6789": "23456789", "ABCD EFGH": "ABCDEFGH"} {
		if got, ok := NormalizeCode(in); !ok || got != want {
			t.Fatalf("%q: %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"ABCD-EFG", "ABCD-EFGI", "0BCDEFGH", "ABCDEFGHJ"} {
		if _, ok := NormalizeCode(in); ok {
			t.Fatalf("accepted %q", in)
		}
	}
	if FormatCode("ABCDEFGH") != "ABCD-EFGH" || NormalizeEmail("  M@Example.COM ") != "m@example.com" || EmailHint("member@example.com") != "m***@example.com" {
		t.Fatal("format")
	}
}

// §11.12.1, §11.11.2: the enrollment QR and the recovery QR's api.
func TestEnrollQR(t *testing.T) {
	q := &EnrollQR{API: "https://account.vettid.org", Secret: bytes.Repeat([]byte{0x2a}, 16)}
	b := q.Marshal()
	if string(b) != `{"v":1,"t":"e","api":"https://account.vettid.org","s":"KioqKioqKioqKioqKioqKg"}` || len(b) != 79 { // ENROLLMENT-CODES §3.2 says 78; the payload as specified is 79
		t.Fatalf("%s (%d)", b, len(b))
	}
	p, err := ParseEnrollQR(b)
	if err != nil || p.API != q.API || !bytes.Equal(p.Secret, q.Secret) {
		t.Fatal(err)
	}
	for _, s := range []string{
		`{"v":1,"t":"r","api":"https://account.vettid.org","s":"KioqKioqKioqKioqKioqKg"}`,
		`{"v":1,"t":"e","api":"https://account.vettid.org/x","s":"KioqKioqKioqKioqKioqKg"}`,
		`{"v":1,"t":"e","api":"ftp://account.vettid.org","s":"KioqKioqKioqKioqKioqKg"}`,
		`{"v":1,"t":"e","api":"https://account.vettid.org","s":"KioqKioqKioqKioqKioqKg=="}`,
		`{"v":1,"t":"e","api":"https://account.vettid.org","s":"KioqKioqKioqKioqKioq"}`,
		`{"v":2,"t":"e","api":"https://account.vettid.org","s":"KioqKioqKioqKioqKioqKg"}`,
		`{"v":1,"t":"e","s":"KioqKioqKioqKioqKioqKg"}`,
	} {
		if _, err := ParseEnrollQR([]byte(s)); err == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	c := testCode()
	c.API = "https://account.vettid.org"
	rq := RecoveryQR(c)
	if !bytes.HasPrefix(rq, []byte(`{"v":1,"t":"r","api":"https://account.vettid.org","vault_id":`)) {
		t.Fatalf("%s", rq)
	}
	if got, err := ParseRecoveryQR(rq); err != nil || got.API != c.API {
		t.Fatal(err)
	}
}

func FuzzParseAppHeader(f *testing.F) {
	f.Add("v=1; vault=; kid=0123456789abcdef0123456789abcdef; ts=1; nonce=AAECAwQFBgcICQoLDA0ODw; sig=MEQ")
	f.Fuzz(func(t *testing.T, s string) {
		r, sig, err := ParseAppHeader(s)
		if err == nil && (r.Header(sig) != s) {
			t.Fatalf("non-canonical header accepted: %q", s)
		}
	})
}

func FuzzParseEnrollQR(f *testing.F) {
	f.Add([]byte(`{"v":1,"t":"e","api":"https://account.vettid.org","s":"KioqKioqKioqKioqKioqKg"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if q, err := ParseEnrollQR(b); err == nil && len(q.Secret) != QRSecretSize {
			t.Fatal("secret size")
		}
	})
}
