package manifest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func specKey(seed byte) *ecdsa.PrivateKey {
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		panic(err)
	}
	return k
}

// specManifest is the §16 manifest (1,060 bytes).
func specManifest() []byte {
	rs := []Release{
		{Number: 3, PCR0: strings.Repeat("ab", 48), PCR1: strings.Repeat("11", 48), PCR2: strings.Repeat("22", 48),
			SealKey: "arn:aws:kms:us-east-1:000000000000:key/test-release-3", Status: StatusDeprecated,
			PublishedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), Notes: "https://vettid.org/releases/3"},
		{Number: 4, PCR0: strings.Repeat("cd", 48), PCR1: strings.Repeat("33", 48), PCR2: strings.Repeat("44", 48),
			SealKey: "arn:aws:kms:us-east-1:000000000000:key/test-release-4", Status: StatusActive,
			PublishedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Notes: "https://vettid.org/releases/4"},
	}
	return Build(7, time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC), rs)
}

// The §16 manifest-signature values.
func TestSpecVector(t *testing.T) {
	k := specKey(0x21)
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if got := base64.StdEncoding.EncodeToString(spki); got != "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERi26GuT8GpaLTazyDN1tvh+uNKqXFRSmPTQFw9HP04O1i7sIwTODQoxYU8ccTIUeE0sFaCHkaP4Kl3q/QxPd4Q==" {
		t.Errorf("spki %s", got)
	}
	m := specManifest()
	if len(m) != 1060 {
		t.Errorf("len %d", len(m))
	}
	h := sha256.Sum256(m)
	if hex.EncodeToString(h[:]) != "d3fc1be2ce9358815863eeae15bebf5c755f168a7ab161c8e5c66500be1288f1" {
		t.Errorf("sha %x", h)
	}
	d := Digest(m)
	if hex.EncodeToString(d[:]) != "9b086ab99783d85706fdacf3dd36f496c16e30f05468450f1efd946fae1ddfad" {
		t.Errorf("digest %x", d)
	}
	s, err := Sign(k, m)
	if err != nil {
		t.Fatal(err)
	}
	if s.KeyID != "1edbb48b6669decd" {
		t.Errorf("key id %s", s.KeyID)
	}
	if got := base64.StdEncoding.EncodeToString(s.Sig); got != "3AyvBQGEjYFOYLlmp+EwyEbvd/34cnEB9jcAA5o691JRXj6eKTHcZHUZw36FgLtpEpYRLAsLlpGYYZWwQZE46w==" {
		t.Errorf("sig %s", got)
	}
	// approval vector
	ss := "vettid/vms/2/release-approval\ntest-vault-0001\n01JB2Z6V9K3M4N5P6Q7R8S9T22\n" + strings.Repeat("ab", 48) + "\n" + strings.Repeat("cd", 48) + "\n4\n7"
	ah := sha256.Sum256([]byte(ss))
	if hex.EncodeToString(ah[:]) != "1217fb681eb6a11899ff5ab2ab1a620f179bb942088dc2b79e9b0466380d10b5" {
		t.Errorf("approval sha %x", ah)
	}
	ak := specKey(0x22)
	aspki, _ := x509.MarshalPKIXPublicKey(&ak.PublicKey)
	if got := base64.StdEncoding.EncodeToString(aspki); got != "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1lqTl3yqPRsIGFL/V6eeRl8WYFdzBLrq1QXdOkhYnPNQGF6JU3LfYiHqOhN1V+Rz/dtnVfBb1QfDxTP86ckShQ==" {
		t.Errorf("approval spki %s", got)
	}
	sig, _ := ak.Sign(nil, ah[:], crypto.SHA256)
	if got := base64.StdEncoding.EncodeToString(sig); got != "MEQCIH8lw3H0EdOnkuiH6yMEMR/zIh16+kPuacXjK77FnYf+AiBGvXMyQ6vhmpA1JRJYd804f5qw9Dtyo7kXZZ/TTSMCSA==" {
		t.Errorf("approval sig %s", got)
	}
}
