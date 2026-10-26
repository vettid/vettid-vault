package releasecfg

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// caCert returns a TEST-ONLY self-signed certificate (base64 DER) shaped
// by edit, issued at notBefore and valid until notAfter.
func caCert(t *testing.T, seed byte, notBefore, notAfter time.Time, edit func(*x509.Certificate)) string {
	t.Helper()
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(seed)), Subject: pkix.Name{CommonName: "TEST staging automation attestation CA"},
		NotBefore: notBefore, NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	var signer crypto.Signer = k
	var pub any = &k.PublicKey
	if edit != nil {
		edit(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

var (
	autoFrom  = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	autoUntil = "2027-06-30"
	autoEnd   = time.Date(2027, 6, 30, 23, 59, 59, 0, time.UTC)
)

func withAutomation(s, roots, until string) string {
	return strings.TrimSuffix(s, "}") + `,"automation_attestation":{"android_roots":[` + roots + `],"until":"` + until + `"}}`
}

func quoted(s ...string) string { return `"` + strings.Join(s, `","`) + `"` }

// VAULT-RELEASES §3.1 (owner decision 2026-10-27): the staging file may
// name automation attestation roots with an end date; the image accepts
// them only in the staging channel, and a production file that names
// them is malformed.
func TestAutomationAttestation(t *testing.T) {
	root := caCert(t, 0x61, autoFrom, autoEnd, nil)
	st := withAutomation(staging(complete(t)), quoted(root), autoUntil)
	c, err := Check(ChannelStaging, []byte(st))
	if err != nil {
		t.Fatal(err)
	}
	if c.Automation == nil || len(c.AutomationRoots()) != 1 || c.Automation.Until.Format(time.DateOnly) != autoUntil {
		t.Fatalf("%+v", c.Automation)
	}
	// Without the member: no roots (the committed staging file today).
	if c, err := Check(ChannelStaging, []byte(staging(complete(t)))); err != nil || c.Automation != nil || c.AutomationRoots() != nil {
		t.Fatal(c, err)
	}
	// Production: the member is malformed, whatever it holds.
	if _, err := Parse([]byte(withAutomation(complete(t), quoted(root), autoUntil))); !errors.Is(err, ErrFormat) {
		t.Fatalf("production file with automation roots: %v", err)
	}
	// And a production configuration never reports roots, however built.
	pc := *c
	pc.Channel = ChannelProd
	if pc.AutomationRoots() != nil {
		t.Fatal("automation roots outside the staging channel")
	}
	var nilc *Config
	if nilc.AutomationRoots() != nil || nilc.CheckEndDates(time.Now()) != nil {
		t.Fatal("nil configuration")
	}
	// Two roots (a rotation) are accepted.
	root2 := caCert(t, 0x62, autoFrom, autoEnd, nil)
	if c, err := Check(ChannelStaging, []byte(withAutomation(staging(complete(t)), quoted(root, root2), autoUntil))); err != nil || len(c.AutomationRoots()) != 2 {
		t.Fatal(err)
	}
	// A placeholder root is missing: the gate refuses the file.
	f, err := Parse([]byte(withAutomation(staging(complete(t)), quoted("TODO-automation-ca"), autoUntil)))
	if err != nil || len(f.Missing) != 1 || f.Missing[0] != "automation_attestation" {
		t.Fatal(f, err)
	}
	if _, err := f.Complete(); !errors.Is(err, ErrIncomplete) {
		t.Fatal(err)
	}
}

func TestAutomationRefusals(t *testing.T) {
	base := staging(complete(t))
	good := caCert(t, 0x61, autoFrom, autoEnd, nil)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	otherKey, _ := ecdsa.ParseRawPrivateKey(elliptic.P256(), bytes.Repeat([]byte{0x77}, 32))
	certWith := func(pub any, signer crypto.Signer) string {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "TEST"}, NotBefore: autoFrom, NotAfter: autoEnd,
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(der)
	}
	// Not self-signed: issued by another key.
	k61, _ := ecdsa.ParseRawPrivateKey(elliptic.P256(), bytes.Repeat([]byte{0x61}, 32))
	issued := func() string {
		parentT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TEST parent"}, NotBefore: autoFrom, NotAfter: autoEnd,
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		parentDER, _ := x509.CreateCertificate(rand.Reader, parentT, parentT, &otherKey.PublicKey, otherKey)
		parent, _ := x509.ParseCertificate(parentDER)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "TEST child"}, NotBefore: autoFrom, NotAfter: autoEnd,
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &k61.PublicKey, otherKey)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(der)
	}()
	for name, file := range map[string]string{
		"no roots":          withAutomation(base, "", autoUntil),
		"three roots":       withAutomation(base, quoted(good, caCert(t, 0x62, autoFrom, autoEnd, nil), caCert(t, 0x63, autoFrom, autoEnd, nil)), autoUntil),
		"same key twice":    withAutomation(base, quoted(good, caCert(t, 0x61, autoFrom, autoEnd.Add(-time.Hour), nil)), autoUntil),
		"not base64":        withAutomation(base, quoted("not base64!"), autoUntil),
		"not a certificate": withAutomation(base, quoted(base64.StdEncoding.EncodeToString([]byte("x"))), autoUntil),
		"not a CA":          withAutomation(base, quoted(caCert(t, 0x61, autoFrom, autoEnd, func(c *x509.Certificate) { c.IsCA = false })), autoUntil),
		"no keyCertSign": withAutomation(base, quoted(caCert(t, 0x61, autoFrom, autoEnd, func(c *x509.Certificate) {
			c.KeyUsage = x509.KeyUsageDigitalSignature
		})), autoUntil),
		"RSA key":           withAutomation(base, quoted(certWith(&rsaKey.PublicKey, rsaKey)), autoUntil),
		"Ed25519 key":       withAutomation(base, quoted(certWith(edKey.Public(), edKey)), autoUntil),
		"not self-signed":   withAutomation(base, quoted(issued), autoUntil),
		"outlives the date": withAutomation(base, quoted(caCert(t, 0x61, autoFrom, autoEnd.Add(2*time.Second), nil)), autoUntil),
		"until too far":     withAutomation(base, quoted(caCert(t, 0x61, autoFrom, autoFrom.AddDate(0, 0, MaxAutomationDays+1), nil)), autoFrom.AddDate(0, 0, MaxAutomationDays+1).Format(time.DateOnly)),
		"until malformed":   withAutomation(base, quoted(good), "2027-6-30"),
		"until a time":      withAutomation(base, quoted(good), "2027-06-30T00:00:00Z"),
		"no until":          strings.TrimSuffix(base, "}") + `,"automation_attestation":{"android_roots":[` + quoted(good) + `]}}`,
		"extra member":      strings.TrimSuffix(base, "}") + `,"automation_attestation":{"android_roots":[` + quoted(good) + `],"until":"` + autoUntil + `","x":1}}`,
		"not an object":     strings.TrimSuffix(base, "}") + `,"automation_attestation":[]}`,
		"roots a string":    strings.TrimSuffix(base, "}") + `,"automation_attestation":{"android_roots":` + quoted(good) + `,"until":"` + autoUntil + `"}}`,
	} {
		if _, err := Parse([]byte(file)); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The longest switch is accepted.
	far := autoFrom.AddDate(0, 0, MaxAutomationDays)
	if _, err := Check(ChannelStaging, []byte(withAutomation(base, quoted(caCert(t, 0x61, autoFrom, far, nil)), far.Format(time.DateOnly)))); err != nil {
		t.Fatal(err)
	}
}

// STAGING-DEVELOPMENT-PLAN §2.5.5: the switch's end date. The gate
// accepts the file through the last day (UTC) and refuses it from the
// next.
func TestAutomationEndDate(t *testing.T) {
	c, err := Check(ChannelStaging, []byte(withAutomation(staging(complete(t)), quoted(caCert(t, 0x61, autoFrom, autoEnd, nil)), autoUntil)))
	if err != nil {
		t.Fatal(err)
	}
	for at, want := range map[time.Time]error{
		autoFrom: nil,
		time.Date(2027, 6, 30, 23, 59, 59, 0, time.UTC):                  nil,
		time.Date(2027, 6, 30, 20, 0, 0, 0, time.FixedZone("", -5*3600)): ErrExpired, // 01:00 UTC on July 1
		time.Date(2027, 7, 1, 0, 0, 0, 0, time.UTC):                      ErrExpired,
	} {
		if err := c.CheckEndDates(at); !errors.Is(err, want) || want == nil && err != nil {
			t.Errorf("%v: %v, want %v", at, err, want)
		}
	}
	// A file without a switch has no end date.
	plain, _ := Check(ChannelStaging, []byte(staging(complete(t))))
	if err := plain.CheckEndDates(time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
}

// The committed production file has no automation member, and cannot
// get one.
func TestCommittedProdHasNoAutomation(t *testing.T) {
	b, err := os.ReadFile("prod.json")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("automation")) {
		t.Fatal("prod.json names automation attestation")
	}
	added := withAutomation(strings.TrimSpace(string(b)), quoted(caCert(t, 0x61, autoFrom, autoEnd, nil)), autoUntil)
	if _, err := Parse([]byte(added)); !errors.Is(err, ErrFormat) {
		t.Fatalf("prod.json with an automation member: %v", err)
	}
	f, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if f.Config.Automation != nil || f.Config.AutomationRoots() != nil {
		t.Fatal("production automation roots")
	}
}
