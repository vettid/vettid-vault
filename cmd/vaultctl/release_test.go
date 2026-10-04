package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave/releasecfg"
	"github.com/vettid/vettid-vault/vms/manifest"
)

// Fixtures shared with internal/keycheck (a staging release-4 key in the
// test account, TEST ONLY).
const fixtures = "../../internal/keycheck/testdata"

func writeFile(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func genKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func spki(t *testing.T, k *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// stagingConfig writes a complete staging channel file pinning keys.
func stagingConfig(t *testing.T, dir string, keys ...*ecdsa.PrivateKey) string {
	var ks []string
	for _, k := range keys {
		ks = append(ks, `"`+base64.StdEncoding.EncodeToString(spki(t, k))+`"`)
	}
	return writeFile(t, dir, "staging.json", []byte(`{"channel":"staging","release":4,"manifest_keys":[`+strings.Join(ks, ",")+`],`+
		`"seal_account":"111122223333","seal_region":"us-east-1",`+
		`"retirement_principal":"arn:aws:iam::111122223333:role/vettid-org-vault-key-retirement","retirement_window_days":7,`+
		`"android_signers":["`+strings.Repeat("5a", 32)+`"],"relay_url":"https://relay.vettid.test"}`))
}

const arn4 = "arn:aws:kms:us-east-1:111122223333:key/00000004-0000-4000-8000-000000000004"

func draft() []byte {
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	return manifest.Build(9, at, []manifest.Release{
		{Number: 3, PCR0: strings.Repeat("ab", 48), PCR1: strings.Repeat("11", 48), PCR2: strings.Repeat("22", 48),
			SealKey: "arn:aws:kms:us-east-1:111122223333:key/00000003-0000-4000-8000-000000000003", Status: "deprecated", PublishedAt: at, Notes: "https://vettid.org/security/releases/3"},
		{Number: 4, PCR0: strings.Repeat("cd", 48), PCR1: strings.Repeat("33", 48), PCR2: strings.Repeat("44", 48),
			SealKey: arn4, Status: "active", PublishedAt: at, Notes: "https://vettid.org/security/releases/4"},
	})
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	return 1
}

// keycheck exits with the failing check's number.
func TestKeycheckExitStatus(t *testing.T) {
	dir := t.TempDir()
	k := genKey(t)
	cfg := stagingConfig(t, dir, k)
	mf := writeFile(t, dir, "draft.json", draft())
	ctx := context.Background()
	for fx, want := range map[string]int{"pass": 0, "check2-multiregion": 2, "check3-grant": 3, "check6-admin": 6, "check7-ifexists": 7, "check8-foreign": 8} {
		err := cmdKeycheck(ctx, nil, []string{"-key-arn", arn4, "-config", cfg, "-manifest", mf, "-fixtures", filepath.Join(fixtures, fx)})
		if got := exitCode(err); got != want {
			t.Errorf("%s: exit %d (%v), want %d", fx, got, err, want)
		}
	}
	// The served document, signed by the pinned key, works the same way.
	s, err := manifest.Sign(k, draft())
	if err != nil {
		t.Fatal(err)
	}
	served := writeFile(t, dir, "served.json", s.Marshal())
	if err := cmdKeycheck(ctx, nil, []string{"-key-arn", arn4, "-config", cfg, "-manifest", served, "-fixtures", filepath.Join(fixtures, "pass")}); err != nil {
		t.Fatal(err)
	}
	// Signed by another key: refused before any check (status 9).
	s2, _ := manifest.Sign(genKey(t), draft())
	other := writeFile(t, dir, "other.json", s2.Marshal())
	if got := exitCode(cmdKeycheck(ctx, nil, []string{"-key-arn", arn4, "-config", cfg, "-manifest", other, "-fixtures", filepath.Join(fixtures, "pass")})); got != keycheckOther {
		t.Fatalf("unpinned manifest key: exit %d", got)
	}
	// The committed channel files: one that still has placeholders has
	// nothing to check against yet (status 9, not a pass); a complete one
	// pins the real account, so the test account's key fails a numbered
	// check (1–8), never passes.
	for _, ch := range []string{"prod", "staging"} {
		path := "../../enclave/releasecfg/" + ch + ".json"
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		f, err := releasecfg.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		err = cmdKeycheck(ctx, nil, []string{"-key-arn", arn4, "-config", path, "-channel", ch, "-manifest", mf, "-fixtures", filepath.Join(fixtures, "pass")})
		if len(f.Missing) > 0 {
			if exitCode(err) != keycheckOther || !strings.Contains(err.Error(), "not final") {
				t.Fatalf("%s placeholders: %v", ch, err)
			}
		} else if code := exitCode(err); code < 1 || code > 8 {
			t.Fatalf("%s (complete) with the test account's key: exit %d (%v), want a failed check 1-8", ch, code, err)
		}
	}
	if exitCode(cmdKeycheck(ctx, nil, []string{"-key-arn", arn4})) != keycheckOther {
		t.Fatal("usage")
	}
}

// render -> check -> digest -> sign (file key A) and import-sig (key B).
func TestManifestCommands(t *testing.T) {
	dir := t.TempDir()
	a, b := genKey(t), genKey(t)
	cfg := stagingConfig(t, dir, a, b)
	ctx := context.Background()
	rel := strings.NewReplacer("P0", strings.Repeat("cd", 48), "P1", strings.Repeat("33", 48), "P2", strings.Repeat("44", 48)).Replace(
		`{"releases":[{"release":4,"pcr0":"P0","pcr1":"P1","pcr2":"P2","seal_key":"` + arn4 + `","status":"active","published_at":"2026-10-01T00:00:00Z","notes":"https://vettid.org/security/releases/4"}]}`)
	list := writeFile(t, dir, "releases.json", []byte(rel))
	m1 := filepath.Join(dir, "m1.json")
	if err := cmdManifest(ctx, nil, []string{"render", "-releases", list, "-serial", "1", "-issued-at", "2026-10-01T12:00:00Z", "-out", m1}); err != nil {
		t.Fatal(err)
	}
	if err := cmdManifest(ctx, nil, []string{"check", "-in", m1}); err != nil {
		t.Fatal(err)
	}
	ec, _ := x509.MarshalECPrivateKey(a)
	keyA := writeFile(t, dir, "a.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ec}))
	s1 := filepath.Join(dir, "s1.json")
	if err := cmdManifest(ctx, nil, []string{"sign", "-in", m1, "-key", keyA, "-config", cfg, "-out", s1}); err != nil {
		t.Fatal(err)
	}
	if err := cmdManifest(ctx, nil, []string{"check", "-in", s1, "-config", cfg}); err != nil {
		t.Fatal(err)
	}
	// The next manifest: serial from the published one.
	m2 := filepath.Join(dir, "m2.json")
	if err := cmdManifest(ctx, nil, []string{"render", "-releases", list, "-previous", s1, "-out", m2}); err != nil {
		t.Fatal(err)
	}
	mb, _ := os.ReadFile(m2)
	m, err := manifest.Parse(mb)
	if err != nil || m.Serial != 2 {
		t.Fatalf("serial: %v", err)
	}
	if err := cmdManifest(ctx, nil, []string{"check", "-in", m2, "-previous", s1}); err != nil {
		t.Fatal(err)
	}
	if err := cmdManifest(ctx, nil, []string{"check", "-in", m1, "-previous", m2}); err == nil {
		t.Fatal("older serial accepted as the successor")
	}
	// Key B signs offline; its DER signature (hex) is imported.
	d := manifest.Digest(mb)
	der, _ := ecdsa.SignASN1(rand.Reader, b, d[:])
	sig := writeFile(t, dir, "sig.hex", []byte(hex.EncodeToString(der)))
	pubB := writeFile(t, dir, "b.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki(t, b)}))
	s2 := filepath.Join(dir, "s2.json")
	if err := cmdManifest(ctx, nil, []string{"import-sig", "-in", m2, "-sig", sig, "-signer-pub", pubB, "-config", cfg, "-out", s2}); err != nil {
		t.Fatal(err)
	}
	if err := cmdManifest(ctx, nil, []string{"check", "-in", s2, "-pin", pubB}); err != nil {
		t.Fatal(err)
	}
	// Not pinned: refused.
	c := genKey(t)
	pubC := writeFile(t, dir, "c.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki(t, c)}))
	if err := cmdManifest(ctx, nil, []string{"check", "-in", s2, "-pin", pubC}); err == nil {
		t.Fatal("served document verified under an unpinned key")
	}
	if err := cmdManifest(ctx, nil, []string{"import-sig", "-in", m2, "-sig", sig, "-signer-pub", pubB, "-pin", pubC, "-out", s2}); err == nil {
		t.Fatal("signature imported for an unpinned key")
	}
	// The committed channel files pin no key yet.
	if err := cmdManifest(ctx, nil, []string{"sign", "-in", m2, "-key", keyA, "-config", "../../enclave/releasecfg/prod.json", "-out", s2}); err == nil {
		t.Fatal("signed against the placeholder prod file")
	}
	if err := cmdManifest(ctx, nil, []string{"digest", "-in", m2}); err != nil {
		t.Fatal(err)
	}
}
