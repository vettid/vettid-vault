package keycheck

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave/awskms"
	"github.com/vettid/vettid-vault/enclave/releasecfg"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/manifest"
)

// The recorded fixtures (testdata/<case>/) are a staging release-4 key in
// the test account 111122223333 (window 7 days) whose policy admits
// release 3: the §11.10.7 example and one variant per failing check.
var (
	arn3 = enclavetest.KeyARN(3)
	arn4 = enclavetest.KeyARN(4)
	pcr3 = strings.Repeat("ab", 48)
	pcr4 = strings.Repeat("cd", 48)
)

// writeConfig writes a complete staging channel file pinning pub, for
// the test account (TEST ONLY).
func writeConfig(t testing.TB, pub *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	cfg := `{"channel":"staging","release":4,"manifest_keys":["` + base64.StdEncoding.EncodeToString(der) + `"],` +
		`"seal_account":"111122223333","seal_region":"us-east-1",` +
		`"retirement_principal":"arn:aws:iam::111122223333:role/vettid-org-vault-key-retirement","retirement_window_days":7,` +
		`"android_signers":["` + strings.Repeat("5a", 32) + `"],"relay_url":"https://relay.vettid.test"}`
	p := filepath.Join(t.TempDir(), "staging.json")
	if err := os.WriteFile(p, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func testKey(t testing.TB) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func config(t testing.TB, pub *ecdsa.PublicKey) *releasecfg.Config {
	b, err := os.ReadFile(writeConfig(t, pub))
	if err != nil {
		t.Fatal(err)
	}
	c, err := releasecfg.Check("staging", b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// draftManifest is the manifest the fixtures belong to: release 3
// deprecated, release 4 active (TEST ONLY).
func draftManifest() []byte {
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	return manifest.Build(9, at, []manifest.Release{
		{Number: 3, PCR0: pcr3, PCR1: strings.Repeat("11", 48), PCR2: strings.Repeat("22", 48), SealKey: arn3, Status: "deprecated", PublishedAt: at, Notes: "https://vettid.org/security/releases/3"},
		{Number: 4, PCR0: pcr4, PCR1: strings.Repeat("33", 48), PCR2: strings.Repeat("44", 48), SealKey: arn4, Status: "active", PublishedAt: at, Notes: "https://vettid.org/security/releases/4"},
	})
}

func TestRecordedFixtures(t *testing.T) {
	cfg := config(t, &testKey(t).PublicKey)
	m, signed, err := LoadManifest(draftManifest(), cfg.ManifestKeys)
	if err != nil || signed {
		t.Fatalf("draft manifest: %v %v", signed, err)
	}
	target, err := Target(m, arn4, 0)
	if err != nil || target != 4 {
		t.Fatalf("target %d %v", target, err)
	}
	for dir, want := range map[string]int{
		"pass": 0, "check2-multiregion": 2, "check3-grant": 3, "check6-admin": 6,
		"check7-ifexists": 7, "check7-window": 7, "check8-foreign": 8,
	} {
		r, err := Fixtures(filepath.Join("testdata", dir))
		if err != nil {
			t.Fatal(err)
		}
		res, err := Run(cfg, m, target, arn4, r)
		if got := FailedCheck(err); got != want || (want == 0 && (err != nil || res.KeyARN != arn4)) {
			t.Errorf("%s: check %d (%v), want %d", dir, got, err, want)
		}
	}
	// The production window (30 days) refuses the staging fixture: the
	// pinned constants are the channel's, not the key's.
	prod := *cfg
	prod.RetirementWindowDays = 30
	r, _ := Fixtures("testdata/pass")
	if _, err := Run(&prod, m, 4, arn4, r); FailedCheck(err) != 7 {
		t.Errorf("30-day window: %v", err)
	}
	// Release 3's key is not this one.
	if _, err := Target(m, arn4, 3); err == nil {
		t.Error("release 3 with release 4's key")
	}
	if _, err := Target(m, "arn:aws:kms:us-east-1:111122223333:key/nope", 0); err == nil {
		t.Error("unknown key")
	}
}

// A signed manifest must verify under the channel's pinned keys.
func TestLoadManifestSigned(t *testing.T) {
	k := testKey(t)
	s, err := manifest.Sign(k, draftManifest())
	if err != nil {
		t.Fatal(err)
	}
	if _, signed, err := LoadManifest(s.Marshal(), []*ecdsa.PublicKey{&k.PublicKey}); err != nil || !signed {
		t.Fatalf("signed: %v %v", signed, err)
	}
	if _, _, err := LoadManifest(s.Marshal(), []*ecdsa.PublicKey{&testKey(t).PublicKey}); err == nil {
		t.Fatal("a manifest signed by an unpinned key")
	}
	if _, _, err := LoadManifest([]byte(`{"v":1}`), nil); err == nil {
		t.Fatal("junk")
	}
}

// Fetch sends the enclave's own requests (SigV4, JSON 1.1) and records
// them; the fake KMS answers with the §11.10.7 policy shape.
func TestFetchAndRecord(t *testing.T) {
	cfg := config(t, &testKey(t).PublicKey)
	fake := enclavetest.NewFakeKMS("keycheck", enclavetest.TestNitroCA().Roots(), time.Now)
	pcrs := []string{enclavetest.Spec(3, "").PCR0Hex(), enclavetest.Spec(4, "").PCR0Hex()}
	fake.AddKey(arn4, enclavetest.GoodPolicy(pcrs[1], pcrs))
	creds := awskms.Credentials{AccessKeyID: "AKIDTEST", SecretAccessKey: "test", SessionToken: "tok"}
	srv := httptest.NewUnstartedServer(enclavetest.NewKMSServer(fake, "us-east-1", creds))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{enclavetest.ServerCert("kms.us-east-1.amazonaws.com")}}
	srv.StartTLS()
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: enclavetest.TLSRoots()},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}}}
	c := awskms.NewClient(hc, "us-east-1", &awskms.CachedCredentials{Source: func(context.Context) (awskms.Credentials, error) { return creds, nil }})
	r, err := Fetch(context.Background(), c, arn4)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	m, err := manifest.Parse(manifest.Build(2, at, []manifest.Release{
		{Number: 3, PCR0: pcrs[0], PCR1: strings.Repeat("11", 48), PCR2: strings.Repeat("22", 48), SealKey: arn3, Status: "deprecated", PublishedAt: at, Notes: "https://vettid.org/r/3"},
		{Number: 4, PCR0: pcrs[1], PCR1: strings.Repeat("33", 48), PCR2: strings.Repeat("44", 48), SealKey: arn4, Status: "active", PublishedAt: at, Notes: "https://vettid.org/r/4"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(cfg, m, 4, arn4, r); err != nil {
		t.Fatalf("live check: %v", err)
	}
	dir := t.TempDir()
	if err := r.Record(dir); err != nil {
		t.Fatal(err)
	}
	r2, err := Fixtures(dir)
	if err != nil || string(r2.GetKeyPolicy) != string(r.GetKeyPolicy) {
		t.Fatalf("record/fixtures round trip: %v", err)
	}
	// A key the caller may not read: the error names the call.
	if _, err := Fetch(context.Background(), c, arn3); err == nil || !strings.Contains(err.Error(), "DescribeKey") {
		t.Fatalf("missing key: %v", err)
	}
}
