package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/vettid/vettid-vault/enclave/releasecfg"
	"github.com/vettid/vettid-vault/internal/autoattest"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/devattest"
)

// localKMS is a TEST-ONLY stand-in for an ECC_NIST_P256 SIGN_VERIFY KMS
// key: a local key that signs digests (DER), as KMS does.
type localKMS struct {
	key   *ecdsa.PrivateKey
	signs int
}

func (l *localKMS) GetPublicKey(_ context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	der, err := x509.MarshalPKIXPublicKey(&l.key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{PublicKey: der, KeySpec: kmstypes.KeySpecEccNistP256, KeyUsage: kmstypes.KeyUsageTypeSignVerify}, nil
}

func (l *localKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	if in.MessageType != kmstypes.MessageTypeDigest || in.SigningAlgorithm != kmstypes.SigningAlgorithmSpecEcdsaSha256 || len(in.Message) != 32 {
		return nil, errors.New("unexpected sign input")
	}
	l.signs++
	sig, err := ecdsa.SignASN1(rand.Reader, l.key, in.Message)
	return &kms.SignOutput{Signature: sig}, err
}

func TestStagingURL(t *testing.T) {
	for _, ok := range []string{"https://account.staging.vettid.org", "https://staging.vettid.org/.well-known/vettid/pcr-manifest.json", "https://ACCOUNT.staging.vettid.org/"} {
		if _, err := stagingURL("x", ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"https://account.vettid.org", "https://vettid.org/.well-known/vettid/pcr-manifest.json", "http://account.staging.vettid.org",
		"https://staging.vettid.org.example.com", "https://xstaging.vettid.org", "https://account.staging.vettid.org:8443", "https://u@account.staging.vettid.org", ""} {
		if _, err := stagingURL("x", bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// stagingWithCA writes the committed staging file plus an automation
// member naming the CA of k, valid to until.
func stagingWithCA(t *testing.T, dir string, ca *kmsCA, until time.Time) (string, *x509.Certificate) {
	t.Helper()
	der, err := autoattest.NewCA(ca, time.Now().Add(-48*time.Hour), until)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../enclave/releasecfg/staging.json")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.TrimSuffix(strings.TrimSpace(string(b)), "}") +
		`,"automation_attestation":{"android_roots":["` + base64.StdEncoding.EncodeToString(der) + `"],"until":"` + until.Format(time.DateOnly) + `"}}`
	return writeFile(t, dir, "staging.json", []byte(s)), cert
}

// The KMS-backed CA, through the command's own pieces: the certificate it
// makes is the one the staging file pins, and the chain it issues for the
// staging identity passes the staging device policy (the vendor roots
// plus the file's automation roots) and fails a policy of the vendor
// roots alone (production's).
func TestStagingKMSAttester(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l := &localKMS{key: enclavetest.TestKey(elliptic.P256(), 0x71)}
	ca, err := newKMSCA(ctx, l, "alias/test")
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().UTC().AddDate(0, 3, 0)
	path, caCert := stagingWithCA(t, dir, ca, until)
	c, err := stagingChannel(path, true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got, err := automationCA(c, ca.pub); err != nil || !got.Equal(caCert) {
		t.Fatal(got, err)
	}
	other := enclavetest.TestKey(elliptic.P256(), 0x72)
	if _, err := automationCA(c, &other.PublicKey); err == nil {
		t.Fatal("an unpinned KMS key was accepted")
	}
	signer, err := developmentSigner(c)
	if err != nil {
		t.Fatal(err)
	}
	g := &globals{state: filepath.Join(dir, "app.json")}
	if _, err := deviceKey(g, false); err == nil {
		t.Fatal("a missing device key loaded")
	}
	key, err := deviceKey(g, true)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(attestKeyPath(g)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatal(fi, err)
	}
	if again, err := deviceKey(g, false); err != nil || !again.Equal(key) {
		t.Fatal("the device key did not round-trip", err)
	}
	at := &autoattest.Attester{Key: key, CA: caCert, CAKey: ca, Package: c.AndroidPackage, Signer: signer, VersionCode: int64(c.AndroidMinVersionCode)}
	var ch [32]byte
	ch[0] = 1
	att, err := at.Attest(ch)
	if err != nil {
		t.Fatal(err)
	}
	if l.signs < 2 { // the CA certificate and the leaf
		t.Fatalf("KMS signed %d times", l.signs)
	}
	var signers []devattest.Signer
	for _, s := range c.AndroidSigners {
		signers = append(signers, devattest.Signer{Digest: s.Digest, Class: s.Class})
	}
	google := []*x509.Certificate{enclavetest.TestAndroidCA().Root.Cert} // standing in for the vendor roots
	pol := &devattest.Policy{AndroidRoots: append(google, c.AutomationRoots()...), AndroidPackage: c.AndroidPackage,
		AndroidSigners: signers, AndroidMinVersionCode: c.AndroidMinVersionCode}
	now := time.Now()
	list := enclavetest.EmptyStatusList(now)
	b, err := devattest.VerifyAttest(pol, att, ch, now, list)
	if err != nil {
		t.Fatalf("staging policy: %v", err)
	}
	if b.SignerClass != devattest.ClassDevelopment {
		t.Fatalf("class %q", b.SignerClass)
	}
	prod := *pol
	prod.AndroidRoots = google
	if _, err := devattest.VerifyAttest(&prod, att, ch, now, list); !errors.Is(err, devattest.ErrRoot) {
		t.Fatalf("vendor roots alone: %v", err)
	}
	// The unlock attester asserts with the device key only.
	unlock := &autoattest.Attester{Key: key}
	if _, err := unlock.Attest(ch); err == nil {
		t.Fatal("an attester without the CA issued a chain")
	}
	as, err := unlock.Assert(devattest.ForChallenge(ch))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := devattest.VerifyAssertion(pol, b, as, devattest.ForChallenge(ch), 0, now, list); err != nil {
		t.Fatal(err)
	}
}

// The commands refuse a production channel file, a staging file without
// an automation CA, and one past its end date.
func TestStagingChannelRefusals(t *testing.T) {
	dir := t.TempDir()
	if _, err := stagingChannel("../../enclave/releasecfg/prod.json", false, time.Now()); err == nil {
		t.Fatal("the production file was accepted")
	}
	if _, err := stagingChannel("../../enclave/releasecfg/staging.json", false, time.Now()); err != nil {
		t.Fatalf("the committed staging file for an unlock: %v", err)
	}
	if _, err := stagingChannel("../../enclave/releasecfg/staging.json", true, time.Now()); err == nil {
		t.Fatal("a staging file without an automation CA was accepted for an enrollment")
	}
	ca, err := newKMSCA(context.Background(), &localKMS{key: enclavetest.TestKey(elliptic.P256(), 0x73)}, "k")
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().UTC().AddDate(0, 0, 2)
	path, _ := stagingWithCA(t, dir, ca, until)
	if _, err := stagingChannel(path, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := stagingChannel(path, true, until.AddDate(0, 0, 1)); !errors.Is(err, releasecfg.ErrExpired) {
		t.Fatalf("past the end date: %v", err)
	}
}

// The portal session sends the account site's cookies and the CSRF
// header (MEMBER-API "Session model") with POST /api/vault/enroll-code.
func TestPortalSession(t *testing.T) {
	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(context.Background())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"secret":"AAAAAAAAAAAAAAAAAAAAAA","code":"ABCDEFGH","expires_at":"2026-10-27T00:05:00Z","api":"https://account.staging.vettid.org"}`))
	}))
	defer srv.Close()
	for _, bad := range []string{"", "token-without-name", "vid_id=x\r\nX: y"} {
		if _, err := portalSession(srv.URL, bad); err == nil {
			t.Errorf("cookie %q accepted", bad)
		}
	}
	ps, err := portalSession(srv.URL, "vid_id=a; vid_rt=b")
	if err != nil {
		t.Fatal(err)
	}
	code, err := ps.IssueEnrollCode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Method != http.MethodPost || got.URL.Path != "/api/vault/enroll-code" || got.Header.Get("Cookie") != "vid_id=a; vid_rt=b" || got.Header.Get("X-VettID-CSRF") != "1" {
		t.Fatalf("%s %s %v", got.Method, got.URL.Path, got.Header)
	}
	if _, err := stagingURL("api", code.API); err != nil {
		t.Fatal(err)
	}
}
