package awskms_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave/awskms"
	"github.com/vettid/vettid-vault/enclave/cms"
	"github.com/vettid/vettid-vault/enclave/egress"
	"github.com/vettid/vettid-vault/internal/enclavetest"
)

type staticCreds struct {
	c     awskms.Credentials
	calls int
	next  *awskms.Credentials
}

func (s *staticCreds) Credentials(_ context.Context, refresh bool) (awskms.Credentials, error) {
	s.calls++
	if refresh && s.next != nil {
		s.c = *s.next
	}
	return s.c, nil
}

const host = "kms.us-east-1.amazonaws.com"

func setup(t *testing.T, creds ...awskms.Credentials) (*enclavetest.KMSServer, *http.Client) {
	fk := enclavetest.NewFakeKMS("client-test", enclavetest.TestNitroCA().Roots(), nil)
	fk.AddKey(enclavetest.KeyARN(3), enclavetest.GoodPolicy(enclavetest.PCRHex(0xa3), []string{enclavetest.PCRHex(0xa3)}))
	srv := enclavetest.NewKMSServer(fk, "us-east-1", creds...)
	hs := httptest.NewUnstartedServer(srv)
	hs.TLS = &tls.Config{Certificates: []tls.Certificate{enclavetest.ServerCert(host)}}
	hs.StartTLS()
	t.Cleanup(hs.Close)
	addr := hs.Listener.Addr().String()
	tr, err := egress.New(egress.Config{Hosts: []egress.Host{{Name: host, Roots: enclavetest.TLSRoots()}},
		Dialer: egress.DialerFunc(func(ctx context.Context, h string, _ uint16) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		})})
	if err != nil {
		t.Fatal(err)
	}
	return srv, tr.Client(30 * time.Second)
}

func TestRecipientRoundTrip(t *testing.T) {
	good := awskms.Credentials{AccessKeyID: "ASIATEST", SecretAccessKey: "secret", SessionToken: "token", Expires: time.Now().Add(time.Hour)}
	srv, hc := setup(t, good)
	c := awskms.NewClient(hc, "us-east-1", &staticCreds{c: good})
	ctx := context.Background()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	nsm := enclavetest.NewFakeNSM(0xa3, 0x13, 0x23, nil)
	att, _ := nsm.Attest(nil, nil, der)
	arn := enclavetest.KeyARN(3)
	blob, cfr, err := c.GenerateDataKey(ctx, arn, att)
	if err != nil {
		t.Fatal(err)
	}
	dk, err := cms.Unwrap(cfr, key)
	if err != nil || len(dk) != 32 {
		t.Fatalf("unwrap: %v", err)
	}
	cfr2, err := c.Decrypt(ctx, arn, blob, att)
	if err != nil {
		t.Fatal(err)
	}
	dk2, err := cms.Unwrap(cfr2, key)
	if err != nil || string(dk2) != string(dk) {
		t.Fatal("decrypt returned another key")
	}
	for _, f := range []func(context.Context, string) ([]byte, error){c.DescribeKey, c.GetKeyPolicy, c.ListGrants} {
		if b, err := f(ctx, arn); err != nil || len(b) == 0 {
			t.Fatalf("read: %v", err)
		}
	}
	if srv.Calls("ListGrants") != 1 {
		t.Fatal("calls")
	}
	// Another release's attestation is refused by the key policy.
	other, _ := enclavetest.NewFakeNSM(0xa4, 0x14, 0x24, nil).Attest(nil, nil, der)
	var ae *awskms.APIError
	if _, err := c.Decrypt(ctx, arn, blob, other); !errors.As(err, &ae) || ae.Type != "AccessDeniedException" {
		t.Fatalf("policy: %v", err)
	}
	if _, err := c.DescribeKey(ctx, enclavetest.KeyARN(9)); !errors.As(err, &ae) || ae.Type != "NotFoundException" {
		t.Fatalf("not found: %v", err)
	}
}

func TestCredentialRefresh(t *testing.T) {
	good := awskms.Credentials{AccessKeyID: "ASIAGOOD", SecretAccessKey: "s1", SessionToken: "t1"}
	_, hc := setup(t, good)
	stale := &staticCreds{c: awskms.Credentials{AccessKeyID: "ASIAOLD", SecretAccessKey: "s0", SessionToken: "t0"}, next: &good}
	c := awskms.NewClient(hc, "us-east-1", stale)
	if _, err := c.DescribeKey(context.Background(), enclavetest.KeyARN(3)); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	bad := &staticCreds{c: awskms.Credentials{AccessKeyID: "ASIAOLD", SecretAccessKey: "s0"}}
	var ae *awskms.APIError
	if _, err := awskms.NewClient(hc, "us-east-1", bad).DescribeKey(context.Background(), enclavetest.KeyARN(3)); !errors.As(err, &ae) || ae.Type != "InvalidSignatureException" {
		t.Fatalf("bad creds: %v", err)
	}
	expired := &staticCreds{c: awskms.Credentials{AccessKeyID: "A", SecretAccessKey: "s", Expires: time.Now().Add(-time.Minute)}}
	if _, err := awskms.NewClient(hc, "us-east-1", expired).DescribeKey(context.Background(), enclavetest.KeyARN(3)); !errors.Is(err, awskms.ErrNoCreds) {
		t.Fatalf("expired creds: %v", err)
	}
}

// A response carrying Plaintext (no Recipient protection) is refused.
func TestPlaintextRefused(t *testing.T) {
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"CiphertextBlob":"AQ==","CiphertextForRecipient":"AQ==","Plaintext":"AAAA","KeyId":"k"}`))
	}))
	defer hs.Close()
	c := &awskms.Client{HTTP: hs.Client(), Region: "us-east-1", Endpoint: hs.URL, Creds: &staticCreds{c: awskms.Credentials{AccessKeyID: "a", SecretAccessKey: "b"}}}
	if _, _, err := c.GenerateDataKey(context.Background(), "k", []byte{1}); !errors.Is(err, awskms.ErrResponse) {
		t.Fatalf("plaintext: %v", err)
	}
}
