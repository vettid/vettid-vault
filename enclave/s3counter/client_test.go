package s3counter_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave/awskms"
	"github.com/vettid/vettid-vault/enclave/s3counter"
	"github.com/vettid/vettid-vault/internal/countertest"
	"github.com/vettid/vettid-vault/vault/counter"
	"github.com/vettid/vettid-vault/vms/recovery"
)

type creds struct{}

func (creds) Credentials(context.Context, bool) (awskms.Credentials, error) {
	return awskms.Credentials{AccessKeyID: "AKIDTEST", SecretAccessKey: "secret", SessionToken: "tok"}, nil
}

func setup(t *testing.T) (*countertest.Bucket, *s3counter.Client, *[]*http.Request) {
	t0 := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	b := countertest.New(t0)
	var seen []*http.Request
	h := b.Handler("111122223333")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Clone(context.Background()))
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	c := &s3counter.Client{HTTP: &http.Client{CheckRedirect: s3counter.NoRedirect}, Bucket: "vettid-org-vault-recovery-111122223333",
		Account: "111122223333", Region: "us-east-1", Creds: creds{}, Endpoint: srv.URL, Now: b.Now}
	return b, c, &seen
}

func TestCounterOverHTTP(t *testing.T) {
	ctx := context.Background()
	b, cl, seen := setup(t)
	n, _ := recovery.NewNames(bytes.Repeat([]byte{0x51}, 32), "test-vault-0001")
	c := counter.New(cl, n, 10*time.Minute)
	if _, err := c.MarkPresent(ctx); err != nil {
		t.Fatal(err)
	}
	b.Advance(73 * time.Hour)
	for k := 1; k <= 3; k++ {
		v, err := c.Status(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		if k == 3 {
			if vd, _ := counter.FirstLook(v, 72*time.Hour); vd != counter.VerdictWait {
				t.Fatalf("attempt 3 before its wait: %s", vd)
			}
			b.Advance(10 * time.Minute)
			v, _ = c.Status(ctx, 1)
		}
		r := c.Spend(ctx, 1, v.Next())
		if r.Outcome != counter.Spent || r.Used != k {
			t.Fatalf("attempt %d: %+v", k, r)
		}
	}
	// More entries than a page: the listing follows the markers.
	for i := 0; i < 10; i++ {
		b.InsertVersion(n.Present(), b.Now().Add(-200*time.Hour), b.Now().Add(time.Hour))
	}
	v, err := c.Status(ctx, 1)
	if err != nil || v.Used != 3 || v.PresentAt.IsZero() {
		t.Fatalf("%+v %v", v, err)
	}
	for _, r := range *seen {
		if r.Host != "vettid-org-vault-recovery-111122223333.s3.us-east-1.amazonaws.com" {
			t.Fatalf("host %q", r.Host)
		}
		a := r.Header.Get("Authorization")
		if !strings.Contains(a, "/us-east-1/s3/aws4_request") || !strings.Contains(a, "x-amz-expected-bucket-owner") {
			t.Fatalf("authorization %q", a)
		}
		if r.Method == http.MethodDelete {
			t.Fatal("the client deleted something")
		}
	}
	if _, err := cl.List(ctx, "other/"); err == nil {
		t.Fatal("a key outside recovery/v1/")
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	cl := &s3counter.Client{HTTP: &http.Client{CheckRedirect: s3counter.NoRedirect}, Bucket: "b", Account: "111122223333", Region: "us-east-1",
		Creds: creds{}, Endpoint: srv.URL}
	if _, err := cl.List(context.Background(), "recovery/v1/x/"); err == nil {
		t.Fatal("a redirect was followed or accepted")
	}
}
