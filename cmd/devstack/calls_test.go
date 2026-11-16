//go:build devenclave

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/callswire"
)

// The issuer stand-in's control routes, and the stand-in itself on its TLS front (calls.vettid.test, the test
// root) with the dev release's TEST attestation.
func TestCallsControl(t *testing.T) {
	s := &stack{opts: &options{}}
	defer s.close()
	s.startCalls()
	mux := http.NewServeMux()
	s.callsControl(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	spec := enclavetest.Spec(release, "")
	nsm := enclavetest.NewFakeNSM(spec.PCR0, spec.PCR1, spec.PCR2, time.Now)
	addr := s.callsTLS
	hc := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: enclavetest.TLSRoots(), ServerName: callsHost, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, n, addr)
		}, ForceAttemptHTTP2: true}}
	c := &callswire.Client{BaseURL: callsURL, HTTP: hc,
		Attest: func(pub ed25519.PublicKey, d [32]byte) ([]byte, error) { return nsm.Attest(d[:], nil, pub) }}
	a, err := c.Credentials(context.Background(), 2)
	if err != nil || len(a.Credentials) != 2 || len(a.TURN) != 2 || a.TURN[0] != "turn:"+callsHost+":3478?transport=udp" {
		t.Fatal(a, err)
	}
	requests := func() []map[string]any {
		t.Helper()
		r, err := http.Get(srv.URL + "/dev/calls")
		if err != nil || r.StatusCode != 200 {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var st struct {
			Requests []map[string]any `json:"requests"`
		}
		_ = json.NewDecoder(r.Body).Decode(&st)
		return st.Requests
	}
	rs := requests()
	if len(rs) != 1 || rs[0]["status"] != float64(200) || rs[0]["attested"] != true || len(rs[0]["usernames"].([]any)) != 2 ||
		rs[0]["usernames"].([]any)[0] != a.Credentials[0].Username {
		t.Fatalf("%v", rs)
	}
	if code, m := post(t, srv.URL+"/dev/calls/fail", `{"status":429,"code":"rate_limited","retry_after":60}`); code != 200 {
		t.Fatal(code, m)
	}
	var e *callswire.Error
	if _, err := c.Credentials(context.Background(), 1); !errors.As(err, &e) || e.Status != 429 || e.RetryAfter != 60 {
		t.Fatalf("injected failure: %v", err)
	}
	for _, bad := range []string{`{"status":200,"code":"x"}`, `{"status":429,"code":"-x"}`, `{`} {
		if code, _ := post(t, srv.URL+"/dev/calls/fail", bad); code != 400 {
			t.Fatalf("%s: %d", bad, code)
		}
	}
	post(t, srv.URL+"/dev/calls/reset", `{}`)
	if rs := requests(); len(rs) != 0 {
		t.Fatalf("after reset: %v", rs)
	}
}
