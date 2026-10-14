//go:build devenclave

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/pushwire"
)

// The push stand-in's control routes, and the stand-in itself on its TLS
// front (push.vettid.test, the test root) with the dev release's TEST
// attestation.
func TestPushControl(t *testing.T) {
	s := &stack{opts: &options{}}
	defer s.close()
	s.startPush()
	mux := http.NewServeMux()
	s.pushControl(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	spec := enclavetest.Spec(release, "")
	nsm := enclavetest.NewFakeNSM(spec.PCR0, spec.PCR1, spec.PCR2, time.Now)
	addr := s.pushTLS
	hc := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: enclavetest.TLSRoots(), ServerName: pushHost, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, n, addr)
		}, ForceAttemptHTTP2: true}}
	c := &pushwire.Client{BaseURL: pushURL, HTTP: hc,
		Attest: func(pub ed25519.PublicKey, d [32]byte) ([]byte, error) { return nsm.Attest(d[:], nil, pub) }}
	_, k, _ := ed25519.GenerateKey(nil)
	pending, err := c.Register(context.Background(), k, pushwire.Registration{Platform: "fcm", Token: "t", AppID: "com.vettid.app"})
	if err != nil {
		t.Fatal(err)
	}
	// PUSH-GATEWAY 0.5.0: the challenge's code, as the app would get it.
	r0, err := http.Get(srv.URL + "/dev/push")
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Challenges []struct {
			Code string `json:"code"`
		} `json:"challenges"`
	}
	_ = json.NewDecoder(r0.Body).Decode(&st)
	r0.Body.Close()
	if len(st.Challenges) != 1 || st.Challenges[0].Code != s.push.LastCode() {
		t.Fatalf("challenges %+v", st)
	}
	blob, err := c.Confirm(context.Background(), k, pending, st.Challenges[0].Code)
	if err != nil {
		t.Fatal(err)
	}
	if code, m := post(t, srv.URL+"/dev/push/fail", `{"status":410,"code":"token_gone"}`); code != 200 {
		t.Fatal(code, m)
	}
	if _, err := c.Wake(context.Background(), k, blob); err == nil {
		t.Fatal("injected failure not answered")
	}
	if _, err := c.Wake(context.Background(), k, blob); err != nil {
		t.Fatal(err)
	}
	code, m := post(t, srv.URL+"/dev/push/wait", `{"wakes":1,"timeout_s":5}`)
	if code != 200 || m["registrations"] != float64(1) || len(m["wakes"].([]any)) != 1 {
		t.Fatal(code, m)
	}
	for _, bad := range []string{`{"status":200,"code":"x"}`, `{"status":410,"code":"-x"}`, `{`} {
		if code, _ := post(t, srv.URL+"/dev/push/fail", bad); code != 400 {
			t.Fatalf("%s: %d", bad, code)
		}
	}
	post(t, srv.URL+"/dev/push/reset", `{}`)
	if code, _ := post(t, srv.URL+"/dev/push/wait", `{"wakes":1,"timeout_s":1}`); code != 404 {
		t.Fatal("wait after reset")
	}
	r, err := http.Get(srv.URL + "/dev/push")
	if err != nil || r.StatusCode != 200 {
		t.Fatal(err)
	}
	r.Body.Close()
}
