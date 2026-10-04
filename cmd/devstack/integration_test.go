//go:build devenclave && integration

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDevStackLocalStack runs the whole stack against LocalStack (make
// integration) on ephemeral ports, with a dev device policy, and drives
// the control port and the member API.
//
//	VAULT_IT_LOCALSTACK=http://127.0.0.1:4566 go test -count=1 -tags 'devenclave integration' ./cmd/devstack/
func TestDevStackLocalStack(t *testing.T) {
	ep := os.Getenv("VAULT_IT_LOCALSTACK")
	if ep == "" {
		t.Skip("VAULT_IT_LOCALSTACK not set (make integration)")
	}
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(pol, []byte(`{"google_attestation_roots":true,"android_packages":["com.vettid.app.dev","com.vettid.app.devstack"],`+
		`"android_signers_sha256":["`+strings.Repeat("ab", 32)+`"],"grapheneos_boot_keys":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	o, err := parseFlags([]string{"-relay-port", "0", "-api-port", "0", "-ctl-port", "0", "-wait-free-mem", "0",
		"-localstack", ep, "-data", filepath.Join(dir, "data"), "-dev-device-policy", pol})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	readyc := make(chan map[string]any, 1)
	errc := make(chan error, 1)
	go func() { errc <- run(ctx, o, func(m map[string]any) { readyc <- m }) }()
	var info map[string]any
	select {
	case info = <-readyc:
	case err := <-errc:
		t.Fatalf("run: %v", err)
	case <-time.After(8 * time.Minute):
		t.Fatal("not ready")
	}
	logs := info["logs"].(string)
	defer func() {
		if t.Failed() {
			for _, f := range []string{"parent.log", "enclave.log", "relay.log"} {
				b, _ := os.ReadFile(filepath.Join(logs, f))
				t.Logf("== %s\n%s", f, b)
			}
		}
	}()
	ctl, api := info["ctl"].(string), info["api"].(string)

	get := func(url string, hdr ...string) (int, map[string]any) {
		req, _ := http.NewRequest("GET", url, nil)
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return r.StatusCode, m
	}
	if code, m := get(ctl + "/dev/trust"); code != 200 || m["device_policy"] == nil || m["nitro_root"] == "" {
		t.Fatalf("trust: %d %v", code, m)
	}
	if b, _ := os.ReadFile(filepath.Join(o.dataDir, "run", "ready.json")); !strings.Contains(string(b), `"peer_guid"`) {
		t.Fatalf("ready.json: %s", b)
	}
	// The enclave runs with the policy.
	if b, _ := os.ReadFile(filepath.Join(logs, "enclave.log")); !strings.Contains(string(b), "DEVELOPMENT device policy") {
		t.Fatalf("enclave log: %s", b)
	}
	// The peer's vault, through the member API and through vaultctl.
	if code, m := get(api+"/api/vault/status", "Authorization", "Bearer "+peerGUID); code != 200 {
		t.Fatalf("api status: %d %v", code, m)
	}
	r, err := http.Post(ctl+"/dev/peer/request", "application/json", strings.NewReader(`{"type":"vault.status"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("peer request: %d %s", r.StatusCode, b)
	}
	// The relay's plain-HTTP port answers.
	if code, _ := get(info["relay_transport"].(string) + "/healthz"); code != 200 {
		t.Fatalf("relay: %d", code)
	}

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(3 * time.Minute):
		t.Fatal("did not stop")
	}
	if code := func() int {
		c := &http.Client{Timeout: time.Second}
		r, err := c.Get(ctl + "/dev/health")
		if err != nil {
			return 0
		}
		r.Body.Close()
		return r.StatusCode
	}(); code != 0 {
		t.Fatalf("control port still up: %d", code)
	}
}
