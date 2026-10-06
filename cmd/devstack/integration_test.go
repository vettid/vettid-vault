//go:build devenclave && integration

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/envelope"
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
		"-localstack", ep, "-data", filepath.Join(dir, "data"), "-dev-device-policy", pol, "-recovery-skew", "24h"})
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

	testRecovery(t, o, info)

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

// testRecovery: a member with a credential gets a recovery code through
// POST /dev/recovery/code (the recovery clock skipped 24 h), the member
// API's recovery routes answer as vault.ts. (The no_credential refusal is
// in TestRecoveryCode: api-enroll always creates a credential.)
func testRecovery(t *testing.T, o *options, info map[string]any) {
	ctl, api := info["ctl"].(string), info["api"].(string)
	call := func(method, url, guid string, body any) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, url, rd)
		if guid != "" {
			req.Header.Set("Authorization", "Bearer "+guid)
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		return r.StatusCode, m
	}
	// A member with a credential, through vaultctl (api-enroll creates it).
	const guid = "member-recovery"
	state := filepath.Join(t.TempDir(), "member.json")
	vaultctlAs := func(state string, env []string, args ...string) string {
		t.Helper()
		cmd := exec.Command(filepath.Join(o.dataDir, "bin", "vaultctl"), append([]string{"-state", state, "-timeout", "150s"}, args...)...)
		cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "VAULTCTL_DEV_RESOLVE=" + relayHost + "=" + info["relay_tls"].(string),
			childProcs}, env...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("vaultctl %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	vaultctl := func(args ...string) string { t.Helper(); return vaultctlAs(state, nil, args...) }
	vaultctl("init", "-role", "app", "-name", "phone", "-relay", relayURL)
	vaultctl("api-enroll", "-api", api, "-guid", guid, "-pin", "13572468")
	if code, m := call("GET", api+"/api/vault/recovery", guid, nil); code != 200 || m["recovery"] != nil {
		t.Fatalf("no recovery yet: %d %v", code, m)
	}

	code, rc := call("POST", ctl+"/dev/recovery/code", "", map[string]any{"guid": guid})
	if code != 200 {
		t.Fatalf("recovery code: %d %v", code, rc)
	}
	qr, err := altchan.ParseRecoveryQR([]byte(rc["qr"].(string)))
	if err != nil || qr.Code != rc["code"] || qr.RecoveryID != rc["recovery_id"] || qr.VaultID != rc["vault_id"] {
		t.Fatalf("qr %v: %v", rc, err)
	}
	vid, rid := qr.VaultID, qr.RecoveryID
	code, m := call("GET", api+"/api/vault/recovery", guid, nil)
	rec, _ := m["recovery"].(map[string]any)
	if code != 200 || rec["state"] != "available" || rec["vault_id"] != vid || rec["recovery_id"] != rid || rec["sealed_code"] == nil {
		t.Fatalf("recovery status: %d %v", code, m)
	}
	if code, m := call("GET", api+"/api/vault/status", guid, nil); code != 200 || m["vault"].(map[string]any)["recovery"] == nil {
		t.Fatalf("vault status: %d %v", code, m)
	}
	if code, m := call("POST", api+"/api/vault/recovery", guid, map[string]any{"browser_key": base64.StdEncoding.EncodeToString(append([]byte{4}, make([]byte, 64)...))}); code != 409 || m["error"] != "recovery_active" {
		t.Fatalf("second request: %d %v", code, m)
	}

	// 0.15.0 (§11.11.7, §11.12.2): a new app claims the recovery with
	// its app key, which then signs its enclave and register requests; a
	// member session no longer reaches them.
	ck, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ckDER, _ := x509.MarshalPKIXPublicKey(&ck.PublicKey)
	scall := func(method, path, vault string, body any) (int, map[string]any) {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req, _ := http.NewRequest(method, api+path, bytes.NewReader(raw))
		nonce, _ := altchan.NewAppNonce()
		ar := &altchan.AppRequest{Method: method, Path: req.URL.EscapedPath(), Query: req.URL.RawQuery, VaultID: vault,
			KID: altchan.AppKeyID(ckDER), TS: time.Now().Unix(), Nonce: nonce, Body: raw}
		h, err := ar.Sign(ck)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(altchan.AppHeaderName, h)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		return r.StatusCode, m
	}
	if code, m := call("GET", api+"/api/vault/enclave", guid, nil); code != 401 {
		t.Fatalf("a session reached enclave: %d %v", code, m)
	}
	if code, m := scall("POST", "/api/vault/recovery/claim", vid, map[string]any{"vault_id": vid, "recovery_id": rid,
		"app_key": base64.StdEncoding.EncodeToString(ckDER)}); code != 200 || m["user_guid"] != guid {
		t.Fatalf("claim: %d %v", code, m)
	}
	// Register: routed and queued like an unlock (the envelope is opaque
	// to the API; this one is not a real request).
	code, enc := scall("GET", "/api/vault/enclave", vid, nil)
	var desc struct {
		Kid string `json:"kid"`
	}
	db, _ := base64.StdEncoding.DecodeString(fmt.Sprint(enc["descriptor"]))
	if code != 200 || json.Unmarshal(db, &desc) != nil || len(desc.Kid) != 16 {
		t.Fatalf("enclave: %d %v", code, enc)
	}
	kid, _ := hex.DecodeString(desc.Kid)
	env := make([]byte, 13444)
	copy(env, append([]byte{2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0}, kid...))
	reg := func(vaultID string) (int, map[string]any) {
		t.Helper()
		reqID, _ := envelope.NewULID(time.Now())
		return scall("POST", "/api/vault/recovery/register", vaultID, map[string]any{"vault_id": vaultID, "request_id": reqID,
			"instance_id": enc["instance_id"], "etk_kid": desc.Kid, "envelope": base64.StdEncoding.EncodeToString(env)})
	}
	if code, m := reg(strings.Repeat("0", 32)); code != 401 {
		t.Fatalf("register to another vault: %d %v", code, m)
	}
	if code, m := reg(vid); code != 202 || m["vault_id"] != vid {
		t.Fatalf("register: %d %v", code, m)
	}
	// That register was random bytes: no marker, the code stays available.
	if _, m := call("GET", api+"/api/vault/recovery", guid, nil); m["recovery"].(map[string]any)["state"] != "available" {
		t.Fatalf("after a bad register: %v", m)
	}

	// A real register by a new app (vaultctl api-recover): the enclave's
	// clear marker reaches the slot, the API records the recovery as
	// registered and stops releasing the code (0.10.6 §11.5, §11.11.7);
	// the unlock result carries credential_backup (§11.11.5 step 1).
	state2 := filepath.Join(t.TempDir(), "new-phone.json")
	vaultctlAs(state2, nil, "init", "-role", "app", "-name", "new phone", "-relay", relayURL)
	out := vaultctlAs(state2, nil, "api-recover", "-api", api, "-guid", guid, "-pin", "13572468", "-qr", rc["qr"].(string), "-attest-seed", "98")
	var rec2 map[string]any
	if err := json.Unmarshal([]byte(out[strings.Index(out, "{"):]), &rec2); err != nil || rec2["slot_code"] != "recovery_registered" ||
		rec2["credential_backup"] != true || rec2["vault_id"] != vid {
		t.Fatalf("api-recover: %v\n%s", err, out)
	}
	code, m = call("GET", api+"/api/vault/recovery", guid, nil)
	rec, _ = m["recovery"].(map[string]any)
	if code != 200 || rec["state"] != "registered" || rec["sealed_code"] != nil || rec["recovery_id"] != rid {
		t.Fatalf("after register: %d %v", code, m)
	}
	if _, m := call("GET", api+"/api/vault/status", guid, nil); m["vault"].(map[string]any)["recovery"].(map[string]any)["state"] != "registered" {
		t.Fatalf("status after register: %v", m)
	}
	if code, m := reg(vid); code != 409 || m["error"] != "recovery_not_available" {
		t.Fatalf("register after registered: %d %v", code, m)
	}
	vaultctlAs(state2, []string{"VAULTCTL_PASSWORD=development password"}, "credential", "recover")

	// Cancel: the recovery ends ({cancelled: true}, then false), register
	// is refused.
	if code, m := call("POST", api+"/api/vault/recovery/cancel", guid, map[string]any{"recovery_id": rid}); code != 200 || m["cancelled"] != true {
		t.Fatalf("cancel: %d %v", code, m)
	}
	if code, m := call("POST", api+"/api/vault/recovery/cancel", guid, map[string]any{"recovery_id": rid}); code != 200 || m["cancelled"] != false {
		t.Fatalf("second cancel: %d %v", code, m)
	}
	if _, m := call("GET", api+"/api/vault/recovery", guid, nil); m["recovery"].(map[string]any)["state"] != "cancelled" {
		t.Fatalf("after cancel: %v", m)
	}
	if code, m := reg(vid); code != 409 || m["error"] != "recovery_not_available" {
		t.Fatalf("register after cancel: %d %v", code, m)
	}

}
