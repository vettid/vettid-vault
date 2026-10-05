//go:build devenclave

package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/altchan"
)

// fakeRecoveryAPI answers the member API's recovery routes as the stand-in
// and the enclave would: the code is sealed to the browser key, and it is
// available once the stack's recovery clock is 24 h ahead.
type fakeRecoveryAPI struct {
	s         *stack
	mu        sync.Mutex
	polls     int
	cancelled []string
	minted    time.Duration // the recovery clock offset at minting
}

const fakeVault = "0123456789abcdef0123456789abcdef"
const fakeRecovery = "01JB2Z6V9K3M4N5P6Q7R8S9T30"

func (f *fakeRecoveryAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	guid := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	switch {
	case r.Method == "POST" && r.URL.Path == "/api/vault/recovery":
		if guid == "busy" {
			writeJSON(w, 409, map[string]any{"error": "recovery_active"})
			return
		}
		bk, _ := base64.StdEncoding.DecodeString(body["browser_key"].(string))
		c := &altchan.RecoveryCode{VaultID: fakeVault, RecoveryID: fakeRecovery, Code: strings.Repeat("A", 32),
			NotBefore: time.Now().Add(24 * time.Hour), Expires: time.Now().Add(48 * time.Hour)}
		if guid == "nocred" {
			c = &altchan.RecoveryCode{VaultID: fakeVault, RecoveryID: fakeRecovery, Error: "no_credential"}
		}
		sealed, err := altchan.SealRecoveryCode(bk, c)
		if err != nil {
			writeJSON(w, 500, nil)
			return
		}
		f.minted = time.Duration(f.s.recOff.Load())
		f.polls = 0
		_ = os.WriteFile(filepath.Join(f.s.runDir, "sealed"), sealed, 0o600)
		writeJSON(w, 202, map[string]any{"recovery_id": fakeRecovery})
	case r.Method == "GET" && r.URL.Path == "/api/vault/requests/"+fakeRecovery:
		f.polls++
		if f.polls < 2 {
			writeJSON(w, 200, map[string]any{"status": "queued"})
			return
		}
		writeJSON(w, 200, map[string]any{"status": "done"})
	case r.Method == "GET" && r.URL.Path == "/api/vault/recovery":
		rec := map[string]any{"recovery_id": fakeRecovery, "vault_id": fakeVault, "state": "pending", "available_at": "2026-10-06T12:00:00.000Z"}
		if time.Duration(f.s.recOff.Load())-f.minted >= 24*time.Hour {
			b, _ := os.ReadFile(filepath.Join(f.s.runDir, "sealed"))
			rec["state"], rec["sealed_code"] = "available", base64.StdEncoding.EncodeToString(b)
		}
		writeJSON(w, 200, map[string]any{"recovery": rec})
	case r.Method == "POST" && r.URL.Path == "/api/vault/recovery/cancel":
		f.cancelled = append(f.cancelled, body["recovery_id"].(string))
		writeJSON(w, 200, map[string]any{"cancelled": true}) // 0.10.6
	default:
		writeJSON(w, 404, map[string]any{"error": "not_found"})
	}
}

func TestRecoveryCode(t *testing.T) {
	dir := t.TempDir()
	s := &stack{opts: &options{recoverySkew: 24 * time.Hour}, relayL: listener(t), apiL: listener(t), ctlL: listener(t), started: time.Now(),
		runDir: dir, recClock: filepath.Join(dir, "recovery-clock")}
	if err := s.setRecoveryOffset(0); err != nil {
		t.Fatal(err)
	}
	api := &fakeRecoveryAPI{s: s}
	go func() { _ = http.Serve(s.apiL, api) }()
	ctl := httptest.NewServer(s.control())
	defer ctl.Close()
	post := func(body string) (int, map[string]any) {
		r, err := http.Post(ctl.URL+"/dev/recovery/code", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return r.StatusCode, m
	}

	code, m := post(`{"guid":"member-1"}`)
	if code != 200 || m["code"] != strings.Repeat("A", 32) || m["vault_id"] != fakeVault || m["recovery_id"] != fakeRecovery {
		t.Fatalf("code: %d %v", code, m)
	}
	qr, err := altchan.ParseRecoveryQR([]byte(m["qr"].(string)))
	if err != nil || qr.Code != m["code"] || qr.VaultID != fakeVault {
		t.Fatalf("qr: %v", err)
	}
	// The clock moved forward once, in the API and the enclave's file.
	if b, _ := os.ReadFile(s.recClock); strings.TrimSpace(string(b)) != "24h0m0s" || time.Until(s.recoveryNow()) < 23*time.Hour {
		t.Fatalf("recovery clock: %q", b)
	}
	// Again: it moves again.
	if code, _ := post(`{"guid":"member-1"}`); code != 200 || time.Duration(s.recOff.Load()) != 48*time.Hour {
		t.Fatalf("second code: %d %v", code, time.Duration(s.recOff.Load()))
	}
	// A vault without a credential: refused, and the recovery cancelled.
	if code, m := post(`{"guid":"nocred"}`); code != 422 || m["error"] != "no_credential" || len(api.cancelled) != 1 {
		t.Fatalf("no credential: %d %v %v", code, m, api.cancelled)
	}
	// Member API refusals pass through; bad bodies are refused.
	if code, m := post(`{"guid":"busy"}`); code != 409 || m["error"] != "recovery_active" {
		t.Fatalf("busy: %d %v", code, m)
	}
	if code, _ := post(`{}`); code != 400 {
		t.Fatalf("no guid: %d", code)
	}
	// Without -recovery-skew there is nothing to play.
	s.opts.recoverySkew = 0
	if code, m := post(`{"guid":"member-1"}`); code != 409 || m["error"] != "no_recovery_skew" {
		t.Fatalf("no skew: %d %v", code, m)
	}
}
