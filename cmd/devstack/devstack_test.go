//go:build devenclave

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/enclavetest"
)

func TestParseFlags(t *testing.T) {
	o, err := parseFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if o.relayPort != 18080 || o.apiPort != 18081 || o.ctlPort != 18082 || o.minFreeGB != 8 || o.localstack != "" || !strings.HasSuffix(o.dataDir, "vettid-devstack") {
		t.Fatalf("defaults: %+v", o)
	}
	o, err = parseFlags([]string{"-relay-port", "0", "-api-port", "0", "-ctl-port", "0", "-wait-free-mem", "0", "-localstack", "http://127.0.0.1:4566"})
	if err != nil || o.relayPort != 0 || o.minFreeGB != 0 {
		t.Fatalf("%+v %v", o, err)
	}
	for _, bad := range [][]string{
		{"-relay-port", "18081"},
		{"-ctl-port", "70000"},
		{"-wait-free-mem", "-1"},
		{"-localstack", "127.0.0.1:4566"},
		{"extra"},
		{"-unknown"},
	} {
		if _, err := parseFlags(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestMemAvailable(t *testing.T) {
	f := filepath.Join(t.TempDir(), "meminfo")
	_ = os.WriteFile(f, []byte("MemTotal:       32000000 kB\nMemFree:  100 kB\nMemAvailable:   9437184 kB\n"), 0o600)
	if v, err := memAvailable(f); err != nil || v != 9<<30 {
		t.Fatalf("%d %v", v, err)
	}
	_ = os.WriteFile(f, []byte("MemTotal: 1 kB\n"), 0o600)
	if _, err := memAvailable(f); err == nil {
		t.Fatal("no MemAvailable accepted")
	}
	if _, err := os.Stat("/proc/meminfo"); err == nil {
		if err := memCheck(context.Background(), 1<<20, 0); err == nil || !strings.Contains(err.Error(), "-wait-free-mem") {
			t.Fatalf("1 PB check: %v", err)
		}
	}
	if err := memCheck(context.Background(), 0, 0); err != nil {
		t.Fatal(err)
	}
}

func TestFindSource(t *testing.T) {
	src, err := findSource()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(src, "cmd", "devstack", "devstack.go")); err != nil {
		t.Fatalf("%s: %v", src, err)
	}
	if isVaultModule(t.TempDir()) {
		t.Fatal("empty dir is the module")
	}
}

func TestLockDir(t *testing.T) {
	d := t.TempDir()
	unlock, err := lockDir(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockDir(d); err == nil {
		t.Fatal("second lock")
	}
	unlock()
	unlock2, err := lockDir(d)
	if err != nil {
		t.Fatal(err)
	}
	unlock2()
}

func TestValidType(t *testing.T) {
	for _, ok := range []string{"vault.status", "connection.invite.create", "credential.unlock_ttl_seconds"} {
		if !validType(ok) {
			t.Errorf("%s refused", ok)
		}
	}
	for _, bad := range []string{"", "-op", "a b", "x;y", strings.Repeat("a", 65), "é"} {
		if validType(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func listener(t *testing.T) net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func post(t *testing.T, url, body string) (int, map[string]any) {
	t.Helper()
	r, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(r.Body).Decode(&m)
	return r.StatusCode, m
}

// The control API against a stub vaultctl.
func TestControl(t *testing.T) {
	p, err := enclavetest.ParseDevDevicePolicy([]byte(`{"android_packages":["com.vettid.app.devstack"],"grapheneos_boot_keys":true}`))
	if err != nil {
		t.Fatal(err)
	}
	s := &stack{opts: &options{}, policy: p, relayL: listener(t), apiL: listener(t), ctlL: listener(t), started: time.Now()}
	var mu sync.Mutex
	var calls [][]string
	pending := []string{
		`{"type":"connection.request","body":{"connection_id":"c1"}}` + "\n" + `{"type":"message.received","body":{"connection_id":"c2","n":2}}`,
	}
	s.vaultctlFn = func(args ...string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, args)
		switch args[0] {
		case "request":
			if args[1] == "fail.me" {
				return "boom", errors.New("exit 1")
			}
			return "sending...\n" + `{"status":"ok","type":"` + args[1] + `","body":` + args[2] + "}\n", nil
		case "events":
			if len(pending) == 0 {
				return "", nil
			}
			out := pending[0]
			pending = pending[1:]
			return out, nil
		}
		return "", errors.New("unexpected")
	}
	srv := httptest.NewServer(s.control())
	defer srv.Close()

	r, err := http.Get(srv.URL + "/dev/trust")
	if err != nil {
		t.Fatal(err)
	}
	var trust map[string]any
	_ = json.NewDecoder(r.Body).Decode(&trust)
	r.Body.Close()
	if trust["nitro_root"] == "" || len(trust["manifest_keys"].([]any)) != 1 || trust["relay_url"] != relayURL {
		t.Fatalf("trust: %v", trust)
	}
	if dp, _ := trust["device_policy"].(map[string]any); dp == nil || dp["grapheneos_boot_keys"] != true {
		t.Fatalf("trust device policy: %v", trust["device_policy"])
	}
	r, err = http.Get(srv.URL + "/dev/info")
	if err != nil {
		t.Fatal(err)
	}
	var info map[string]any
	_ = json.NewDecoder(r.Body).Decode(&info)
	r.Body.Close()
	if info["peer_guid"] != peerGUID || !strings.HasPrefix(info["api"].(string), "http://127.0.0.1:") {
		t.Fatalf("info: %v", info)
	}

	code, m := post(t, srv.URL+"/dev/peer/request", `{"type":"vault.status","body":{"a":1}}`)
	if code != 200 || m["type"] != "vault.status" || m["body"].(map[string]any)["a"] != float64(1) {
		t.Fatalf("%d %v", code, m)
	}
	code, m = post(t, srv.URL+"/dev/peer/request", `{"type":"vault.status"}`)
	if code != 200 || len(m["body"].(map[string]any)) != 0 {
		t.Fatalf("no body: %d %v", code, m)
	}
	if code, _ := post(t, srv.URL+"/dev/peer/request", `{"type":"fail.me"}`); code != 502 {
		t.Fatalf("vaultctl failure: %d", code)
	}
	for _, bad := range []string{`{"type":"-op"}`, `{}`, `{"type":"vault.status","body":[1]}`, `nope`} {
		if code, _ := post(t, srv.URL+"/dev/peer/request", bad); code != 400 {
			t.Fatalf("%s: %d", bad, code)
		}
	}

	// The second event is kept while the first is returned.
	code, m = post(t, srv.URL+"/dev/peer/event", `{"type":"message.received","match":{"n":"2"},"timeout_s":10}`)
	if code != 200 || m["body"].(map[string]any)["connection_id"] != "c2" {
		t.Fatalf("event: %d %v", code, m)
	}
	code, m = post(t, srv.URL+"/dev/peer/event", `{"type":"connection.request","timeout_s":10}`)
	if code != 200 || m["body"].(map[string]any)["connection_id"] != "c1" {
		t.Fatalf("kept event: %d %v", code, m)
	}
	code, _ = post(t, srv.URL+"/dev/peer/event", `{"type":"connection.request","timeout_s":1}`)
	if code != 404 {
		t.Fatalf("timeout: %d", code)
	}
	mu.Lock()
	for _, c := range calls {
		if c[0] == "request" && c[1] == "-op" {
			t.Fatal("dash type reached vaultctl")
		}
	}
	mu.Unlock()
}

func TestLogged(t *testing.T) {
	h := logged("x", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
		http.NewResponseController(w).Flush()
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/a", bytes.NewReader(nil)))
	if rec.Code != 204 || !rec.Flushed {
		t.Fatalf("%d %v", rec.Code, rec.Flushed)
	}
}
