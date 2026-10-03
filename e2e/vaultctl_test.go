//go:build devenclave && e2e

package e2e

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/relaytest"
)

// vaultctl drives a dev vault end to end: init an app, create a vault that
// enrolls it, run the vault, finish enrollment, and query status.
func TestVaultctlSmoke(t *testing.T) {
	r := relaytest.Start(t, nil)
	dir := t.TempDir()
	bin := filepath.Join(dir, "vaultctl")
	build := exec.Command("go", "build", "-tags", "devenclave", "-o", bin, "../cmd/vaultctl")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	app := filepath.Join(dir, "app.json")
	store := filepath.Join(dir, "store")
	run := func(args ...string) string {
		t.Helper()
		var out bytes.Buffer
		cmd := exec.Command(bin, append([]string{"-state", app, "-timeout", "60s"}, args...)...)
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err != nil {
			t.Fatalf("vaultctl %v: %v\n%s", args, err, out.String())
		}
		return out.String()
	}
	run("init", "-role", "app", "-name", "phone", "-relay", r.URL)
	vaultID := strings.TrimSpace(run("vault-create", "-store", store, "-relay", r.URL, "-pin", "2468", "-app", app))
	if len(vaultID) != 32 {
		t.Fatalf("vault id %q", vaultID)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vr := exec.CommandContext(ctx, bin, "vault-run", "-store", store, "-vault-id", vaultID, "-pin", "2468", "-ws")
	var vlog bytes.Buffer
	vr.Stdout, vr.Stderr = &vlog, &vlog
	if err := vr.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = vr.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = vr.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			cancel()
		}
		if t.Failed() {
			t.Logf("vault-run output:\n%s", vlog.String())
		}
	}()
	run("enroll-wait")
	out := run("request", "vault.status", "{}")
	if !strings.Contains(out, `"status": "ok"`) || !strings.Contains(out, vaultID) {
		t.Fatalf("status: %s", out)
	}
	// A vault is used only with a credential (§3.5.7).
	t.Setenv("VAULTCTL_PASSWORD", "correct horse battery staple")
	if out = run("request", "vault.enroll.confirm"); !strings.Contains(out, "credential_required") {
		t.Fatalf("confirm without a credential: %s", out)
	}
	run("credential", "create")
	run("request", "vault.enroll.confirm")

	// V4 batch 1 (§10.6–§10.9) through vaultctl's feature commands.
	val := filepath.Join(dir, "value")
	if err := os.WriteFile(val, []byte("seed words here"), 0o600); err != nil {
		t.Fatal(err)
	}
	out = run("credential", "secret-add", "-name", "seed", "-category", "seed_phrase", "-value-file", val)
	id := between(out, `"secret_id": "`, `"`)
	if out = run("credential", "secret-get", "-id", id); !strings.Contains(out, "seed words here") {
		t.Fatalf("critical secret: %s", out)
	}
	if out = run("credential", "secret-list"); !strings.Contains(out, `"seed"`) || strings.Contains(out, "seed words") {
		t.Fatalf("critical list: %s", out)
	}
	out = run("secret", "put", "-name", "wifi", "-value-file", val)
	sid := between(out, `"secret_id": "`, `"`)
	if out = run("secret", "get", "-id", sid); !strings.Contains(out, "seed words here") {
		t.Fatalf("secret: %s", out)
	}
	run("profile", "set", `{"version":0,"name":"Phone Owner","set":{"contact.email":{"value":"o@example.org"}},"shared":["contact.email"]}`)
	if out = run("profile", "get"); !strings.Contains(out, "o@example.org") {
		t.Fatalf("profile: %s", out)
	}
	run("settings", "set", "0", `{"app.theme":"dark","feed.retention_days":14}`)
	if out = run("settings", "get"); !strings.Contains(out, `"app.theme": "dark"`) {
		t.Fatalf("settings: %s", out)
	}
	if out = run("audit", "-kinds", "credential"); !strings.Contains(out, "credential.secret.read") {
		t.Fatalf("audit: %s", out)
	}
	run("feed", "guides", "-guides", `[{"guide_id":"welcome","version":1,"title":"Welcome","message":"Hi"}]`)
	if out = run("feed", "list"); !strings.Contains(out, `"guide"`) || !strings.Contains(out, "credential.secret.read") {
		t.Fatalf("feed: %s", out)
	}
}

// between returns the text between the first a and the next b.
func between(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	s = s[i+len(a):]
	if j := strings.Index(s, b); j >= 0 {
		return s[:j]
	}
	return ""
}

// vaultctl drives the alternate channel through an in-process enclave:
// enroll an app, unlock and run the vault, query it, approve a release
// move and unlock under the new release.
func TestVaultctlAltchan(t *testing.T) {
	r := relaytest.Start(t, nil)
	dir := t.TempDir()
	bin := filepath.Join(dir, "vaultctl")
	build := exec.Command("go", "build", "-tags", "devenclave", "-o", bin, "../cmd/vaultctl")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	app := filepath.Join(dir, "app.json")
	st := filepath.Join(dir, "store")
	run := func(args ...string) string {
		t.Helper()
		var out bytes.Buffer
		cmd := exec.Command(bin, append([]string{"-state", app, "-timeout", "90s"}, args...)...)
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err != nil {
			t.Fatalf("vaultctl %v: %v\n%s", args, err, out.String())
		}
		return out.String()
	}
	common := []string{"-store", st, "-relay", r.URL, "-guid", "member-1", "-pin", "13579", "-platform", "ios"}
	run("init", "-role", "app", "-name", "phone", "-relay", r.URL)
	vid := strings.TrimSpace(run(append([]string{"altchan-enroll"}, common...)...))
	if len(vid) != 32 {
		t.Fatalf("vault id %q", vid)
	}
	runVault := func(extra ...string) (stop func()) {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		cmd := exec.CommandContext(ctx, bin, append(append([]string{"-state", app, "-timeout", "120s", "altchan-unlock"}, common...), extra...)...)
		out := &syncBuffer{}
		cmd.Stdout, cmd.Stderr = out, out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(60 * time.Second)
		for !strings.Contains(out.String(), "running until interrupted") {
			if time.Now().After(deadline) {
				cancel()
				t.Fatalf("altchan-unlock did not start:\n%s", out.String())
			}
			time.Sleep(100 * time.Millisecond)
		}
		return func() {
			_ = cmd.Process.Signal(os.Interrupt)
			done := make(chan struct{})
			go func() { _ = cmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(15 * time.Second):
				cancel()
			}
			if t.Failed() {
				t.Logf("altchan-unlock output:\n%s", out.String())
			}
		}
	}
	stop := runVault()
	out := run("request", "vault.status", "{}")
	if !strings.Contains(out, `"status": "ok"`) || !strings.Contains(out, vid) {
		t.Fatalf("status: %s", out)
	}
	stop()
	// Approve release 4: the vault moves and locks.
	out = run(append(append([]string{"altchan-unlock"}, common...), "-releases", "3,4", "-approve", "4")...)
	if !strings.Contains(out, `"result": "moved"`) {
		t.Fatalf("move: %s", out)
	}
	stop = runVault("-releases", "3,4")
	defer stop()
	out = run("request", "vault.status", "{}")
	if !strings.Contains(out, `"status": "ok"`) {
		t.Fatalf("status under release 4: %s", out)
	}
}

// syncBuffer is a bytes.Buffer safe for a writing process and a reader.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
