//go:build devenclave && e2e

package e2e

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	run("request", "vault.enroll.confirm")
}
