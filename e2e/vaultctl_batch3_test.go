//go:build devenclave && e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/relaytest"
)

// V4 batch 3 through vaultctl (VAULT-PLAN V4 exit: vaultctl scripts
// exercise the types through the real relay): an agent paired with an
// initial LEASH grant reads the catalog; a grant issued later lets it read
// a named secret and is revoked again; the owner catalogs a critical
// secret, defines an action and lists grants and critical-secret uses.
func TestVaultctlBatch3(t *testing.T) {
	r := relaytest.Start(t, nil)
	dir := t.TempDir()
	bin := filepath.Join(dir, "vaultctl")
	if out, err := exec.Command("go", "build", "-tags", "devenclave", "-o", bin, "../cmd/vaultctl").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	app, agent, store := filepath.Join(dir, "app.json"), filepath.Join(dir, "agent.json"), filepath.Join(dir, "store")
	runErr := func(state string, args ...string) (string, error) {
		var out bytes.Buffer
		cmd := exec.Command(bin, append([]string{"-state", state, "-timeout", "60s"}, args...)...)
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		return out.String(), err
	}
	runAs := func(state string, args ...string) string {
		t.Helper()
		out, err := runErr(state, args...)
		if err != nil {
			t.Fatalf("vaultctl %v: %v\n%s", args, err, out)
		}
		return out
	}
	run := func(args ...string) string { t.Helper(); return runAs(app, args...) }
	poll := func(state, marker string) string {
		t.Helper()
		for range 30 {
			if out := runAs(state, "events", "-wait", "1s"); strings.Contains(out, marker) {
				return out
			}
		}
		t.Fatalf("no %s", marker)
		return ""
	}

	run("init", "-role", "app", "-name", "phone", "-relay", r.URL)
	vaultID := strings.TrimSpace(run("vault-create", "-store", store, "-relay", r.URL, "-pin", "2468", "-app", app))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vr := exec.CommandContext(ctx, bin, "vault-run", "-store", store, "-vault-id", vaultID, "-pin", "2468")
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
	t.Setenv("VAULTCTL_PASSWORD", "correct horse battery staple")
	run("credential", "create")
	run("request", "vault.enroll.confirm")

	val := filepath.Join(dir, "value")
	if err := os.WriteFile(val, []byte("hunter22"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := run("secret", "put", "-name", "wifi", "-value-file", val, "-discoverability", "cataloged")
	wifi := between(out, `"secret_id": "`, `"`)

	// Pair an agent with an initial grant and a first access session.
	runAs(agent, "init", "-role", "agent", "-name", "helper", "-relay", r.URL)
	out = run("request", "device.pair.create", `{"role":"agent"}`)
	link := between(out, `"link": "`, `"`)
	paired := make(chan error, 1)
	go func() {
		out, err := runErr(agent, "pair", "-link", link)
		if err != nil {
			err = fmt.Errorf("%v: %s", err, out)
		}
		paired <- err
	}()
	out = poll(app, "device.pair.pending")
	run("request", "device.pair.approve", `{"pairing_id":"`+between(out, `"pairing_id": "`, `"`)+`","session_seconds":600,`+
		`"grants":[{"scope":"secrets.catalog","approval":"auto"}]}`)
	if err := <-paired; err != nil {
		t.Fatal(err)
	}
	agentID := between(runAs(agent, "whoami"), `"device_id": "`, `"`)
	if out = runAs(agent, "agent", "grants"); !strings.Contains(out, `"secrets.catalog"`) {
		t.Fatalf("agent grants: %s", out)
	}
	if out = runAs(agent, "agent", "request", "-op", "catalog"); !strings.Contains(out, wifi) || strings.Contains(out, "hunter22") {
		t.Fatalf("catalog: %s", out)
	}
	if out, err := runErr(agent, "agent", "request", "-op", "secret.get", "-secret", wifi); err == nil || !strings.Contains(out, "forbidden") {
		t.Fatalf("secret.get without a grant: %v %s", err, out)
	}
	out = run("leash", "issue", "-agent", agentID, "-scope", "secrets.get", "-approval", "auto", "-secrets", wifi)
	gid := between(out, `"grant_id": "`, `"`)
	if out = runAs(agent, "agent", "request", "-op", "secret.get", "-secret", wifi); !strings.Contains(out, "hunter22") {
		t.Fatalf("secret.get: %s", out)
	}
	if out = run("leash", "list", "-agent", agentID); strings.Count(out, `"grant_id"`) != 2 {
		t.Fatalf("leash list: %s", out)
	}
	run("leash", "revoke", "-id", gid)
	if out, err := runErr(agent, "agent", "request", "-op", "secret.get", "-secret", wifi); err == nil || !strings.Contains(out, "forbidden") {
		t.Fatalf("after revoke: %v %s", err, out)
	}

	// The other batch-3 commands on one vault.
	seed := filepath.Join(dir, "seed")
	if err := os.WriteFile(seed, bytes.Repeat([]byte{7}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	out = run("credential", "secret-add", "-name", "signer", "-category", "signing_key", "-value-file", seed)
	crit := between(out, `"secret_id": "`, `"`)
	run("critical", "catalog", "-id", crit)
	if out = run("credential", "secret-list"); !strings.Contains(out, `"cataloged": true`) {
		t.Fatalf("catalog flag: %s", out)
	}
	if out = run("critical", "list"); !strings.Contains(out, `"incoming"`) {
		t.Fatalf("critical list: %s", out)
	}
	out = run("action", "define", "-name", "Lunch?", "-kind", "respond")
	if between(out, `"action_id": "`, `"`) == "" {
		t.Fatalf("action define: %s", out)
	}
	if out = run("action", "list"); !strings.Contains(out, "Lunch?") {
		t.Fatalf("action list: %s", out)
	}
	if out = run("grant", "list"); !strings.Contains(out, `"given"`) {
		t.Fatalf("grant list: %s", out)
	}
	if out = run("audit", "-kinds", "leash"); !strings.Contains(out, "leash.grant.revoked") || !strings.Contains(out, "leash.secret.read") {
		t.Fatalf("audit: %s", out)
	}
}
