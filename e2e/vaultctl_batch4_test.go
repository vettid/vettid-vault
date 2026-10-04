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

// V4 batch 4 through vaultctl (VAULT-PLAN V4 exit): the wallet on
// regtest (create with an imported phrase, an address, a synthetic PSBT
// inspected, refused outside the unlock window and signed), and the
// location and presence commands on one vault.
func TestVaultctlBatch4(t *testing.T) {
	r := relaytest.Start(t, nil)
	dir := t.TempDir()
	bin := filepath.Join(dir, "vaultctl")
	if out, err := exec.Command("go", "build", "-tags", "devenclave", "-o", bin, "../cmd/vaultctl").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	app, store := filepath.Join(dir, "app.json"), filepath.Join(dir, "store")
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

	run("init", "-role", "app", "-name", "phone", "-relay", r.URL)
	vaultID := strings.TrimSpace(run("vault-create", "-store", store, "-relay", r.URL, "-pin", "246802", "-app", app))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vr := exec.CommandContext(ctx, bin, "vault-run", "-store", store, "-vault-id", vaultID, "-pin", "246802")
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

	// The wallet on regtest: an imported phrase as a critical item, a
	// receive address, a synthetic PSBT inspected and signed.
	t.Setenv("VAULTCTL_MNEMONIC", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	out := run("wallet", "create", "-name", "Savings", "-network", "regtest", "-import", "-tags", "money")
	wid := between(out, `"wallet_id": "`, `"`)
	if !strings.Contains(out, `"fingerprint": "73c5da0a"`) || strings.Contains(out, "abandon") {
		t.Fatalf("create: %s", out)
	}
	if out = run("wallet", "list"); !strings.Contains(out, wid) {
		t.Fatalf("list: %s", out)
	}
	out = run("wallet", "address", "-wallet", wid, "-label", "shop")
	if !strings.Contains(out, `"address": "bcrt1p`) || !strings.Contains(out, `"type": "p2tr"`) {
		t.Fatalf("address: %s", out)
	}
	psbt := filepath.Join(dir, "spend.psbt")
	run("wallet", "test-psbt", "-wallet", wid, "-to", "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "-amount", "300000", "-out", psbt)
	if out = run("wallet", "inspect", "-wallet", wid, "-psbt", psbt); !strings.Contains(out, `"fee_sats": 1000`) || !strings.Contains(out, `"sending_sats": 300000`) {
		t.Fatalf("inspect: %s", out)
	}
	if out, err := runErr(app, "wallet", "sign", "-wallet", wid, "-psbt", psbt); err == nil || !strings.Contains(out, "credential_locked") {
		t.Fatalf("sign outside the unlock window: %v %s", err, out)
	}
	run("credential", "unlock")
	if out = run("wallet", "sign", "-wallet", wid, "-psbt", psbt); !strings.Contains(out, `"tx": "02000000`) {
		t.Fatalf("sign: %s", out)
	}
	if out = run("wallet", "history", "-wallet", wid); !strings.Contains(out, `"sending_sats": 300000`) {
		t.Fatalf("history: %s", out)
	}
	if out = run("item", "get", "-id", wid); !strings.Contains(out, `"crypto_wallet"`) || strings.Contains(out, "abandon") {
		t.Fatalf("item: %s", out)
	}

	// Location and presence without connections: listings and policy.
	if out = run("location", "list"); !strings.Contains(out, `"outgoing"`) {
		t.Fatalf("location list: %s", out)
	}
	if out = run("presence", "get"); !strings.Contains(out, `"share": "all"`) {
		t.Fatalf("presence get: %s", out)
	}
	if out = run("presence", "set", "-version", "0", "-state", "busy"); !strings.Contains(out, `"version": 1`) {
		t.Fatalf("presence set: %s", out)
	}
	if out = run("audit", "-kinds", "wallet"); !strings.Contains(out, "wallet.signed") {
		t.Fatalf("audit: %s", out)
	}
}
