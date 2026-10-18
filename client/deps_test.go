package client

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNoBitcoinDeps checks that importing client does not compile the
// Bitcoin libraries: they belong to client/wallet (and vms/btc) only, so
// that a program using client without the wallet does not carry them.
func TestNoBitcoinDeps(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go command not found: %v", err)
	}
	out, err := exec.Command(gobin, "list", "-deps", "github.com/vettid/vettid-vault/client").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	deps := strings.Fields(string(out))
	if len(deps) == 0 {
		t.Fatal("go list -deps printed nothing")
	}
	for _, p := range deps {
		if strings.HasPrefix(p, "github.com/btcsuite/") || strings.HasPrefix(p, "github.com/decred/") ||
			p == "github.com/vettid/vettid-vault/vms/btc" || p == "github.com/vettid/vettid-vault/client/wallet" {
			t.Errorf("client depends on %s", p)
		}
	}
}

// TestWalletDeps checks the test above can fail: client/wallet does
// depend on the Bitcoin libraries.
func TestWalletDeps(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go command not found: %v", err)
	}
	out, err := exec.Command(gobin, "list", "-deps", "github.com/vettid/vettid-vault/client/wallet").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	var btcsuite, decred bool
	for _, p := range strings.Fields(string(out)) {
		btcsuite = btcsuite || strings.HasPrefix(p, "github.com/btcsuite/")
		decred = decred || strings.HasPrefix(p, "github.com/decred/")
	}
	if !btcsuite || !decred {
		t.Errorf("client/wallet: btcsuite %v, decred %v; want both", btcsuite, decred)
	}
}
