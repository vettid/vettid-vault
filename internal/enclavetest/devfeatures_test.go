package enclavetest_test

import (
	"reflect"
	"testing"

	"github.com/vettid/vettid-vault/features/all"
	"github.com/vettid/vettid-vault/internal/enclavetest"
)

// The development enclave's feature list (VAULT-MESSAGING 0.26.0
// §11.10.8, "The development build"): everything by default, or the list
// its test configuration names, so that production's list (none) is run
// before a production release.
func TestDevFeatures(t *testing.T) {
	names := func(args []string) []string {
		t.Helper()
		p, err := enclavetest.DevVaultPlatform(append(enclavetest.DevVaultArgs(3, "https://relay.vettid.test"), args...))
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, f := range p.Features() {
			out = append(out, f.Name())
		}
		return out
	}
	if got := names(nil); len(got) != 16 {
		t.Fatalf("default: %v", got)
	}
	if got := enclavetest.DevVaultFeatureArgs(nil); got != nil {
		t.Fatalf("args for the default: %v", got)
	}
	prod, err := enclavetest.ParseDevFeatures("none")
	if err != nil || prod == nil || len(prod) != 0 {
		t.Fatalf("none: %v %v", prod, err)
	}
	if got := names(enclavetest.DevVaultFeatureArgs(prod)); len(got) != 8 {
		t.Fatalf("production's list: %v", got)
	}
	some, err := enclavetest.ParseDevFeatures("wallet,actions")
	if err != nil || !reflect.DeepEqual(some, []string{"actions", "wallet"}) {
		t.Fatalf("%v %v", some, err)
	}
	if got := names(enclavetest.DevVaultFeatureArgs(some)); len(got) != 10 {
		t.Fatalf("two features: %v", got)
	}
	if every, err := enclavetest.ParseDevFeatures("all"); err != nil || !reflect.DeepEqual(every, all.Optional()) {
		t.Fatalf("all: %v %v", every, err)
	}
	for _, bad := range []string{"", "audit", "calls,calls", "calls,", "teleport", "ALL"} {
		if _, err := enclavetest.ParseDevFeatures(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := enclavetest.DevVaultPlatform(append(enclavetest.DevVaultArgs(3, "https://relay.vettid.test"), "-features", "audit")); err == nil {
		t.Fatal("a vault process accepted an always-registered name")
	}
}
