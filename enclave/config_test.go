package enclave_test

import (
	"testing"

	"github.com/vettid/vettid-vault/enclave"
)

// The release device policy never carries development packages (the dev
// enclave's device policy file is the only setter).
func TestReleaseConfigNoDevPackages(t *testing.T) {
	cfg := enclave.ReleaseConfig("i-1", enclave.DefaultRelayURL)
	if cfg.DeviceAttest == nil || cfg.DeviceAttest.AndroidPackage == "" {
		t.Fatal("no Android policy")
	}
	if len(cfg.DeviceAttest.AndroidDevPackages) != 0 {
		t.Fatalf("release policy has development packages: %v", cfg.DeviceAttest.AndroidDevPackages)
	}
}
