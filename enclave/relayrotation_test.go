package enclave_test

import (
	"errors"
	"testing"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/vault"
)

// The vault's own relay-key rotation is unfinished: an enclave core with
// the switch on and without its test-only companion is refused.
func TestCoreRefusesRelayKeyRotation(t *testing.T) {
	_, err := enclave.NewCore(enclave.CoreDeps{Vault: vault.Options{RelayKeyRotation: true}})
	if !errors.Is(err, vault.ErrRelayKeyRotationUnfinished) {
		t.Fatalf("NewCore: %v", err)
	}
}
