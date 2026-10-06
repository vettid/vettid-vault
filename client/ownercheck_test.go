package client_test

import (
	"testing"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/vault"
)

func TestOwnerCheckTypeMatchesVault(t *testing.T) {
	if client.TypeOwnerCheck != vault.TypeOwnerCheck {
		t.Fatalf("client sends %q, the vault registers %q", client.TypeOwnerCheck, vault.TypeOwnerCheck)
	}
}
