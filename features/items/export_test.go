package items

import (
	"github.com/vettid/vettid-vault/features/credential"
	"github.com/vettid/vettid-vault/features/itemspec"
)

// OpenSealed decrypts a critical item's ciphertext with a credential
// entry (tests of the envelope encryption).
func OpenSealed(vaultID string, it *itemspec.Item, e *credential.Item) ([]byte, error) {
	return open(vaultID, it, e)
}
