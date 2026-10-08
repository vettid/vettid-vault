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

// SetKeptHook sees the stored values a critical replacement opens for its
// kept values (0.21.0), before they are wiped; nil removes it.
func SetKeptHook(h func(fields map[string][]byte)) {
	if h == nil {
		testHookKept = nil
		return
	}
	testHookKept = func(v *Values) {
		m := map[string][]byte{}
		for id, x := range v.Fields {
			m[id] = x
		}
		h(m)
	}
}
