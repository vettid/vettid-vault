//go:build vmsvectors

package paircode

// SealWithNonce is Seal with a given nonce, for the vectors only (the
// vmsvectors build): the vault always seals with a fresh one.
func SealWithNonce(kw, nonce []byte, purpose, r, claimID string, sc, bundle []byte) ([]byte, error) {
	return sealWithNonce(kw, nonce, purpose, r, claimID, sc, bundle)
}
