package suite

import (
	"golang.org/x/crypto/chacha20poly1305"
)

// RandomBytes returns n bytes from the library's randomness source.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if err := randRead(b); err != nil {
		return nil, err
	}
	return b, nil
}

// NewNonce returns a fresh random 192-bit XChaCha20-Poly1305 nonce (§4.2).
func NewNonce() ([]byte, error) { return RandomBytes(XNonceSize) }

// SealX encrypts with XChaCha20-Poly1305 (session mode, bundles, blobs).
// The returned slice is the ciphertext with the 16-byte tag appended.
func SealX(key, nonce, aad, plaintext []byte) ([]byte, error) {
	if len(key) != KeySize || len(nonce) != XNonceSize {
		return nil, ErrKeySize
	}
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrKeySize
	}
	return a.Seal(nil, nonce, plaintext, aad), nil
}

// OpenX decrypts with XChaCha20-Poly1305. The tag is checked in constant
// time by the AEAD.
func OpenX(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	if len(key) != KeySize || len(nonce) != XNonceSize {
		return nil, ErrKeySize
	}
	if len(ciphertext) < TagSize {
		return nil, ErrDecrypt
	}
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrKeySize
	}
	pt, err := a.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
