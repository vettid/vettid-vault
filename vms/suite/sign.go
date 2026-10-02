package suite

import (
	"crypto/ed25519"
	"errors"
)

// ErrSignature is returned when a signature does not verify.
var ErrSignature = errors.New("suite: signature verification failed")

// Sign returns Ed25519(priv, label || msg). Every signature in suite 2 is
// domain-separated by a suite-numbered label (§13.4).
func Sign(priv ed25519.PrivateKey, label string, msg []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, ErrKeySize
	}
	m := make([]byte, 0, len(label)+len(msg))
	m = append(append(m, label...), msg...)
	return ed25519.Sign(priv, m), nil
}

// Verify checks an Ed25519 signature over label || msg.
func Verify(pub ed25519.PublicKey, label string, msg, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return ErrSignature
	}
	m := make([]byte, 0, len(label)+len(msg))
	m = append(append(m, label...), msg...)
	if !ed25519.Verify(pub, m, sig) {
		return ErrSignature
	}
	return nil
}

// IdentityFromSeed derives an Ed25519 identity key from a 32-byte seed.
func IdentityFromSeed(seed []byte) (ed25519.PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, ErrKeySize
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// GenerateIdentity creates a new Ed25519 key from the library's randomness
// source.
func GenerateIdentity() (ed25519.PrivateKey, error) {
	seed := make([]byte, ed25519.SeedSize)
	defer Wipe(seed)
	if err := randRead(seed); err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// EqualPublic compares two Ed25519 public keys in constant time.
func EqualPublic(a, b ed25519.PublicKey) bool {
	return len(a) == ed25519.PublicKeySize && len(b) == ed25519.PublicKeySize && Equal(a, b)
}
