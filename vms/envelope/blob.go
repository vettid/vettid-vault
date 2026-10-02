package envelope

import (
	"crypto/sha256"

	"github.com/vettid/vettid-vault/vms/suite"
)

// Claim-check blobs (§5.5):
//
//	blob   = nonce(24) || XChaCha20-Poly1305(key, nonce, aad = "vettid/vms/2/blob", content)
//	sha256 = SHA-256(blob)    // checked in constant time before decryption
//	size   = len(content)

// BlobDecision says how content of a given size must travel.
type BlobDecision int

const (
	// Inline: send in the envelope.
	Inline BlobDecision = iota
	// BlobRecommended: over 64 KiB; the blob flow SHOULD be used.
	BlobRecommended
	// BlobRequired: would not fit in an envelope; the blob flow MUST be used.
	BlobRequired
)

// DecideBlob classifies content of n bytes whose inner plaintext JSON (with
// the content embedded) would be jsonLen bytes.
func DecideBlob(n, jsonLen int) BlobDecision {
	if _, err := PaddedLen(jsonLen); err != nil {
		return BlobRequired
	}
	if n > BlobThreshold {
		return BlobRecommended
	}
	return Inline
}

// SealBlob encrypts content under a fresh key. It returns the blob to
// upload, the key, and SHA-256(blob).
func SealBlob(content []byte) (blob, key []byte, sum [32]byte, err error) {
	key, err = suite.RandomBytes(suite.KeySize)
	if err != nil {
		return nil, nil, sum, err
	}
	nonce, err := suite.NewNonce()
	if err != nil {
		return nil, nil, sum, err
	}
	ct, err := suite.SealX(key, nonce, []byte(suite.LabelBlob), content)
	if err != nil {
		return nil, nil, sum, err
	}
	blob = append(nonce, ct...)
	return blob, key, sha256.Sum256(blob), nil
}

// OpenBlob checks SHA-256(blob) against the expected digest in constant
// time, then decrypts.
func OpenBlob(blob, key []byte, sum [32]byte) ([]byte, error) {
	got := sha256.Sum256(blob)
	if !suite.Equal(got[:], sum[:]) {
		return nil, ErrDecrypt
	}
	if len(blob) < suite.XNonceSize+suite.TagSize {
		return nil, ErrDecrypt
	}
	pt, err := suite.OpenX(key, blob[:suite.XNonceSize], []byte(suite.LabelBlob), blob[suite.XNonceSize:])
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
