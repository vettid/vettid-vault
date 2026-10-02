//go:build devenclave

// Package devenclave is development and test support that release builds
// cannot compile in: every file carries the `devenclave` build tag, so any
// release package that imported it would fail to build (`make check-tcb`
// also verifies no release package depends on it).
//
// It provides a sealer keyed by a caller-supplied key instead of
// KMS-under-attestation, and constructors that create and unlock a vault
// directly with a PIN, standing in for the alternate channel (§11, phase
// V3).
package devenclave

import (
	"context"
	"errors"

	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Sealer is the development sealer: XChaCha20-Poly1305 under a fixed key.
// It provides none of the guarantees of a real enclave sealer.
type Sealer struct {
	key []byte
}

// NewSealer returns a dev sealer for a 32-byte key.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, errors.New("devenclave: sealer key must be 32 bytes")
	}
	return &Sealer{key: append([]byte(nil), key...)}, nil
}

const sealAAD = "vettid/dev-sealer\x00"

// Seal implements vault.Sealer.
func (s *Sealer) Seal(_ context.Context, pt, aad []byte) ([]byte, error) {
	n, err := suite.NewNonce()
	if err != nil {
		return nil, err
	}
	ct, err := suite.SealX(s.key, n, append([]byte(sealAAD), aad...), pt)
	if err != nil {
		return nil, err
	}
	return append(n, ct...), nil
}

// Unseal implements vault.Sealer.
func (s *Sealer) Unseal(_ context.Context, b, aad []byte) ([]byte, error) {
	if len(b) < suite.XNonceSize+suite.TagSize {
		return nil, errors.New("devenclave: sealed blob too short")
	}
	return suite.OpenX(s.key, b[:suite.XNonceSize], append([]byte(sealAAD), aad...), b[suite.XNonceSize:])
}

var _ vault.Sealer = (*Sealer)(nil)

// Release is the release name dev vaults are sealed to. It is not a PCR0:
// dev vaults never run in a real enclave.
var Release = vault.Release{PCR0: "dev", Number: 1}

// Create creates and unlocks a vault directly with a PIN (dev only). It
// fills in the KDF parameters with the minimum allowed (fast tests) unless
// set.
func Create(ctx context.Context, p vault.CreateParams) (*vault.Manager, error) {
	if p.Release.PCR0 == "" {
		p.Release = Release
	}
	if p.KDF.Alg == "" {
		k, err := vault.MinKDF()
		if err != nil {
			return nil, err
		}
		p.KDF = k
	}
	return vault.Create(ctx, p)
}

// Unlock unlocks a vault directly with a PIN (dev only).
func Unlock(ctx context.Context, p vault.UnlockParams) (*vault.Manager, vault.UnlockResult, error) {
	if p.Release.PCR0 == "" {
		p.Release = Release
	}
	return vault.Unlock(ctx, p)
}
