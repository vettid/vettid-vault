package manifesttool

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSAPI is the part of the KMS client the signer uses.
type KMSAPI interface {
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(ctx context.Context, in *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error)
}

// KMSSigner signs with an AWS KMS key (manifest key A, VAULT-RELEASES
// §6.1): an ECC_NIST_P256 SIGN_VERIFY key, ECDSA_SHA_256 over the
// precomputed digest (MessageType DIGEST). The caller's credentials must
// be allowed kms:Sign and kms:GetPublicKey (the manifest-signer role).
type KMSSigner struct {
	API   KMSAPI
	KeyID string
}

// Public implements Signer: the key's public key, after checking its
// spec and usage.
func (k KMSSigner) Public(ctx context.Context) (*ecdsa.PublicKey, error) {
	out, err := k.API.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(k.KeyID)})
	if err != nil {
		return nil, fmt.Errorf("kms GetPublicKey: %w", err)
	}
	if out.KeySpec != kmstypes.KeySpecEccNistP256 || out.KeyUsage != kmstypes.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("kms key %s is %s/%s, not ECC_NIST_P256/SIGN_VERIFY", k.KeyID, out.KeySpec, out.KeyUsage)
	}
	return ParsePublicKey(out.PublicKey)
}

// SignDigest implements Signer.
func (k KMSSigner) SignDigest(ctx context.Context, d [32]byte) ([]byte, error) {
	out, err := k.API.Sign(ctx, &kms.SignInput{KeyId: aws.String(k.KeyID), Message: d[:],
		MessageType: kmstypes.MessageTypeDigest, SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256})
	if err != nil {
		return nil, fmt.Errorf("kms Sign: %w", err)
	}
	if len(out.Signature) == 0 {
		return nil, errors.New("kms Sign: empty signature")
	}
	return RawSignature(out.Signature)
}
