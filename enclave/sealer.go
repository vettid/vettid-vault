package enclave

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/vettid/vettid-vault/enclave/cms"
	"github.com/vettid/vettid-vault/enclave/keypolicy"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/manifest"
	"github.com/vettid/vettid-vault/vms/nitro"
	"github.com/vettid/vettid-vault/vms/suite"
)

// NSM is the Nitro Security Module.
type NSM interface {
	// Attest returns a signed attestation document carrying the given
	// optional fields.
	Attest(userData, nonce, publicKey []byte) ([]byte, error)
	// Measurements returns the enclave's PCR0-2.
	Measurements() (nitro.Measurements, error)
}

// KMS is the part of AWS KMS the enclave uses (§11.10.2, §11.10.7). The
// enclave calls it itself, over TLS it terminates with SigV4 signing
// (phase V3b). Responses to the three read calls are the raw JSON bodies.
type KMS interface {
	// GenerateDataKey (KeySpec AES_256, Recipient = recipient) returns
	// CiphertextBlob and CiphertextForRecipient.
	GenerateDataKey(ctx context.Context, keyARN string, recipient []byte) (blob, forRecipient []byte, err error)
	// Decrypt (KeyId = keyARN, Recipient = recipient) returns
	// CiphertextForRecipient.
	Decrypt(ctx context.Context, keyARN string, blob, recipient []byte) (forRecipient []byte, err error)
	DescribeKey(ctx context.Context, keyARN string) ([]byte, error)
	GetKeyPolicy(ctx context.Context, keyARN string) ([]byte, error)
	ListGrants(ctx context.Context, keyARN string) ([]byte, error)
}

// Errors.
var (
	ErrSealed = errors.New("enclave: sealed object invalid")
	ErrKMS    = errors.New("enclave: KMS request failed")
)

// recipient is the enclave's RSA key for KMS Recipient responses: its
// public key goes into the attestation document KMS checks; KMS encrypts
// data keys to it (RSAES-OAEP-SHA-256).
type recipient struct {
	key *rsa.PrivateKey
	der []byte
}

func newRecipient() (*recipient, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, err
	}
	return &recipient{key: k, der: der}, nil
}

const sealLabel = "vettid/vms/2/seal"

// kmsSealer seals objects to one release's key (§11.10.2):
//
//	sealed = 0x01 || len(key_arn) (2) || key_arn || len(blob) (2) || blob || nonce (24)
//	         || XChaCha20-Poly1305(data_key, nonce, aad', plaintext)
//	aad'   = "vettid/vms/2/seal" || 0x00 || release || 0x00 || key_arn || 0x00 || aad
//
// (lengths big-endian). blob is KMS's CiphertextBlob for a fresh AES-256
// data key, which only an enclave the key's policy admits ever holds in
// plaintext (Recipient). The data key is cached while the vault is
// unlocked and wiped on Destroy.
//
// To unseal, the sealer takes the key ARN from the object, requires it to
// be in the pinned namespace (and equal to keyARN when that is set), and
// calls KMS Decrypt with it as KeyId; the caller then requires it to be the
// verified manifest's seal_key (OpenedKey).
type kmsSealer struct {
	kms     KMS
	nsm     NSM
	rcpt    *recipient
	keyARN  string
	release string
	allow   func(arn string) bool

	mu      sync.Mutex
	dataKey []byte
	blob    []byte
	opened  string
}

var _ vault.Sealer = (*kmsSealer)(nil)

func sealAAD(release, arn string, aad []byte) []byte {
	a := []byte(sealLabel + "\x00" + release + "\x00" + arn + "\x00")
	return append(a, aad...)
}

func (s *kmsSealer) attest() ([]byte, error) {
	return s.nsm.Attest(nil, nil, s.rcpt.der)
}

// Seal implements vault.Sealer.
func (s *kmsSealer) Seal(ctx context.Context, pt, aad []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keyARN == "" || len(s.keyARN) > 0xffff {
		return nil, ErrKMS
	}
	if s.dataKey == nil || s.opened != s.keyARN {
		att, err := s.attest()
		if err != nil {
			return nil, ErrKMS
		}
		blob, cfr, err := s.kms.GenerateDataKey(ctx, s.keyARN, att)
		if err != nil {
			return nil, ErrKMS
		}
		dk, err := cms.Unwrap(cfr, s.rcpt.key)
		if err != nil || len(dk) != 32 || len(blob) == 0 || len(blob) > 0xffff {
			return nil, ErrKMS
		}
		suite.Wipe(s.dataKey)
		s.dataKey, s.blob, s.opened = dk, blob, s.keyARN
	}
	nonce, err := suite.NewNonce()
	if err != nil {
		return nil, err
	}
	ct, err := suite.SealX(s.dataKey, nonce, sealAAD(s.release, s.keyARN, aad), pt)
	if err != nil {
		return nil, err
	}
	out := binary.BigEndian.AppendUint16([]byte{1}, uint16(len(s.keyARN)))
	out = append(out, s.keyARN...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(s.blob)))
	out = append(out, s.blob...)
	out = append(out, nonce...)
	return append(out, ct...), nil
}

func parseSealed(b []byte) (arn string, blob, nonce, ct []byte, ok bool) {
	if len(b) < 3 || b[0] != 1 {
		return "", nil, nil, nil, false
	}
	n := int(binary.BigEndian.Uint16(b[1:3]))
	b = b[3:]
	if n == 0 || len(b) < n+2 {
		return "", nil, nil, nil, false
	}
	arn, b = string(b[:n]), b[n:]
	m := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if m == 0 || len(b) < m+suite.XNonceSize+suite.TagSize {
		return "", nil, nil, nil, false
	}
	return arn, b[:m], b[m : m+suite.XNonceSize], b[m+suite.XNonceSize:], true
}

// Unseal implements vault.Sealer.
func (s *kmsSealer) Unseal(ctx context.Context, b, aad []byte) ([]byte, error) {
	arn, blob, nonce, ct, ok := parseSealed(b)
	if !ok || s.allow == nil || !s.allow(arn) || s.keyARN != "" && arn != s.keyARN {
		return nil, ErrSealed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dataKey == nil || s.opened != arn || !suite.Equal(blob, s.blob) {
		att, err := s.attest()
		if err != nil {
			return nil, ErrKMS
		}
		cfr, err := s.kms.Decrypt(ctx, arn, blob, att)
		if err != nil {
			return nil, ErrSealed
		}
		dk, err := cms.Unwrap(cfr, s.rcpt.key)
		if err != nil || len(dk) != 32 {
			return nil, ErrSealed
		}
		suite.Wipe(s.dataKey)
		s.dataKey, s.blob, s.opened = dk, append([]byte(nil), blob...), arn
	}
	pt, err := suite.OpenX(s.dataKey, nonce, sealAAD(s.release, arn, aad), ct)
	if err != nil {
		return nil, ErrSealed
	}
	if s.keyARN == "" {
		s.keyARN = arn // later seals reuse the key (and its data key)
	}
	return pt, nil
}

// OpenedKey returns the key ARN of the last object unsealed or sealed.
func (s *kmsSealer) OpenedKey() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opened
}

// Destroy wipes the cached data key.
func (s *kmsSealer) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	suite.Wipe(s.dataKey)
	s.dataKey, s.blob = nil, nil
}

// checkKey runs §11.10.7 on a release's sealing key: it reads the key's
// metadata, policy and grants from KMS and checks them.
func (in *Instance) checkKey(ctx context.Context, m *manifest.Manifest, target *manifest.Release) (*vault.SealKeyRecord, error) {
	arn := target.SealKey
	desc, err := in.kms.DescribeKey(ctx, arn)
	if err != nil {
		return nil, ErrKMS
	}
	pol, err := in.kms.GetKeyPolicy(ctx, arn)
	if err != nil {
		return nil, ErrKMS
	}
	gr, err := in.kms.ListGrants(ctx, arn)
	if err != nil {
		return nil, ErrKMS
	}
	r, err := keypolicy.Check(keypolicy.Input{KeyARN: arn, Account: in.cfg.SealAccount, Region: in.cfg.SealRegion,
		Manifest: m, Target: target.Number, DescribeKey: desc, GetKeyPolicy: pol, ListGrants: gr})
	if err != nil {
		return nil, err
	}
	return &vault.SealKeyRecord{KeyARN: r.KeyARN, PolicySHA256: r.PolicySHA256[:], VerifiedBy: in.meas.PCR0}, nil
}

// inNamespace reports whether a seal_key is a KMS key ARN in the pinned
// account and region (§11.10.2).
func (in *Instance) inNamespace(arn string) bool {
	if in.cfg.SealAccount == "" || in.cfg.SealRegion == "" {
		return false
	}
	p := "arn:aws:kms:" + in.cfg.SealRegion + ":" + in.cfg.SealAccount + ":key/"
	return len(arn) > len(p) && arn[:len(p)] == p
}

func (in *Instance) sealerFor(keyARN, release string) *kmsSealer {
	return &kmsSealer{kms: in.kms, nsm: in.nsm, rcpt: in.rcpt, keyARN: keyARN, release: release, allow: in.inNamespace}
}
