package vault

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/vettid/vettid-vault/vms/suite"
)

// Sealer seals the sealed header to the enclave (§3.3). Release builds get
// a KMS/attestation sealer in phase V3; the only implementation today is
// the development sealer in package devenclave, which release builds cannot
// compile in.
type Sealer interface {
	Seal(ctx context.Context, plaintext, aad []byte) ([]byte, error)
	Unseal(ctx context.Context, sealed, aad []byte) ([]byte, error)
}

// Labels for the at-rest formats (VAULT-MESSAGING §3.3.1).
const (
	labelDEK    = "vettid/vms/2/dek"
	labelState  = "vettid/vms/2/state"
	labelHeader = "vettid/vms/2/header"
)

// KDFParams are the DEK's KDF parameters, kept in the sealed header.
type KDFParams struct {
	Alg       string `json:"alg"` // "argon2id"
	Time      uint32 `json:"t"`
	MemoryKiB uint32 `json:"m"`
	Threads   uint8  `json:"p"`
	Salt      []byte `json:"salt"` // 16 bytes
}

// DefaultKDF returns production parameters (Argon2id, t=3, m=64 MiB, p=1)
// with a fresh salt.
func DefaultKDF() (KDFParams, error) { return newKDF(3, 64*1024, 1) }

// MinKDF are the weakest parameters accepted (used by tests and dev runs).
func MinKDF() (KDFParams, error) { return newKDF(1, 8*1024, 1) }

func newKDF(t, m uint32, p uint8) (KDFParams, error) {
	salt, err := suite.RandomBytes(16)
	if err != nil {
		return KDFParams{}, err
	}
	return KDFParams{Alg: "argon2id", Time: t, MemoryKiB: m, Threads: p, Salt: salt}, nil
}

func (k KDFParams) valid() bool {
	return k.Alg == "argon2id" && k.Time >= 1 && k.Time <= 10 && k.MemoryKiB >= 8*1024 &&
		k.MemoryKiB <= 1024*1024 && k.Threads >= 1 && k.Threads <= 4 && len(k.Salt) == 16
}

// ErrKDF is returned for unacceptable KDF parameters.
var ErrKDF = errors.New("vault: invalid KDF parameters")

// deriveDEK computes the DEK:
//
//	x   = Argon2id(PIN, salt, t, m, p, 32)
//	DEK = HKDF-SHA-256(ikm = x, salt = pepper, info = "vettid/vms/2/dek" || vault_id, 32)
//
// The pepper is a random 32-byte secret kept only in the sealed header, so
// stolen state cannot be brute-forced against PINs outside the enclave.
func deriveDEK(pin string, k KDFParams, pepper []byte, vaultID string) ([]byte, error) {
	if !k.valid() || len(pepper) != 32 || pin == "" {
		return nil, ErrKDF
	}
	x := argon2.IDKey([]byte(pin), k.Salt, k.Time, k.MemoryKiB, k.Threads, 32)
	defer suite.Wipe(x)
	return hkdf.Key(sha256.New, x, pepper, labelDEK+vaultID, 32)
}

// UnlockKey is an app allowed to unlock (§3.3): its keys and its
// device-attestation binding (§11.7), which only the sealed header holds
// authoritatively (the iOS assertion counter advances here).
type UnlockKey struct {
	DeviceID    string          `json:"device_id"`
	IK          []byte          `json:"ik"`
	KEM         []byte          `json:"kem"`
	Attestation json.RawMessage `json:"attestation,omitempty"`
}

// Release identifies an enclave release (§11.10): its PCR0 (lowercase hex)
// and its release number, which the image embeds.
type Release struct {
	PCR0   string
	Number uint64
}

// SealKeyRecord is seal_key_verified (§3.3, §11.10.7): the sealing key a
// header is sealed under and the SHA-256 of the policy that passed the
// checks, with the release that ran them.
type SealKeyRecord struct {
	KeyARN       string `json:"key_arn"`
	PolicySHA256 []byte `json:"policy_sha256"`
	VerifiedBy   string `json:"verified_by"`
}

// Backoff is the unlock backoff state (§11.8).
type Backoff struct {
	Failures  int       `json:"failures"`
	NotBefore time.Time `json:"not_before"`
}

// Header is the sealed header (§3.3). It never holds the relay key,
// session keys or feature data.
type Header struct {
	V           int         `json:"v"`
	VaultID     string      `json:"vault_id"`
	UserGUID    string      `json:"user_guid"`
	Provisional bool        `json:"provisional"`
	CreatedAt   time.Time   `json:"created_at"`
	KDF         KDFParams   `json:"kdf"`
	Pepper      []byte      `json:"pepper"`
	UnlockKeys  []UnlockKey `json:"unlock_keys"`
	Backoff     Backoff     `json:"backoff"`
	StateSeq    uint64      `json:"state_seq"`
	HeaderSeq   uint64      `json:"header_seq"`
	// Release fields (§11.10): the release this header is sealed to, the
	// highest manifest serial seen, and the verified sealing key.
	SealedRelease   string         `json:"sealed_release"`
	ManifestSerial  uint64         `json:"manifest_serial"`
	SealKeyVerified *SealKeyRecord `json:"seal_key_verified,omitempty"`
	// Recovery (§11.11): the recovery in progress, and the steps taken
	// while the vault was locked (moved to the audit log at unlock).
	Recovery *RecoveryRecord `json:"recovery,omitempty"`
	// HasCredential records whether the vault has a Protean Credential
	// (§3.5.7), so that a locked vault without one refuses recovery.
	HasCredential bool            `json:"has_credential,omitempty"`
	RecoveryLog   []RecoveryEvent `json:"recovery_log,omitempty"`
}

func headerAAD(vaultID string) []byte { return []byte(labelHeader + "\x00" + vaultID) }

func sealHeader(ctx context.Context, s Sealer, h *Header) ([]byte, error) {
	b, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	defer suite.Wipe(b)
	return s.Seal(ctx, b, headerAAD(h.VaultID))
}

func unsealHeader(ctx context.Context, s Sealer, blob []byte, vaultID, release string) (*Header, error) {
	b, err := s.Unseal(ctx, blob, headerAAD(vaultID))
	if err != nil {
		return nil, ErrHeader
	}
	defer suite.Wipe(b)
	var h Header
	if err := json.Unmarshal(b, &h); err != nil || h.V != 1 || h.VaultID != vaultID || h.SealedRelease != release {
		return nil, ErrHeader
	}
	return &h, nil
}

// State blob layout:
//
//	blob = 0x01 || state_seq (8, big-endian) || nonce (24) || XChaCha20-Poly1305(DEK, nonce, aad, json)
//	aad  = "vettid/vms/2/state" || 0x00 || vault_id || 0x00 || blob[0:9]
const stateBlobVersion = 1

func stateAAD(vaultID string, prefix []byte) []byte {
	a := []byte(labelState + "\x00" + vaultID + "\x00")
	return append(a, prefix...)
}

func encryptState(dek []byte, vaultID string, seq uint64, plaintext []byte) ([]byte, error) {
	prefix := binary.BigEndian.AppendUint64([]byte{stateBlobVersion}, seq)
	nonce, err := suite.NewNonce()
	if err != nil {
		return nil, err
	}
	ct, err := suite.SealX(dek, nonce, stateAAD(vaultID, prefix), plaintext)
	if err != nil {
		return nil, err
	}
	out := append(prefix, nonce...)
	return append(out, ct...), nil
}

// decryptState returns the plaintext and the state_seq bound into the AAD.
func decryptState(dek []byte, vaultID string, blob []byte) ([]byte, uint64, error) {
	if len(blob) < 9+suite.XNonceSize+suite.TagSize || blob[0] != stateBlobVersion {
		return nil, 0, ErrState
	}
	pt, err := suite.OpenX(dek, blob[9:9+suite.XNonceSize], stateAAD(vaultID, blob[:9]), blob[9+suite.XNonceSize:])
	if err != nil {
		return nil, 0, ErrState
	}
	return pt, binary.BigEndian.Uint64(blob[1:9]), nil
}

// PeekHeader unseals a header blob (the enclave's check for an existing
// vault at enrollment, §11.3). It returns a copy without secrets.
func PeekHeader(ctx context.Context, s Sealer, blob []byte, vaultID, release string) (*Header, error) {
	h, err := unsealHeader(ctx, s, blob, vaultID, release)
	if err != nil {
		return nil, err
	}
	suite.Wipe(h.Pepper)
	h.Pepper = nil
	return h, nil
}
