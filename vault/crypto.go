package vault

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/vms/recovery"
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

// DefaultKDF returns the unlock key's parameters (§11.14.1: Argon2id,
// t=3, m=64 MiB, p=1; lower in a vettid_testcost build) with a fresh salt.
func DefaultKDF() (KDFParams, error) {
	p, err := recovery.NewUnlockParams()
	return fromParams(p), err
}

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

// ProvisionalUntil is when a provisional vault's enrollment window ends
// (§11.3): EnrollUntil, or CreatedAt + EnrollWindow for a header from a
// release before the time scale, so a window started there keeps its
// real time (STAGING-TIME-SCALE §5.5).
func (h *Header) ProvisionalUntil() time.Time {
	if !h.EnrollUntil.IsZero() {
		return h.EnrollUntil
	}
	return h.CreatedAt.Add(EnrollWindow)
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
	// EnrollUntil is the end of a provisional vault's enrollment window
	// (§11.3): CreatedAt plus EnrollWindow divided by the time scale
	// (0.43.0, STAGING-TIME-SCALE S13). Zero in a header from a release
	// before the scale, whose window is CreatedAt + EnrollWindow.
	EnrollUntil time.Time `json:"enroll_until,omitzero"`
	// Recovery (§11.11): the recovery in progress, and the steps taken
	// while the vault was locked (moved to the audit log at unlock).
	Recovery *RecoveryRecord `json:"recovery,omitempty"`
	// HasCredential records whether the vault has a Protean Credential
	// (§3.5.7), so that a locked vault without one refuses recovery.
	HasCredential bool `json:"has_credential,omitempty"`
	// Deleting marks a deletion in progress (§12.5): any later unlock or
	// recovery finishes it instead of opening the vault.
	Deleting    bool            `json:"deleting,omitempty"`
	RecoveryLog []RecoveryEvent `json:"recovery_log,omitempty"`
	// AppKey is the app's app key (SPKI DER, 0.15.0, §11.12.2), kept with
	// its unlock key; AppKeySeq counts its changes (1 at enrollment, + 1
	// at each transfer or recovery). Both are reported to the host (§11.5).
	AppKey    []byte `json:"app_key,omitempty"`
	AppKeySeq uint64 `json:"app_key_seq,omitempty"`
	// CredentialBackup records whether the vault keeps a backup copy of
	// its credential (0.16.0, §3.3, §3.5.6), so whether it can be
	// recovered; nil in a header written before 0.16.0.
	CredentialBackup *bool `json:"credential_backup,omitempty"`
	// Release R (§11.14.1, §11.14.2, §11.14.3): the current DEK wrapped
	// under the unlock key (KDF above is the unlock key's), its version,
	// the phone's secret check, a DEK replacement in progress, and the
	// recovery part.
	DEKVersion  uint64         `json:"dek_version"`
	DEKWrap     []byte         `json:"dek_wrap"`
	SecretCheck []byte         `json:"secret_check"`
	Next        *HeaderNext    `json:"next,omitempty"`
	Rec         RecoveryHeader `json:"recovery_r"`
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
	if err := json.Unmarshal(b, &h); err != nil || h.V != HeaderVersion || h.VaultID != vaultID || h.SealedRelease != release {
		return nil, ErrHeader
	}
	return &h, nil
}

func stateAAD(vaultID string, prefix []byte) []byte {
	a := []byte(labelState + "\x00" + vaultID + "\x00")
	return append(a, prefix...)
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
