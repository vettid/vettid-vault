package vault

import (
	"encoding/binary"
	"time"

	"github.com/vettid/vettid-vault/vms/recovery"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Release R (VAULT-MESSAGING 0.33.0 §11.14.1, §11.14.2): the DEK is 32
// random bytes with a version, wrapped in the sealed header under a key
// derived from the PIN, the pepper and the phone's unlock secret, and
// replaced at every change of PIN, password or phone in three writes. The
// state names its dek_version in the clear (format 0x02).

// HeaderVersion is the sealed header's version from release R; a header
// of an earlier release (1) is refused (no vault is carried into release
// R, §11.14.14).
const HeaderVersion = 2

// Replacement reasons (HeaderNext.Reason).
const (
	ReplacePIN      = "pin"
	ReplacePassword = "password"
	ReplaceReset    = "reset"
	ReplaceRenew    = "renew"
	ReplaceTransfer = "transfer"
	ReplaceRecovery = "recovery"
)

// RecoveryWrap is the header's recovery.wrap (§11.14.3): the recovery key
// under the PIN and the password together, and the opener of the DEK of
// OpenerDEKVersion under the recovery key.
type RecoveryWrap struct {
	V                int       `json:"v"`
	Generation       uint64    `json:"generation"`
	KDF              KDFParams `json:"kdf"`
	Wrap             []byte    `json:"wrap"`
	Opener           []byte    `json:"opener"`
	OpenerDEKVersion uint64    `json:"opener_dek_version"`
}

// RecoveryHeader is the header's recovery part (§11.14.3).
type RecoveryHeader struct {
	// CounterKey names the vault's counter objects; made at enrollment and
	// never changed.
	CounterKey []byte `json:"counter_key"`
	// Generation names one pair of PIN and password; 0 until first armed.
	Generation uint64        `json:"generation"`
	Wrap       *RecoveryWrap `json:"wrap,omitempty"`
	// ChangeRequired: ten attempts of the generation were used, or the
	// password does not meet the arming rules; not armed again until a
	// PIN or password change has completed.
	ChangeRequired bool `json:"change_required,omitempty"`
	// ClosedUnchanged: the generation before Generation was closed with
	// the secrets unchanged (backup off, a change that did not complete):
	// the next arming needs no used attempt in it (§11.14.3).
	ClosedUnchanged bool `json:"closed_unchanged,omitempty"`
}

// HeaderNext is the `next` part of a DEK replacement's first header write
// (§11.14.2).
type HeaderNext struct {
	Reason      string    `json:"reason"`
	DEKVersion  uint64    `json:"dek_version"`
	KDF         KDFParams `json:"kdf"`
	DEKWrapNext []byte    `json:"dek_wrap_next"`
	SecretCheck []byte    `json:"secret_check_next"`
	// The new phone's unlock key and app key (a transfer, a recovery),
	// with the next app_key_seq.
	App       *UnlockKey `json:"app,omitempty"`
	AppKey    []byte     `json:"app_key,omitempty"`
	AppKeySeq uint64     `json:"app_key_seq,omitempty"`
	// Wrap is the recovery wrap after the replacement: a new generation's
	// (PIN, password, reset) or the current one with the opener for the
	// next DEK; nil for a vault that is not armed.
	Wrap *RecoveryWrap `json:"wrap,omitempty"`
	// HeaderSeq is the header_seq of the write that carried this part.
	HeaderSeq  uint64    `json:"header_seq"`
	TransferID string    `json:"transfer_id,omitempty"`
	At         time.Time `json:"at"`
}

func toParams(k KDFParams) recovery.Params {
	return recovery.Params{Alg: k.Alg, Time: k.Time, MemoryKiB: k.MemoryKiB, Threads: k.Threads, Salt: k.Salt}
}

func fromParams(p recovery.Params) KDFParams {
	return KDFParams{Alg: p.Alg, Time: p.Time, MemoryKiB: p.MemoryKiB, Threads: p.Threads, Salt: p.Salt}
}

// deriveUnlockKey is §11.14.1's unlock_key from the PIN, the phone's
// secret, the KDF parameters and the pepper.
func deriveUnlockKey(pin string, secret []byte, k KDFParams, pepper []byte, vaultID string) ([]byte, error) {
	if pin == "" || len(secret) != recovery.SecretSize || !k.valid() {
		return nil, ErrKDF
	}
	x, err := recovery.UnlockX(pin, toParams(k))
	if err != nil {
		return nil, ErrKDF
	}
	defer suite.Wipe(x)
	return recovery.UnlockKey(x, secret, pepper, vaultID)
}

// State blob layout (release R, §11.14.1):
//
//	blob = 0x02 || state_seq (8) || dek_version (8) || nonce (24) || XChaCha20-Poly1305(DEK, nonce, aad, json)
//	aad  = "vettid/vms/2/state" || 0x00 || vault_id || 0x00 || blob[0:17]
//
// A 0x01 blob (the releases before R) is refused.
const (
	stateBlobVersion = 2
	statePrefixLen   = 17
)

func encryptState(dek []byte, dekVersion uint64, vaultID string, seq uint64, plaintext []byte) ([]byte, error) {
	prefix := binary.BigEndian.AppendUint64([]byte{stateBlobVersion}, seq)
	prefix = binary.BigEndian.AppendUint64(prefix, dekVersion)
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

// StateDEKVersion reads a state blob's clear dek_version (ok false for a
// blob that is not format 0x02).
func StateDEKVersion(blob []byte) (uint64, bool) {
	if len(blob) < statePrefixLen+suite.XNonceSize+suite.TagSize || blob[0] != stateBlobVersion {
		return 0, false
	}
	return binary.BigEndian.Uint64(blob[9:17]), true
}

// decryptState returns the plaintext and the state_seq bound into the AAD.
func decryptState(dek []byte, vaultID string, blob []byte) ([]byte, uint64, error) {
	if _, ok := StateDEKVersion(blob); !ok {
		return nil, 0, ErrState
	}
	pt, err := suite.OpenX(dek, blob[statePrefixLen:statePrefixLen+suite.XNonceSize], stateAAD(vaultID, blob[:statePrefixLen]), blob[statePrefixLen+suite.XNonceSize:])
	if err != nil {
		return nil, 0, ErrState
	}
	return pt, binary.BigEndian.Uint64(blob[1:9]), nil
}
