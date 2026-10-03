// Package altchan holds the pure crypto and wire helpers of the alternate
// channel (VAULT-MESSAGING §11) that the §16 test vectors pin: the ETK
// descriptor's attestation user_data, the vault bundle user_data, the
// device-attestation challenge and the unlock signing string. The enclave
// side of §11 (ETK lifecycle, enroll, unlock, attestation verification) is
// built in phase V3.
package altchan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// ErrField is returned for a field that cannot appear in a signed string.
var ErrField = errors.New("altchan: invalid field")

// PaddedSize is the fixed padded size of alternate-channel plaintexts
// (results, and requests other than enroll and unlock).
const PaddedSize = envelope.AltChannelPadded

// RequestPaddedSize is the fixed padded size of vault.enroll and
// vault.unlock, which carry the release manifest (§5.4, §11.3, §11.4).
const RequestPaddedSize = 12288

// ETKUserData returns the Nitro attestation user_data for an ETK
// descriptor: SHA-256("vettid/vms/2/etk" || descriptor_bytes) (§11.2).
func ETKUserData(descriptor []byte) [32]byte {
	return suite.LabeledHash(suite.LabelETK, descriptor)
}

// VaultUserData returns the user_data of the attestation in vault.enrolled:
// SHA-256("vettid/vms/2/vault" || vault_bundle) (§11.3).
func VaultUserData(vaultBundle []byte) [32]byte {
	return suite.LabeledHash(suite.LabelVault, vaultBundle)
}

// DevattChallenge returns the device-attestation challenge (§11.7):
//
//	SHA-256("vettid/vms/2/devatt" || request_id || vault_id_or_empty || ts)
//
// request_id is the 26-character ULID, vault_id the opaque id string as
// carried in JSON (empty at enrollment), and ts the inner `ts` of the
// request envelope (24 characters). Because request_id and ts have fixed
// lengths, the concatenation is unambiguous. Android signs this challenge
// with the attested key; iOS uses it as App Attest clientDataHash.
func DevattChallenge(requestID, vaultID, ts string) ([32]byte, error) {
	if !envelope.ValidULID(requestID) || !validVaultID(vaultID, true) {
		return [32]byte{}, ErrField
	}
	if _, err := envelope.ParseTS(ts); err != nil {
		return [32]byte{}, ErrField
	}
	return suite.LabeledHash(suite.LabelDevatt, []byte(requestID), []byte(vaultID), []byte(ts)), nil
}

// validVaultID accepts printable ASCII without spaces or newlines.
func validVaultID(s string, allowEmpty bool) bool {
	if s == "" {
		return allowEmpty
	}
	if len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// UnlockFields are the inputs of the unlock signing string (§11.4).
type UnlockFields struct {
	UserGUID     string
	VaultID      string
	RequestID    string
	TS           string // inner ts
	ETKKid       suite.Kid
	MinStateSeq  uint64
	MinHeaderSeq uint64
	PIN          string
	Token        string
	// Manifest is the exact manifest bytes in the request (§11.10.1);
	// ToPCR0 the release_update target, "" without one.
	Manifest []byte
	ToPCR0   string
	// CancelRecovery adds a 13th line, "cancel_recovery" (§11.11.4).
	CancelRecovery bool
}

// UnlockSigningString returns the string `sig` covers in vault.unlock
// (§11.4), fields separated by a literal newline, no trailing newline:
//
//	"vettid/vms/2/unlock" \n user_guid \n vault_id \n request_id \n ts \n etk_kid_hex \n
//	min_state_seq \n min_header_seq \n hex(SHA-256(pin)) \n hex(SHA-256(token)) \n
//	hex(SHA-256(manifest_bytes)) \n to_pcr0_hex_or_empty
//
// Integers are decimal; hex is lowercase. No field may contain a newline.
func UnlockSigningString(f UnlockFields) (string, error) {
	if !validVaultID(f.UserGUID, false) || !validVaultID(f.VaultID, false) || !envelope.ValidULID(f.RequestID) {
		return "", ErrField
	}
	if _, err := envelope.ParseTS(f.TS); err != nil {
		return "", ErrField
	}
	if f.PIN == "" || f.Token == "" || strings.ContainsAny(f.PIN+f.Token, "\r\n") || len(f.Manifest) == 0 {
		return "", ErrField
	}
	if f.ToPCR0 != "" && !validPCRHex(f.ToPCR0) {
		return "", ErrField
	}
	pin := sha256.Sum256([]byte(f.PIN))
	tok := sha256.Sum256([]byte(f.Token))
	man := sha256.Sum256(f.Manifest)
	lines := []string{
		suite.LabelUnlock,
		f.UserGUID,
		f.VaultID,
		f.RequestID,
		f.TS,
		f.ETKKid.String(),
		strconv.FormatUint(f.MinStateSeq, 10),
		strconv.FormatUint(f.MinHeaderSeq, 10),
		hex.EncodeToString(pin[:]),
		hex.EncodeToString(tok[:]),
		hex.EncodeToString(man[:]),
		f.ToPCR0,
	}
	if f.CancelRecovery {
		lines = append(lines, "cancel_recovery")
	}
	return strings.Join(lines, "\n"), nil
}

func validPCRHex(s string) bool {
	if len(s) != 96 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// LabelApproval is the release-approval label (§11.10.3).
const LabelApproval = "vettid/vms/2/release-approval"

// ApprovalSigningString returns the release-approval signing string
// (§11.10.3), fields separated by a literal newline, no trailing newline:
//
//	"vettid/vms/2/release-approval" \n vault_id \n request_id \n from_pcr0_hex \n
//	to_pcr0_hex \n to_release \n manifest_serial
func ApprovalSigningString(vaultID, requestID, fromPCR0, toPCR0 string, toRelease, serial uint64) (string, error) {
	if !validVaultID(vaultID, false) || !envelope.ValidULID(requestID) || !validPCRHex(fromPCR0) || !validPCRHex(toPCR0) ||
		toRelease == 0 || serial == 0 {
		return "", ErrField
	}
	return strings.Join([]string{LabelApproval, vaultID, requestID, fromPCR0, toPCR0,
		strconv.FormatUint(toRelease, 10), strconv.FormatUint(serial, 10)}, "\n"), nil
}
