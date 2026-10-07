// Package suite implements suite 2 of VAULT-MESSAGING §4: HPKE (RFC 9180)
// in base mode with KEM MLKEM768X25519, KDF HKDF-SHA256 and AEAD
// ChaCha20-Poly1305 for sealed mode; XChaCha20-Poly1305 for session mode;
// HKDF-SHA-256 for derivations; Ed25519 for signatures. It also holds the
// protocol labels (§4.1), key ids (§4.4) and the downgrade rules (§13.4).
//
// Secrets never appear in errors. Types that hold secret material redact
// themselves when formatted.
package suite

import (
	"crypto/sha256"
	"errors"
)

// Suite identifiers (§4.1).
const (
	// Suite1 is PQC-MIGRATION's classical transition suite. It MUST NOT be
	// sent or accepted.
	Suite1 uint8 = 1
	// Suite2 is the suite this package implements.
	Suite2 uint8 = 2
	// Suite3 is reserved for PQC Phase 2 (hybrid signatures).
	Suite3 uint8 = 3
)

// HPKE algorithm identifiers for suite 2 (§4.1).
const (
	KEMID  uint16 = 0x647a // MLKEM768X25519
	KDFID  uint16 = 0x0001 // HKDF-SHA256
	AEADID uint16 = 0x0003 // ChaCha20-Poly1305
)

// Sizes pinned by §3.2, §4.3 and the §16 vectors.
const (
	EKSize      = 1216 // MLKEM768X25519 encapsulation key
	EncSize     = 1120 // MLKEM768X25519 encapsulated key
	SeedSize    = 32   // decapsulation key seed
	KidSize     = 8
	KeySize     = 32 // session and exported keys
	XNonceSize  = 24 // XChaCha20-Poly1305 nonce
	TagSize     = 16 // Poly1305 tag
	EpochIDSize = 16
	HashSize    = sha256.Size
)

// Labels (§4.1, §4.3, §4.4, §6.3, §6.4, §11). All are ASCII with no
// terminator and embed the suite number.
const (
	LabelKid       = "vettid/vms/2/kid"
	InfoSealed     = "vettid/vms/2/sealed"
	LabelHsKs      = "vettid/vms/2/hs-ks"
	LabelHsKe      = "vettid/vms/2/hs-ke"
	LabelTh1       = "vettid/vms/2/th1"
	LabelTh        = "vettid/vms/2/th"
	LabelSession   = "vettid/vms/2/session"
	LabelI2R       = "vettid/vms/2/i2r"
	LabelR2I       = "vettid/vms/2/r2i"
	LabelKidI2R    = "vettid/vms/2/kid-i2r"
	LabelKidR2I    = "vettid/vms/2/kid-r2i"
	LabelRK        = "vettid/vms/2/rk"
	LabelEpoch     = "vettid/vms/2/epoch"
	LabelSigResp   = "vettid/vms/2/sig-resp"
	LabelSigFin    = "vettid/vms/2/sig-fin"
	LabelSAS       = "vettid/vms/2/sas"
	LabelSASCommit = "vettid/vms/2/sas-commit" // 0.10.3 (§6.3)
	LabelBundle    = "vettid/vms/2/bundle"
	LabelETK       = "vettid/vms/2/etk"
	LabelVault     = "vettid/vms/2/vault"
	LabelDevatt    = "vettid/vms/2/devatt"
	LabelIKFP      = "vettid/vms/2/ik-fp" // 0.18.0 (§10.8)
	LabelUnlock    = "vettid/vms/2/unlock"
	InfoCall       = "vettid/vms/2/call"
	LabelCallKey   = "vettid/vms/2/call-key"
	LabelRotate    = "vettid/vms/2/rotate" // identity.rotate statements (§3.4)
	LabelBlob      = "vettid/vms/2/blob"   // claim-check blobs (§5.5)
	labelPrefix    = "vettid/vms/2/"
	labelPrefixV3  = "vettid/vms/3/"
)

var _ = labelPrefixV3 // documented for suite 3; not used by suite 2

// Errors. None of them carries key material, plaintext or input bytes.
var (
	ErrSuite1           = errors.New("suite: suite 1 is never accepted")
	ErrUnsupportedSuite = errors.New("suite: unsupported suite")
	ErrDowngrade        = errors.New("suite: suite below the pinned suite")
	ErrBadOffer         = errors.New("suite: malformed suites offer")
	ErrNoCommonSuite    = errors.New("suite: no acceptable suite offered")
	ErrKeySize          = errors.New("suite: wrong key size")
	ErrBadKey           = errors.New("suite: invalid key")
	ErrDecrypt          = errors.New("suite: decryption failed")
	ErrContextUsed      = errors.New("suite: HPKE context already used for a message")
	ErrDestroyed        = errors.New("suite: key destroyed")
	ErrRandom           = errors.New("suite: randomness unavailable")
)

// LabeledHash returns SHA-256(label || parts...).
func LabeledHash(label string, parts ...[]byte) [HashSize]byte {
	h := sha256.New()
	h.Write([]byte(label))
	for _, p := range parts {
		h.Write(p)
	}
	var out [HashSize]byte
	h.Sum(out[:0])
	return out
}
