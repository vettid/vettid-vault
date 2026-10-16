// Package recovery holds the derivations, wire formats and names of
// VettID's recovery and unlock from release R (VAULT-MESSAGING 0.33.0
// §11.14; VAULT-HOST-PROTOCOL 0.1.10 §8.1): the unlock key derived from
// the PIN and the phone's unlock secret, the wraps of the random DEK, the
// recovery wrap under the PIN and the credential password together, its
// openers, the tag of the last wrong pair, the attempt counter's object
// names, the schedule of waits, and the two signing strings. It is pure:
// no I/O, no clock and no state. The vault, the vectors and the reference
// client use it; the Android app reproduces it byte for byte (§16).
package recovery

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/vettid/vettid-vault/vms/suite"
)

// Labels (§11.14.1, §11.14.2, §11.14.3, §11.14.6; VAULT-HOST-PROTOCOL §8.1).
const (
	LabelUnlockKey     = "vettid/vms/2/unlock-key"
	LabelDEKWrap       = "vettid/vms/2/dek-wrap"
	LabelDEKWrapNext   = "vettid/vms/2/dek-wrap-next"
	LabelSecretCheck   = "vettid/vms/2/unlock-secret-check"
	LabelUnlockSecret  = "vettid/vms/2/unlock-secret"
	LabelRecoveryWrap  = "vettid/vms/2/recovery-wrap"
	LabelOpener        = "vettid/vms/2/recovery-opener"
	LabelWrongTag      = "vettid/vms/2/recovery-wrong-tag"
	LabelCounterVault  = "vettid/vms/2/counter/vault"
	LabelCounterName   = "vettid/vms/2/counter/name"
	LabelRecoveryOpen  = "vettid/vms/2/recovery-open"
	LabelRecoveryReq   = "vettid/vms/2/recovery-request"
	CounterPrefixRoot  = "recovery/v1/"
	SecretSize         = 32 // unlock_secret, DEK, recovery_key, counter_key
	WrapSize           = suite.XNonceSize + SecretSize + suite.TagSize
	WrapNextSize       = suite.XNonceSize + 2*SecretSize + suite.TagSize
	MaxAttempts        = 10
	MaxPasswordBytes   = 1024
	MinPasswordRunes   = 12
	GuessabilityFloor  = 1e10
	MaxWrongAgain      = 3
	ConfirmWindowSecs  = 600 // the two 10-minute limits of step 4b, counter clock
	StatusMaxAgeSecs   = 60  // step 3b, enclave clock
	PresentLockHours   = 96
	CounterLockYears   = 100
	DefaultQuietSecs   = 259200
	ProductionWaitUnit = 86400
)

// StagingCounterLockHours is the staging channel's lock period of the
// counter's token, success and close records; production's is
// CounterLockYears (VAULT-MESSAGING 0.33.2 §11.14.4). The channel is the
// measured one (releasecfg.CounterLock).
const StagingCounterLockHours = 24

// Errors.
var (
	ErrSize   = errors.New("recovery: wrong size")
	ErrParams = errors.New("recovery: KDF parameters below the floor")
	ErrOpen   = errors.New("recovery: does not open")
)

func u64(n uint64) []byte { return binary.BigEndian.AppendUint64(nil, n) }

func cat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

var zero = []byte{0}

// --- §11.14.1 the unlock key, dek_wrap and secret_check ---

// UnlockX is Argon2id(PIN, salt, t, m, p, 32) at the everyday unlock
// parameters (§11.14.1: t = 3, m = 64 MiB, p = 1).
func UnlockX(pin string, p Params) ([]byte, error) {
	if err := p.checkUnlock(); err != nil {
		return nil, err
	}
	return argon2.IDKey([]byte(pin), p.Salt, p.Time, p.MemoryKiB, p.Threads, 32), nil
}

// UnlockKey is HKDF-SHA-256(ikm = x || unlock_secret, salt = pepper,
// info = "vettid/vms/2/unlock-key" || 0x00 || vault_id, L = 32).
func UnlockKey(x, unlockSecret, pepper []byte, vaultID string) ([]byte, error) {
	if len(x) != 32 || len(unlockSecret) != SecretSize || len(pepper) != 32 {
		return nil, ErrSize
	}
	ikm := cat(x, unlockSecret)
	defer suite.Wipe(ikm)
	return hkdf.Key(sha256.New, ikm, pepper, LabelUnlockKey+"\x00"+vaultID, 32)
}

func dekWrapAAD(vaultID string, dekVersion uint64) []byte {
	return cat([]byte(LabelDEKWrap), zero, []byte(vaultID), zero, u64(dekVersion))
}

func dekWrapNextAAD(vaultID string, dekVersion uint64) []byte {
	return cat([]byte(LabelDEKWrapNext), zero, []byte(vaultID), zero, u64(dekVersion))
}

func sealWithNonce(key, aad, pt []byte) ([]byte, error) {
	nonce, err := suite.NewNonce()
	if err != nil {
		return nil, err
	}
	return sealNonce(key, nonce, aad, pt)
}

func sealNonce(key, nonce, aad, pt []byte) ([]byte, error) {
	ct, err := suite.SealX(key, nonce, aad, pt)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), nonce...), ct...), nil
}

func openWithNonce(key, aad, blob []byte, want int) ([]byte, error) {
	if len(blob) != suite.XNonceSize+want+suite.TagSize {
		return nil, ErrSize
	}
	pt, err := suite.OpenX(key, blob[:suite.XNonceSize], aad, blob[suite.XNonceSize:])
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

// WrapDEK is dek_wrap = nonce || XChaCha20-Poly1305(unlock_key, nonce,
// "vettid/vms/2/dek-wrap" || 0x00 || vault_id || 0x00 || dek_version, DEK).
func WrapDEK(unlockKey, dek []byte, vaultID string, dekVersion uint64) ([]byte, error) {
	if len(dek) != SecretSize {
		return nil, ErrSize
	}
	return sealWithNonce(unlockKey, dekWrapAAD(vaultID, dekVersion), dek)
}

// OpenDEK opens a dek_wrap.
func OpenDEK(unlockKey, wrap []byte, vaultID string, dekVersion uint64) ([]byte, error) {
	return openWithNonce(unlockKey, dekWrapAAD(vaultID, dekVersion), wrap, SecretSize)
}

// WrapDEKNext is dek_wrap_next (§11.14.2): both DEKs under the next unlock
// key, the AAD naming the next DEK's version.
func WrapDEKNext(unlockKeyNext, dek0, dek1 []byte, vaultID string, dekVersion1 uint64) ([]byte, error) {
	if len(dek0) != SecretSize || len(dek1) != SecretSize {
		return nil, ErrSize
	}
	pt := cat(dek0, dek1)
	defer suite.Wipe(pt)
	return sealWithNonce(unlockKeyNext, dekWrapNextAAD(vaultID, dekVersion1), pt)
}

// OpenDEKNext opens a dek_wrap_next and returns DEK_0 and DEK_1.
func OpenDEKNext(unlockKeyNext, wrap []byte, vaultID string, dekVersion1 uint64) (dek0, dek1 []byte, err error) {
	pt, err := openWithNonce(unlockKeyNext, dekWrapNextAAD(vaultID, dekVersion1), wrap, 2*SecretSize)
	if err != nil {
		return nil, nil, err
	}
	dek0 = append([]byte(nil), pt[:SecretSize]...)
	dek1 = append([]byte(nil), pt[SecretSize:]...)
	suite.Wipe(pt)
	return dek0, dek1, nil
}

// SecretCheck is HMAC-SHA-256(key = pepper, msg =
// "vettid/vms/2/unlock-secret-check" || 0x00 || vault_id || 0x00 ||
// unlock_secret). It does not depend on the PIN.
func SecretCheck(pepper []byte, vaultID string, unlockSecret []byte) ([]byte, error) {
	if len(pepper) != 32 || len(unlockSecret) != SecretSize {
		return nil, ErrSize
	}
	m := hmac.New(sha256.New, pepper)
	m.Write(cat([]byte(LabelSecretCheck), zero, []byte(vaultID), zero, unlockSecret))
	return m.Sum(nil), nil
}

// PhoneUnlockSecret is what the phone's hardware key computes (§11.14.1):
// HMAC-SHA-256(phone key, "vettid/vms/2/unlock-secret" || 0x00 ||
// vault_id || 0x00 || epoch). The vault never computes it; the reference
// client and the vectors do, standing in for the Keystore key.
func PhoneUnlockSecret(phoneKey []byte, vaultID string, epoch uint64) []byte {
	m := hmac.New(sha256.New, phoneKey)
	m.Write(cat([]byte(LabelUnlockSecret), zero, []byte(vaultID), zero, u64(epoch)))
	return m.Sum(nil)
}

// --- §11.14.3 the recovery wrap and its openers ---

// Secrets is len(PIN) (2) || PIN || len(password) (2) || password, the
// password already NFC-normalized (NormalizePassword).
func Secrets(pin string, password []byte) ([]byte, error) {
	if len(pin) == 0 || len(pin) > 0xffff || len(password) == 0 || len(password) > MaxPasswordBytes {
		return nil, ErrSize
	}
	out := make([]byte, 0, 4+len(pin)+len(password))
	out = binary.BigEndian.AppendUint16(out, uint16(len(pin)))
	out = append(out, pin...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(password)))
	return append(out, password...), nil
}

// HeavyX is Argon2id(secrets, salt, t, m, p, 32) at the recovery wrap's
// heavy parameters. Parameters below the build's floor are refused
// (HeavyFloor: t = 3, m = 1 GiB in every release build).
func HeavyX(secrets []byte, p Params) ([]byte, error) {
	if err := p.checkHeavy(); err != nil {
		return nil, err
	}
	return argon2.IDKey(secrets, p.Salt, p.Time, p.MemoryKiB, p.Threads, 32), nil
}

func wrapInfo(vaultID string, generation uint64) []byte {
	return cat([]byte(LabelRecoveryWrap), zero, []byte(vaultID), zero, u64(generation))
}

// WrapKey is K = HKDF-SHA-256(ikm = x, salt = pepper, info =
// "vettid/vms/2/recovery-wrap" || 0x00 || vault_id || 0x00 || generation).
func WrapKey(x, pepper []byte, vaultID string, generation uint64) ([]byte, error) {
	if len(x) != 32 || len(pepper) != 32 {
		return nil, ErrSize
	}
	return hkdf.Key(sha256.New, x, pepper, string(wrapInfo(vaultID, generation)), 32)
}

// WrapRecoveryKey is wrap = nonce || XChaCha20-Poly1305(K, nonce, aad_w,
// recovery_key), aad_w equal to K's info.
func WrapRecoveryKey(k, recoveryKey []byte, vaultID string, generation uint64) ([]byte, error) {
	if len(recoveryKey) != SecretSize {
		return nil, ErrSize
	}
	return sealWithNonce(k, wrapInfo(vaultID, generation), recoveryKey)
}

// OpenRecoveryKey opens a wrap (ErrOpen for a wrong pair).
func OpenRecoveryKey(k, wrap []byte, vaultID string, generation uint64) ([]byte, error) {
	return openWithNonce(k, wrapInfo(vaultID, generation), wrap, SecretSize)
}

func openerAAD(vaultID string, generation, dekVersion uint64) []byte {
	return cat([]byte(LabelOpener), zero, []byte(vaultID), zero, u64(generation), u64(dekVersion))
}

// MakeOpener is opener = nonce || XChaCha20-Poly1305(recovery_key, nonce,
// "vettid/vms/2/recovery-opener" || 0x00 || vault_id || 0x00 ||
// generation || dek_version, DEK).
func MakeOpener(recoveryKey, dek []byte, vaultID string, generation, dekVersion uint64) ([]byte, error) {
	if len(recoveryKey) != SecretSize || len(dek) != SecretSize {
		return nil, ErrSize
	}
	return sealWithNonce(recoveryKey, openerAAD(vaultID, generation, dekVersion), dek)
}

// OpenOpener opens an opener and returns the DEK.
func OpenOpener(recoveryKey, opener []byte, vaultID string, generation, dekVersion uint64) ([]byte, error) {
	return openWithNonce(recoveryKey, openerAAD(vaultID, generation, dekVersion), opener, SecretSize)
}

// WrongTag is last_wrong (§11.14.6): HMAC-SHA-256(key = HKDF-SHA-256(ikm =
// x, salt = pepper, info = "vettid/vms/2/recovery-wrong-tag", L = 32),
// msg = vault_id || 0x00 || recovery_id || 0x00 || device_ik (32 bytes)).
func WrongTag(x, pepper []byte, vaultID, recoveryID string, deviceIK []byte) ([]byte, error) {
	if len(x) != 32 || len(pepper) != 32 || len(deviceIK) != 32 {
		return nil, ErrSize
	}
	k, err := hkdf.Key(sha256.New, x, pepper, LabelWrongTag, 32)
	if err != nil {
		return nil, err
	}
	defer suite.Wipe(k)
	m := hmac.New(sha256.New, k)
	m.Write(cat([]byte(vaultID), zero, []byte(recoveryID), zero, deviceIK))
	return m.Sum(nil), nil
}

// --- the schedule of waits (§11.14.6) ---

// waitUnits is W(k) in units, k = 1 … 9; after attempt 10 there is no
// next attempt.
var waitUnits = [MaxAttempts + 1]uint64{0, 0, 1, 2, 4, 8, 16, 30, 30, 30, 0}

// WaitUnits returns W(k) in units of recovery_wait_unit_seconds for
// attempt k (1 … 10); W(10) is 0 because no attempt follows it.
func WaitUnits(k int) uint64 {
	if k < 1 || k > MaxAttempts {
		return 0
	}
	return waitUnits[k]
}

// --- VAULT-HOST-PROTOCOL §8.1 counter object names ---

// Counter record kinds.
const (
	KindPresent = "present"
	KindToken   = "t"
	KindWait    = "w"
	KindSuccess = "s"
	KindClose   = "c"
)

func mac16(counterKey []byte, msg []byte) string {
	m := hmac.New(sha256.New, counterKey)
	m.Write(msg)
	return hex.EncodeToString(m.Sum(nil)[:16])
}

// Names computes one vault's counter object names from its counter_key.
type Names struct {
	key     []byte
	vaultID string
	tag     string
}

// NewNames returns the names of vault_id under counter_key (32 bytes).
func NewNames(counterKey []byte, vaultID string) (*Names, error) {
	if len(counterKey) != SecretSize || vaultID == "" {
		return nil, ErrSize
	}
	k := append([]byte(nil), counterKey...)
	return &Names{key: k, vaultID: vaultID, tag: mac16(k, cat([]byte(LabelCounterVault), zero, []byte(vaultID)))}, nil
}

// VaultTag is hex(first 16 bytes of HMAC-SHA-256(counter_key,
// "vettid/vms/2/counter/vault" || 0x00 || vault_id)).
func (n *Names) VaultTag() string { return n.tag }

// Prefix is recovery/v1/<vault_tag>/, every name of the vault.
func (n *Names) Prefix() string { return CounterPrefixRoot + n.tag + "/" }

func (n *Names) mac(kind string, g, i uint64) string {
	return mac16(n.key, cat([]byte(LabelCounterName), zero, []byte(n.vaultID), zero, u64(g), zero, []byte(kind), zero, u64(i)))
}

// GenPrefix is recovery/v1/<vault_tag>/g<g, 16 hex>/.
func (n *Names) GenPrefix(g uint64) string {
	h := strconv.FormatUint(g, 16)
	return n.Prefix() + "g" + strings.Repeat("0", 16-len(h)) + h + "/"
}

// Present is the present marker's one key.
func (n *Names) Present() string { return n.Prefix() + "present-" + n.mac(KindPresent, 0, 0) }

// Token is the token of attempt k (1 … 10) of generation g.
func (n *Names) Token(g uint64, k int) string { return n.numbered(KindToken, g, k) }

// Wait is the wait record after attempt k.
func (n *Names) Wait(g uint64, k int) string { return n.numbered(KindWait, g, k) }

// Success is the success record of attempt k.
func (n *Names) Success(g uint64, k int) string { return n.numbered(KindSuccess, g, k) }

// Close is generation g's close record.
func (n *Names) Close(g uint64) string { return n.GenPrefix(g) + "c-" + n.mac(KindClose, g, 0) }

func (n *Names) numbered(kind string, g uint64, k int) string {
	nn := strconv.Itoa(k)
	if k < 10 {
		nn = "0" + nn
	}
	return n.GenPrefix(g) + kind + nn + "-" + n.mac(kind, g, uint64(k))
}

// Wipe zeroizes the counter key copy.
func (n *Names) Wipe() { suite.Wipe(n.key) }

// --- signing strings (§11.14.6, §11.14.8) ---

func hexSHA(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// OpenFields are what vault.recovery.open's sig covers.
type OpenFields struct {
	UserGUID, VaultID, RequestID, RecoveryID, TS, ETKKid string
	Secrets, Token, Manifest, UnlockSecret               []byte
}

// OpenSigningString is the string the registered phone's device key
// signs (§11.14.6), literal newlines, no trailing newline. No field may
// contain CR or LF.
func OpenSigningString(f OpenFields) (string, error) {
	for _, s := range []string{f.UserGUID, f.VaultID, f.RequestID, f.RecoveryID, f.TS, f.ETKKid} {
		if s == "" || strings.ContainsAny(s, "\r\n") {
			return "", ErrSize
		}
	}
	return strings.Join([]string{LabelRecoveryOpen, f.UserGUID, f.VaultID, f.RequestID, f.RecoveryID, f.TS, f.ETKKid,
		hexSHA(f.Secrets), hexSHA(f.Token), hexSHA(f.Manifest), hexSHA(f.UnlockSecret)}, "\n"), nil
}

// Recovery request operations (§11.14.8).
const (
	OpRecovery       = "recovery"
	OpRecoveryCancel = "recovery_cancel"
)

// RequestSigningString is what the member API's recovery request key
// signs (§11.14.8). browserKey is nil for a cancel, whose last line is
// empty.
func RequestSigningString(op, vaultID, userGUID, requestID, signedAt string, browserKey []byte) (string, error) {
	for _, s := range []string{op, vaultID, userGUID, requestID, signedAt} {
		if s == "" || strings.ContainsAny(s, "\r\n") {
			return "", ErrSize
		}
	}
	last := ""
	switch op {
	case OpRecovery:
		if len(browserKey) == 0 {
			return "", ErrSize
		}
		last = hexSHA(browserKey)
	case OpRecoveryCancel:
	default:
		return "", ErrSize
	}
	return strings.Join([]string{LabelRecoveryReq, op, vaultID, userGUID, requestID, signedAt, last}, "\n"), nil
}
