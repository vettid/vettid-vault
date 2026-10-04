// Package devattest verifies platform device attestation inside the
// enclave (VAULT-MESSAGING §11.7): Android hardware key attestation and
// iOS App Attest at enrollment and app pairing, and the device-key
// signatures (device_assertion, release approvals) at every unlock.
//
// Verification is local cryptography against vendor roots pinned in the
// image (package pins); tests use test roots. The attested key and the data
// needed for later checks form a Binding, which the enclave stores in the
// sealed header with the app's unlock key and never releases: attestation
// keys and chains are stable device identifiers.
package devattest

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/vms/altchan"
)

// Errors. They name the failed check and never carry input bytes.
var (
	ErrFormat         = errors.New("devattest: malformed attestation")
	ErrPlatform       = errors.New("devattest: platform not allowed")
	ErrChain          = errors.New("devattest: certificate chain invalid")
	ErrRoot           = errors.New("devattest: chain does not end at a pinned root")
	ErrChallenge      = errors.New("devattest: challenge mismatch")
	ErrSecurityLevel  = errors.New("devattest: key not hardware-backed")
	ErrRootOfTrust    = errors.New("devattest: device not locked or boot not verified (or OS key not allowed)")
	ErrApplication    = errors.New("devattest: application id mismatch")
	ErrKeyProperties  = errors.New("devattest: key properties not allowed")
	ErrRevoked        = errors.New("devattest: certificate revoked")
	ErrRevocationList = errors.New("devattest: revocation status list missing or stale")
	ErrSignature      = errors.New("devattest: signature invalid")
	ErrCounter        = errors.New("devattest: assertion counter did not increase")
	ErrEnvironment    = errors.New("devattest: not the production App Attest environment")
	ErrKeyID          = errors.New("devattest: key id mismatch")
)

// Policy is what a release pins (§11.7). An empty Android package or iOS
// App ID disables that platform: verification fails closed.
type Policy struct {
	AndroidRoots []*x509.Certificate // compared by SubjectPublicKeyInfo
	// AndroidPackage is the VettID app's package name.
	AndroidPackage string
	// AndroidDevPackages are further package names accepted in place of
	// AndroidPackage. Development only: set by the dev enclave's device
	// policy file (debug and dev-stack application ids);
	// release configurations leave it empty.
	AndroidDevPackages []string
	// AndroidSigners are SHA-256 digests of the app's signing
	// certificates; every digest in an attestation must be listed.
	AndroidSigners [][]byte
	// AndroidMinVersion is the lowest attestationVersion accepted.
	AndroidMinVersion int64
	// AndroidSelfSignedBootKeys are the verified boot key fingerprints
	// (RootOfTrust.verifiedBootKey, 32 bytes) for which verifiedBootState
	// SelfSigned is accepted: the GrapheneOS keys pinned in the release
	// (pins.GrapheneOSVerifiedBootKeys, §11.7, 0.9.0). Empty: Verified only.
	AndroidSelfSignedBootKeys [][]byte

	IOSRoots *x509.CertPool
	// IOSAppID is "<team id>.<bundle id>".
	IOSAppID string
}

// Revocation lists for enrollment and unlock (§11.7).
const (
	EnrollListMaxAge = 24 * time.Hour
	UnlockListMaxAge = 7 * 24 * time.Hour
)

// Binding is the attested device key and what later checks need. It is
// stored only in the sealed header.
type Binding struct {
	Platform string `json:"platform"`
	// PublicKey: Android: the attested key's SubjectPublicKeyInfo (DER,
	// P-256). iOS: the uncompressed P-256 point (65 bytes).
	PublicKey []byte `json:"pk"`
	// Serials are the Android chain's certificate serial numbers (lowercase
	// hex), rechecked against the status list at each unlock.
	Serials []string `json:"serials,omitempty"`
	// KeyID and Counter are the App Attest key id and the highest
	// assertion counter seen.
	KeyID   []byte `json:"key_id,omitempty"`
	Counter uint32 `json:"counter"`
}

// Signed is what a device signs with its attestation key: Android signs
// Message with ECDSA-SHA256; iOS asserts with ClientDataHash.
type Signed struct {
	Message        []byte
	ClientDataHash [32]byte
}

// ForChallenge is the unlock device_assertion (§11.7): Android signs the
// 32-byte challenge, iOS uses it as clientDataHash.
func ForChallenge(ch [32]byte) Signed { return Signed{Message: ch[:], ClientDataHash: ch} }

// ForString is a signed string such as the release approval (§11.10.3):
// Android signs its bytes, iOS asserts with clientDataHash = SHA-256(s).
func ForString(s string) Signed {
	return Signed{Message: []byte(s), ClientDataHash: sha256.Sum256([]byte(s))}
}

// VerifyAttest verifies a device_attest object against the challenge
// (§11.7) and returns the binding. Android requires a status list fetched
// within the last 24 h.
func VerifyAttest(p *Policy, d *altchan.DeviceAttest, challenge [32]byte, now time.Time, list *StatusList) (*Binding, error) {
	if p == nil || d == nil {
		return nil, ErrFormat
	}
	switch d.Platform {
	case altchan.PlatformAndroid:
		b, err := verifyAndroid(p, d.Chain, challenge, now)
		if err != nil {
			return nil, err
		}
		if err := list.Check(b.Serials, now, EnrollListMaxAge); err != nil {
			return nil, err
		}
		return b, nil
	case altchan.PlatformIOS:
		return verifyIOS(p, d.KeyID, d.Attestation, challenge, now)
	}
	return nil, ErrPlatform
}

// VerifyAssertion verifies a device_assertion (or a release approval) made
// with the bound key and returns the updated binding (the iOS counter
// advances). minCounter is the counter the assertion must exceed (iOS);
// pass b.Counter normally. Android rechecks the stored chain against a
// status list at most 7 days old.
func VerifyAssertion(p *Policy, b *Binding, a *altchan.DeviceAssertion, s Signed, minCounter uint32, now time.Time, list *StatusList) (*Binding, error) {
	if p == nil || b == nil || a == nil || a.Platform != b.Platform {
		return nil, ErrPlatform
	}
	switch b.Platform {
	case altchan.PlatformAndroid:
		if p.AndroidPackage == "" {
			return nil, ErrPlatform
		}
		if err := verifyAndroidSig(b, s.Message, a.Sig); err != nil {
			return nil, err
		}
		if err := list.Check(b.Serials, now, UnlockListMaxAge); err != nil {
			return nil, err
		}
		nb := *b
		return &nb, nil
	case altchan.PlatformIOS:
		if p.IOSAppID == "" {
			return nil, ErrPlatform
		}
		c, err := verifyIOSAssertion(p, b, a.Assertion, s.ClientDataHash, minCounter)
		if err != nil {
			return nil, err
		}
		nb := *b
		if c > nb.Counter {
			nb.Counter = c
		}
		return &nb, nil
	}
	return nil, ErrPlatform
}
