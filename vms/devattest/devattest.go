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
	"encoding/hex"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/suite"
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
	// AndroidAutomationRoots are the staging automation attestation CA's
	// roots (VAULT-RELEASES §3.1, VAULT-MESSAGING 0.66.0 §11.10.8),
	// accepted beside AndroidRoots: a chain ending at one of them must
	// report a signer of class automation, and a chain ending at any other
	// root must not. Only a staging configuration sets it
	// (releasecfg.Config.AutomationRoots).
	AndroidAutomationRoots []*x509.Certificate
	// AndroidPackage is the VettID app's package name.
	AndroidPackage string
	// AndroidMinVersionCode is the release constant
	// android_min_version_code (0.33.0, release R, §11.14.14): an
	// attestation of an older app version is refused; 0: no minimum.
	AndroidMinVersionCode uint64
	// AndroidDevPackages are further package names accepted in place of
	// AndroidPackage. Development only: set by the dev enclave's device
	// policy file (debug and dev-stack application ids);
	// release configurations leave it empty.
	AndroidDevPackages []string
	// AndroidSigners are the app signing certificates the release pins
	// (§11.7.1, §11.10.8): an attestation must report exactly one signing
	// digest, and it must be one of these.
	AndroidSigners []Signer
	// AndroidAcceptUnbound lets an Android key whose binding holds no
	// signer (a vault enrolled before 0.27.0) unlock without the
	// certificate chain that would bind it. It is the staging channel's
	// exception at release S10 (§11.7.1, "Vaults enrolled before 0.27.0");
	// no production configuration sets it (releasecfg.AcceptsUnbound).
	AndroidAcceptUnbound bool
	// AndroidMinVersion is the lowest attestationVersion accepted.
	AndroidMinVersion int64
	// AndroidSelfSignedBootKeys are the verified boot key fingerprints
	// (RootOfTrust.verifiedBootKey, 32 bytes) for which verifiedBootState
	// SelfSigned is accepted: the GrapheneOS keys pinned in the release
	// (pins.GrapheneOSVerifiedBootKeys, §11.7, 0.9.0). Empty: Verified only.
	AndroidSelfSignedBootKeys [][]byte

	IOSRoots *x509.CertPool
	// IOSAppID is "<team id>.<bundle id>": the channel's ios_app_id
	// (0.35.0, §11.10.8) in a release configuration.
	IOSAppID string
	// IOSDevAppIDs are further App IDs accepted in place of IOSAppID, at
	// an attestation and at each assertion. Development only: set by the
	// dev enclave's device policy file (the debug and dev-stack bundle
	// ids); release configurations leave it empty.
	IOSDevAppIDs []string
	// IOSDevelopmentEnvironment also accepts the development App Attest
	// environment (aaguid "appattestdevelop"). Development only, like
	// IOSDevAppIDs; a release configuration accepts production only.
	IOSDevelopmentEnvironment bool
}

// Signer classes (§11.7.1): what the vault reports for a vault bound to
// a pinned signer. Identifiers, never member-facing wording.
const (
	ClassVettID      = "vettid"      // a key only VettID holds: the F-Droid and direct builds
	ClassGooglePlay  = "google_play" // the Play app-signing key, which Google holds
	ClassDevelopment = "development" // a development key; never in a production release
	// ClassAutomation is the staging automation's signer (0.66.0): a
	// digest no APK can carry, reported only by chains of the staging
	// automation attestation CA; never in a production release.
	ClassAutomation = "automation"
)

// ValidClass reports whether c is a signer class.
func ValidClass(c string) bool {
	return c == ClassVettID || c == ClassGooglePlay || c == ClassDevelopment || c == ClassAutomation
}

// Signer is a pinned Android signing certificate: the SHA-256 of the
// certificate and its class.
type Signer struct {
	Digest []byte
	Class  string
}

// SignerClass returns the class of the pinned signer with this digest
// (64 lowercase hex digits, as a Binding records it), and whether the
// release pins it.
func (p *Policy) SignerClass(digestHex string) (string, bool) {
	if p == nil || len(digestHex) != 2*sha256.Size {
		return "", false
	}
	class, pinned := "", false
	for _, s := range p.AndroidSigners {
		if len(s.Digest) == sha256.Size && suite.Equal([]byte(hex.EncodeToString(s.Digest)), []byte(digestHex)) {
			class, pinned = s.Class, true
		}
	}
	return class, pinned
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
	// Signer (Android, 0.27.0, §11.7.1) is the signing-certificate digest
	// the key's attestation reported: 64 lowercase hex digits. Empty in a
	// binding made before 0.27.0 (the key is then unbound) and on iOS.
	Signer string `json:"signer,omitempty"`
	// SignerClass is the class the recording release gave that signer. It
	// is kept so that a later release that no longer pins the signer can
	// still name its class in device.signer_changed; what a running
	// release reports for a pinned signer is always its own class.
	SignerClass string `json:"signer_class,omitempty"`
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
		b, err := verifyAndroid(p, d.Chain, &challenge, &now)
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

// Signer refusal reasons (§11.7.1, the `ref` of device.signer_refused).
const (
	RefusedUnpinned = "unpinned" // the recorded signer is not pinned by the running release
	RefusedUnbound  = "unbound"  // no recorded signer and no valid chain
)

// CheckSigner is the 0.27.0 rule for an Android key whose signature has
// just verified (an unlock's device_assertion or a release approval,
// §11.7.1): the key's recorded signer must be pinned by the running
// release. It returns "" when the key may go on, or the refusal's reason.
// An iOS binding has no signer and always passes. A binding without a
// signer passes only under AndroidAcceptUnbound (staging S10); binding it
// from a chain is BindSigner, which the caller tries first.
func CheckSigner(p *Policy, b *Binding) string {
	if p == nil || b == nil || b.Platform != altchan.PlatformAndroid {
		return ""
	}
	if b.Signer == "" {
		if p.AndroidAcceptUnbound {
			return ""
		}
		return RefusedUnbound
	}
	if _, pinned := p.SignerClass(b.Signer); !pinned {
		return RefusedUnpinned
	}
	return ""
}

// BindSigner binds an Android key that has no recorded signer from the
// certificate chain of that key, re-sent by the app (§11.7.1, "Vaults
// enrolled before 0.27.0"). The chain is verified as at attestation
// (pinned root, the chain rules of checkAndroidChain, the attestation
// extension, the channel's package, exactly one pinned signing digest),
// with two differences: the leaf's public key
// must equal the bound key and the chain's serial numbers must equal the
// stored ones, and the challenge and the certificates' validity periods
// are not checked again (both were when the chain was first accepted, and
// the equal serials tie this chain to that one). A chain ending at an
// automation root is refused (ErrRoot): no unbound key was enrolled
// through one, and its until would go unchecked. It returns the binding
// with the signer recorded. Any failure is ErrApplication, ErrChain or
// the attestation error; the caller answers `attestation`. That includes
// a chain an earlier release accepted and this one refuses (a chain
// extended below an attested key): such a key stays unbound.
func BindSigner(p *Policy, b *Binding, chain [][]byte) (*Binding, error) {
	if p == nil || b == nil || b.Platform != altchan.PlatformAndroid || b.Signer != "" {
		return nil, ErrPlatform
	}
	nb, err := verifyAndroid(p, chain, nil, nil)
	if err != nil {
		return nil, err
	}
	// A binding without a signer predates the automation CA, and the
	// validity periods are not checked here, so an automation chain is
	// never bound this way.
	if nb.SignerClass == ClassAutomation {
		return nil, ErrRoot
	}
	if !suite.Equal(nb.PublicKey, b.PublicKey) || len(nb.Serials) != len(b.Serials) {
		return nil, ErrChain
	}
	for i := range nb.Serials {
		if nb.Serials[i] != b.Serials[i] {
			return nil, ErrChain
		}
	}
	out := *b
	out.Signer, out.SignerClass = nb.Signer, nb.SignerClass
	return &out, nil
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
