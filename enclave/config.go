package enclave

import (
	"crypto/ecdsa"
	"crypto/x509"
	"time"

	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/devattest"
	"github.com/vettid/vettid-vault/vms/nitro"
	"github.com/vettid/vettid-vault/vms/pins"
)

// Config is what a release image pins (§11.7, §11.10).
type Config struct {
	// InstanceID names this instance in descriptors (§11.2).
	InstanceID string
	// ReleaseNumber is the number this image embeds (covered by PCR0,
	// §11.10.1). It must match the manifest entry for the running PCR0.
	ReleaseNumber uint64
	// ManifestKeys are the pinned manifest public keys (one or two).
	ManifestKeys []*ecdsa.PublicKey
	// SealAccount and SealRegion are the pinned sealing-key namespace
	// (§11.10.2).
	SealAccount, SealRegion string
	// DeviceAttest is the device attestation policy (§11.7).
	DeviceAttest *devattest.Policy
	// RelayURL is the relay new vaults register at (§11.3).
	RelayURL string
	// KDF returns the KDF parameters for new vaults (default
	// vault.DefaultKDF: Argon2id t=3, m=64 MiB, p=1).
	KDF func() (vault.KDFParams, error)
	// RecoveryNow, if set, is the clock of the recovery's delay and expiry
	// (§11.11): tests move it past the 24 h delay. Release configurations
	// leave it nil (the enclave clock).
	RecoveryNow func() time.Time
}

// Release pins. Values that VAULT-PLAN phase V5 creates (the manifest
// key, the sealing-key account and region) and the Android app-signing
// certificate digest are not known yet: they are empty, and an image built
// with them empty refuses every enrollment and unlock (fail closed).
const (
	releaseNumber  = 0 // set per release; 0 is not a release
	androidPackage = "com.vettid.app"
	iosAppID       = "3X25CJ86MV.com.vettid.app"
	sealAccount    = ""
	sealRegion     = ""
)

// ReleaseRelayURL is the relay release vaults register at (§11.3), and the
// only relay host on the release egress allowlist.
const ReleaseRelayURL = "https://relay.vettid.org"

// ReleaseRegion returns the pinned sealing-key region ("" until V5), which
// is also the region of the KMS endpoint on the egress allowlist.
func ReleaseRegion() string { return sealRegion }

// androidSigners are the SHA-256 digests of the VettID app's signing
// certificates (pinned with the first release).
var androidSigners [][]byte

// manifestKeys are the pinned manifest public keys (V5).
var manifestKeys []*ecdsa.PublicKey

// ReleaseConfig returns the configuration a release image runs with: the
// vendor roots from package pins and the constants above.
func ReleaseConfig(instanceID, relayURL string) Config {
	apple := x509.NewCertPool()
	apple.AddCert(pins.AppleAppAttestRoot())
	return Config{
		InstanceID: instanceID, ReleaseNumber: releaseNumber, ManifestKeys: manifestKeys,
		SealAccount: sealAccount, SealRegion: sealRegion, RelayURL: relayURL,
		DeviceAttest: &devattest.Policy{
			AndroidRoots: pins.GoogleAttestationRoots(), AndroidPackage: androidPackage, AndroidSigners: androidSigners,
			IOSRoots: apple, IOSAppID: iosAppID,
		},
	}
}

// NitroRoots returns the pinned AWS Nitro root for verifying attestation
// documents (the reference client's default).
func NitroRoots() *x509.CertPool { return nitro.Pool(pins.NitroRoot()) }
