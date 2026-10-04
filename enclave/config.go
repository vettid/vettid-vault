package enclave

import (
	"crypto/ecdsa"
	"crypto/x509"
	"time"

	"github.com/vettid/vettid-vault/enclave/releasecfg"
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
	// RetirementPrincipal and RetirementWindowDays are the pinned
	// retirement role and pending window that a release key's policy may
	// allow to schedule its deletion (§11.10.7, 0.10.0); empty: no key
	// may allow it.
	RetirementPrincipal  string
	RetirementWindowDays int
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

// Release pins that are the same in every channel. The per-channel
// constants (release number, manifest keys, sealing-key account and
// region, retirement principal and window, Android signing digests, relay
// URL) are the committed channel file the build embeds (package
// releasecfg, §11.10.8). A build without a channel, or with an incomplete
// channel file, pins none of them and refuses every enrollment and unlock
// (fail closed).
const (
	androidPackage = "com.vettid.app"
	iosAppID       = "3X25CJ86MV.com.vettid.app"
)

// DefaultRelayURL is the relay of a build without channel constants.
const DefaultRelayURL = "https://relay.vettid.org"

// release returns the embedded channel constants, or nil.
func release() *releasecfg.Config {
	_, c := releasecfg.Embedded()
	return c
}

// ReleaseChannel returns the channel this image was built for ("" for a
// build without one).
func ReleaseChannel() string {
	ch, _ := releasecfg.Embedded()
	return ch
}

// ReleaseRelayURL returns the relay release vaults register at (§11.3);
// its host is the only relay host on the release egress allowlist.
func ReleaseRelayURL() string {
	if c := release(); c != nil {
		return c.RelayURL
	}
	return DefaultRelayURL
}

// ReleaseRegion returns the pinned sealing-key region ("" without
// complete channel constants), which is also the region of the KMS
// endpoint on the egress allowlist.
func ReleaseRegion() string {
	if c := release(); c != nil {
		return c.SealRegion
	}
	return ""
}

// ReleaseConfig returns the configuration a release image runs with: the
// vendor roots from package pins and the embedded channel constants.
func ReleaseConfig(instanceID, relayURL string) Config {
	apple := x509.NewCertPool()
	apple.AddCert(pins.AppleAppAttestRoot())
	cfg := Config{
		InstanceID: instanceID, RelayURL: relayURL,
		DeviceAttest: &devattest.Policy{
			AndroidRoots: pins.GoogleAttestationRoots(), AndroidPackage: androidPackage,
			AndroidSelfSignedBootKeys: pins.GrapheneOSVerifiedBootKeys(),
			IOSRoots:                  apple, IOSAppID: iosAppID,
		},
	}
	if c := release(); c != nil {
		cfg.ReleaseNumber, cfg.ManifestKeys = c.Release, c.ManifestKeys
		cfg.SealAccount, cfg.SealRegion = c.SealAccount, c.SealRegion
		cfg.RetirementPrincipal, cfg.RetirementWindowDays = c.RetirementPrincipal, c.RetirementWindowDays
		cfg.DeviceAttest.AndroidSigners = c.AndroidSigners
	}
	return cfg
}

// NitroRoots returns the pinned AWS Nitro root for verifying attestation
// documents (the reference client's default).
func NitroRoots() *x509.CertPool { return nitro.Pool(pins.NitroRoot()) }
