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
	// PushURL is the channel's push gateway (0.24.0, §11.10.8, §14);
	// empty: push.register is answered unavailable.
	PushURL string
	// KDF returns the KDF parameters for new vaults (default
	// vault.DefaultKDF: Argon2id t=3, m=64 MiB, p=1).
	KDF func() (vault.KDFParams, error)
	// Before027, if set, makes this instance behave as releases before
	// 0.27.0 did (§11.7.1): device bindings are written without the
	// signer, an unlock's `chain` is ignored and no signer rule is
	// applied. Tests use it to make a vault "enrolled before 0.27.0" and
	// to play the release such a vault comes from. Release
	// configurations leave it false (ReleaseConfig never sets it).
	Before027 bool
	// RecoveryNow, if set, is the clock of the recovery's delay and expiry
	// (§11.11): tests move it past the 24 h delay. Release configurations
	// leave it nil (the enclave clock).
	RecoveryNow func() time.Time
	// Recovery holds release R's constants (VAULT-MESSAGING 0.33.0
	// §11.10.8, §11.14): the attempt counter's bucket, the member API's
	// recovery request keys, the wait unit and quiet period, whether the
	// release offers recovery, and the minimum Android version code. A
	// zero Counter: the counter is unreachable (every counted operation
	// answers counter_unavailable).
	Recovery RecoveryConfig
	// TimeScale is the staging time scale (VAULT-MESSAGING 0.43.0
	// §11.10.8, STAGING-TIME-SCALE): a release image's is
	// releasecfg.Config.TimeScale (the staging file's value in the
	// staging channel, 1 otherwise); a development configuration may set
	// 1 to releasecfg.MaxDevTimeScale (devstack -time-scale). Zero: 1.
	// Read through TimeScaleOf, which returns 1 in a production image
	// whatever this says.
	TimeScale uint64
}

// TimeScaleOf is the time scale an instance runs with: 1 in an image built
// for the production channel whatever the configuration says (a second
// guard beside releasecfg's, STAGING-TIME-SCALE §4 item 2), otherwise
// cfg.TimeScale bounded to 1..releasecfg.MaxDevTimeScale.
func TimeScaleOf(cfg Config) uint64 {
	return timeScaleFor(ReleaseChannel(), cfg.TimeScale)
}

func timeScaleFor(channel string, n uint64) uint64 {
	switch {
	case channel == releasecfg.ChannelProd, n <= 1:
		return 1
	case channel == releasecfg.ChannelStaging && n != releasecfg.StagingTimeScale:
		return 1
	case n > releasecfg.MaxDevTimeScale:
		return releasecfg.MaxDevTimeScale
	}
	return n
}

// RecoveryConfig are release R's recovery constants.
type RecoveryConfig struct {
	Counter               releasecfg.Counter
	RequestKeys           []releasecfg.RequestKey
	WaitUnit              time.Duration
	Quiet                 time.Duration
	CounterLock           time.Duration // releasecfg.CounterLock (the measured channel's); zero: production's
	Offered               bool
	AndroidMinVersionCode uint64
}

// The per-channel constants (release number, manifest keys, sealing-key
// account and region, retirement principal and window, Android package
// and signing digests, iOS App ID, relay and push URLs, the optional
// features) are the committed channel file the build embeds (package
// releasecfg, §11.10.8). A build without a channel, or with an incomplete
// channel file, pins none of them and refuses every enrollment and unlock
// (fail closed): its device policy has no Android package, no signer and
// no iOS App ID, and it registers no optional feature.
//
// The Android package was a constant here until 0.26.0, the iOS App ID
// until 0.35.0; both are the channel's now (android_package, ios_app_id),
// so that a staging image accepts only the staging app and a production
// image only production's.

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

// ReleasePushURL returns the channel's push gateway ("" without complete
// channel constants); its host is on the release egress allowlist.
func ReleasePushURL() string {
	if c := release(); c != nil {
		return c.PushURL
	}
	return ""
}

// ReleaseFeatures returns the optional features this image registers
// (0.26.0, §11.10.8, "Feature allowlist"): the embedded channel file's
// list, and none without complete channel constants (such an image
// refuses every enrollment and unlock anyway). The list is part of the
// embedded file, so it is measured; nothing at run time can change it.
func ReleaseFeatures() []string {
	if c := release(); c != nil {
		return append([]string{}, c.Features...)
	}
	return []string{}
}

// ReleaseCounterHost returns the recovery counter bucket's virtual-hosted
// name ("" without complete channel constants), on the release egress
// allowlist (VAULT-HOST-PROTOCOL 0.1.10 §8, §8.1).
func ReleaseCounterHost() string {
	if c := release(); c != nil && c.RecoveryCounter.Bucket != "" {
		return c.RecoveryCounter.Host()
	}
	return ""
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
	return releaseConfigFor(release(), instanceID, relayURL)
}

// releaseConfigFor builds the configuration from channel constants c (the
// embedded ones in ReleaseConfig; nil: none).
func releaseConfigFor(c *releasecfg.Config, instanceID, relayURL string) Config {
	apple := x509.NewCertPool()
	apple.AddCert(pins.AppleAppAttestRoot())
	cfg := Config{
		InstanceID: instanceID, RelayURL: relayURL,
		DeviceAttest: &devattest.Policy{
			AndroidRoots:              pins.GoogleAttestationRoots(),
			AndroidSelfSignedBootKeys: pins.GrapheneOSVerifiedBootKeys(),
			IOSRoots:                  apple,
		},
	}
	if c != nil {
		cfg.ReleaseNumber, cfg.ManifestKeys = c.Release, c.ManifestKeys
		cfg.SealAccount, cfg.SealRegion = c.SealAccount, c.SealRegion
		cfg.RetirementPrincipal, cfg.RetirementWindowDays = c.RetirementPrincipal, c.RetirementWindowDays
		// The package is checked where an attestation is verified
		// (enrollment, a transfer's hs.init, a recovery's register,
		// §11.7); an unlock and a release approval verify the stored
		// key's signature and do not look at the package again.
		cfg.DeviceAttest.AndroidPackage = c.AndroidPackage
		// 0.35.0: the iOS App ID likewise, at an App Attest attestation
		// and at each assertion (whose rpIdHash names it).
		cfg.DeviceAttest.IOSAppID = c.IOSAppID
		// 0.27.0 (§11.7.1): the pinned signers with their classes, and
		// whether a vault enrolled before the rule may still unlock
		// unbound (staging, up to S10; never production).
		for _, sg := range c.AndroidSigners {
			cfg.DeviceAttest.AndroidSigners = append(cfg.DeviceAttest.AndroidSigners, devattest.Signer{Digest: sg.Digest, Class: sg.Class})
		}
		cfg.DeviceAttest.AndroidAcceptUnbound = c.AcceptsUnbound()
		cfg.PushURL = c.PushURL
		cfg.Recovery = RecoveryConfig{Counter: c.RecoveryCounter, RequestKeys: c.RecoveryRequestKeys,
			WaitUnit: time.Duration(c.RecoveryWaitUnitSeconds) * time.Second, Quiet: time.Duration(c.RecoveryQuietSeconds) * time.Second,
			CounterLock: c.CounterLock(), Offered: c.RecoveryOffered, AndroidMinVersionCode: c.AndroidMinVersionCode}
		cfg.DeviceAttest.AndroidMinVersionCode = c.AndroidMinVersionCode
		// 0.43.0: the measured scale, 1 outside the staging channel.
		cfg.TimeScale = c.TimeScale()
	}
	return cfg
}

// NitroRoots returns the pinned AWS Nitro root for verifying attestation
// documents (the reference client's default).
func NitroRoots() *x509.CertPool { return nitro.Pool(pins.NitroRoot()) }
