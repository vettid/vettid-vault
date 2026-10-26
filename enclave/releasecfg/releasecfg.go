// Package releasecfg holds the constants that define a release image of
// one channel (VAULT-MESSAGING §11.10.8, VAULT-RELEASES §5.2): the
// release number, the pinned manifest keys, the sealing-key account and
// region, the retirement principal and window, the Android
// signing certificates with their classes (0.27.0), the relay URL, (VAULT-MESSAGING 0.24.0)
// the push gateway URL, (0.26.0) the Android package and the optional
// features the image registers, (0.35.0) the iOS App ID, (0.43.0) the
// staging time scale, and the staging channel's automation attestation
// roots with their end date (VAULT-RELEASES §3.1, AutomationRoots).
//
// Each channel's constants are a committed file (prod.json, staging.json)
// that the build embeds, selected by the build tag vettid_channel_prod or
// vettid_channel_staging (scripts/build-eif.sh CHANNEL=...). Everything
// that defines a release is in the tagged tree, so the image is
// reproducible from the tag; there are no -ldflags -X values and no
// build-time secrets. A build without a channel tag embeds nothing (dev
// builds, the hardware smoke test).
//
// Values that do not exist yet are placeholders ("TODO-..."). A release
// build refuses a file with any placeholder or missing value (Check), and
// an image whose embedded file is incomplete pins nothing, so it refuses
// every enrollment and unlock (fail closed).
//
// GrapheneOS verified-boot keys and the vendor roots are the same for
// every channel and stay in package pins.
package releasecfg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/devattest"
	"github.com/vettid/vettid-vault/vms/manifest"
	"github.com/vettid/vettid-vault/vms/recovery"
)

// Channels.
const (
	ChannelProd    = "prod"
	ChannelStaging = "staging"
)

// Placeholder prefixes a value that does not exist yet.
const Placeholder = "TODO-"

// Pinned retirement windows per channel (VAULT-RELEASES §3.1, §4.1).
var windowDays = map[string]uint64{ChannelProd: 30, ChannelStaging: 7}

// PushURLs are the channels' push gateways (VAULT-MESSAGING 0.24.0
// §11.10.8, PUSH-GATEWAY §10.4): a channel file must name its own, so a
// staging image can never wake through the production gateway or the
// reverse. The hosts are the ones vettid.org's DNS firewall allows.
var PushURLs = map[string]string{ChannelProd: "https://push.vettid.org", ChannelStaging: "https://push.staging.vettid.org"}

// AndroidPackages are the channels' Android packages (VAULT-MESSAGING
// 0.26.0 §11.10.8, "Android package"): a channel file must name its own,
// so a production image can never accept the staging app's package in key
// attestation, nor the reverse. One value, not a list.
var AndroidPackages = map[string]string{ChannelProd: "com.vettid.app", ChannelStaging: "com.vettid.app.staging"}

// IOSAppIDs are the channels' iOS App IDs, "<team id>.<bundle id>"
// (VAULT-MESSAGING 0.35.0 §11.10.8, "iOS App ID"): as for the Android
// package, a channel file must name its own, so a production image can
// never accept the staging app's App Attest attestations, nor the
// reverse. One value, not a list.
var IOSAppIDs = map[string]string{ChannelProd: "3X25CJ86MV.com.vettid.app", ChannelStaging: "3X25CJ86MV.com.vettid.app.staging"}

// optionalFeatures are the names a channel file's "features" may list
// (0.26.0 §11.10.8, "Feature allowlist"), in ascending byte order: the
// feature packages' own names (features/<name>). The always-registered
// features (audit, feed, messaging, credential, items, grants, critical,
// connauth) are not names of the list, so no file can switch them off.
// features/all keeps the same list (it cannot import this package);
// TestOptionalFeaturesMatchTheCode holds the two together.
var optionalFeatures = []string{"actions", "calls", "intro", "leash", "location", "presence", "wallet"}

// OptionalFeatures returns the names "features" may list, ascending.
func OptionalFeatures() []string { return append([]string(nil), optionalFeatures...) }

// Errors.
var (
	// ErrFeatureRemoved: the file's feature list lacks a name the
	// channel's previous release listed (a list only grows, 0.26.0).
	ErrFeatureRemoved = errors.New("releasecfg: a feature of the previous release is not listed")

	// ErrExpired: a staging-only switch of the file is past its end date
	// (STAGING-DEVELOPMENT-PLAN §2.5.5); the release gate refuses it.
	ErrExpired = errors.New("releasecfg: a staging-only switch is past its end date")

	ErrFormat     = errors.New("releasecfg: malformed channel file")
	ErrIncomplete = errors.New("releasecfg: placeholder or missing value")
	ErrChannel    = errors.New("releasecfg: wrong channel")
)

// Config is a channel's complete release constants.
type Config struct {
	Channel              string
	Release              uint64
	ManifestKeys         []*ecdsa.PublicKey
	SealAccount          string
	SealRegion           string
	RetirementPrincipal  string
	RetirementWindowDays int
	// AndroidSigners are the pinned Android signing certificates, each
	// with its class (0.27.0, §11.7.1, §11.10.8): 1 to 4, distinct.
	AndroidSigners []Signer
	RelayURL       string
	// PushURL is the channel's push gateway (0.24.0, §11.10.8).
	PushURL string
	// AndroidPackage is the Android package accepted in key attestation
	// (0.26.0, §11.7, §11.10.8): the channel's own.
	AndroidPackage string
	// IOSAppID is the App ID accepted in App Attest (0.35.0, §11.7,
	// §11.10.8): the channel's own.
	IOSAppID string
	// Features are the optional features the image registers (0.26.0,
	// §11.10.8), ascending; empty: none (never nil in a parsed file).
	Features []string
	// Release R (VAULT-MESSAGING 0.33.0 §11.10.8, §11.14; VAULT-RELEASES
	// 0.1.28 §5.2): the attempt counter's bucket, the member API's
	// recovery request keys, the wait unit and quiet period, whether the
	// release offers recovery, and the minimum Android version code.
	RecoveryCounter         Counter
	RecoveryRequestKeys     []RequestKey
	RecoveryWaitUnitSeconds uint64
	RecoveryQuietSeconds    uint64
	RecoveryOffered         bool
	AndroidMinVersionCode   uint64
	// FileTimeScale is the channel file's time_scale (VAULT-MESSAGING
	// 0.43.0 §11.10.8, STAGING-TIME-SCALE): production exactly 1, staging
	// 1 or 24. The vault reads it only through TimeScale, never directly.
	FileTimeScale uint64
	// Automation is the staging file's automation attestation member
	// (VAULT-RELEASES §3.1), nil without one. The image reads its roots
	// only through AutomationRoots, never directly.
	Automation *Automation
}

// Automation is the staging channel's automation attestation CA
// (VAULT-RELEASES §3.1: staging accepts "test CA and the real vendor
// roots"; owner decision 2026-10-27): Android key attestation roots
// accepted beside Google's, held by VettID's staging account, so that an
// automated test without a phone can enroll a staging app device. Until is
// the switch's end date (STAGING-DEVELOPMENT-PLAN §2.5.5): the last day,
// UTC, on which the release gate accepts the file, and no root's validity
// ends after that day, so the image itself stops accepting chains from it
// then (§11.7 chain rule 7). A production file with the member is
// malformed.
type Automation struct {
	AndroidRoots []*x509.Certificate
	Until        time.Time // 00:00 UTC of the last day
}

// The automation member's bounds: one or two roots (a rotation), and an
// end date at most MaxAutomationDays after the newest root's notBefore,
// so the switch is renewed by a reviewed change at least once a year.
const (
	maxAutomationRoots = 2
	MaxAutomationDays  = 400
)

// AutomationRoots returns the automation attestation roots this release
// accepts beside the vendor roots. Like TimeScale it is decided by the
// measured channel: the file's roots only in the staging channel, none
// for any other channel or no configuration, so no production image
// accepts them whatever its file says (Parse refuses the member there
// too).
func (c *Config) AutomationRoots() []*x509.Certificate {
	if c == nil || c.Channel != ChannelStaging || c.Automation == nil {
		return nil
	}
	return append([]*x509.Certificate(nil), c.Automation.AndroidRoots...)
}

// CheckEndDates is the release gate's date rule (STAGING-DEVELOPMENT-PLAN
// §2.5.5): a staging-only switch with an end date is refused after that
// day (UTC). It is separate from Check because it depends on the day the
// gate runs: cmd/releasecfg runs it at the build's SOURCE_DATE_EPOCH when
// one is set (an image build, so a rebuild of a tagged release stays
// reproducible) and at the current time otherwise (the release workflow's
// gate, CI). An image does not run it: its roots' validity periods end
// with the switch.
func (c *Config) CheckEndDates(now time.Time) error {
	if c != nil && c.Automation != nil && !now.UTC().Before(c.Automation.Until.AddDate(0, 0, 1)) {
		return fmt.Errorf("%w: automation_attestation ended %s", ErrExpired, c.Automation.Until.Format(time.DateOnly))
	}
	return nil
}

// Counter is the recovery attempt counter's S3 bucket (§11.14.4,
// VAULT-HOST-PROTOCOL §8.1): one per channel, in the channel's vault
// account, named vettid-org-vault-recovery-<account>.
type Counter struct {
	Bucket, Account, Region string
}

// Host is the bucket's virtual-hosted name, the only name the enclave
// reaches it by.
func (c Counter) Host() string { return c.Bucket + ".s3." + c.Region + ".amazonaws.com" }

// RequestKey is a pinned public key of the member API's recovery request
// key (§11.14.8): ECDSA P-256, with the key id the queue message names.
type RequestKey struct {
	KeyID string
	Key   *ecdsa.PublicKey
}

// The build rules of §11.14.14 (VAULT-RELEASES §5.2): a production file
// whose wait unit is below a day or whose quiet period is below 72 hours
// is malformed, so a production image can never carry staging's short
// unit. A staging file may shorten the unit (600 s); before 0.43.0 it
// kept production's quiet period.
//
// From 0.43.0 (STAGING-TIME-SCALE §5.4) the quiet period's lower bound of
// MinQuietSeconds is a production rule only: a staging file states the
// quiet period as MinQuietSeconds / time_scale (10,800 s at 24), exactly.
const (
	ProdMinWaitUnitSeconds = 86400
	MinQuietSeconds        = 259200
	// MaxQuietSeconds keeps the quiet period plus the 10-minute window of
	// step 4b below the present records' 96-hour lock (§11.14.4 G5), so a
	// timely confirming read always sees every present record that matters.
	MaxQuietSeconds     = recovery.PresentLockHours*3600 - recovery.ConfirmWindowSecs - 1
	StagingMinWaitUnit  = 60
	maxRecoverySeconds  = 30 * 86400
	CounterBucketPrefix = "vettid-org-vault-recovery-"
)

// File is a parsed channel file: the complete constants and the names of
// those still missing (placeholders, or release 0).
type File struct {
	Config  Config
	Missing []string
}

const maxFile = 16 << 10

// Parse parses a channel file strictly: exactly the members below, the
// channel's own retirement window, and every value well-formed or a
// placeholder.
func Parse(b []byte) (*File, error) {
	if len(b) == 0 || len(b) > maxFile {
		return nil, ErrFormat
	}
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, ErrFormat
	}
	members := []string{"channel", "release", "manifest_keys", "seal_account", "seal_region",
		"retirement_principal", "retirement_window_days", "android_signers", "relay_url", "push_url", "android_package", "ios_app_id", "features",
		"recovery_counter", "recovery_request_keys", "recovery_wait_unit_seconds", "recovery_quiet_seconds", "recovery_offered",
		"android_min_version_code", "time_scale"}
	// Optional members: automation_attestation (staging only).
	optional := 0
	if o.Has("automation_attestation") {
		optional++
	}
	if len(o) != len(members)+optional {
		return nil, ErrFormat
	}
	for _, m := range members {
		if !o.Has(m) {
			return nil, ErrFormat
		}
	}
	f := &File{}
	c := &f.Config
	missing := func(name string) { f.Missing = append(f.Missing, name) }
	if c.Channel, err = o.String("channel"); err != nil || windowDays[c.Channel] == 0 {
		return nil, ErrFormat
	}
	if c.Release, err = o.Uint("release", 0, strictjson.MaxSafeInteger); err != nil {
		return nil, ErrFormat
	}
	if c.Release == 0 {
		missing("release")
	}
	// Manifest keys: one or two P-256 SubjectPublicKeyInfo (base64 DER).
	keys, err := strings2(o, "manifest_keys", 1, 2)
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for _, k := range keys {
		if isPlaceholder(k) {
			missing("manifest_keys")
			continue
		}
		pub, err := parseKey(k)
		if err != nil {
			return nil, err
		}
		id, _ := manifest.KeyID(pub)
		if ids[id] {
			return nil, ErrFormat
		}
		ids[id] = true
		c.ManifestKeys = append(c.ManifestKeys, pub)
	}
	if c.SealAccount, err = value(o, "seal_account", validAccount, missing); err != nil {
		return nil, err
	}
	if c.SealRegion, err = value(o, "seal_region", validRegion, missing); err != nil {
		return nil, err
	}
	if c.RetirementPrincipal, err = value(o, "retirement_principal", validRole, missing); err != nil {
		return nil, err
	}
	if c.RetirementPrincipal != "" && c.SealAccount != "" && !strings.HasPrefix(c.RetirementPrincipal, "arn:aws:iam::"+c.SealAccount+":role/") {
		return nil, ErrFormat // the retirement role lives in the sealing-key account
	}
	w, err := o.Uint("retirement_window_days", 0, 1000)
	if err != nil || w != windowDays[c.Channel] {
		return nil, ErrFormat
	}
	c.RetirementWindowDays = int(w)
	if c.AndroidSigners, err = parseSigners(o, c.Channel, missing); err != nil {
		return nil, err
	}
	if c.RelayURL, err = value(o, "relay_url", validRelayURL, missing); err != nil {
		return nil, err
	}
	if c.PushURL, err = value(o, "push_url", func(s string) bool { return s == PushURLs[c.Channel] }, missing); err != nil {
		return nil, err
	}
	if c.AndroidPackage, err = value(o, "android_package", func(s string) bool { return s == AndroidPackages[c.Channel] }, missing); err != nil {
		return nil, err
	}
	if c.IOSAppID, err = value(o, "ios_app_id", func(s string) bool { return s == IOSAppIDs[c.Channel] }, missing); err != nil {
		return nil, err
	}
	raw, err := o.Array("features")
	if err != nil {
		return nil, ErrFormat
	}
	if c.Features, err = parseFeatures(raw); err != nil {
		return nil, err
	}
	if c.FileTimeScale, err = parseTimeScale(o, c.Channel); err != nil {
		return nil, err
	}
	if err := parseRecovery(o, c, missing); err != nil {
		return nil, err
	}
	if o.Has("automation_attestation") {
		if c.Channel != ChannelStaging {
			return nil, ErrFormat // never in production (VAULT-RELEASES §3.1)
		}
		if c.Automation, err = parseAutomation(o, missing); err != nil {
			return nil, err
		}
	}
	f.Missing = dedupe(f.Missing)
	return f, nil
}

// Signer is a pinned Android signing certificate (0.27.0, §11.7.1): the
// SHA-256 of the certificate and the class the vault reports for a vault
// bound to it.
type Signer struct {
	Digest []byte
	Class  string
}

// StagingUnboundThrough is the last staging release that lets a vault
// enrolled before 0.27.0 unlock without binding its signer (§11.7.1,
// "Vaults enrolled before 0.27.0"; owner decision 2026-10-11): S10, the
// first staging release with the rule. Staging releases after it refuse
// such a vault (signer_refused), and so does every production release.
const StagingUnboundThrough = 10

// AcceptsUnbound reports whether this release's images let an Android key
// without a recorded signer unlock unbound. It is a function of the
// measured channel and release number, never a member of the file: true
// only in the staging channel up to StagingUnboundThrough, so no
// production channel file can express it.
func (c *Config) AcceptsUnbound() bool {
	return c != nil && c.Channel == ChannelStaging && c.Release <= StagingUnboundThrough
}

// Counter lock periods (VAULT-MESSAGING 0.33.2 §11.14.4,
// VAULT-HOST-PROTOCOL 0.1.12 §8.1; owner decision 2026-10-16): how long
// the recovery attempt counter's token, success and close records are
// locked. Production 100 years, staging one day.
const (
	ProdCounterLock    = recovery.CounterLockYears * 365 * 24 * time.Hour
	StagingCounterLock = recovery.StagingCounterLockHours * time.Hour
)

// CounterLock is this release's counter lock period. Like
// AcceptsUnbound it is a function of the measured channel, never a member
// of the file or anything the host supplies: staging's period only in
// the staging channel, production's otherwise (no configuration, or any
// other channel, gets the long one).
func (c *Config) CounterLock() time.Duration {
	if c != nil && c.Channel == ChannelStaging {
		return StagingCounterLock
	}
	return ProdCounterLock
}

// The staging time scale (VAULT-MESSAGING 0.43.0 §11.10.8, VAULT-RELEASES
// 0.1.32 §5.2, STAGING-TIME-SCALE; owner decision 2026-10-18): the number
// by which the vault divides the waits of 1 hour or more that
// STAGING-TIME-SCALE §2.1 lists. A production file must say exactly 1
// (missing or a placeholder is malformed, as for every member), a staging
// file 1 or 24; a development build has no file and takes its scale from
// the dev stack (1 to MaxDevTimeScale).
const (
	ProdTimeScale    = 1
	StagingTimeScale = 24
	MaxDevTimeScale  = 86400
)

// parseTimeScale reads "time_scale": a positive integer, exactly 1 in the
// production file and 1 or 24 in the staging file.
func parseTimeScale(o strictjson.Object, channel string) (uint64, error) {
	n, err := o.Uint("time_scale", 1, MaxDevTimeScale)
	if err != nil {
		return 0, ErrFormat
	}
	switch channel {
	case ChannelProd:
		if n != ProdTimeScale {
			return 0, ErrFormat
		}
	case ChannelStaging:
		if n != 1 && n != StagingTimeScale {
			return 0, ErrFormat
		}
	default:
		return 0, ErrFormat
	}
	return n, nil
}

// TimeScale is this release's time scale. Like CounterLock it is decided
// by the measured channel: the file's value only in the staging channel
// (where Parse allows 1 or 24), and 1 for any other channel or no
// configuration, so a production image never scales whatever its file
// says (STAGING-TIME-SCALE §4 item 2).
func (c *Config) TimeScale() uint64 {
	if c != nil && c.Channel == ChannelStaging && (c.FileTimeScale == 1 || c.FileTimeScale == StagingTimeScale) {
		return c.FileTimeScale
	}
	return ProdTimeScale
}

// parseSigners reads "android_signers" (0.27.0, §11.10.8): 1 to 4
// objects {"digest": "<64 lowercase hex>", "class": "vettid" |
// "google_play" | "development"} with distinct digests. Malformed: an
// entry without a class or with an unknown one, a member besides the two,
// a repeated digest, the bare list of digest strings used before 0.27.0,
// and class development in the production file. A placeholder digest is
// reported missing, as any placeholder.
func parseSigners(o strictjson.Object, channel string, missing func(string)) ([]Signer, error) {
	arr, err := o.Array("android_signers")
	if err != nil || len(arr) < 1 || len(arr) > 4 {
		return nil, ErrFormat
	}
	var out []Signer
	seen := map[string]bool{}
	for _, raw := range arr {
		e, err := strictjson.AsObject(raw)
		if err != nil || len(e) != 2 || !e.Has("digest") || !e.Has("class") {
			return nil, ErrFormat // the bare-string form included
		}
		class, err := e.String("class")
		if err != nil || !devattest.ValidClass(class) {
			return nil, ErrFormat
		}
		if channel == ChannelProd && class == devattest.ClassDevelopment {
			return nil, ErrFormat // a development key is never pinned in production
		}
		s, err := e.String("digest")
		if err != nil {
			return nil, ErrFormat
		}
		if isPlaceholder(s) {
			missing("android_signers")
			continue
		}
		d, err := hex.DecodeString(s)
		if err != nil || len(d) != 32 || hex.EncodeToString(d) != s || seen[s] {
			return nil, ErrFormat
		}
		seen[s] = true
		out = append(out, Signer{Digest: d, Class: class})
	}
	return out, nil
}

// parseFeatures reads a "features" array (0.26.0 §11.10.8, the release
// check's rule 1): zero or more of the seven optional names, each at most
// once, in ascending byte order. Anything else is malformed: a value that
// is not a string, a placeholder, a name that is not one of the seven (an
// always-registered feature's included), a repeated name, names out of
// order.
func parseFeatures(arr []json.RawMessage) ([]string, error) {
	out := make([]string, 0, len(arr))
	for _, raw := range arr {
		s, err := strictjson.AsString(raw)
		if err != nil || !isOptional(s) {
			return nil, ErrFormat
		}
		if n := len(out); n > 0 && out[n-1] >= s {
			return nil, ErrFormat // repeated or out of order
		}
		out = append(out, s)
	}
	return out, nil
}

func isOptional(name string) bool {
	for _, n := range optionalFeatures {
		if n == name {
			return true
		}
	}
	return false
}

// PreviousFeatures reads the feature list of the channel file of a
// channel's previous release (the release check's rule 2). Only
// "channel" and "features" are read, because the file is whatever format
// its own release had: a file from before 0.26.0 has no "features" and
// counts as listing all seven, which is what those releases registered.
func PreviousFeatures(channel string, b []byte) ([]string, error) {
	if len(b) == 0 || len(b) > maxFile {
		return nil, ErrFormat
	}
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, ErrFormat
	}
	if ch, err := o.String("channel"); err != nil || windowDays[ch] == 0 {
		return nil, ErrFormat
	} else if ch != channel {
		return nil, ErrChannel
	}
	if !o.Has("features") {
		return OptionalFeatures(), nil
	}
	arr, err := o.Array("features")
	if err != nil {
		return nil, ErrFormat
	}
	return parseFeatures(arr)
}

// CheckGrows is the release check's rule 2 (0.26.0 §11.10.8, "Never
// off"): every feature the channel's previous release listed is still
// listed, because members may hold that feature's state. A name added
// passes.
func CheckGrows(c *Config, previous []string) error {
	var gone []string
	for _, p := range previous {
		found := false
		for _, n := range c.Features {
			found = found || n == p
		}
		if !found {
			gone = append(gone, p)
		}
	}
	if len(gone) > 0 {
		return fmt.Errorf("%w: %s", ErrFeatureRemoved, strings.Join(gone, ", "))
	}
	return nil
}

// Complete returns the constants, or ErrIncomplete naming what is missing.
func (f *File) Complete() (*Config, error) {
	if len(f.Missing) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrIncomplete, strings.Join(f.Missing, ", "))
	}
	c := f.Config
	return &c, nil
}

// Check is the release build's gate (scripts/build-eif.sh, the
// Dockerfile): the file parses, is the named channel's, and has no
// placeholder or missing value.
func Check(channel string, b []byte) (*Config, error) {
	f, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if f.Config.Channel != channel {
		return nil, ErrChannel
	}
	return f.Complete()
}

// Embedded returns the channel this binary was built for ("" without a
// channel tag) and its constants; nil constants if there is no channel or
// the embedded file is incomplete or malformed (the image then refuses
// every enrollment and unlock).
func Embedded() (string, *Config) {
	if channel == "" {
		return "", nil
	}
	c, err := Check(channel, embedded)
	if err != nil {
		return channel, nil
	}
	return channel, c
}

func isPlaceholder(s string) bool { return strings.HasPrefix(s, Placeholder) }

// value reads a string member: a placeholder is reported missing (""),
// anything else must be valid.
func value(o strictjson.Object, name string, valid func(string) bool, missing func(string)) (string, error) {
	s, err := o.String(name)
	if err != nil {
		return "", ErrFormat
	}
	if isPlaceholder(s) {
		missing(name)
		return "", nil
	}
	if !valid(s) {
		return "", ErrFormat
	}
	return s, nil
}

func strings2(o strictjson.Object, name string, min, max int) ([]string, error) {
	arr, err := o.Array(name)
	if err != nil || len(arr) < min || len(arr) > max {
		return nil, ErrFormat
	}
	out := make([]string, 0, len(arr))
	for _, raw := range arr {
		s, err := strictjson.AsString(raw)
		if err != nil {
			return nil, ErrFormat
		}
		out = append(out, s)
	}
	return out, nil
}

func parseKey(s string) (*ecdsa.PublicKey, error) {
	der, err := strictjson.DecodeStd(s, -1)
	if err != nil {
		return nil, ErrFormat
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, ErrFormat
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, ErrFormat
	}
	return pub, nil
}

func validAccount(a string) bool {
	if len(a) != 12 {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] < '0' || a[i] > '9' {
			return false
		}
	}
	return true
}

func validRegion(r string) bool {
	if r == "" || len(r) > 32 {
		return false
	}
	for i := 0; i < len(r); i++ {
		if c := r[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// validRole accepts arn:aws:iam::<12 digits>:role/<name> (not the root).
func validRole(s string) bool {
	const pfx = "arn:aws:iam::"
	if !strings.HasPrefix(s, pfx) || len(s) < len(pfx)+12+len(":role/")+1 || !validAccount(s[len(pfx):len(pfx)+12]) {
		return false
	}
	rest := s[len(pfx)+12:]
	if !strings.HasPrefix(rest, ":role/") {
		return false
	}
	name := rest[len(":role/"):]
	if strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || strings.Contains(name, "//") || len(name) > 512 {
		return false
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("+=,.@_-/", c) >= 0) {
			return false
		}
	}
	return true
}

// validRelayURL accepts https://<host> with no path, port, user, query or
// fragment.
func validRelayURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Port() == "" && u.User == nil &&
		u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.String() == s && strings.ToLower(u.Host) == u.Host
}

func dedupe(s []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// parseRecovery reads release R's members (§11.10.8) and applies the
// build rules of §11.14.14: the counter bucket is the channel's own (in
// the sealing account, under the pinned name), the production wait unit
// is at least a day, the production quiet period at least 72 hours, and
// (0.43.0) the staging quiet period exactly 72 hours / time_scale. It
// runs after parseTimeScale.
func parseRecovery(o strictjson.Object, c *Config, missing func(string)) error {
	co, err := o.Object("recovery_counter")
	if err != nil || len(co) != 3 || !co.Has("bucket") || !co.Has("account") || !co.Has("region") {
		return ErrFormat
	}
	if c.RecoveryCounter.Account, err = value(co, "account", validAccount, missing); err != nil {
		return err
	}
	if c.RecoveryCounter.Region, err = value(co, "region", validRegion, missing); err != nil {
		return err
	}
	if c.RecoveryCounter.Bucket, err = value(co, "bucket", func(s string) bool { return strings.HasPrefix(s, CounterBucketPrefix) }, missing); err != nil {
		return err
	}
	rc := c.RecoveryCounter
	if rc.Account != "" && (rc.Account != c.SealAccount && c.SealAccount != "" || rc.Bucket != "" && rc.Bucket != CounterBucketPrefix+rc.Account) {
		return ErrFormat // another channel's bucket or account
	}
	arr, err := o.Array("recovery_request_keys")
	if err != nil || len(arr) < 1 || len(arr) > 2 {
		return ErrFormat
	}
	seen := map[string]bool{}
	for _, raw := range arr {
		e, err := strictjson.AsObject(raw)
		if err != nil || len(e) != 2 || !e.Has("key_id") || !e.Has("spki") {
			return ErrFormat
		}
		id, err1 := e.String("key_id")
		sp, err2 := e.String("spki")
		if err1 != nil || err2 != nil {
			return ErrFormat
		}
		if isPlaceholder(id) || isPlaceholder(sp) {
			missing("recovery_request_keys")
			continue
		}
		if !validKeyID(id) || seen[id] {
			return ErrFormat
		}
		seen[id] = true
		pub, err := parseKey(sp)
		if err != nil {
			return err
		}
		c.RecoveryRequestKeys = append(c.RecoveryRequestKeys, RequestKey{KeyID: id, Key: pub})
	}
	if c.RecoveryWaitUnitSeconds, err = o.Uint("recovery_wait_unit_seconds", 1, maxRecoverySeconds); err != nil {
		return ErrFormat
	}
	min := uint64(StagingMinWaitUnit)
	if c.Channel == ChannelProd {
		min = ProdMinWaitUnitSeconds
	}
	if c.RecoveryWaitUnitSeconds < min {
		return ErrFormat
	}
	if c.RecoveryQuietSeconds, err = o.Uint("recovery_quiet_seconds", 1, MaxQuietSeconds); err != nil {
		return ErrFormat
	}
	switch c.Channel {
	case ChannelProd:
		if c.RecoveryQuietSeconds < MinQuietSeconds {
			return ErrFormat
		}
	default: // staging: the production period divided by the file's scale
		if c.FileTimeScale == 0 || c.RecoveryQuietSeconds != MinQuietSeconds/c.FileTimeScale {
			return ErrFormat
		}
	}
	if c.RecoveryOffered, err = o.Bool("recovery_offered"); err != nil {
		return ErrFormat
	}
	if c.AndroidMinVersionCode, err = o.Uint("android_min_version_code", 0, 1<<31-1); err != nil {
		return ErrFormat
	}
	if c.AndroidMinVersionCode == 0 {
		missing("android_min_version_code")
	}
	return nil
}

func validKeyID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-_:/", c) >= 0) {
			return false
		}
	}
	return true
}

// parseAutomation reads the staging file's "automation_attestation":
// {"android_roots": ["<b64 DER certificate>", ...], "until": "YYYY-MM-DD"}.
// Each root is a self-signed CA certificate with an ECDSA P-256 or P-384
// key whose validity ends no later than the end of the until day (UTC);
// the roots' keys are distinct; until is at most MaxAutomationDays after
// the newest root's notBefore. A placeholder root is reported missing.
func parseAutomation(o strictjson.Object, missing func(string)) (*Automation, error) {
	ao, err := o.Object("automation_attestation")
	if err != nil || len(ao) != 2 || !ao.Has("android_roots") || !ao.Has("until") {
		return nil, ErrFormat
	}
	us, err := ao.String("until")
	if err != nil {
		return nil, ErrFormat
	}
	until, err := time.Parse(time.DateOnly, us)
	if err != nil || until.Format(time.DateOnly) != us {
		return nil, ErrFormat
	}
	end := until.AddDate(0, 0, 1) // the first instant after the last day
	roots, err := strings2(ao, "android_roots", 1, maxAutomationRoots)
	if err != nil {
		return nil, err
	}
	a := &Automation{Until: until}
	seen := map[string]bool{}
	var newest time.Time
	for _, s := range roots {
		if isPlaceholder(s) {
			missing("automation_attestation")
			continue
		}
		der, err := strictjson.DecodeStd(s, -1)
		if err != nil {
			return nil, ErrFormat
		}
		c, err := x509.ParseCertificate(der)
		if err != nil || !c.BasicConstraintsValid || !c.IsCA || c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, ErrFormat
		}
		pub, ok := c.PublicKey.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() && pub.Curve != elliptic.P384() {
			return nil, ErrFormat
		}
		if c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) != nil {
			return nil, ErrFormat // not self-signed
		}
		if !c.NotBefore.Before(c.NotAfter) || !c.NotAfter.Before(end) || seen[string(c.RawSubjectPublicKeyInfo)] {
			return nil, ErrFormat
		}
		seen[string(c.RawSubjectPublicKeyInfo)] = true
		if c.NotBefore.After(newest) {
			newest = c.NotBefore
		}
		a.AndroidRoots = append(a.AndroidRoots, c)
	}
	if !newest.IsZero() && until.After(newest.AddDate(0, 0, MaxAutomationDays)) {
		return nil, ErrFormat
	}
	return a, nil
}
