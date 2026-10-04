// Package releasecfg holds the constants that define a release image of
// one channel (VAULT-MESSAGING §11.10.8, VAULT-RELEASES §5.2): the
// release number, the pinned manifest keys, the sealing-key account and
// region, the retirement principal and window, the Android
// signing-certificate digests and the relay URL.
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
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/manifest"
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

// Errors.
var (
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
	AndroidSigners       [][]byte
	RelayURL             string
}

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
		"retirement_principal", "retirement_window_days", "android_signers", "relay_url"}
	if len(o) != len(members) {
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
	signers, err := strings2(o, "android_signers", 1, 4)
	if err != nil {
		return nil, err
	}
	for _, s := range signers {
		if isPlaceholder(s) {
			missing("android_signers")
			continue
		}
		d, err := hex.DecodeString(s)
		if err != nil || len(d) != 32 || hex.EncodeToString(d) != s {
			return nil, ErrFormat
		}
		c.AndroidSigners = append(c.AndroidSigners, d)
	}
	if c.RelayURL, err = value(o, "relay_url", validRelayURL, missing); err != nil {
		return nil, err
	}
	f.Missing = dedupe(f.Missing)
	return f, nil
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
