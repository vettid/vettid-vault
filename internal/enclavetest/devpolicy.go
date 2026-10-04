package enclavetest

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/devattest"
	"github.com/vettid/vettid-vault/vms/pins"
)

// A dev device policy (DEVELOPMENT ONLY, the dev enclave's
// -dev-device-policy FILE) extends the TEST device-attestation policy
// (Policy) so that a real phone running a debug or dev-stack build of the
// app can enroll against a local dev stack with its real Keystore
// attestation. It only adds to the TEST policy; it never removes the TEST
// roots, package, signer or boot key. Release builds cannot load one: the
// flag exists only in the devenclave build of vault-enclave, and `make
// check-tcb` proves it.
//
// The file is one strict JSON object (no duplicate or unknown members,
// exact member names), at most MaxDevDevicePolicySize bytes:
//
//	{
//	  "google_attestation_roots": true,
//	  "android_roots_pem": ["-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"],
//	  "android_packages": ["com.vettid.app.dev", "com.vettid.app.devstack"],
//	  "android_signers_sha256": ["<64 hex digits, or 32 colon-separated pairs>"],
//	  "grapheneos_boot_keys": true
//	}
//
// google_attestation_roots adds pins.GoogleAttestationRoots() (the Google
// Hardware Attestation roots, including Key Attestation CA1); android_roots_pem
// adds further self-signed CA roots; android_packages are accepted besides
// com.vettid.app; android_signers_sha256 are further signing-certificate
// digests; grapheneos_boot_keys adds pins.GrapheneOSVerifiedBootKeys() for
// verifiedBootState SelfSigned. Every member is optional, but the policy
// must add something.
type DevDevicePolicy struct {
	GoogleRoots bool
	ExtraRoots  []*x509.Certificate
	Packages    []string
	Signers     [][]byte
	GrapheneOS  bool
	raw         []byte
}

// MaxDevDevicePolicySize bounds a dev device policy file (it is passed to
// each vault process as one argument).
const MaxDevDevicePolicySize = 32 << 10

// Bounds on each list.
const (
	maxDevRoots    = 8
	maxDevPackages = 16
	maxDevSigners  = 16
)

var (
	ErrDevPolicy = errors.New("enclavetest: invalid dev device policy")
	// An Android application id: two or more dot-separated segments, each
	// a letter followed by letters, digits or underscores.
	androidPackageRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)
)

var devPolicyMembers = map[string]bool{
	"google_attestation_roots": true,
	"android_roots_pem":        true,
	"android_packages":         true,
	"android_signers_sha256":   true,
	"grapheneos_boot_keys":     true,
}

func devPolicyErr(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrDevPolicy}, a...)...)
}

// ParseDevDevicePolicy parses a dev device policy file strictly.
func ParseDevDevicePolicy(b []byte) (*DevDevicePolicy, error) {
	if len(b) == 0 || len(b) > MaxDevDevicePolicySize {
		return nil, devPolicyErr("size must be 1-%d bytes", MaxDevDevicePolicySize)
	}
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDevPolicy, err)
	}
	for name := range o {
		if !devPolicyMembers[name] {
			return nil, devPolicyErr("unknown member %q", truncate(name))
		}
	}
	p := &DevDevicePolicy{raw: bytes.Clone(b)}
	if o.Has("google_attestation_roots") {
		if p.GoogleRoots, err = o.Bool("google_attestation_roots"); err != nil {
			return nil, devPolicyErr("google_attestation_roots: %v", err)
		}
	}
	if o.Has("grapheneos_boot_keys") {
		if p.GrapheneOS, err = o.Bool("grapheneos_boot_keys"); err != nil {
			return nil, devPolicyErr("grapheneos_boot_keys: %v", err)
		}
	}
	roots, err := stringList(o, "android_roots_pem", maxDevRoots)
	if err != nil {
		return nil, err
	}
	seenRoot := map[string]bool{}
	for i, s := range roots {
		c, err := parseRootPEM(s)
		if err != nil {
			return nil, devPolicyErr("android_roots_pem[%d]: %v", i, err)
		}
		if seenRoot[string(c.Raw)] {
			return nil, devPolicyErr("android_roots_pem[%d]: duplicate", i)
		}
		seenRoot[string(c.Raw)] = true
		p.ExtraRoots = append(p.ExtraRoots, c)
	}
	pkgs, err := stringList(o, "android_packages", maxDevPackages)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for i, s := range pkgs {
		if len(s) > 255 || !androidPackageRE.MatchString(s) {
			return nil, devPolicyErr("android_packages[%d]: not an Android package name", i)
		}
		if seen[s] {
			return nil, devPolicyErr("android_packages[%d]: duplicate", i)
		}
		seen[s] = true
		p.Packages = append(p.Packages, s)
	}
	signers, err := stringList(o, "android_signers_sha256", maxDevSigners)
	if err != nil {
		return nil, err
	}
	seen = map[string]bool{}
	for i, s := range signers {
		d, ok := parseDigest(s)
		if !ok {
			return nil, devPolicyErr("android_signers_sha256[%d]: not a SHA-256 digest (64 hex digits or 32 colon-separated pairs)", i)
		}
		if seen[string(d)] {
			return nil, devPolicyErr("android_signers_sha256[%d]: duplicate", i)
		}
		seen[string(d)] = true
		p.Signers = append(p.Signers, d)
	}
	if !p.GoogleRoots && !p.GrapheneOS && len(p.ExtraRoots) == 0 && len(p.Packages) == 0 && len(p.Signers) == 0 {
		return nil, devPolicyErr("the policy adds nothing")
	}
	return p, nil
}

func truncate(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

// stringList reads an optional array of strings with at most max entries.
func stringList(o strictjson.Object, name string, max int) ([]string, error) {
	arr, present, err := o.OptArray(name)
	if err != nil {
		return nil, devPolicyErr("%s: %v", name, err)
	}
	if !present {
		return nil, nil
	}
	if len(arr) > max {
		return nil, devPolicyErr("%s: at most %d entries", name, max)
	}
	out := make([]string, 0, len(arr))
	for i, raw := range arr {
		s, err := strictjson.AsString(raw)
		if err != nil {
			return nil, devPolicyErr("%s[%d]: not a string", name, i)
		}
		out = append(out, s)
	}
	return out, nil
}

// parseRootPEM parses exactly one PEM CERTIFICATE block (surrounding
// whitespace allowed) holding a self-signed CA certificate.
func parseRootPEM(s string) (*x509.Certificate, error) {
	blk, rest := pem.Decode([]byte(s))
	if blk == nil || blk.Type != "CERTIFICATE" || len(blk.Headers) != 0 {
		return nil, errors.New("not one PEM CERTIFICATE block")
	}
	if len(bytes.TrimSpace(rest)) != 0 || !strings.HasPrefix(strings.TrimSpace(s), "-----BEGIN CERTIFICATE-----\n") {
		return nil, errors.New("data outside the PEM block")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, errors.New("not an X.509 certificate")
	}
	if !c.IsCA || !c.BasicConstraintsValid {
		return nil, errors.New("not a CA certificate")
	}
	if c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) != nil {
		return nil, errors.New("not self-signed")
	}
	return c, nil
}

// parseDigest accepts 64 hex digits, or 32 colon-separated pairs (as
// keytool prints), in either case.
func parseDigest(s string) ([]byte, bool) {
	switch len(s) {
	case 2 * sha256.Size:
	case 3*sha256.Size - 1:
		for i := 2; i < len(s); i += 3 {
			if s[i] != ':' {
				return nil, false
			}
		}
		s = strings.ReplaceAll(s, ":", "")
	default:
		return nil, false
	}
	d, err := hex.DecodeString(s)
	if err != nil || len(d) != sha256.Size {
		return nil, false
	}
	return d, true
}

// Apply returns a copy of base extended by the dev policy (base is not
// modified). A nil receiver returns base unchanged.
func (p *DevDevicePolicy) Apply(base *devattest.Policy) *devattest.Policy {
	if p == nil {
		return base
	}
	out := *base
	out.AndroidRoots = append([]*x509.Certificate(nil), base.AndroidRoots...)
	if p.GoogleRoots {
		out.AndroidRoots = append(out.AndroidRoots, pins.GoogleAttestationRoots()...)
	}
	out.AndroidRoots = append(out.AndroidRoots, p.ExtraRoots...)
	out.AndroidDevPackages = append(append([]string(nil), base.AndroidDevPackages...), p.Packages...)
	out.AndroidSigners = append(append([][]byte(nil), base.AndroidSigners...), p.Signers...)
	out.AndroidSelfSignedBootKeys = append([][]byte(nil), base.AndroidSelfSignedBootKeys...)
	if p.GrapheneOS {
		out.AndroidSelfSignedBootKeys = append(out.AndroidSelfSignedBootKeys, pins.GrapheneOSVerifiedBootKeys()...)
	}
	return &out
}

// Raw returns the policy file as parsed (it is passed on to the vault
// processes, which parse it again).
func (p *DevDevicePolicy) Raw() []byte { return bytes.Clone(p.raw) }

// Summary describes the policy for logs and the dev stack's control port:
// root subjects and SHA-256 fingerprints, packages, signer digests (hex).
func (p *DevDevicePolicy) Summary() map[string]any {
	roots := []string{}
	for _, c := range p.ExtraRoots {
		fp := sha256.Sum256(c.Raw)
		roots = append(roots, c.Subject.String()+" sha256:"+hex.EncodeToString(fp[:]))
	}
	signers := []string{}
	for _, s := range p.Signers {
		signers = append(signers, hex.EncodeToString(s))
	}
	return map[string]any{
		"google_attestation_roots": p.GoogleRoots,
		"android_roots":            roots,
		"android_packages":         append([]string{}, p.Packages...),
		"android_signers_sha256":   signers,
		"grapheneos_boot_keys":     p.GrapheneOS,
	}
}
