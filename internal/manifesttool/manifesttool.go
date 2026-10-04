// Package manifesttool builds, checks and signs release manifests
// (VAULT-MESSAGING §11.10.1, VAULT-RELEASES §6.1, §7) for `vaultctl
// manifest`:
//
//   - Render turns a release list (the entries of vault/releases.json or
//     a hand-written list) into canonical manifest bytes: compact JSON in
//     the §11.10.1 member order, entries sorted by release number,
//     candidates left out;
//   - Canonical reports whether manifest bytes are exactly what Render
//     would write for their content;
//   - signers sign the §11.10.1 digest: AWS KMS (key A, ECC_NIST_P256,
//     ECDSA_SHA_256 over the digest), a PEM private key file (test and
//     development keys only), or a signature made elsewhere and imported
//     (key B, on an offline hardware token);
//   - Assemble checks a signature against the pinned public keys and
//     writes the served document.
//
// Nothing here holds a real key: tests generate their own.
package manifesttool

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/vms/manifest"
)

// StatusCandidate marks a release that is in vault/releases.json (its key
// and stack exist) but not yet in the manifest (VAULT-RELEASES §10.1
// step 5). Render leaves it out.
const StatusCandidate = "candidate"

// Entry is one release in a release list. Unknown members of the list
// (vault/releases.json carries more: tag, commit, instance settings) are
// ignored.
type Entry struct {
	Release     uint64 `json:"release"`
	PCR0        string `json:"pcr0"`
	PCR1        string `json:"pcr1"`
	PCR2        string `json:"pcr2"`
	SealKey     string `json:"seal_key"`
	Status      string `json:"status"`
	PublishedAt string `json:"published_at"`
	EndsAt      string `json:"ends_at,omitempty"`
	Notes       string `json:"notes"`
}

// List is a release list: {"releases": [...]}.
type List struct {
	Releases []Entry `json:"releases"`
}

const timeLayout = "2006-01-02T15:04:05Z"

func parseTime(name, s string) (time.Time, error) {
	t, err := time.Parse(timeLayout, s)
	if err != nil || t.Format(timeLayout) != s {
		return time.Time{}, fmt.Errorf("%s %q is not RFC 3339 in whole seconds UTC", name, s)
	}
	return t, nil
}

// ParseList parses a release list. Duplicate member names are refused.
func ParseList(b []byte) (*List, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	var l List
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("release list: %w", err)
	}
	if dec.More() {
		return nil, errors.New("release list: trailing data")
	}
	return &l, nil
}

// Render writes the manifest bytes for serial and issuedAt from the
// list's entries that are not candidates, and parses them back with the
// strict parser (size, PCR, status and uniqueness rules).
func Render(l *List, serial uint64, issuedAt time.Time) ([]byte, *manifest.Manifest, error) {
	var rs []manifest.Release
	for _, e := range l.Releases {
		switch e.Status {
		case StatusCandidate:
			continue
		case manifest.StatusActive, manifest.StatusDeprecated, manifest.StatusRetired, manifest.StatusRemoved:
		default:
			return nil, nil, fmt.Errorf("release %d: unknown status %q", e.Release, e.Status)
		}
		pa, err := parseTime("published_at", e.PublishedAt)
		if err != nil {
			return nil, nil, fmt.Errorf("release %d: %w", e.Release, err)
		}
		r := manifest.Release{Number: e.Release, PCR0: e.PCR0, PCR1: e.PCR1, PCR2: e.PCR2, SealKey: e.SealKey,
			Status: e.Status, PublishedAt: pa, Notes: e.Notes}
		if e.EndsAt != "" {
			if r.EndsAt, err = parseTime("ends_at", e.EndsAt); err != nil {
				return nil, nil, fmt.Errorf("release %d: %w", e.Release, err)
			}
		}
		rs = append(rs, r)
	}
	if len(rs) == 0 {
		return nil, nil, errors.New("no release to list")
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].Number < rs[j].Number })
	if serial == 0 {
		return nil, nil, errors.New("serial must be at least 1")
	}
	b := manifest.Build(serial, issuedAt.UTC().Truncate(time.Second), rs)
	m, err := manifest.Parse(b)
	if err != nil {
		return nil, nil, fmt.Errorf("rendered manifest refused by the parser (%d bytes): %w", len(b), err)
	}
	return b, m, nil
}

// Canonical reports whether b (already parsed as m) is exactly the
// rendering of its content: no unknown members, §11.10.1 member order.
func Canonical(m *manifest.Manifest) bool {
	return bytes.Equal(manifest.Build(m.Serial, m.IssuedAt, m.Releases), m.Bytes)
}

// Summary describes manifest bytes.
type Summary struct {
	Serial   uint64   `json:"serial"`
	IssuedAt string   `json:"issued_at"`
	SHA256   string   `json:"manifest_sha256"`
	Bytes    int      `json:"bytes"`
	Object   string   `json:"object_key"`
	Releases []string `json:"releases"`
}

// Summarize describes m.
func Summarize(m *manifest.Manifest) Summary {
	s := Summary{Serial: m.Serial, IssuedAt: m.IssuedAt.UTC().Format(timeLayout), SHA256: manifest.SHA256Hex(m.Bytes),
		Bytes: len(m.Bytes), Object: manifest.ObjectKey(manifest.SHA256Hex(m.Bytes))}
	for _, r := range m.Releases {
		s.Releases = append(s.Releases, fmt.Sprintf("%d %s", r.Number, r.Status))
	}
	return s
}

// CheckSuccessor checks that next may follow prev (the published
// manifest): a higher serial (VAULT-RELEASES §7: by exactly one is the
// rule for publications; a skipped canary serial is allowed, so only
// "higher" is enforced), no release disappears while it is not removed,
// statuses only move forward, and no PCR or key of a listed release
// changes.
func CheckSuccessor(prev, next *manifest.Manifest) error {
	if next.Serial <= prev.Serial {
		return fmt.Errorf("serial %d is not above the published %d", next.Serial, prev.Serial)
	}
	rank := map[string]int{manifest.StatusActive: 0, manifest.StatusDeprecated: 1, manifest.StatusRetired: 2, manifest.StatusRemoved: 3}
	for _, p := range prev.Releases {
		n, ok := next.ByNumber(p.Number)
		if !ok {
			if p.Status != manifest.StatusRemoved {
				return fmt.Errorf("release %d (%s) is dropped before it is removed", p.Number, p.Status)
			}
			continue
		}
		if n.PCR0 != p.PCR0 || n.PCR1 != p.PCR1 || n.PCR2 != p.PCR2 || n.SealKey != p.SealKey {
			return fmt.Errorf("release %d's PCRs or seal_key changed", p.Number)
		}
		if rank[n.Status] < rank[p.Status] {
			return fmt.Errorf("release %d goes back from %s to %s", p.Number, p.Status, n.Status)
		}
	}
	return nil
}

// Signer signs a manifest digest (SHA-256 of the label, 0x00 and the
// manifest bytes) with ECDSA P-256 and returns r || s (64 bytes).
type Signer interface {
	Public(ctx context.Context) (*ecdsa.PublicKey, error)
	SignDigest(ctx context.Context, digest [32]byte) ([]byte, error)
}

// Sign signs manifest bytes with s, checks the signature and that the
// signer's key is pinned, and returns the served document.
func Sign(ctx context.Context, s Signer, manifestBytes []byte, pinned []*ecdsa.PublicKey) (*manifest.Served, error) {
	pub, err := s.Public(ctx)
	if err != nil {
		return nil, err
	}
	sig, err := s.SignDigest(ctx, manifest.Digest(manifestBytes))
	if err != nil {
		return nil, err
	}
	return Assemble(manifestBytes, sig, pub, pinned)
}

// Assemble builds the served document from manifest bytes, a signature
// (r || s, or ASN.1 DER as tokens and KMS return it) and the signing
// public key, which must be one of pinned; the signature must verify.
func Assemble(manifestBytes, sig []byte, pub *ecdsa.PublicKey, pinned []*ecdsa.PublicKey) (*manifest.Served, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil, errors.New("the signing key is not a P-256 key")
	}
	id, err := manifest.KeyID(pub)
	if err != nil {
		return nil, err
	}
	isPinned := false
	for _, k := range pinned {
		if kid, err := manifest.KeyID(k); err == nil && kid == id {
			isPinned = true
		}
	}
	if !isPinned {
		return nil, fmt.Errorf("the signing key %s is not one of the pinned manifest keys", id)
	}
	raw, err := RawSignature(sig)
	if err != nil {
		return nil, err
	}
	s := &manifest.Served{Manifest: append([]byte(nil), manifestBytes...), Sig: raw, KeyID: id}
	if _, err := manifest.Verify(s, []*ecdsa.PublicKey{pub}); err != nil {
		return nil, err
	}
	return s, nil
}

// RawSignature converts a signature to r || s: 64 raw bytes are taken as
// they are, anything else must be an ASN.1 DER ECDSA signature.
func RawSignature(sig []byte) ([]byte, error) {
	if len(sig) == 64 {
		return append([]byte(nil), sig...), nil
	}
	var v struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(sig, &v)
	if err != nil || len(rest) != 0 || v.R == nil || v.S == nil || v.R.Sign() <= 0 || v.S.Sign() <= 0 ||
		v.R.BitLen() > 256 || v.S.BitLen() > 256 {
		return nil, errors.New("signature is neither 64 raw bytes (r || s) nor an ASN.1 DER ECDSA signature")
	}
	out := make([]byte, 64)
	v.R.FillBytes(out[:32])
	v.S.FillBytes(out[32:])
	return out, nil
}

// DecodeBytes reads a signature or key file's content: PEM, hex or
// base64 text, or raw binary.
func DecodeBytes(b []byte) []byte {
	for _, c := range b {
		if (c < 0x20 || c > 0x7e) && c != '\n' && c != '\r' && c != '\t' {
			return b // binary
		}
	}
	t := strings.TrimSpace(string(b))
	if p, _ := pem.Decode([]byte(t)); p != nil {
		return p.Bytes
	}
	if h, err := hex.DecodeString(t); err == nil && len(t) > 0 {
		return h
	}
	if d, err := base64.StdEncoding.DecodeString(t); err == nil && len(t) > 0 {
		return d
	}
	return b
}

// ParsePublicKey reads a P-256 public key: SubjectPublicKeyInfo as PEM,
// base64 or hex DER (as in the channel files).
func ParsePublicKey(b []byte) (*ecdsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(DecodeBytes(b))
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("public key: not ECDSA P-256")
	}
	return pub, nil
}

// FileSigner signs with a PEM private key ("EC PRIVATE KEY" or PKCS #8).
// For test and development manifests only: production keys never leave
// KMS or the offline token.
type FileSigner struct{ Key *ecdsa.PrivateKey }

// ParsePrivateKey reads a PEM P-256 private key.
func ParsePrivateKey(b []byte) (*ecdsa.PrivateKey, error) {
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, errors.New("private key: not PEM")
	}
	if k, err := x509.ParseECPrivateKey(p.Bytes); err == nil && k.Curve == elliptic.P256() {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		return nil, fmt.Errorf("private key: %w", err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("private key: not ECDSA P-256")
	}
	return ek, nil
}

// Public implements Signer.
func (f FileSigner) Public(context.Context) (*ecdsa.PublicKey, error) { return &f.Key.PublicKey, nil }

// SignDigest implements Signer.
func (f FileSigner) SignDigest(_ context.Context, d [32]byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, f.Key, d[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}
