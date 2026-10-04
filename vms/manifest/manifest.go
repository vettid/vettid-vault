// Package manifest parses and verifies VettID's signed release manifest
// (VAULT-MESSAGING §11.10.1): the list of enclave releases, their PCRs,
// sealing keys and statuses, signed with ECDSA P-256 over the exact bytes.
//
// Apps and release images pin the manifest public keys. Since 0.10.0 an
// enroll or unlock request carries only the manifest's SHA-256 and serial;
// the host supplies the served document (from the vault data bucket's
// manifests/<sha256>.json) and the enclave verifies it against the hash in
// the sealed request (§11.3, §11.4, §11.10.4). The reference client
// verifies the manifest before it sends a PIN (§11.10.6).
package manifest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Label is the signature domain separator.
const Label = "vettid/pcr-manifest/1"

// Limits (0.10.0: 64 KiB of manifest bytes, room for 15-30 live entries
// of about 530 bytes; the served document base64-encodes them).
const (
	MaxBytes      = 65536
	MaxServed     = 90112
	MaxSealKey    = 256
	MaxNotes      = 1024
	pcrHexLen     = 96
	timeLayoutSec = "2006-01-02T15:04:05Z"
)

// Statuses (§11.10.1). The set is fixed at release 1: parsers refuse any
// other status.
const (
	StatusActive     = "active"
	StatusDeprecated = "deprecated"
	StatusRetired    = "retired"
	// StatusRemoved (0.10.0): the release has ended; its key is pending
	// deletion or deleted. Listed only while a live key admits its PCR0.
	StatusRemoved = "removed"
)

// Errors.
var (
	ErrFormat    = errors.New("manifest: malformed")
	ErrSignature = errors.New("manifest: signature invalid")
	ErrKey       = errors.New("manifest: unknown key id")
	ErrSerial    = errors.New("manifest: serial lower than one already seen")
	ErrNoRelease = errors.New("manifest: release not listed")
	// ErrMissing: no document was supplied for the request's hash.
	ErrMissing = errors.New("manifest: document missing")
	// ErrHash: the document is not the one the request names (its hash
	// or serial differs).
	ErrHash = errors.New("manifest: document does not match the request")
)

// Release is one manifest entry.
type Release struct {
	Number      uint64
	PCR0        string
	PCR1        string
	PCR2        string
	SealKey     string
	Status      string
	PublishedAt time.Time
	// EndsAt is the release's end date (0.10.0, optional; zero if
	// absent): set on deprecated and retired entries, kept on removed ones.
	EndsAt time.Time
	Notes  string
}

// Manifest is a parsed manifest.
type Manifest struct {
	Serial   uint64
	IssuedAt time.Time
	Releases []Release
	// Bytes are the exact signed bytes.
	Bytes []byte
}

func validPCR(s string) bool {
	if len(s) != pcrHexLen {
		return false
	}
	zero := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
		if c != '0' {
			zero = false
		}
	}
	return !zero // debug (all-zero) PCRs MUST NOT appear
}

// ValidPCR reports whether s is a lowercase-hex, non-debug SHA-384 PCR.
func ValidPCR(s string) bool { return validPCR(s) }

func parseSecondTime(s string) (time.Time, bool) {
	if len(s) != len(timeLayoutSec) {
		return time.Time{}, false
	}
	t, err := time.Parse(timeLayoutSec, s)
	if err != nil || t.Format(timeLayoutSec) != s {
		return time.Time{}, false
	}
	return t, true
}

func validNotes(s string) bool {
	if s == "" || len(s) > MaxNotes {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
}

func validSealKey(s string) bool {
	if s == "" || len(s) > MaxSealKey {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Parse parses manifest bytes strictly (§11.10.1): at most 65,536 bytes of
// compact JSON with the §5.3 rules, v = 1, entries sorted by unique release
// number, unique PCR0s, valid non-debug PCRs, known statuses and https
// notes, and a well-formed ends_at wherever present (its status is not
// checked, for forward compatibility). Unknown members are ignored (§5.3).
func Parse(b []byte) (*Manifest, error) {
	if len(b) == 0 || len(b) > MaxBytes {
		return nil, ErrFormat
	}
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, ErrFormat
	}
	var c bytes.Buffer
	if json.Compact(&c, b) != nil || c.Len() != len(b) {
		return nil, ErrFormat // compact JSON only
	}
	if v, err := o.Uint("v", 1, 1); err != nil || v != 1 {
		return nil, ErrFormat
	}
	m := &Manifest{Bytes: append([]byte(nil), b...)}
	if m.Serial, err = o.Uint("serial", 1, strictjson.MaxSafeInteger); err != nil {
		return nil, ErrFormat
	}
	ia, err := o.String("issued_at")
	if err != nil {
		return nil, ErrFormat
	}
	var ok bool
	if m.IssuedAt, ok = parseSecondTime(ia); !ok {
		return nil, ErrFormat
	}
	arr, err := o.Array("releases")
	if err != nil || len(arr) == 0 {
		return nil, ErrFormat
	}
	seen := map[string]bool{}
	for _, raw := range arr {
		e, err := strictjson.AsObject(raw)
		if err != nil {
			return nil, ErrFormat
		}
		var r Release
		if r.Number, err = e.Uint("release", 1, strictjson.MaxSafeInteger); err != nil {
			return nil, ErrFormat
		}
		for _, f := range []struct {
			name string
			dst  *string
		}{{"pcr0", &r.PCR0}, {"pcr1", &r.PCR1}, {"pcr2", &r.PCR2}, {"seal_key", &r.SealKey}, {"status", &r.Status}, {"notes", &r.Notes}} {
			if *f.dst, err = e.String(f.name); err != nil {
				return nil, ErrFormat
			}
		}
		if !validPCR(r.PCR0) || !validPCR(r.PCR1) || !validPCR(r.PCR2) || !validSealKey(r.SealKey) || !validNotes(r.Notes) {
			return nil, ErrFormat
		}
		switch r.Status {
		case StatusActive, StatusDeprecated, StatusRetired, StatusRemoved:
		default:
			return nil, ErrFormat
		}
		pa, err := e.String("published_at")
		if err != nil {
			return nil, ErrFormat
		}
		if r.PublishedAt, ok = parseSecondTime(pa); !ok {
			return nil, ErrFormat
		}
		if ea, present, err := e.OptString("ends_at"); err != nil {
			return nil, ErrFormat
		} else if present {
			if r.EndsAt, ok = parseSecondTime(ea); !ok {
				return nil, ErrFormat
			}
		}
		if n := len(m.Releases); n > 0 && r.Number <= m.Releases[n-1].Number {
			return nil, ErrFormat // sorted, unique release numbers
		}
		if seen[r.PCR0] {
			return nil, ErrFormat
		}
		seen[r.PCR0] = true
		m.Releases = append(m.Releases, r)
	}
	return m, nil
}

// ByPCR0 returns the entry with the given PCR0 (lowercase hex).
func (m *Manifest) ByPCR0(pcr0 string) (*Release, bool) {
	for i := range m.Releases {
		if suite.Equal([]byte(m.Releases[i].PCR0), []byte(pcr0)) {
			return &m.Releases[i], true
		}
	}
	return nil, false
}

// ByNumber returns the entry with the given release number.
func (m *Manifest) ByNumber(n uint64) (*Release, bool) {
	for i := range m.Releases {
		if m.Releases[i].Number == n {
			return &m.Releases[i], true
		}
	}
	return nil, false
}

// Newest returns the active entry with the highest release number.
func (m *Manifest) Newest() (*Release, bool) {
	for i := len(m.Releases) - 1; i >= 0; i-- {
		if m.Releases[i].Status == StatusActive {
			return &m.Releases[i], true
		}
	}
	return nil, false
}

// Served is the served document (§11.10.1).
type Served struct {
	Manifest []byte
	Sig      []byte // r || s, 64 bytes
	KeyID    string // 16 lowercase hex
}

// ParseServed parses the served document strictly. Unknown members are
// ignored.
func ParseServed(raw []byte) (*Served, error) {
	if len(raw) == 0 || len(raw) > MaxServed {
		return nil, ErrFormat
	}
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		return nil, ErrFormat
	}
	return servedFrom(o)
}

// ServedFrom parses a served document already parsed as an object (a
// member of an enroll or unlock request).
func ServedFrom(o strictjson.Object) (*Served, error) { return servedFrom(o) }

func servedFrom(o strictjson.Object) (*Served, error) {
	var s Served
	var err error
	if s.Manifest, err = o.Base64("manifest", -1); err != nil || len(s.Manifest) == 0 || len(s.Manifest) > MaxBytes {
		return nil, ErrFormat
	}
	if s.Sig, err = o.Base64("sig", 64); err != nil {
		return nil, ErrFormat
	}
	if s.KeyID, err = o.String("key_id"); err != nil || len(s.KeyID) != 16 {
		return nil, ErrFormat
	}
	if _, err := hex.DecodeString(s.KeyID); err != nil || hex.EncodeToString(mustHex(s.KeyID)) != s.KeyID {
		return nil, ErrFormat
	}
	return &s, nil
}

func mustHex(s string) []byte { b, _ := hex.DecodeString(s); return b }

// Marshal encodes the served document (members in §11.10.1 order).
func (s *Served) Marshal() []byte {
	return strictjson.NewBuilder().String("manifest", base64.StdEncoding.EncodeToString(s.Manifest)).
		String("sig", base64.StdEncoding.EncodeToString(s.Sig)).String("key_id", s.KeyID).Bytes()
}

// SHA256Hex returns hex(SHA-256(manifest bytes)): the manifest_sha256 an
// enroll or unlock request carries, and the name of the bucket object
// manifests/<sha256>.json (0.10.0).
func SHA256Hex(manifest []byte) string {
	h := sha256.Sum256(manifest)
	return hex.EncodeToString(h[:])
}

// ValidSHA256Hex reports whether s is 64 lowercase hex characters.
func ValidSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ObjectKey is the vault data bucket key of a served document by its
// manifest_sha256 (0.10.0).
func ObjectKey(sha256Hex string) string { return "manifests/" + sha256Hex + ".json" }

// KeyID returns hex(SHA-256(SubjectPublicKeyInfo DER)[0:8]).
func KeyID(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", ErrKey
	}
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:8]), nil
}

// Digest returns SHA-256("vettid/pcr-manifest/1" || 0x00 || manifest).
func Digest(manifest []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(Label))
	h.Write([]byte{0})
	h.Write(manifest)
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d
}

// Verify checks the served document against the pinned keys (key_id
// selects one) and parses the manifest. It does not apply the serial rule;
// see CheckSerial.
func Verify(s *Served, pinned []*ecdsa.PublicKey) (*Manifest, error) {
	var key *ecdsa.PublicKey
	for _, k := range pinned {
		if k == nil || k.Curve != elliptic.P256() {
			continue
		}
		if id, err := KeyID(k); err == nil && suite.Equal([]byte(id), []byte(s.KeyID)) {
			key = k
			break
		}
	}
	if key == nil {
		return nil, ErrKey
	}
	if len(s.Sig) != 64 {
		return nil, ErrSignature
	}
	d := Digest(s.Manifest)
	r := new(big.Int).SetBytes(s.Sig[:32])
	sv := new(big.Int).SetBytes(s.Sig[32:])
	if !ecdsa.Verify(key, d[:], r, sv) {
		return nil, ErrSignature
	}
	return Parse(s.Manifest)
}

// VerifyByHash verifies a served document the host supplied for a request
// that names its manifest by hash and serial (0.10.0, M1), in this order:
// a document is present, it parses, SHA-256 of its manifest bytes equals
// sha256Hex, its signature verifies under a pinned key, the manifest
// parses strictly, and its serial equals serial. The caller then applies
// the serial rule (CheckSerial) and finds its own entry.
func VerifyByHash(doc []byte, sha256Hex string, serial uint64, pinned []*ecdsa.PublicKey) (*Manifest, error) {
	if len(doc) == 0 {
		return nil, ErrMissing
	}
	s, err := ParseServed(doc)
	if err != nil {
		return nil, err
	}
	if !ValidSHA256Hex(sha256Hex) || !suite.Equal([]byte(SHA256Hex(s.Manifest)), []byte(sha256Hex)) {
		return nil, ErrHash
	}
	m, err := Verify(s, pinned)
	if err != nil {
		return nil, err
	}
	if m.Serial != serial {
		return nil, ErrHash
	}
	return m, nil
}

// CheckSerial refuses a manifest older than one already seen (§11.10.1).
func (m *Manifest) CheckSerial(seen uint64) error {
	if m.Serial < seen {
		return ErrSerial
	}
	return nil
}

// Sign signs manifest bytes (deterministically, RFC 6979) and returns the
// served document. It is used by tests, the vector generator and tooling;
// VettID's production key lives in a hardware key store.
func Sign(priv *ecdsa.PrivateKey, manifest []byte) (*Served, error) {
	d := Digest(manifest)
	der, err := priv.Sign(nil, d[:], crypto.SHA256)
	if err != nil {
		return nil, ErrSignature
	}
	var sig struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &sig); err != nil || len(rest) != 0 {
		return nil, ErrSignature
	}
	out := make([]byte, 64)
	sig.R.FillBytes(out[:32])
	sig.S.FillBytes(out[32:])
	id, err := KeyID(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Served{Manifest: append([]byte(nil), manifest...), Sig: out, KeyID: id}, nil
}

// Build writes manifest bytes in the §11.10.1 member order (tests and
// tooling).
func Build(serial uint64, issuedAt time.Time, rs []Release) []byte {
	arr := []byte{'['}
	for i, r := range rs {
		if i > 0 {
			arr = append(arr, ',')
		}
		e := strictjson.NewBuilder().Uint("release", r.Number).String("pcr0", r.PCR0).
			String("pcr1", r.PCR1).String("pcr2", r.PCR2).String("seal_key", r.SealKey).
			String("status", r.Status).String("published_at", r.PublishedAt.UTC().Format(timeLayoutSec))
		if !r.EndsAt.IsZero() {
			e.String("ends_at", r.EndsAt.UTC().Format(timeLayoutSec))
		}
		arr = append(arr, e.String("notes", r.Notes).Bytes()...)
	}
	arr = append(arr, ']')
	return strictjson.NewBuilder().Uint("v", 1).Uint("serial", serial).
		String("issued_at", issuedAt.UTC().Format(timeLayoutSec)).Raw("releases", arr).Bytes()
}
