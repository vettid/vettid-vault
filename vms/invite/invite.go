// Package invite implements the crypto and wire parts of invitations and
// pairing (VAULT-MESSAGING §6.4, §6.7): the claim bundle, its encryption
// and hash commitment, the QR / link payload, and the invite TTL rules.
package invite

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Errors.
var (
	ErrQR      = errors.New("invite: malformed QR / link payload")
	ErrBundle  = errors.New("invite: malformed bundle")
	ErrHash    = errors.New("invite: bundle does not match the commitment")
	ErrDecrypt = errors.New("invite: bundle decryption failed")
	ErrExpired = errors.New("invite: invite expired")
	ErrTTL     = errors.New("invite: TTL not allowed")
	ErrKind    = errors.New("invite: bundle kind does not match the QR")
)

// Kind is the QR `t` value: c (connection), p (app), d (desktop), a (agent).
type Kind string

const (
	KindConnection Kind = "c"
	KindApp        Kind = "p"
	KindDesktop    Kind = "d"
	KindAgent      Kind = "a"
)

// BundleKind returns the bundle `kind` that corresponds to a QR kind. §6.4
// shows "connection"; the pairing kinds are not spelled out, so this uses
// the hs.init purposes ("app", "desktop", "agent").
func (k Kind) BundleKind() (string, bool) {
	switch k {
	case KindConnection:
		return string(handshake.PurposeConnection), true
	case KindApp:
		return string(handshake.PurposeApp), true
	case KindDesktop:
		return string(handshake.PurposeDesktop), true
	case KindAgent:
		return string(handshake.PurposeAgent), true
	}
	return "", false
}

// QRVersion is the QR payload `v`.
const QRVersion = 2

// ClaimIDLen is the length of a relay claim id (RELAY-PROTOCOL §6.9).
const ClaimIDLen = 26

// QR is the QR / link payload (§6.4).
type QR struct {
	Kind    Kind
	Relay   string   // relay base URL
	ClaimID string   // 26-char lowercase base32
	Hash    [32]byte // SHA-256(blob)
	Key     []byte   // k_b, 32 bytes
	Exp     int64    // unix seconds
}

func validClaimID(s string) bool {
	if len(s) != ClaimIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

// Marshal encodes the compact JSON payload, members in the order of §6.4.
// b64url values are unpadded (RFC 4648 §5).
func (q *QR) Marshal() ([]byte, error) {
	if err := q.validate(); err != nil {
		return nil, err
	}
	return strictjson.NewBuilder().
		Uint("v", QRVersion).
		String("t", string(q.Kind)).
		String("r", q.Relay).
		String("c", q.ClaimID).
		String("h", base64.RawURLEncoding.EncodeToString(q.Hash[:])).
		String("k", base64.RawURLEncoding.EncodeToString(q.Key)).
		Uint("e", uint64(q.Exp)).
		Bytes(), nil
}

// Link returns the base64url (unpadded) encoding of the payload, for links.
func (q *QR) Link() (string, error) {
	b, err := q.Marshal()
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (q *QR) validate() error {
	if _, ok := q.Kind.BundleKind(); !ok {
		return ErrQR
	}
	if handshake.ValidateRelayURL(q.Relay) != nil || !validClaimID(q.ClaimID) || len(q.Key) != suite.KeySize || q.Exp <= 0 {
		return ErrQR
	}
	return nil
}

// ParseQR parses the compact JSON payload strictly.
func ParseQR(b []byte) (*QR, error) {
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, ErrQR
	}
	if _, err := o.Uint("v", QRVersion, QRVersion); err != nil {
		return nil, ErrQR
	}
	q := &QR{}
	t, err := o.String("t")
	if err != nil {
		return nil, ErrQR
	}
	q.Kind = Kind(t)
	if q.Relay, err = o.String("r"); err != nil {
		return nil, ErrQR
	}
	if q.ClaimID, err = o.String("c"); err != nil {
		return nil, ErrQR
	}
	hs, err := o.String("h")
	if err != nil {
		return nil, ErrQR
	}
	h, err := strictjson.DecodeRawURL(hs, 32)
	if err != nil {
		return nil, ErrQR
	}
	copy(q.Hash[:], h)
	ks, err := o.String("k")
	if err != nil {
		return nil, ErrQR
	}
	if q.Key, err = strictjson.DecodeRawURL(ks, suite.KeySize); err != nil {
		return nil, ErrQR
	}
	e, err := o.Uint("e", 1, strictjson.MaxSafeInteger)
	if err != nil {
		return nil, ErrQR
	}
	q.Exp = int64(e)
	if err := q.validate(); err != nil {
		return nil, err
	}
	return q, nil
}

// ParseLink decodes a base64url link payload and parses it.
func ParseLink(s string) (*QR, error) {
	b, err := strictjson.DecodeRawURL(s, -1)
	if err != nil || len(b) > 1024 {
		return nil, ErrQR
	}
	return ParseQR(b)
}

// BundleVersion is the bundle `v`.
const BundleVersion = 1

// MaxHintName bounds the optional hint name.
const MaxHintName = 128

// Bundle is the claim bundle (§6.4).
type Bundle struct {
	Kind     string // "connection", "app", "desktop" or "agent"
	InviteID string // ULID (the pairing id for pairing bundles)
	Remote   bool
	Vault    handshake.Principal
	Token    string    // open token, exp = invite exp
	Exp      time.Time // RFC 3339, second precision
	HintName string    // optional
}

const expLayout = "2006-01-02T15:04:05Z"

func (b *Bundle) validate() error {
	switch b.Kind {
	case "connection", "app", "desktop", "agent":
	default:
		return ErrBundle
	}
	if b.Remote && b.Kind != "connection" {
		return ErrBundle
	}
	if !envelope.ValidULID(b.InviteID) || !handshake.ValidToken(b.Token) || b.Exp.IsZero() ||
		len(b.HintName) > MaxHintName || b.Vault.KEM == nil {
		return ErrBundle
	}
	if b.Exp.Nanosecond() != 0 {
		return ErrBundle
	}
	if len(b.Vault.IK) != 32 || handshake.ValidateRelayAddr(b.Vault.Relay) != nil {
		return ErrBundle
	}
	return nil
}

// Marshal encodes the bundle JSON.
func (b *Bundle) Marshal() ([]byte, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}
	bb := strictjson.NewBuilder().
		Uint("v", BundleVersion).
		Uint("suite", uint64(suite.Suite2)).
		String("kind", b.Kind).
		String("invite_id", b.InviteID).
		Bool("remote", b.Remote).
		Raw("vault", handshake.MarshalPrincipal(b.Vault)).
		String("token", b.Token).
		String("exp", b.Exp.UTC().Format(expLayout))
	if b.HintName != "" {
		bb.Raw("hint", strictjson.NewBuilder().String("name", b.HintName).Bytes())
	}
	return bb.Bytes(), nil
}

// ParseBundle parses the bundle JSON strictly.
func ParseBundle(raw []byte) (*Bundle, error) {
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		return nil, ErrBundle
	}
	if _, err := o.Uint("v", BundleVersion, BundleVersion); err != nil {
		return nil, ErrBundle
	}
	s, err := o.Uint("suite", 0, 255)
	if err != nil {
		return nil, ErrBundle
	}
	if err := suite.Check(int(s), 0); err != nil {
		return nil, err
	}
	b := &Bundle{}
	if b.Kind, err = o.String("kind"); err != nil {
		return nil, ErrBundle
	}
	if b.InviteID, err = o.String("invite_id"); err != nil {
		return nil, ErrBundle
	}
	if b.Remote, err = o.Bool("remote"); err != nil {
		return nil, ErrBundle
	}
	vo, err := o.Object("vault")
	if err != nil {
		return nil, ErrBundle
	}
	if b.Vault, err = handshake.ParsePrincipal(vo); err != nil {
		return nil, ErrBundle
	}
	if b.Token, err = o.String("token"); err != nil {
		return nil, ErrBundle
	}
	es, err := o.String("exp")
	if err != nil {
		return nil, ErrBundle
	}
	if b.Exp, err = time.Parse(expLayout, es); err != nil || b.Exp.Format(expLayout) != es {
		return nil, ErrBundle
	}
	if o.Has("hint") {
		ho, err := o.Object("hint")
		if err != nil {
			return nil, ErrBundle
		}
		if n, _, err := ho.OptString("name"); err != nil {
			return nil, ErrBundle
		} else {
			b.HintName = n
		}
	}
	if err := b.validate(); err != nil {
		return nil, err
	}
	return b, nil
}

// SealBundle encrypts bundle JSON under a fresh random key k_b (§6.4):
//
//	blob = nonce(24) || XChaCha20-Poly1305(k_b, nonce, aad = "vettid/vms/2/bundle", json)
//
// It returns the blob, k_b and SHA-256(blob) for the QR.
func SealBundle(bundleJSON []byte) (blob, kb []byte, h [32]byte, err error) {
	if kb, err = suite.RandomBytes(suite.KeySize); err != nil {
		return nil, nil, h, err
	}
	nonce, err := suite.NewNonce()
	if err != nil {
		return nil, nil, h, err
	}
	ct, err := suite.SealX(kb, nonce, []byte(suite.LabelBundle), bundleJSON)
	if err != nil {
		return nil, nil, h, err
	}
	blob = append(nonce, ct...)
	return blob, kb, sha256.Sum256(blob), nil
}

// OpenBundle verifies a fetched claim blob against the QR and returns the
// bundle: SHA-256(blob) must equal `h` (constant time) before anything is
// decrypted; the bundle must decrypt under `k`, parse strictly, have the
// kind the QR names, expire exactly at `e`, and not have expired.
func OpenBundle(blob []byte, q *QR, now time.Time) (*Bundle, error) {
	got := sha256.Sum256(blob)
	if !suite.Equal(got[:], q.Hash[:]) {
		return nil, ErrHash
	}
	if len(blob) < suite.XNonceSize+suite.TagSize {
		return nil, ErrDecrypt
	}
	pt, err := suite.OpenX(q.Key, blob[:suite.XNonceSize], []byte(suite.LabelBundle), blob[suite.XNonceSize:])
	if err != nil {
		return nil, ErrDecrypt
	}
	b, err := ParseBundle(pt)
	if err != nil {
		return nil, err
	}
	want, _ := q.Kind.BundleKind()
	if b.Kind != want {
		return nil, ErrKind
	}
	if b.Exp.Unix() != q.Exp {
		return nil, ErrBundle
	}
	if !now.Before(b.Exp) {
		return nil, ErrExpired
	}
	return b, nil
}
