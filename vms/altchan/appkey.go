package altchan

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Enrollment codes and app keys (VAULT-MESSAGING 0.15.0, §11.12;
// ENROLLMENT-CODES.md). The app never signs in to the member API: the
// portal issues a setup code, the app redeems it with its app key, a
// per-app P-256 key that then signs every app request to the API. The
// enclave records the key (app.api_key in vault.enroll and
// vault.recovery.register, api_key in a transfer's hs.init) and reports
// it to the host; it never verifies app-key signatures (§11.12.2). These
// are the wire forms both sides share, pinned by the appkey.json vectors.

// ErrAppKey is a malformed app key, header or setup code.
var ErrAppKey = errors.New("altchan: invalid app key")

// MaxAppKeyB64 bounds an app key's base64 (a P-256 SPKI DER is 91 bytes).
const MaxAppKeyB64 = 256

// ParseAppKey parses an app key: the standard base64 of the SPKI DER of a
// P-256 public key, in its canonical encoding (§11.12.2). It returns the
// key and the DER bytes.
func ParseAppKey(b64 string) (*ecdsa.PublicKey, []byte, error) {
	if b64 == "" || len(b64) > MaxAppKeyB64 {
		return nil, nil, ErrAppKey
	}
	der, err := strictjson.DecodeStd(b64, -1)
	if err != nil {
		return nil, nil, ErrAppKey
	}
	pub, err := ParseAppKeyDER(der)
	if err != nil {
		return nil, nil, err
	}
	return pub, der, nil
}

// ParseAppKeyDER parses the SPKI DER of a P-256 public key; the DER must be
// the canonical encoding of the key it holds.
func ParseAppKeyDER(der []byte) (*ecdsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, ErrAppKey
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, ErrAppKey
	}
	again, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil || !suite.Equal(again, der) {
		return nil, ErrAppKey
	}
	return pub, nil
}

// AppKeyID is akid: the first 16 bytes of SHA-256(SPKI DER), 32 lowercase
// hex (§11.12.2).
func AppKeyID(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:16])
}

// LabelAppRequest is the first line of the app request signing string.
const LabelAppRequest = "vettid/member-api/app/1"

// AppHeaderName is the request header that carries the signature.
const AppHeaderName = "X-VettID-App"

// AppRequest is one signed app request's fields (§11.12.2).
type AppRequest struct {
	Method  string
	Path    string // as sent
	Query   string // raw, without "?"
	VaultID string // "" for a redeem
	KID     string // akid
	TS      int64  // Unix seconds
	Nonce   string // base64url of 16 bytes, no padding
	Body    []byte // exact bytes (empty for a GET)
}

// SigningString is what the app key signs (each \n a literal newline, no
// trailing newline):
//
//	"vettid/member-api/app/1" \n METHOD \n path \n query \n vault_id \n akid \n ts \n nonce \n hex(SHA-256(body))
func (r *AppRequest) SigningString() string {
	h := sha256.Sum256(r.Body)
	return strings.Join([]string{LabelAppRequest, r.Method, r.Path, r.Query, r.VaultID, r.KID,
		strconv.FormatInt(r.TS, 10), r.Nonce, hex.EncodeToString(h[:])}, "\n")
}

// NewAppNonce returns a fresh 16-byte nonce, base64url without padding.
func NewAppNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Sign signs the request with the app key and returns the header value:
//
//	v=1; vault=<vault_id or empty>; kid=<akid>; ts=<Unix s>; nonce=<b64url>; sig=<b64url DER ECDSA>
func (r *AppRequest) Sign(key *ecdsa.PrivateKey) (string, error) {
	h := sha256.Sum256([]byte(r.SigningString()))
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		return "", err
	}
	return r.Header(sig), nil
}

// Header formats the header value with sig.
func (r *AppRequest) Header(sig []byte) string {
	return "v=1; vault=" + r.VaultID + "; kid=" + r.KID + "; ts=" + strconv.FormatInt(r.TS, 10) + "; nonce=" + r.Nonce +
		"; sig=" + base64.RawURLEncoding.EncodeToString(sig)
}

// ParseAppHeader parses the header value strictly (exactly these six
// members, in this order) and returns the fields it carries and the
// signature. The caller fills Method, Path, Query and Body.
func ParseAppHeader(v string) (*AppRequest, []byte, error) {
	parts := strings.Split(v, "; ")
	names := []string{"v", "vault", "kid", "ts", "nonce", "sig"}
	if len(parts) != len(names) {
		return nil, nil, ErrAppKey
	}
	vals := make([]string, len(names))
	for i, p := range parts {
		k, val, ok := strings.Cut(p, "=")
		if !ok || k != names[i] {
			return nil, nil, ErrAppKey
		}
		vals[i] = val
	}
	if vals[0] != "1" || vals[1] != "" && !validVaultID(vals[1], false) || !lowerHex(vals[2], 32) {
		return nil, nil, ErrAppKey
	}
	ts, err := strconv.ParseInt(vals[3], 10, 64)
	if err != nil || ts <= 0 || strconv.FormatInt(ts, 10) != vals[3] {
		return nil, nil, ErrAppKey
	}
	if n, err := base64.RawURLEncoding.DecodeString(vals[4]); err != nil || len(n) != 16 ||
		base64.RawURLEncoding.EncodeToString(n) != vals[4] {
		return nil, nil, ErrAppKey
	}
	sig, err := base64.RawURLEncoding.DecodeString(vals[5])
	if err != nil || len(sig) == 0 || len(sig) > 80 || base64.RawURLEncoding.EncodeToString(sig) != vals[5] {
		return nil, nil, ErrAppKey
	}
	return &AppRequest{VaultID: vals[1], KID: vals[2], TS: ts, Nonce: vals[4]}, sig, nil
}

// Verify checks sig over the request under pub, whose akid must be the
// request's.
func (r *AppRequest) Verify(pub *ecdsa.PublicKey, der, sig []byte) bool {
	if AppKeyID(der) != r.KID {
		return false
	}
	h := sha256.Sum256([]byte(r.SigningString()))
	return ecdsa.VerifyASN1(pub, h[:], sig)
}

// The setup code (§11.12.1).
const (
	// CodeAlphabet is the typed code's 31 symbols (no 0, 1, I, L or O).
	CodeAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
	// CodeLength is the typed code's length (about 39.6 bits).
	CodeLength = 8
	// QRSecretSize is the QR secret's size: 16 bytes, 22 characters
	// base64url without padding.
	QRSecretSize = 16
	// QRTypeEnroll is the enrollment QR's `t`.
	QRTypeEnroll = "e"
)

// CodeFromBytes draws a typed code from a stream of random bytes by
// rejection sampling: bytes 248–255 are discarded, the rest taken mod 31,
// so every symbol is uniform. It returns the code and how many bytes it
// read, or ErrAppKey if the stream ran out.
func CodeFromBytes(r []byte) (string, int, error) {
	var b strings.Builder
	n := 0
	for _, c := range r {
		n++
		if c >= 248 {
			continue
		}
		b.WriteByte(CodeAlphabet[int(c)%len(CodeAlphabet)])
		if b.Len() == CodeLength {
			return b.String(), n, nil
		}
	}
	return "", n, ErrAppKey
}

// NewCode returns a fresh typed code.
func NewCode() (string, error) {
	for {
		buf := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			return "", err
		}
		if c, _, err := CodeFromBytes(buf); err == nil {
			return c, nil
		}
	}
}

// NormalizeCode normalizes a typed code as the API does: spaces and
// hyphens removed, upper case. It reports whether the result is a code of
// the alphabet (the app refuses others before sending, §11.12.1).
func NormalizeCode(s string) (string, bool) {
	s = strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(s))
	if len(s) != CodeLength {
		return s, false
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(CodeAlphabet, s[i]) < 0 {
			return s, false
		}
	}
	return s, true
}

// FormatCode shows a code as XXXX-XXXX.
func FormatCode(c string) string {
	if len(c) != CodeLength {
		return c
	}
	return c[:4] + "-" + c[4:]
}

// NormalizeEmail trims and lower-cases an email as the API does.
func NormalizeEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// EnrollQR is the setup code's QR payload (§11.12.1):
// {"v":1,"t":"e","api":"<member API origin>","s":"<22 chars base64url>"}.
type EnrollQR struct {
	API    string
	Secret []byte // 16 bytes
}

// Marshal encodes the payload in its member order.
func (q *EnrollQR) Marshal() []byte {
	return strictjson.NewBuilder().Uint("v", 1).String("t", QRTypeEnroll).String("api", q.API).
		String("s", base64.RawURLEncoding.EncodeToString(q.Secret)).Bytes()
}

// SecretString is the QR secret as carried: 22 characters base64url.
func (q *EnrollQR) SecretString() string { return base64.RawURLEncoding.EncodeToString(q.Secret) }

// ParseEnrollQR parses the payload strictly.
func ParseEnrollQR(b []byte) (*EnrollQR, error) {
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, ErrMalformed
	}
	if v, err := o.Uint("v", 1, 1); err != nil || v != 1 {
		return nil, ErrMalformed
	}
	if t, err := o.String("t"); err != nil || t != QRTypeEnroll {
		return nil, ErrMalformed
	}
	q := &EnrollQR{}
	if q.API, err = o.String("api"); err != nil || !validOrigin(q.API) {
		return nil, ErrMalformed
	}
	s, err := o.String("s")
	if err != nil {
		return nil, ErrMalformed
	}
	if q.Secret, err = ParseQRSecret(s); err != nil {
		return nil, ErrMalformed
	}
	return q, nil
}

// ParseQRSecret parses the 22-character base64url QR secret.
func ParseQRSecret(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != QRSecretSize || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, ErrAppKey
	}
	return b, nil
}

// validOrigin accepts an https origin (scheme and host, optional port, no
// path) or, for a development stack, an http one.
func validOrigin(s string) bool {
	rest, ok := strings.CutPrefix(s, "https://")
	if !ok {
		if rest, ok = strings.CutPrefix(s, "http://"); !ok {
			return false
		}
	}
	if rest == "" || len(s) > 256 || strings.ContainsAny(rest, "/?#@ \t\r\n") {
		return false
	}
	return true
}

// EmailHint is the masked email of the redeem answer and the account
// snapshot (§11.12.1, §11.13): the local part's first character, "***",
// "@" and the domain.
func EmailHint(email string) string {
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" {
		return ""
	}
	r := []rune(local)
	return string(r[0]) + "***@" + domain
}
