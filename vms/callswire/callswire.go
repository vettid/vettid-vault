// Package callswire is the wire format of the calling service's credential issuer as a vault uses it
// (CALLING-SERVICE §5.2, VAULT-MESSAGING §10.10 "Servers and credentials"): the request's body, the answer and
// the vault's checks of it, and the error codes. The request is signed per Relay Protocol §4.1 with an Ed25519 key
// made for that one request and carries a Nitro attestation of it (Client).
//
// The vault does not interpret a username: a credential is opaque, checked only for its shape and its expiry.
package callswire

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/vms/callwire"
	"github.com/vettid/vettid-vault/vms/strictjson"
)

// Issuer paths and the attestation header (CALLING-SERVICE §5.2).
const (
	PathCredentials   = "/v1/credentials"
	PathHealth        = "/v1/health"
	HeaderAttestation = "X-VettID-Attestation"
)

// Issuer error codes (CALLING-SERVICE §5.2; Relay Protocol §7.1 grammar).
const (
	CodeSignatureInvalid   = "signature_invalid"
	CodeTimestampStale     = "timestamp_stale"
	CodeAttestationInvalid = "attestation_invalid"
	CodeBadRequest         = "bad_request"
	CodeRateLimited        = "rate_limited"
	CodeInternal           = "internal"
)

// Sizes and bounds (VAULT-MESSAGING §10.10).
const (
	// MaxCount is the most credentials one request asks for, and the most an answer may carry.
	MaxCount = 4
	// MaxURLs is the most URLs of each kind (STUN, TURN) an answer may carry.
	MaxURLs = 4
	// MaxField bounds a username and a credential (1-512 bytes, no control characters).
	MaxField = 512
	// MaxAhead is a credential's lifetime as the issuer stamps it: exp 6 h after the issuer's clock (CALLING-SERVICE
	// §5.3, D14).
	MaxAhead = 6 * time.Hour
	// ExpAllowance is how far the vault's clock may be behind the issuer's: an exp is accepted up to MaxAhead +
	// ExpAllowance ahead of the vault's clock (VAULT-MESSAGING §10.10, 0.90.14). A clock allowance, not a longer
	// lifetime: without it a vault clock behind by a second would discard every answer.
	ExpAllowance = 5 * time.Minute
	// MaxAnswer bounds an answer's body. The enclave's supervisor passes at most MaxAnswer+1 bytes on, so an
	// oversized answer is still recognised behind it.
	MaxAnswer = 16 << 10
)

// ErrResponse is an answer that does not pass the vault's checks: it is discarded as a failed attempt.
var ErrResponse = errors.New("callswire: issuer answer refused")

// Credential is one TURN credential: opaque to the vault. It prints no username or credential.
type Credential struct {
	Username   string
	Credential string
	Exp        time.Time // whole seconds
}

// String keeps the credential out of logs and errors: only its expiry.
func (c Credential) String() string {
	return "callswire.Credential{exp: " + c.Exp.UTC().Format(time.RFC3339) + "}"
}

// GoString is String, for %#v.
func (c Credential) GoString() string { return c.String() }

// Answer is a checked issuer answer. It prints no credential.
type Answer struct {
	STUN        []string
	TURN        []string
	Credentials []Credential
}

// String keeps the credentials out of logs and errors: only how many there are.
func (a Answer) String() string {
	return "callswire.Answer{stun: " + strconv.Itoa(len(a.STUN)) + ", turn: " + strconv.Itoa(len(a.TURN)) +
		", credentials: " + strconv.Itoa(len(a.Credentials)) + "}"
}

// GoString is String, for %#v.
func (a Answer) GoString() string { return a.String() }

// RequestBody is the request's body, {"count":n}, n in 1..MaxCount.
func RequestBody(count int) []byte {
	return strictjson.NewBuilder().Uint("count", uint64(count)).Bytes()
}

// ParseAnswer reads a 200 answer and holds it to VAULT-MESSAGING §10.10: every URL a stun:/stuns: (in stun) or
// turn:/turns: (in turn) URL that passes the ICE configuration's own rule, at most MaxURLs of each kind, at most
// MaxCount credentials, each username and credential 1-MaxField bytes without control characters, and each exp in
// the future and at most MaxAhead + ExpAllowance ahead of now. Anything else is ErrResponse: the whole answer is discarded.
// Members the vault does not know are ignored.
func ParseAnswer(body []byte, now time.Time) (*Answer, error) {
	if len(body) > MaxAnswer {
		return nil, ErrResponse
	}
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, ErrResponse
	}
	a := &Answer{}
	if a.STUN, err = urls(o, "stun", "stun:", "stuns:"); err != nil {
		return nil, err
	}
	if a.TURN, err = urls(o, "turn", "turn:", "turns:"); err != nil {
		return nil, err
	}
	raw, err := o.Array("credentials")
	if err != nil || len(raw) > MaxCount {
		return nil, ErrResponse
	}
	for _, r := range raw {
		c, err := credential(r, now)
		if err != nil {
			return nil, err
		}
		a.Credentials = append(a.Credentials, c)
	}
	return a, nil
}

func urls(o strictjson.Object, name string, prefixes ...string) ([]string, error) {
	raw, err := o.Array(name)
	if err != nil || len(raw) > MaxURLs {
		return nil, ErrResponse
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		u, err := strictjson.AsString(r)
		if err != nil || !callwire.ValidURL(u) || !hasPrefix(u, prefixes) {
			return nil, ErrResponse
		}
		out = append(out, u)
	}
	return out, nil
}

func hasPrefix(u string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(u, p) {
			return true
		}
	}
	return false
}

func credential(raw json.RawMessage, now time.Time) (Credential, error) {
	o, err := strictjson.AsObject(raw)
	if err != nil {
		return Credential{}, ErrResponse
	}
	user, err1 := o.String("username")
	cred, err2 := o.String("credential")
	if err1 != nil || err2 != nil || !field(user) || !field(cred) {
		return Credential{}, ErrResponse
	}
	exp, err := o.Uint("exp", 1, 1<<53)
	if err != nil {
		return Credential{}, ErrResponse
	}
	t := time.Unix(int64(exp), 0).UTC()
	if !t.After(now) || t.Sub(now) > MaxAhead+ExpAllowance {
		return Credential{}, ErrResponse
	}
	return Credential{Username: user, Credential: cred, Exp: t}, nil
}

func field(s string) bool { return s != "" && len(s) <= MaxField && callwire.ValidField(s) }

// Error is an issuer error answer (Relay Protocol §7.1).
type Error struct {
	Status     int
	Code       string
	RetryAfter int // seconds; 0 when absent
}

func (e *Error) Error() string { return "calling service: " + strconv.Itoa(e.Status) + " " + e.Code }

// MaxRetryAfter is the longest retry_after taken from an answer.
const MaxRetryAfter = 3600

// ParseError reads an error body; a body without a code gets "http_<status>". retry_after is clamped to
// [0, MaxRetryAfter].
func ParseError(status int, body []byte) *Error {
	e := &Error{Status: status}
	var v struct {
		Code       string          `json:"code"`
		RetryAfter json.RawMessage `json:"retry_after"`
	}
	if len(body) <= 4096 && json.Unmarshal(body, &v) == nil && validCode(v.Code) {
		e.Code = v.Code
		if n, err := strictjson.AsUint(v.RetryAfter, 0, 1<<31); err == nil {
			e.RetryAfter = int(min(n, MaxRetryAfter))
		}
	}
	if e.Code == "" {
		e.Code = "http_" + strconv.Itoa(status)
	}
	return e
}

func validCode(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}
