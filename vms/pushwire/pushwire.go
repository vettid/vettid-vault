// Package pushwire is the wire format of push (VAULT-MESSAGING 0.24.0 §14,
// PUSH-GATEWAY 0.5.0): the app's registration as `push.register` carries
// it and the gateway's `POST /v1/register` takes it, its checks, the
// vault's token hash, the gateway's paths, bodies and error codes.
// Registration is two requests (PUSH-GATEWAY 0.5.0 §5.1): /v1/register
// answers a pending registration and sends a challenge code to the token
// by push; /v1/confirm, with the code the app returned, answers the wake
// blob.
//
// The vault never sees inside a wake blob (PUSH-GATEWAY §4): it is an
// opaque string here, bounded in size.
package pushwire

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

// Platforms, environments and the wake class.
const (
	PlatformFCM    = "fcm"
	PlatformAPNs   = "apns"
	EnvProduction  = "production"
	EnvSandbox     = "sandbox"
	ClassNotify    = "notify"
	LabelTokenHash = "vettid/vms/2/push-token"
)

// Gateway paths (PUSH-GATEWAY §5) and the attestation header (§5.1).
const (
	PathRegister      = "/v1/register"
	PathConfirm       = "/v1/confirm" // PUSH-GATEWAY 0.5.0 §5.1
	PathWake          = "/v1/wake"
	PathHealth        = "/v1/health"
	HeaderAttestation = "X-VettID-Attestation"
)

// Gateway error codes (PUSH-GATEWAY §7; Relay Protocol §7.1 grammar).
const (
	CodeSignatureInvalid    = "signature_invalid"
	CodeTimestampStale      = "timestamp_stale"
	CodeReplayDetected      = "replay_detected"
	CodeAttestationInvalid  = "attestation_invalid"
	CodeBadRequest          = "bad_request"
	CodePlatformInvalid     = "platform_invalid"
	CodeAppInvalid          = "app_invalid"
	CodeTokenInvalid        = "token_invalid"
	CodeTokenGone           = "token_gone"
	CodeBlobInvalid         = "blob_invalid"
	CodeRateLimited         = "rate_limited"
	CodeProviderUnavailable = "provider_unavailable"
	CodeChallengeInvalid    = "challenge_invalid" // 0.5.0: /v1/confirm only (403)
	CodeInternal            = "internal"
)

// Sizes.
const (
	MaxFCMToken  = 4096
	MinAPNsToken = 64
	MaxAPNsToken = 200
	MaxAppID     = 255
	// MaxBlob bounds a wake blob (PUSH-GATEWAY §4: at most 6,144 bytes).
	MaxBlob = 6144
	// MaxRetryAfter is the longest retry_after the vault waits (§14.2).
	MaxRetryAfter = 3600
	// MaxChallengeCode bounds a challenge code as the app passes it on
	// (PUSH-GATEWAY 0.5.0: the gateway makes 22 characters and takes at
	// most 64).
	MaxChallengeCode = 64
)

// ErrInvalid is a registration that fails §14.1 check 2.
var ErrInvalid = errors.New("pushwire: invalid registration")

// Registration is the app's push registration: the body of push.register
// and of the gateway's POST /v1/register. Token is the platform token: the
// vault holds it only while the request runs.
type Registration struct {
	Platform    string
	Token       string
	AppID       string
	Environment string // apns only: production or sandbox
}

var appIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Validate applies §14.1 check 2 (PUSH-GATEWAY §5.1 step 3 without the
// gateway's app list): platform fcm or apns; the token's shape per
// platform; app_id 1-255 bytes of [A-Za-z0-9][A-Za-z0-9._-]*; environment
// production or sandbox, required for apns and absent for fcm.
func (r Registration) Validate() error {
	switch r.Platform {
	case PlatformFCM:
		if r.Environment != "" || !printable(r.Token, 1, MaxFCMToken) {
			return ErrInvalid
		}
	case PlatformAPNs:
		if r.Environment != EnvProduction && r.Environment != EnvSandbox || !lowerHex(r.Token) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	if len(r.AppID) < 1 || len(r.AppID) > MaxAppID || !appIDRE.MatchString(r.AppID) {
		return ErrInvalid
	}
	return nil
}

// printable: n bytes of printable ASCII (0x21-0x7E), min <= n <= max.
func printable(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// lowerHex: 64-200 lowercase hex digits, an even count.
func lowerHex(s string) bool {
	if len(s) < MinAPNsToken || len(s) > MaxAPNsToken || len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ParseRegistration parses {platform, token, app_id, environment?}
// strictly (no other members) and validates it. A body that does not parse
// or validate is ErrInvalid.
func ParseRegistration(body []byte) (Registration, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return Registration{}, ErrInvalid
	}
	for k := range o {
		switch k {
		case "platform", "token", "app_id", "environment":
		default:
			return Registration{}, ErrInvalid
		}
	}
	var r Registration
	if r.Platform, err = o.String("platform"); err != nil {
		return Registration{}, ErrInvalid
	}
	if r.Token, err = o.String("token"); err != nil {
		return Registration{}, ErrInvalid
	}
	if r.AppID, err = o.String("app_id"); err != nil {
		return Registration{}, ErrInvalid
	}
	env, present, err := o.OptString("environment")
	if err != nil || present && env == "" {
		return Registration{}, ErrInvalid
	}
	r.Environment = env
	if err := r.Validate(); err != nil {
		return Registration{}, err
	}
	return r, nil
}

// Body is the gateway's register body (PUSH-GATEWAY §5.1; the member
// order of §15's vector).
func (r Registration) Body() []byte {
	b := strictjson.NewBuilder().String("platform", r.Platform).String("token", r.Token)
	if r.Environment != "" {
		b.String("environment", r.Environment)
	}
	return b.String("app_id", r.AppID).Bytes()
}

// TokenHash is the registration's idempotence hash (§14.1 check 4):
// SHA-256("vettid/vms/2/push-token" || lp(platform) || lp(app_id) ||
// lp(environment) || lp(token)), lp(x) being x's 2-byte big-endian length
// and its bytes (§10.9); an absent environment is empty.
func (r Registration) TokenHash() [32]byte {
	h := sha256.New()
	h.Write([]byte(LabelTokenHash))
	for _, s := range []string{r.Platform, r.AppID, r.Environment, r.Token} {
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(s)))
		h.Write(l[:])
		h.Write([]byte(s))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// EqualHash compares two token hashes in constant time.
func EqualHash(a, b []byte) bool {
	return len(a) == 32 && len(b) == 32 && subtle.ConstantTimeCompare(a, b) == 1
}

// ValidBlob reports whether s can be a wake blob: 1-6,144 bytes of
// base64url without padding. The vault checks nothing more (§4: opaque).
func ValidBlob(s string) bool {
	if len(s) == 0 || len(s) > MaxBlob {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// ValidPending reports whether s can be a pending registration
// (PUSH-GATEWAY 0.5.0 §4): sealed like a wake blob and bounded alike.
func ValidPending(s string) bool { return ValidBlob(s) }

// ValidChallengeCode reports whether s can be a challenge code: 1-64
// base64url characters without padding (PUSH-GATEWAY 0.5.0 §5.1).
func ValidChallengeCode(s string) bool { return len(s) <= MaxChallengeCode && ValidBlob(s) }

// ParsePending parses the gateway's 202 answer to a registration
// (PUSH-GATEWAY 0.5.0 §5.1): {pending}.
func ParsePending(body []byte) (string, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", ErrResponse
	}
	p, err := o.String("pending")
	if err != nil || !ValidPending(p) {
		return "", ErrResponse
	}
	return p, nil
}

// ConfirmBody is the confirmation's body (PUSH-GATEWAY 0.5.0 §5.1).
func ConfirmBody(pending, code string) []byte {
	return strictjson.NewBuilder().String("pending", pending).String("code", code).Bytes()
}

// ParseConfirm parses a confirmation body strictly (the gateway's side):
// exactly pending and code, both strings.
func ParseConfirm(body []byte) (pending, code string, err error) {
	o, err := strictjson.ParseObject(body)
	if err != nil || len(o) != 2 {
		return "", "", ErrInvalid
	}
	if pending, err = o.String("pending"); err != nil || pending == "" {
		return "", "", ErrInvalid
	}
	if code, err = o.String("code"); err != nil || code == "" || len(code) > MaxChallengeCode {
		return "", "", ErrInvalid
	}
	return pending, code, nil
}

// ParseRegistered parses the gateway's 201 body: {wake_blob} (the answer
// to a confirmation since PUSH-GATEWAY 0.5.0).
func ParseRegistered(body []byte) (string, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", ErrResponse
	}
	b, err := o.String("wake_blob")
	if err != nil || !ValidBlob(b) {
		return "", ErrResponse
	}
	return b, nil
}

// WakeBody is the wake request's body (PUSH-GATEWAY §5.2).
func WakeBody(blob string) []byte {
	return strictjson.NewBuilder().String("wake_blob", blob).String("class", ClassNotify).Bytes()
}

// ParseWake parses a wake request body strictly (the gateway's side).
func ParseWake(body []byte) (blob, class string, err error) {
	o, err := strictjson.ParseObject(body)
	if err != nil || len(o) != 2 {
		return "", "", ErrInvalid
	}
	if blob, err = o.String("wake_blob"); err != nil {
		return "", "", ErrInvalid
	}
	if class, err = o.String("class"); err != nil {
		return "", "", ErrInvalid
	}
	return blob, class, nil
}

// ErrResponse is a gateway answer that does not parse.
var ErrResponse = errors.New("pushwire: malformed gateway answer")

// ParseWoken parses the gateway's 202 body: {reseal?}. A reseal is
// returned only if it can be a blob.
func ParseWoken(body []byte) (reseal string, err error) {
	if len(strings.TrimSpace(string(body))) == 0 {
		return "", nil
	}
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", ErrResponse
	}
	r, present, err := o.OptString("reseal")
	if err != nil || present && !ValidBlob(r) {
		return "", ErrResponse
	}
	return r, nil
}

// Error is a gateway error answer (Relay Protocol §7.1: {code, message?,
// retry_after?}) with its HTTP status.
type Error struct {
	Status     int
	Code       string
	RetryAfter int // seconds; 0 when absent
}

func (e *Error) Error() string { return "push gateway: " + strconv.Itoa(e.Status) + " " + e.Code }

// ParseError reads an error body; a body without a code gets
// "http_<status>". retry_after is clamped to [0, MaxRetryAfter].
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
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// ErrorBody is a gateway error body (the stand-in's side).
func ErrorBody(code string, retryAfter int) []byte {
	b := strictjson.NewBuilder().String("code", code)
	if retryAfter > 0 {
		b.Uint("retry_after", uint64(retryAfter))
	}
	return b.Bytes()
}

// Gone reports whether a wake's error drops the registration (§14.2:
// 410 token_gone, 400 token_invalid, 410 blob_invalid).
func (e *Error) Gone() bool {
	return e.Status == 410 && (e.Code == CodeTokenGone || e.Code == CodeBlobInvalid) || e.Status == 400 && e.Code == CodeTokenInvalid
}
