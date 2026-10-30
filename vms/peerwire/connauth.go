package peerwire

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Member authentication between connections (§10.4): the challenger's
// vault sends connection.authenticate.challenge; the responder's member
// approves in their app and the responder's vault answers
// connection.authenticate.response, signed with the member's credential
// key (§3.5.1); connection.authenticate.rotated carries the credential-key
// rotation statements (§3.5.5) to a connection that pinned an earlier key.
const (
	ConnAuthLabel = "vettid/vms/2/conn-auth"
	// ConnAuthPurposeLabel signs a challenge with a purpose (0.65.0).
	ConnAuthPurposeLabel = "vettid/vms/2/conn-auth-purpose"
	ConnAuthNonceSize    = 32
	// ConnAuthChallengeTTL is how long a challenge stays answerable.
	ConnAuthChallengeTTL = 10 * time.Minute
	// ConnAuthMaxContext bounds a challenge's context, in bytes.
	ConnAuthMaxContext = 256

	TypeConnAuthChallenge = "connection.authenticate.challenge"
	TypeConnAuthResponse  = "connection.authenticate.response"
	TypeConnAuthRotated   = "connection.authenticate.rotated"
	// TypeConnAuthWithdraw (0.80.0): the challenger will no longer accept
	// the challenge named by request_id.
	TypeConnAuthWithdraw = "connection.authenticate.withdraw"
)

// Purposes (0.65.0): why the member is asked. Any other value received
// is treated as absent.
const (
	PurposeSignIn   = "signin"
	PurposeApproval = "approval"
)

// KnownPurpose reports whether p is a purpose this version signs and
// gates by: PurposeSignIn or PurposeApproval.
func KnownPurpose(p string) bool { return p == PurposeSignIn || p == PurposeApproval }

// Response statuses.
const (
	ConnAuthSigned = "signed"
	ConnAuthDenied = "denied"
)

// Errors.
var (
	// ErrBody is a body that breaks its schema.
	ErrBody = errors.New("peerwire: malformed body")
	// ErrSignature is a response that does not verify over its challenge.
	ErrSignature = errors.New("peerwire: signature does not verify")
)

// ConnAuthMessage returns the signed bytes:
//
//	challenger_ik (32) || responder_ik (32) || nonce (32) || request_id (26) || context
//
// signed as Ed25519(credential key, "vettid/vms/2/conn-auth" || message).
func ConnAuthMessage(challengerIK, responderIK, nonce []byte, requestID, ctxt string) []byte {
	m := make([]byte, 0, 32+32+ConnAuthNonceSize+len(requestID)+len(ctxt))
	m = append(append(append(m, challengerIK...), responderIK...), nonce...)
	return append(append(m, requestID...), ctxt...)
}

// ConnAuthPurposeMessage returns the bytes signed for a challenge with a
// purpose (0.65.0):
//
//	len(purpose) (1) || purpose || m
//
// where m is ConnAuthMessage's, signed under ConnAuthPurposeLabel.
func ConnAuthPurposeMessage(purpose string, m []byte) []byte {
	out := make([]byte, 0, 1+len(purpose)+len(m))
	return append(append(append(out, byte(len(purpose))), purpose...), m...)
}

// ConnAuthChallenge is a connection.authenticate.challenge body:
// {request_id, nonce, context?, purpose?, match_code?}.
type ConnAuthChallenge struct {
	RequestID string // a ULID
	Nonce     []byte // ConnAuthNonceSize bytes
	Context   string // "" when absent; at most ConnAuthMaxContext bytes
	// Purpose is PurposeSignIn, PurposeApproval or "" (none). A parsed
	// challenge holds "" for an unknown value (0.65.0).
	Purpose string
	// MatchCode (0.79.0) is display only and not signed: exactly 2 or 3
	// ASCII digits, and only with PurposeSignIn. A parsed challenge holds
	// "" for anything else (malformed, or no sign-in purpose).
	MatchCode string
}

// ValidMatchCode reports whether s is a match code: [0-9]{2,3}.
func ValidMatchCode(s string) bool {
	if len(s) < 2 || len(s) > 3 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// OptMatchCode reads an optional `match_code` for a challenge with the
// given purpose: the code when it is valid and the purpose is signin,
// "" otherwise (absent, not a string, malformed, or another purpose).
// Never an error: a bad code is ignored (0.79.0).
func OptMatchCode(o strictjson.Object, purpose string) string {
	if purpose != PurposeSignIn {
		return ""
	}
	if v, _, err := o.OptString("match_code"); err == nil && ValidMatchCode(v) {
		return v
	}
	return ""
}

// NewConnAuthChallenge returns a challenge with a fresh random nonce.
func NewConnAuthChallenge(requestID, ctxt string) (*ConnAuthChallenge, error) {
	if !envelope.ValidULID(requestID) || len(ctxt) > ConnAuthMaxContext {
		return nil, ErrBody
	}
	nonce, err := suite.RandomBytes(ConnAuthNonceSize)
	if err != nil {
		return nil, err
	}
	return &ConnAuthChallenge{RequestID: requestID, Nonce: nonce, Context: ctxt}, nil
}

// Marshal returns the challenge body.
func (c *ConnAuthChallenge) Marshal() []byte {
	b := strictjson.NewBuilder().String("request_id", c.RequestID).Base64("nonce", c.Nonce)
	if c.Context != "" {
		b.String("context", c.Context)
	}
	if KnownPurpose(c.Purpose) {
		b.String("purpose", c.Purpose)
	}
	if c.Purpose == PurposeSignIn && ValidMatchCode(c.MatchCode) {
		b.String("match_code", c.MatchCode)
	}
	return b.Bytes()
}

// Message returns the bytes the responder signs for this challenge
// without a purpose (ConnAuthMessage).
func (c *ConnAuthChallenge) Message(challengerIK, responderIK []byte) []byte {
	return ConnAuthMessage(challengerIK, responderIK, c.Nonce, c.RequestID, c.Context)
}

// Signed returns the label and bytes the responder signs for this
// challenge: with a known purpose, ConnAuthPurposeMessage under
// ConnAuthPurposeLabel; without, Message under ConnAuthLabel (0.65.0).
func (c *ConnAuthChallenge) Signed(challengerIK, responderIK []byte) (label string, m []byte) {
	m = c.Message(challengerIK, responderIK)
	if KnownPurpose(c.Purpose) {
		return ConnAuthPurposeLabel, ConnAuthPurposeMessage(c.Purpose, m)
	}
	return ConnAuthLabel, m
}

// challengePurpose reads a challenge's optional `purpose`: a known
// purpose, or "" for anything else (absent, unknown, or not a string),
// which a receiver treats as absent (0.65.0).
func challengePurpose(o strictjson.Object) string {
	if v, _, err := o.OptString("purpose"); err == nil && KnownPurpose(v) {
		return v
	}
	return ""
}

// connAuthContext parses an optional `context` member: a string of at most
// ConnAuthMaxContext bytes ("" when absent).
func connAuthContext(o strictjson.Object) (string, error) {
	v, _, err := o.OptString("context")
	if err != nil || len(v) > ConnAuthMaxContext {
		return "", ErrBody
	}
	return v, nil
}

// ParseConnAuthChallenge parses a challenge body (from a peer) strictly.
func ParseConnAuthChallenge(body []byte) (*ConnAuthChallenge, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, ErrBody
	}
	c := &ConnAuthChallenge{}
	if c.RequestID, err = o.String("request_id"); err != nil || !envelope.ValidULID(c.RequestID) {
		return nil, ErrBody
	}
	if c.Nonce, err = o.Base64("nonce", ConnAuthNonceSize); err != nil {
		return nil, ErrBody
	}
	if c.Context, err = connAuthContext(o); err != nil {
		return nil, err
	}
	c.Purpose = challengePurpose(o)
	c.MatchCode = OptMatchCode(o, c.Purpose)
	return c, nil
}

// ParseConnAuthWithdraw reads a connection.authenticate.withdraw body,
// {request_id} (0.80.0, §10.4): the request_id, and false for a body whose
// request_id is missing or not a string. Further members are ignored. The
// id is not checked further: an id that names no open challenge is
// ignored by the receiver.
func ParseConnAuthWithdraw(body []byte) (string, bool) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", false
	}
	id, err := o.String("request_id")
	if err != nil || id == "" {
		return "", false
	}
	return id, true
}

// ConnAuthWithdrawBody returns the body of a withdraw for requestID.
func ConnAuthWithdrawBody(requestID string) []byte {
	return strictjson.NewBuilder().String("request_id", requestID).Bytes()
}

// ConnAuthResponse is a connection.authenticate.response body:
// {request_id, status: "signed", key, sig, signed_at, purpose?, rotations?}
// or {request_id, status: "denied"}.
type ConnAuthResponse struct {
	RequestID string
	Status    string // ConnAuthSigned or ConnAuthDenied
	// With ConnAuthSigned only:
	Key       ed25519.PublicKey       // the member's credential key
	Sig       []byte                  // over the challenge's ConnAuthMessage
	SignedAt  time.Time               // millisecond precision on the wire
	Rotations []*credwire.KeyRotation // optional: from the key the challenger pinned to Key
	// Purpose is the purpose the signature commits to (0.65.0): the
	// challenge's, or "" when signed without one. A parsed response holds
	// the value as sent, and HasPurpose whether the member was there at
	// all (a non-string value: present, Purpose ""); a present one that is
	// not the challenge's known purpose fails VerifyConnAuthResponse.
	Purpose    string
	HasPurpose bool
}

// SignConnAuth answers challenge c, sent by the vault whose identity key is
// challengerIK to the vault whose identity key is responderIK, with the
// member's credential key: over the purpose too when c has a known one,
// which the response then echoes (0.65.0). rotations, if any, lead from
// the key that challenger pinned to key (credwire.ChainFrom).
func SignConnAuth(key ed25519.PrivateKey, challengerIK, responderIK []byte, c *ConnAuthChallenge, signedAt time.Time,
	rotations []*credwire.KeyRotation) (*ConnAuthResponse, error) {
	label, m := c.Signed(challengerIK, responderIK)
	sig, err := suite.Sign(key, label, m)
	if err != nil {
		return nil, err
	}
	r := &ConnAuthResponse{RequestID: c.RequestID, Status: ConnAuthSigned, Key: key.Public().(ed25519.PublicKey), Sig: sig,
		SignedAt: signedAt, Rotations: rotations}
	if KnownPurpose(c.Purpose) {
		r.Purpose = c.Purpose
	}
	return r, nil
}

// DeniedConnAuth is the refusal of the challenge requestID.
func DeniedConnAuth(requestID string) *ConnAuthResponse {
	return &ConnAuthResponse{RequestID: requestID, Status: ConnAuthDenied}
}

// Marshal returns the response body.
func (r *ConnAuthResponse) Marshal() []byte {
	b := strictjson.NewBuilder().String("request_id", r.RequestID).String("status", r.Status)
	if r.Status != ConnAuthSigned {
		return b.Bytes()
	}
	b.Base64("key", r.Key).Base64("sig", r.Sig).String("signed_at", envelope.FormatTS(r.SignedAt))
	if r.Purpose != "" {
		b.String("purpose", r.Purpose)
	}
	if len(r.Rotations) > 0 {
		b.Raw("rotations", MarshalRotations(r.Rotations))
	}
	return b.Bytes()
}

// ParseConnAuthResponse parses a response body (from a peer) strictly. The
// signature is not checked (VerifyConnAuthResponse), nor are the rotation
// statements' (credwire.FollowChain).
func ParseConnAuthResponse(body []byte) (*ConnAuthResponse, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, ErrBody
	}
	r := &ConnAuthResponse{}
	if r.RequestID, err = o.String("request_id"); err != nil || !envelope.ValidULID(r.RequestID) {
		return nil, ErrBody
	}
	if r.Status, err = o.String("status"); err != nil {
		return nil, ErrBody
	}
	switch r.Status {
	case ConnAuthSigned:
		if r.Key, err = o.Base64("key", ed25519.PublicKeySize); err != nil {
			return nil, ErrBody
		}
		if r.Sig, err = o.Base64("sig", ed25519.SignatureSize); err != nil {
			return nil, ErrBody
		}
		sa, err := o.String("signed_at")
		if err != nil {
			return nil, ErrBody
		}
		if r.SignedAt, err = envelope.ParseTS(sa); err != nil {
			return nil, ErrBody
		}
		if _, r.HasPurpose = o["purpose"]; r.HasPurpose {
			r.Purpose, _, _ = o.OptString("purpose")
		}
		if raw, ok := o["rotations"]; ok {
			if r.Rotations, err = ParseRotations(raw); err != nil {
				return nil, err
			}
		}
	case ConnAuthDenied:
	default:
		return nil, ErrBody
	}
	return r, nil
}

// VerifyConnAuthResponse checks a signed response to challenge c, which
// the vault whose identity key is challengerIK sent to the vault whose
// identity key is responderIK: the signature by the key the response
// names over the challenge. Whether that key is the one pinned is
// PinnedKeyChanged's question.
//
// With a purpose (0.65.0): a response that carries one must carry the
// challenge's, and is verified over the purpose under
// ConnAuthPurposeLabel; one that carries a purpose for a challenge
// without one fails. A response without a purpose is verified over the
// message alone, also for a challenge with one (a vault before 0.65.0
// ignores the member): r.Purpose then stays "", and the caller decides
// whether a signature that does not commit to the purpose is enough.
func VerifyConnAuthResponse(r *ConnAuthResponse, challengerIK, responderIK []byte, c *ConnAuthChallenge) error {
	if r.Status != ConnAuthSigned || r.RequestID != c.RequestID {
		return ErrSignature
	}
	label, m := ConnAuthLabel, c.Message(challengerIK, responderIK)
	if r.Purpose != "" || r.HasPurpose {
		if !KnownPurpose(c.Purpose) || r.Purpose != c.Purpose {
			return ErrSignature
		}
		label, m = ConnAuthPurposeLabel, ConnAuthPurposeMessage(r.Purpose, m)
	}
	if suite.Verify(r.Key, label, m, r.Sig) != nil {
		return ErrSignature
	}
	return nil
}

// PinnedKeyChanged reports whether key, verified in a response, is a
// change from the pinned credential key (§10.4): a key other than the pin
// is a change unless a valid chain of rotation statements (the response's
// rotations) leads from the pin to it. Nothing pinned is no change.
func PinnedKeyChanged(pinned, key ed25519.PublicKey, rotations []*credwire.KeyRotation) bool {
	if len(pinned) == 0 || suite.EqualPublic(pinned, key) {
		return false
	}
	end, err := credwire.FollowChain(pinned, rotations)
	return err != nil || !suite.EqualPublic(end, key)
}

// ParseRotations parses a `rotations` array: 1–32 statements (signatures
// unchecked).
func ParseRotations(raw json.RawMessage) ([]*credwire.KeyRotation, error) {
	arr, err := strictjson.AsArray(raw)
	if err != nil || len(arr) == 0 || len(arr) > credwire.MaxKeyChain {
		return nil, ErrBody
	}
	out := make([]*credwire.KeyRotation, 0, len(arr))
	for _, r := range arr {
		kr, err := credwire.ParseKeyRotation(r)
		if err != nil {
			return nil, ErrBody
		}
		out = append(out, kr)
	}
	return out, nil
}

// MarshalRotations returns the JSON array of the statements.
func MarshalRotations(rs []*credwire.KeyRotation) []byte {
	arr := []byte{'['}
	for i, r := range rs {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, r.Marshal()...)
	}
	return append(arr, ']')
}

// ConnAuthRotatedBody is a connection.authenticate.rotated body:
// {rotations}, the statements from the key the connection pinned.
func ConnAuthRotatedBody(rs []*credwire.KeyRotation) []byte {
	return strictjson.NewBuilder().Raw("rotations", MarshalRotations(rs)).Bytes()
}

// ParseConnAuthRotated parses a connection.authenticate.rotated body
// strictly (the statements' signatures are checked by credwire.FollowChain).
func ParseConnAuthRotated(body []byte) ([]*credwire.KeyRotation, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, ErrBody
	}
	raw, ok := o["rotations"]
	if !ok {
		return nil, ErrBody
	}
	return ParseRotations(raw)
}
