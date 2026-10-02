package handshake

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Inner `type` values of the handshake messages (§10).
const (
	TypeInit = "hs.init"
	TypeResp = "hs.resp"
	TypeFin  = "hs.fin"
)

// Purpose is the hs.init purpose (§6.2).
type Purpose string

const (
	PurposeApp        Purpose = "app"
	PurposeDesktop    Purpose = "desktop"
	PurposeAgent      Purpose = "agent"
	PurposeConnection Purpose = "connection"
	PurposeRekey      Purpose = "rekey"
	PurposeReconnect  Purpose = "reconnect"
)

// Valid reports whether p is a defined purpose.
func (p Purpose) Valid() bool {
	switch p {
	case PurposeApp, PurposeDesktop, PurposeAgent, PurposeConnection, PurposeRekey, PurposeReconnect:
		return true
	}
	return false
}

// IsPairing reports whether p pairs an owner device or agent (§6.7).
func (p Purpose) IsPairing() bool {
	return p == PurposeApp || p == PurposeDesktop || p == PurposeAgent
}

// Field limits. The spec leaves these open; they bound what a parser keeps.
const (
	MaxCtxLen     = 128
	MaxTokenLen   = 4096
	MaxURLLen     = 256
	MaxRotations  = 32
	MaxOpaqueJSON = 16 * 1024 // profile
	MailboxLen    = 26
)

// RelayAddr is a principal's relay address (§6.2 `relay`).
type RelayAddr struct {
	URL     string
	Mailbox string
	PK      ed25519.PublicKey
}

// Principal is the `from` member of hs.init, and the `vault` member of a
// claim bundle.
type Principal struct {
	IK    ed25519.PublicKey
	KEM   *suite.PublicKey
	Relay RelayAddr
}

// Init is the hs.init body (§6.2).
type Init struct {
	Purpose        Purpose
	Ctx            string
	From           Principal
	Eph            *suite.PublicKey
	Token          string // "" when absent (rekey only)
	ReconnectToken string // "" when absent
	Suites         []int
	Profile        json.RawMessage       // optional object
	Rotations      []*Rotation           // reconnect only
	DeviceAttest   *altchan.DeviceAttest // purpose app only (§6.7, §11.7)
}

// Resp is the hs.resp body (§6.2).
type Resp struct {
	Token          string
	ReconnectToken string
	Suite          int
	Rotations      []*Rotation
	Sig            []byte
}

// MailboxID derives a relay mailbox id from a relay public key
// (RELAY-PROTOCOL §3.2).
func MailboxID(pk ed25519.PublicKey) string {
	h := sha256.Sum256(pk)
	s := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:]))
	return s[:MailboxLen]
}

// ValidateRelayAddr checks a relay address: an absolute https base URL
// (http only for loopback hosts, for development), with no user info,
// query or fragment; a 32-byte relay key; and a mailbox id equal to the one
// derived from that key.
func ValidateRelayAddr(a RelayAddr) error {
	if len(a.PK) != ed25519.PublicKeySize {
		return ErrBody
	}
	if a.Mailbox != MailboxID(a.PK) {
		return ErrBody
	}
	return ValidateRelayURL(a.URL)
}

// ValidateRelayURL checks a relay base URL (see ValidateRelayAddr).
func ValidateRelayURL(s string) error {
	if len(s) == 0 || len(s) > MaxURLLen {
		return ErrBody
	}
	u, err := url.Parse(s)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Host == "" {
		return ErrBody
	}
	if strings.ContainsAny(s, " \t\r\n") || u.ForceQuery {
		return ErrBody
	}
	switch u.Scheme {
	case "https":
	case "http":
		h := u.Hostname()
		if ip := net.ParseIP(h); !(h == "localhost" || (ip != nil && ip.IsLoopback())) {
			return ErrBody
		}
	default:
		return ErrBody
	}
	return nil
}

// ValidToken checks the shape of a PASETO v4.public deposit token. The
// signature is not verified here: a token is checked by the relay that
// accepts deposits under it.
func ValidToken(s string) bool {
	const prefix = "v4.public."
	if len(s) <= len(prefix) || len(s) > MaxTokenLen || !strings.HasPrefix(s, prefix) {
		return false
	}
	for i := len(prefix); i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func validCtx(s string) bool {
	if len(s) == 0 || len(s) > MaxCtxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// tokenRules gives, per purpose, whether token and reconnect_token are
// required (1), optional (0) or forbidden (-1), in hs.init and hs.resp.
//
//   - Pairing (app/desktop/agent): standing token required; reconnect
//     tokens are for connections only (§6.6), so forbidden.
//   - connection, reconnect: both required (§6.6: "delivered in hs.init,
//     hs.resp").
//   - rekey: both optional (existing tokens stay valid).
func tokenRules(p Purpose) (token, reconnect int) {
	switch p {
	case PurposeApp, PurposeDesktop, PurposeAgent:
		return 1, -1
	case PurposeConnection, PurposeReconnect:
		return 1, 1
	default:
		return 0, 0
	}
}

func checkTokenRule(rule int, v string) error {
	switch {
	case v == "" && rule == 1:
		return ErrBody
	case v != "" && rule == -1:
		return ErrBody
	case v != "" && !ValidToken(v):
		return ErrBody
	}
	return nil
}

func marshalRelay(a RelayAddr) []byte {
	return strictjson.NewBuilder().
		String("url", a.URL).
		String("mailbox", a.Mailbox).
		Base64("pk", a.PK).
		Bytes()
}

// MarshalPrincipal encodes {ik, kem, relay}.
func MarshalPrincipal(p Principal) []byte {
	return strictjson.NewBuilder().
		Base64("ik", p.IK).
		Base64("kem", p.KEM.Bytes()).
		Raw("relay", marshalRelay(p.Relay)).
		Bytes()
}

// ParsePrincipal parses and validates {ik, kem, relay}.
func ParsePrincipal(o strictjson.Object) (Principal, error) {
	var p Principal
	ik, err := o.Base64("ik", ed25519.PublicKeySize)
	if err != nil {
		return p, ErrBody
	}
	ek, err := o.Base64("kem", suite.EKSize)
	if err != nil {
		return p, ErrBody
	}
	kem, err := suite.ParsePublicKey(ek)
	if err != nil {
		return p, ErrBody
	}
	ro, err := o.Object("relay")
	if err != nil {
		return p, ErrBody
	}
	var r RelayAddr
	if r.URL, err = ro.String("url"); err != nil {
		return p, ErrBody
	}
	if r.Mailbox, err = ro.String("mailbox"); err != nil {
		return p, ErrBody
	}
	pk, err := ro.Base64("pk", ed25519.PublicKeySize)
	if err != nil {
		return p, ErrBody
	}
	r.PK = pk
	if err := ValidateRelayAddr(r); err != nil {
		return p, err
	}
	return Principal{IK: ik, KEM: kem, Relay: r}, nil
}

func validatePrincipal(p Principal) error {
	if len(p.IK) != ed25519.PublicKeySize || p.KEM == nil {
		return ErrBody
	}
	return ValidateRelayAddr(p.Relay)
}

func marshalRotations(rs []*Rotation) []byte {
	out := []byte{'['}
	for i, r := range rs {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, r.Marshal()...)
	}
	return append(out, ']')
}

func parseRotations(o strictjson.Object) ([]*Rotation, bool, error) {
	arr, present, err := o.OptArray("rotations")
	if err != nil || len(arr) > MaxRotations {
		return nil, present, ErrBody
	}
	var rs []*Rotation
	for _, raw := range arr {
		r, err := ParseRotation(raw)
		if err != nil {
			return nil, present, ErrBody
		}
		rs = append(rs, r)
	}
	return rs, present, nil
}

func optOpaque(o strictjson.Object, name string) (json.RawMessage, bool, error) {
	raw, present, err := o.OptObjectRaw(name)
	if err != nil || len(raw) > MaxOpaqueJSON {
		return nil, present, ErrBody
	}
	if present {
		c, err := strictjson.CompactObject(raw)
		if err != nil {
			return nil, present, ErrBody
		}
		raw = c
	}
	return raw, present, nil
}

// validate applies the field rules of §6.2 that depend on the purpose.
func (in *Init) validate() error {
	if !in.Purpose.Valid() || !validCtx(in.Ctx) || in.Eph == nil {
		return ErrBody
	}
	if err := validatePrincipal(in.From); err != nil {
		return err
	}
	// The ephemeral key must be fresh: never the initiator's static key.
	if in.Eph.Equal(in.From.KEM) {
		return ErrBody
	}
	tr, rr := tokenRules(in.Purpose)
	if checkTokenRule(tr, in.Token) != nil || checkTokenRule(rr, in.ReconnectToken) != nil {
		return ErrBody
	}
	if err := suite.ValidateOffer(in.Suites); err != nil {
		return err
	}
	if len(in.Profile) > 0 && !(in.Purpose.IsPairing() || in.Purpose == PurposeConnection) {
		return ErrBody
	}
	if len(in.Rotations) > 0 && in.Purpose != PurposeReconnect {
		return ErrBody
	}
	if len(in.Rotations) > MaxRotations {
		return ErrBody
	}
	if in.DeviceAttest != nil && in.Purpose != PurposeApp {
		return ErrBody
	}
	return nil
}

// Marshal encodes the hs.init body.
func (in *Init) Marshal() ([]byte, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	b := strictjson.NewBuilder().
		String("purpose", string(in.Purpose)).
		String("ctx", in.Ctx).
		Raw("from", MarshalPrincipal(in.From)).
		Base64("eph", in.Eph.Bytes())
	if in.Token != "" {
		b.String("token", in.Token)
	}
	if in.ReconnectToken != "" {
		b.String("reconnect_token", in.ReconnectToken)
	}
	b.Raw("suites", marshalInts(in.Suites))
	if len(in.Profile) > 0 {
		c, err := strictjson.CompactObject(in.Profile)
		if err != nil || len(c) > MaxOpaqueJSON {
			return nil, ErrBody
		}
		b.Raw("profile", c)
	}
	if len(in.Rotations) > 0 {
		b.Raw("rotations", marshalRotations(in.Rotations))
	}
	if in.DeviceAttest != nil {
		c, err := in.DeviceAttest.Marshal()
		if err != nil {
			return nil, ErrBody
		}
		b.Raw("device_attest", c)
	}
	return b.Bytes(), nil
}

func marshalInts(v []int) []byte {
	out := []byte{'['}
	for i, s := range v {
		if i > 0 {
			out = append(out, ',')
		}
		out = strconv.AppendInt(out, int64(s), 10)
	}
	return append(out, ']')
}

// ParseInit parses and validates an hs.init body.
func ParseInit(body []byte) (*Init, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, ErrBody
	}
	in := &Init{}
	p, err := o.String("purpose")
	if err != nil {
		return nil, ErrBody
	}
	in.Purpose = Purpose(p)
	if in.Ctx, err = o.String("ctx"); err != nil {
		return nil, ErrBody
	}
	fo, err := o.Object("from")
	if err != nil {
		return nil, ErrBody
	}
	if in.From, err = ParsePrincipal(fo); err != nil {
		return nil, ErrBody
	}
	eph, err := o.Base64("eph", suite.EKSize)
	if err != nil {
		return nil, ErrBody
	}
	if in.Eph, err = suite.ParsePublicKey(eph); err != nil {
		return nil, ErrBody
	}
	if t, ok, err := o.OptString("token"); err != nil || (ok && t == "") {
		return nil, ErrBody
	} else {
		in.Token = t
	}
	if t, ok, err := o.OptString("reconnect_token"); err != nil || (ok && t == "") {
		return nil, ErrBody
	} else {
		in.ReconnectToken = t
	}
	arr, err := o.Array("suites")
	if err != nil || len(arr) == 0 || len(arr) > suite.MaxOffer {
		return nil, ErrBody
	}
	for _, raw := range arr {
		v, err := strictjson.AsUint(raw, 0, 255)
		if err != nil {
			return nil, ErrBody
		}
		in.Suites = append(in.Suites, int(v))
	}
	if in.Profile, _, err = optOpaque(o, "profile"); err != nil {
		return nil, ErrBody
	}
	if raw, ok := o["device_attest"]; ok {
		if in.DeviceAttest, err = altchan.ParseDeviceAttest(raw); err != nil {
			return nil, ErrBody
		}
	}
	var present bool
	if in.Rotations, present, err = parseRotations(o); err != nil {
		return nil, ErrBody
	}
	if present && in.Purpose != PurposeReconnect {
		return nil, ErrBody
	}
	if err := in.validate(); err != nil {
		return nil, err
	}
	return in, nil
}

func (r *Resp) validate(p Purpose) error {
	tr, rr := tokenRules(p)
	if checkTokenRule(tr, r.Token) != nil || checkTokenRule(rr, r.ReconnectToken) != nil {
		return ErrBody
	}
	if r.Suite < 0 || r.Suite > 255 || len(r.Sig) != ed25519.SignatureSize {
		return ErrBody
	}
	if len(r.Rotations) > 0 && p != PurposeReconnect {
		return ErrBody
	}
	if len(r.Rotations) > MaxRotations {
		return ErrBody
	}
	return nil
}

// Marshal encodes the hs.resp body for a handshake of purpose p.
func (r *Resp) Marshal(p Purpose) ([]byte, error) {
	if err := r.validate(p); err != nil {
		return nil, err
	}
	b := strictjson.NewBuilder()
	if r.Token != "" {
		b.String("token", r.Token)
	}
	if r.ReconnectToken != "" {
		b.String("reconnect_token", r.ReconnectToken)
	}
	b.Uint("suite", uint64(r.Suite))
	if len(r.Rotations) > 0 {
		b.Raw("rotations", marshalRotations(r.Rotations))
	}
	b.Base64("sig", r.Sig)
	return b.Bytes(), nil
}

// ParseResp parses and validates an hs.resp body for a handshake of
// purpose p.
func ParseResp(body []byte, p Purpose) (*Resp, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, ErrBody
	}
	r := &Resp{}
	if t, ok, err := o.OptString("token"); err != nil || (ok && t == "") {
		return nil, ErrBody
	} else {
		r.Token = t
	}
	if t, ok, err := o.OptString("reconnect_token"); err != nil || (ok && t == "") {
		return nil, ErrBody
	} else {
		r.ReconnectToken = t
	}
	s, err := o.Uint("suite", 0, 255)
	if err != nil {
		return nil, ErrBody
	}
	r.Suite = int(s)
	var present bool
	if r.Rotations, present, err = parseRotations(o); err != nil {
		return nil, ErrBody
	}
	if present && p != PurposeReconnect {
		return nil, ErrBody
	}
	if r.Sig, err = o.Base64("sig", ed25519.SignatureSize); err != nil {
		return nil, ErrBody
	}
	if err := r.validate(p); err != nil {
		return nil, err
	}
	return r, nil
}

// MarshalFin encodes the hs.fin body {sig}.
func MarshalFin(sig []byte) ([]byte, error) {
	if len(sig) != ed25519.SignatureSize {
		return nil, ErrBody
	}
	return strictjson.NewBuilder().Base64("sig", sig).Bytes(), nil
}

// ParseFin parses an hs.fin body and returns sig_I.
func ParseFin(body []byte) ([]byte, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, ErrBody
	}
	sig, err := o.Base64("sig", ed25519.SignatureSize)
	if err != nil {
		return nil, ErrBody
	}
	return sig, nil
}
