package altchan

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/manifest"
	"github.com/vettid/vettid-vault/vms/suite"
)

// ErrMalformed is returned for a malformed request, result or descriptor.
var ErrMalformed = errors.New("altchan: malformed message")

// Inner types (§10).
const (
	TypeEnroll       = "vault.enroll"
	TypeUnlock       = "vault.unlock"
	TypeUnlockResult = "vault.unlock.result"
	TypeEnrollResult = "vault.enroll.result"
)

// ResultEnvelopeSize is the size of every sealed result (§11.4): a
// 4,096-byte padded inner plaintext in a sealed envelope.
const ResultEnvelopeSize = envelope.OverheadSealed + PaddedSize

// RequestEnvelopeSize is the size of a sealed enroll or unlock request.
const RequestEnvelopeSize = envelope.OverheadSealed + RequestPaddedSize

// ValidPIN accepts 4-32 ASCII digits.
func ValidPIN(p string) bool {
	if len(p) < 4 || len(p) > 32 {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return false
		}
	}
	return true
}

// RelayAddr is a relay address {url, mailbox, pk}.
type RelayAddr struct {
	URL     string
	Mailbox string
	PK      ed25519.PublicKey
}

func (a RelayAddr) marshal() []byte {
	return strictjson.NewBuilder().String("url", a.URL).String("mailbox", a.Mailbox).Base64("pk", a.PK).Bytes()
}

// EnrollRequest is the vault.enroll body (§11.3).
type EnrollRequest struct {
	UserGUID  string
	RequestID string
	Nonce     []byte // 32 bytes
	PIN       string
	IK        ed25519.PublicKey
	KEM       *suite.PublicKey
	Relay     RelayAddr
	OpenToken string
	Name      string
	Attest    *DeviceAttest
	Manifest  *manifest.Served
}

// Marshal encodes the body in §11.3 member order.
func (r *EnrollRequest) Marshal() ([]byte, error) {
	da, err := r.Attest.Marshal()
	if err != nil {
		return nil, err
	}
	app := strictjson.NewBuilder().Base64("ik", r.IK).Base64("kem", r.KEM.Bytes()).Raw("relay", r.Relay.marshal()).
		String("open_token", r.OpenToken).String("name", r.Name).Raw("device_attest", da).Bytes()
	return strictjson.NewBuilder().String("user_guid", r.UserGUID).String("request_id", r.RequestID).
		Base64("nonce", r.Nonce).String("pin", r.PIN).Raw("app", app).Raw("manifest", r.Manifest.Marshal()).Bytes(), nil
}

// EnrollKEM extracts app.kem first, so that a later failure can be
// answered with a sealed result.
func EnrollKEM(o strictjson.Object) (*suite.PublicKey, error) {
	app, err := o.Object("app")
	if err != nil {
		return nil, ErrMalformed
	}
	ek, err := app.Base64("kem", suite.EKSize)
	if err != nil {
		return nil, ErrMalformed
	}
	k, err := suite.ParsePublicKey(ek)
	if err != nil {
		return nil, ErrMalformed
	}
	return k, nil
}

// ParseEnrollRequest parses the body strictly.
func ParseEnrollRequest(o strictjson.Object) (*EnrollRequest, error) {
	r := &EnrollRequest{}
	var err error
	if r.KEM, err = EnrollKEM(o); err != nil {
		return nil, err
	}
	app, _ := o.Object("app")
	if r.UserGUID, err = o.String("user_guid"); err != nil {
		return nil, ErrMalformed
	}
	if r.RequestID, err = o.String("request_id"); err != nil {
		return nil, ErrMalformed
	}
	if r.Nonce, err = o.Base64("nonce", 32); err != nil {
		return nil, ErrMalformed
	}
	if r.PIN, err = o.String("pin"); err != nil || !ValidPIN(r.PIN) {
		return nil, ErrMalformed
	}
	if r.IK, err = app.Base64("ik", ed25519.PublicKeySize); err != nil {
		return nil, ErrMalformed
	}
	ro, err := app.Object("relay")
	if err != nil {
		return nil, ErrMalformed
	}
	if r.Relay.URL, err = ro.String("url"); err != nil {
		return nil, ErrMalformed
	}
	if r.Relay.Mailbox, err = ro.String("mailbox"); err != nil {
		return nil, ErrMalformed
	}
	if r.Relay.PK, err = ro.Base64("pk", ed25519.PublicKeySize); err != nil {
		return nil, ErrMalformed
	}
	if r.OpenToken, err = app.String("open_token"); err != nil || r.OpenToken == "" || len(r.OpenToken) > 4096 {
		return nil, ErrMalformed
	}
	if r.Name, err = app.String("name"); err != nil || len(r.Name) > 128 {
		return nil, ErrMalformed
	}
	da, ok := app["device_attest"]
	if !ok {
		return nil, ErrMalformed
	}
	if r.Attest, err = ParseDeviceAttest(da); err != nil {
		return nil, ErrMalformed
	}
	mo, err := o.Object("manifest")
	if err != nil {
		return nil, ErrMalformed
	}
	if r.Manifest, err = manifest.ServedFrom(mo); err != nil {
		return nil, ErrMalformed
	}
	return r, nil
}

// ReleaseUpdate is the unlock's release_update (§11.10.3).
type ReleaseUpdate struct {
	To        string
	ToRelease uint64
	Approval  *DeviceAssertion
}

// UnlockRequest is the vault.unlock body (§11.4).
type UnlockRequest struct {
	UserGUID, VaultID, RequestID string
	DeviceIK                     ed25519.PublicKey
	PIN                          string
	MinStateSeq, MinHeaderSeq    uint64
	Token                        string
	Assertion                    *DeviceAssertion
	Manifest                     *manifest.Served
	Update                       *ReleaseUpdate
	CancelRecovery               bool // §11.11.4
	Sig                          []byte
}

// Marshal encodes the body in §11.4 member order.
func (r *UnlockRequest) Marshal() ([]byte, error) {
	da, err := r.Assertion.Marshal()
	if err != nil {
		return nil, err
	}
	b := strictjson.NewBuilder().String("user_guid", r.UserGUID).String("vault_id", r.VaultID).
		String("request_id", r.RequestID).Base64("device_ik", r.DeviceIK).String("pin", r.PIN).
		Uint("min_state_seq", r.MinStateSeq).Uint("min_header_seq", r.MinHeaderSeq).String("token", r.Token).
		Raw("device_assertion", da).Raw("manifest", r.Manifest.Marshal())
	if u := r.Update; u != nil {
		ap, err := u.Approval.Marshal()
		if err != nil {
			return nil, err
		}
		b.Raw("release_update", strictjson.NewBuilder().String("to", u.To).Uint("to_release", u.ToRelease).Raw("approval", ap).Bytes())
	}
	if r.CancelRecovery {
		b.Bool("cancel_recovery", true)
	}
	return b.Base64("sig", r.Sig).Bytes(), nil
}

// ParseUnlockRequest parses the body strictly.
func ParseUnlockRequest(o strictjson.Object) (*UnlockRequest, error) {
	r := &UnlockRequest{}
	var err error
	for _, f := range []struct {
		n string
		d *string
	}{{"user_guid", &r.UserGUID}, {"vault_id", &r.VaultID}, {"request_id", &r.RequestID}, {"pin", &r.PIN}, {"token", &r.Token}} {
		if *f.d, err = o.String(f.n); err != nil {
			return nil, ErrMalformed
		}
	}
	if !ValidPIN(r.PIN) || r.Token == "" || len(r.Token) > 4096 {
		return nil, ErrMalformed
	}
	if r.DeviceIK, err = o.Base64("device_ik", ed25519.PublicKeySize); err != nil {
		return nil, ErrMalformed
	}
	if r.MinStateSeq, err = o.Uint("min_state_seq", 0, strictjson.MaxSafeInteger); err != nil {
		return nil, ErrMalformed
	}
	if r.MinHeaderSeq, err = o.Uint("min_header_seq", 0, strictjson.MaxSafeInteger); err != nil {
		return nil, ErrMalformed
	}
	da, ok := o["device_assertion"]
	if !ok {
		return nil, ErrMalformed
	}
	if r.Assertion, err = ParseDeviceAssertion(da); err != nil {
		return nil, ErrMalformed
	}
	mo, err := o.Object("manifest")
	if err != nil {
		return nil, ErrMalformed
	}
	if r.Manifest, err = manifest.ServedFrom(mo); err != nil {
		return nil, ErrMalformed
	}
	if raw, present, err := o.OptObjectRaw("release_update"); err != nil {
		return nil, ErrMalformed
	} else if present {
		uo, _ := strictjson.AsObject(raw)
		u := &ReleaseUpdate{}
		if u.To, err = uo.String("to"); err != nil || !manifest.ValidPCR(u.To) {
			return nil, ErrMalformed
		}
		if u.ToRelease, err = uo.Uint("to_release", 1, strictjson.MaxSafeInteger); err != nil {
			return nil, ErrMalformed
		}
		ap, ok := uo["approval"]
		if !ok {
			return nil, ErrMalformed
		}
		if u.Approval, err = ParseDeviceAssertion(ap); err != nil {
			return nil, ErrMalformed
		}
		r.Update = u
	}
	if o.Has("cancel_recovery") {
		if v, err := o.Bool("cancel_recovery"); err != nil || !v {
			return nil, ErrMalformed // present only as true
		}
		r.CancelRecovery = true
	}
	if r.Sig, err = o.Base64("sig", ed25519.SignatureSize); err != nil {
		return nil, ErrMalformed
	}
	return r, nil
}

// SealRequest builds a sealed request envelope (§11.3, §11.4): inner id =
// request_id, sender_kid all-zero, padded to exactly 12,288 bytes.
func SealRequest(etk *suite.PublicKey, typ, requestID string, ts time.Time, body []byte) ([]byte, error) {
	in := &envelope.Inner{ID: requestID, Type: typ, TS: ts, Body: body}
	b, err := in.Marshal(envelope.ModeSealed)
	if err != nil {
		return nil, err
	}
	padded, err := envelope.PadFixed(b, RequestPaddedSize)
	if err != nil {
		return nil, err
	}
	env, _, err := envelope.SealSealed(etk, suite.Anonymous, padded)
	return env, err
}

// SealResult seals a result to the device: inner `typ`, re = the request
// id, padded to exactly 4,096 bytes.
func SealResult(kem *suite.PublicKey, typ, requestID string, body []byte, now time.Time) ([]byte, error) {
	id, err := envelope.NewULID(now)
	if err != nil {
		return nil, err
	}
	in := &envelope.Inner{ID: id, Type: typ, TS: now, Re: requestID, Status: envelope.StatusOK, Body: body}
	b, err := in.Marshal(envelope.ModeSealed)
	if err != nil {
		return nil, err
	}
	padded, err := envelope.PadFixed(b, PaddedSize)
	if err != nil {
		return nil, err
	}
	env, _, err := envelope.SealSealed(kem, suite.Anonymous, padded)
	return env, err
}

// OpenResult opens a sealed result with the device's KEM key and checks
// its type and that it answers requestID. Any failure (including the
// random bytes the enclave returns when it cannot answer) is ErrMalformed.
func OpenResult(raw []byte, kem *suite.PrivateKey, typ, requestID string) (json.RawMessage, error) {
	if len(raw) != ResultEnvelopeSize {
		return nil, ErrMalformed
	}
	env, err := envelope.Parse(raw)
	if err != nil || env.Mode() != envelope.ModeSealed {
		return nil, ErrMalformed
	}
	padded, _, err := envelope.OpenSealed(env, kem)
	if err != nil {
		return nil, ErrMalformed
	}
	js, err := envelope.UnpadFixed(padded, PaddedSize)
	if err != nil {
		return nil, ErrMalformed
	}
	in, err := envelope.ParseInner(js, envelope.ModeSealed)
	if err != nil || in.Type != typ || in.Re != requestID {
		return nil, ErrMalformed
	}
	return in.Body, nil
}

// UnlockResult is the body of vault.unlock.result (§11.4).
type UnlockResult struct {
	OK             bool
	Code           string
	StateSeq       uint64
	HeaderSeq      uint64
	RetryAfter     uint64 // seconds
	Token          string
	Release        string
	ReleaseNumber  uint64
	ReleaseStatus  string
	ManifestSerial uint64
	Update         *UpdateResult
	// RecoveryCancelled: this unlock cancelled a recovery (§11.11.4).
	RecoveryCancelled bool
	// VaultBundle is present for the recovered app's unlock (§11.11.5):
	// {v, suite, ik, kem, relay} as in vault.enrolled.
	VaultBundle []byte
}

// UpdateResult is the result's `update` member.
type UpdateResult struct {
	To     string
	Result string
	Code   string
}

// Marshal encodes the body.
func (r *UnlockResult) Marshal() []byte {
	b := strictjson.NewBuilder().Bool("ok", r.OK)
	if !r.OK {
		return b.String("code", r.Code).Uint("header_seq", r.HeaderSeq).Uint("retry_after", r.RetryAfter).Bytes()
	}
	b.Uint("state_seq", r.StateSeq).Uint("header_seq", r.HeaderSeq)
	if r.Token != "" {
		b.String("token", r.Token)
	}
	b.String("release", r.Release).Uint("release_number", r.ReleaseNumber).String("release_status", r.ReleaseStatus).
		Uint("manifest_serial", r.ManifestSerial)
	if u := r.Update; u != nil {
		ub := strictjson.NewBuilder().String("to", u.To).String("result", u.Result)
		if u.Code != "" {
			ub.String("code", u.Code)
		}
		b.Raw("update", ub.Bytes())
	}
	if r.RecoveryCancelled {
		b.Bool("recovery_cancelled", true)
	}
	if len(r.VaultBundle) > 0 {
		b.Base64("vault_bundle", r.VaultBundle)
	}
	return b.Bytes()
}

// ParseUnlockResult parses the body strictly.
func ParseUnlockResult(raw json.RawMessage) (*UnlockResult, error) {
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		return nil, ErrMalformed
	}
	r := &UnlockResult{}
	if r.OK, err = o.Bool("ok"); err != nil {
		return nil, ErrMalformed
	}
	if r.HeaderSeq, err = o.Uint("header_seq", 0, strictjson.MaxSafeInteger); err != nil {
		return nil, ErrMalformed
	}
	if !r.OK {
		if r.Code, err = o.String("code"); err != nil {
			return nil, ErrMalformed
		}
		if r.RetryAfter, err = o.Uint("retry_after", 0, strictjson.MaxSafeInteger); err != nil {
			return nil, ErrMalformed
		}
		return r, nil
	}
	if r.StateSeq, err = o.Uint("state_seq", 0, strictjson.MaxSafeInteger); err != nil {
		return nil, ErrMalformed
	}
	if r.Token, _, err = o.OptString("token"); err != nil {
		return nil, ErrMalformed
	}
	if r.Release, err = o.String("release"); err != nil || !manifest.ValidPCR(r.Release) {
		return nil, ErrMalformed
	}
	if r.ReleaseNumber, err = o.Uint("release_number", 1, strictjson.MaxSafeInteger); err != nil {
		return nil, ErrMalformed
	}
	if r.ReleaseStatus, err = o.String("release_status"); err != nil {
		return nil, ErrMalformed
	}
	if r.ManifestSerial, err = o.Uint("manifest_serial", 0, strictjson.MaxSafeInteger); err != nil {
		return nil, ErrMalformed
	}
	if raw, present, err := o.OptObjectRaw("update"); err != nil {
		return nil, ErrMalformed
	} else if present {
		uo, _ := strictjson.AsObject(raw)
		u := &UpdateResult{}
		if u.To, err = uo.String("to"); err != nil {
			return nil, ErrMalformed
		}
		if u.Result, err = uo.String("result"); err != nil {
			return nil, ErrMalformed
		}
		if u.Code, _, err = uo.OptString("code"); err != nil {
			return nil, ErrMalformed
		}
		r.Update = u
	}
	if o.Has("recovery_cancelled") {
		if r.RecoveryCancelled, err = o.Bool("recovery_cancelled"); err != nil {
			return nil, ErrMalformed
		}
	}
	if o.Has("vault_bundle") {
		if r.VaultBundle, err = o.Base64("vault_bundle", -1); err != nil || len(r.VaultBundle) > 2048 {
			return nil, ErrMalformed
		}
	}
	return r, nil
}

// EnrollResult is the body of vault.enroll.result: the enclave's answer in
// the response slot (success also arrives as vault.enrolled over the
// relay).
type EnrollResult struct {
	OK      bool
	Code    string
	VaultID string
}

// Marshal encodes the body.
func (r *EnrollResult) Marshal() []byte {
	b := strictjson.NewBuilder().Bool("ok", r.OK)
	if r.OK {
		return b.String("vault_id", r.VaultID).Bytes()
	}
	return b.String("code", r.Code).Bytes()
}

// ParseEnrollResult parses the body strictly.
func ParseEnrollResult(raw json.RawMessage) (*EnrollResult, error) {
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		return nil, ErrMalformed
	}
	r := &EnrollResult{}
	if r.OK, err = o.Bool("ok"); err != nil {
		return nil, ErrMalformed
	}
	if r.OK {
		r.VaultID, err = o.String("vault_id")
	} else {
		r.Code, err = o.String("code")
	}
	if err != nil {
		return nil, ErrMalformed
	}
	return r, nil
}

// ValidInstanceID reports whether s is an instance id (§11.1):
// [A-Za-z0-9_-]{1,48}.
func ValidInstanceID(s string) bool {
	if len(s) == 0 || len(s) > 48 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// Descriptor is the ETK descriptor (§11.2).
type Descriptor struct {
	InstanceID string
	Kid        suite.Kid
	ETK        *suite.PublicKey
	Release    string
	NotAfter   time.Time
	// Bytes are the exact served bytes.
	Bytes []byte
}

// MarshalDescriptor writes the descriptor in §11.2 member order.
func MarshalDescriptor(instanceID string, etk *suite.PublicKey, release string, notAfter time.Time) []byte {
	return strictjson.NewBuilder().Uint("v", 1).Uint("suite", uint64(suite.Suite2)).String("instance_id", instanceID).
		String("kid", etk.Kid().String()).String("etk", base64.StdEncoding.EncodeToString(etk.Bytes())).
		String("release", release).String("not_after", notAfter.UTC().Format(time.RFC3339)).Bytes()
}

// ParseDescriptor parses descriptor bytes strictly: v = 1, suite 2, kid =
// the kid of etk, a non-debug PCR0 as release, and not_after.
func ParseDescriptor(b []byte) (*Descriptor, error) {
	if len(b) == 0 || len(b) > 4096 {
		return nil, ErrMalformed
	}
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, ErrMalformed
	}
	if v, err := o.Uint("v", 1, 1); err != nil || v != 1 {
		return nil, ErrMalformed
	}
	if s, err := o.Uint("suite", 2, 2); err != nil || s != 2 {
		return nil, ErrMalformed
	}
	d := &Descriptor{Bytes: append([]byte(nil), b...)}
	if d.InstanceID, err = o.String("instance_id"); err != nil || !ValidInstanceID(d.InstanceID) {
		return nil, ErrMalformed
	}
	kid, err := o.String("kid")
	if err != nil {
		return nil, ErrMalformed
	}
	if d.Kid, err = suite.ParseKidHex(kid); err != nil || d.Kid.String() != kid {
		return nil, ErrMalformed
	}
	ek, err := o.Base64("etk", suite.EKSize)
	if err != nil {
		return nil, ErrMalformed
	}
	if d.ETK, err = suite.ParsePublicKey(ek); err != nil || !d.ETK.Kid().Equal(d.Kid) {
		return nil, ErrMalformed
	}
	if d.Release, err = o.String("release"); err != nil || !manifest.ValidPCR(d.Release) {
		return nil, ErrMalformed
	}
	na, err := o.String("not_after")
	if err != nil {
		return nil, ErrMalformed
	}
	if d.NotAfter, err = time.Parse(time.RFC3339, na); err != nil || d.NotAfter.UTC().Format(time.RFC3339) != na {
		return nil, ErrMalformed
	}
	return d, nil
}
