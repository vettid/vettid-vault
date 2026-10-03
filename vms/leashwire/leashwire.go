// Package leashwire is the signed LEASH delegation of VAULT-MESSAGING
// §10.11: the exact canonical bytes of a grant's statement and the
// member's credential-key signature over them. A delegation is verifiable
// without the vault; the vault itself enforces grants and never relies on
// one.
package leashwire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"strconv"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Label and limits.
const (
	Label = "vettid/vms/2/leash"
	// Format is the statement's "v".
	Format = 1
	// MaxBytes bounds a statement.
	MaxBytes = 8192
	// MaxList bounds connections and secrets.
	MaxList = 64
)

// ErrDelegation is the only parse and verification error.
var ErrDelegation = errors.New("leashwire: invalid delegation")

// Delegation is one signed grant statement.
type Delegation struct {
	VaultIK     ed25519.PublicKey
	AgentIK     ed25519.PublicKey
	GrantID     string
	Version     uint64
	Scope       string
	Approval    string
	Connections []string
	Secrets     []string
	IssuedAt    time.Time // whole seconds
	Expires     time.Time // whole seconds; zero: the grant has no expiry (LEASH §3.2)
	// StatusTTL is the lifetime of the status statements the vault (the
	// status issuer, VaultIK) issues for this delegation.
	StatusTTL time.Duration
}

// Status statement limits (§10.11).
const (
	LabelStatus      = "vettid/vms/2/leash-status"
	MinStatusTTL     = time.Minute
	MaxStatusTTL     = time.Hour
	DefaultStatusTTL = 15 * time.Minute
	// StatusSkew is the clock skew a verifier allows on not_after.
	StatusSkew = time.Minute
	// MaxRotations bounds the rotation chain carried with a statement.
	MaxRotations = 32
)

// Marshal returns the canonical bytes (§10.11).
func (d *Delegation) Marshal() []byte {
	b := strictjson.NewBuilder().Uint("v", Format).Base64("vault_ik", d.VaultIK).Base64("agent_ik", d.AgentIK).
		String("grant_id", d.GrantID).Uint("version", d.Version).String("scope", d.Scope).String("approval", d.Approval)
	if len(d.Connections) > 0 {
		b.Raw("connections", strList(d.Connections))
	}
	if len(d.Secrets) > 0 {
		b.Raw("secrets", strList(d.Secrets))
	}
	b.Uint("status_ttl", uint64(d.StatusTTL/time.Second)).Uint("iat", uint64(d.IssuedAt.Unix()))
	if !d.Expires.IsZero() {
		b.Uint("exp", uint64(d.Expires.Unix()))
	}
	return b.Bytes()
}

func strList(l []string) []byte {
	out := []byte{'['}
	for i, s := range l {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, strictjson.MarshalString(s)...)
	}
	return append(out, ']')
}

func list(o strictjson.Object, name string) ([]string, error) {
	raw, present, err := o.OptArray(name)
	if err != nil {
		return nil, ErrDelegation
	}
	if !present {
		return nil, nil
	}
	if len(raw) == 0 || len(raw) > MaxList {
		return nil, ErrDelegation
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		s, err := strictjson.AsString(r)
		if err != nil || !envelope.ValidULID(s) {
			return nil, ErrDelegation
		}
		out = append(out, s)
	}
	return out, nil
}

// Parse parses a statement strictly and requires its canonical form.
func Parse(b []byte) (*Delegation, error) {
	if len(b) == 0 || len(b) > MaxBytes {
		return nil, ErrDelegation
	}
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, ErrDelegation
	}
	if v, err := o.Uint("v", Format, Format); err != nil || v != Format {
		return nil, ErrDelegation
	}
	d := &Delegation{}
	if d.VaultIK, err = o.Base64("vault_ik", ed25519.PublicKeySize); err != nil {
		return nil, ErrDelegation
	}
	if d.AgentIK, err = o.Base64("agent_ik", ed25519.PublicKeySize); err != nil {
		return nil, ErrDelegation
	}
	if d.GrantID, err = o.String("grant_id"); err != nil || !envelope.ValidULID(d.GrantID) {
		return nil, ErrDelegation
	}
	if d.Version, err = o.Uint("version", 1, strictjson.MaxSafeInteger); err != nil {
		return nil, ErrDelegation
	}
	if d.Scope, err = o.String("scope"); err != nil || d.Scope == "" || len(d.Scope) > 64 {
		return nil, ErrDelegation
	}
	if d.Approval, err = o.String("approval"); err != nil || d.Approval != "ask" && d.Approval != "auto" {
		return nil, ErrDelegation
	}
	if d.Connections, err = list(o, "connections"); err != nil {
		return nil, ErrDelegation
	}
	if d.Secrets, err = list(o, "secrets"); err != nil {
		return nil, ErrDelegation
	}
	ttl, err := o.Uint("status_ttl", uint64(MinStatusTTL/time.Second), uint64(MaxStatusTTL/time.Second))
	if err != nil {
		return nil, ErrDelegation
	}
	d.StatusTTL = time.Duration(ttl) * time.Second
	iat, err := o.Uint("iat", 1, 1<<40)
	if err != nil {
		return nil, ErrDelegation
	}
	d.IssuedAt = time.Unix(int64(iat), 0).UTC()
	exp, hasExp, err := o.OptUint("exp", 1, 1<<40)
	if err != nil || hasExp && exp <= iat {
		return nil, ErrDelegation
	}
	if hasExp {
		d.Expires = time.Unix(int64(exp), 0).UTC()
	}
	if subtle.ConstantTimeCompare(d.Marshal(), b) != 1 {
		return nil, ErrDelegation // not canonical
	}
	return d, nil
}

// Sign signs the canonical bytes with the member's credential key.
func Sign(key ed25519.PrivateKey, statement []byte) ([]byte, error) {
	if _, err := Parse(statement); err != nil {
		return nil, err
	}
	return suite.Sign(key, Label, statement)
}

// Verify checks a delegation: canonical form, the signature under the
// member's credential key, and that it is valid at now (issued, and not
// past its exp if it has one). It returns the parsed statement. Whether
// the grant is still in force is the vault's to say (LEASH §3.4): a
// verifier also needs the vault's current grants, as the agent holds them
// in leash.grant.updated.
func Verify(key ed25519.PublicKey, statement, sig []byte, now time.Time) (*Delegation, error) {
	d, err := Parse(statement)
	if err != nil {
		return nil, err
	}
	if suite.Verify(key, Label, statement, sig) != nil {
		return nil, ErrDelegation
	}
	if now.Before(d.IssuedAt.Add(-time.Minute)) || !d.Expires.IsZero() && !now.Before(d.Expires) {
		return nil, ErrDelegation
	}
	return d, nil
}

// String is for debugging only and never prints keys.
func (d *Delegation) String() string {
	return "leash delegation " + d.GrantID + " v" + strconv.FormatUint(d.Version, 10) + " " + d.Scope
}

// Status is a status statement (§10.11): the status issuer (the vault
// the delegation names, or its successor through identity.rotate) says the
// delegation is valid until NotAfter.
type Status struct {
	Delegation []byte // SHA-256 of the delegation's bytes
	GrantID    string
	IssuedAt   time.Time
	NotAfter   time.Time
}

// Marshal returns the statement's canonical bytes.
func (st *Status) Marshal() []byte {
	return strictjson.NewBuilder().Uint("v", Format).Base64("delegation", st.Delegation).String("grant_id", st.GrantID).
		String("status", "valid").Uint("issued_at", uint64(st.IssuedAt.Unix())).Uint("not_after", uint64(st.NotAfter.Unix())).Bytes()
}

// ParseStatus parses a status statement strictly (canonical form).
func ParseStatus(b []byte) (*Status, error) {
	if len(b) == 0 || len(b) > 1024 {
		return nil, ErrDelegation
	}
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, ErrDelegation
	}
	if v, err := o.Uint("v", Format, Format); err != nil || v != Format {
		return nil, ErrDelegation
	}
	st := &Status{}
	if st.Delegation, err = o.Base64("delegation", sha256.Size); err != nil {
		return nil, ErrDelegation
	}
	if st.GrantID, err = o.String("grant_id"); err != nil || !envelope.ValidULID(st.GrantID) {
		return nil, ErrDelegation
	}
	if v, err := o.String("status"); err != nil || v != "valid" {
		return nil, ErrDelegation
	}
	ia, err := o.Uint("issued_at", 1, 1<<40)
	if err != nil {
		return nil, ErrDelegation
	}
	na, err := o.Uint("not_after", 1, 1<<40)
	if err != nil || na <= ia || na-ia > uint64(MaxStatusTTL/time.Second) {
		return nil, ErrDelegation
	}
	st.IssuedAt, st.NotAfter = time.Unix(int64(ia), 0).UTC(), time.Unix(int64(na), 0).UTC()
	if subtle.ConstantTimeCompare(st.Marshal(), b) != 1 {
		return nil, ErrDelegation
	}
	return st, nil
}

// NewStatus returns the statement for a delegation issued now: valid for
// its status_ttl, never past the delegation's own exp.
func NewStatus(delegation []byte, now time.Time) (*Status, error) {
	d, err := Parse(delegation)
	if err != nil {
		return nil, err
	}
	iat := now.UTC().Truncate(time.Second)
	na := iat.Add(d.StatusTTL)
	if !d.Expires.IsZero() && d.Expires.Before(na) {
		na = d.Expires
	}
	if !na.After(iat) {
		return nil, ErrDelegation
	}
	h := sha256.Sum256(delegation)
	return &Status{Delegation: h[:], GrantID: d.GrantID, IssuedAt: iat, NotAfter: na}, nil
}

// SignStatus signs a statement with the vault's current identity key.
func SignStatus(ik ed25519.PrivateKey, statement []byte) ([]byte, error) {
	if _, err := ParseStatus(statement); err != nil {
		return nil, err
	}
	return suite.Sign(ik, LabelStatus, statement)
}

// Presented is what an agent shows a relying party: the delegation, the
// member's signature, a status statement, its signature, and the vault's
// identity.rotate statements from the delegation's vault_ik to the key
// that signed the statement (empty if it has not rotated).
type Presented struct {
	Delegation, DelegationSig []byte
	Status, StatusSig         []byte
	Rotations                 []*handshake.Rotation
}

// VerifyPresented is the relying party's check (§10.11), offline: the
// member's signature on the delegation (memberKey is the credential key
// the relying party trusts), the delegation's own validity, the status
// statement's signer is the delegation's status issuer (vault_ik,
// followed through the rotation chain), its signature, that it names this
// delegation, and now ≤ not_after (+ StatusSkew).
func VerifyPresented(memberKey ed25519.PublicKey, p *Presented, now time.Time) (*Delegation, error) {
	d, err := Verify(memberKey, p.Delegation, p.DelegationSig, now)
	if err != nil {
		return nil, err
	}
	st, err := ParseStatus(p.Status)
	if err != nil {
		return nil, err
	}
	if len(p.Rotations) > MaxRotations {
		return nil, ErrDelegation
	}
	issuer, _, err := handshake.ResolveChain(d.VaultIK, p.Rotations)
	if err != nil {
		return nil, ErrDelegation
	}
	if suite.Verify(issuer, LabelStatus, p.Status, p.StatusSig) != nil {
		return nil, ErrDelegation
	}
	h := sha256.Sum256(p.Delegation)
	if subtle.ConstantTimeCompare(h[:], st.Delegation) != 1 || st.GrantID != d.GrantID {
		return nil, ErrDelegation
	}
	if now.Before(st.IssuedAt.Add(-StatusSkew)) || now.After(st.NotAfter.Add(StatusSkew)) {
		return nil, ErrDelegation
	}
	return d, nil
}
