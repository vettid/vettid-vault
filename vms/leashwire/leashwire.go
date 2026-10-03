// Package leashwire is the signed LEASH delegation of VAULT-MESSAGING
// §10.11: the exact canonical bytes of a grant's statement and the
// member's credential-key signature over them. A delegation is verifiable
// without the vault; the vault itself enforces grants and never relies on
// one.
package leashwire

import (
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"strconv"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Label and limits.
const (
	Label = "vettid/vms/2/leash"
	// Format is the statement's "v".
	Format = 1
	// MaxLifetime bounds exp - iat: a delegation cannot be revoked
	// offline, so it lives at most 24 h.
	MaxLifetime = 24 * time.Hour
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
	Expires     time.Time // whole seconds
}

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
	return b.Uint("iat", uint64(d.IssuedAt.Unix())).Uint("exp", uint64(d.Expires.Unix())).Bytes()
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
	iat, err := o.Uint("iat", 1, 1<<40)
	if err != nil {
		return nil, ErrDelegation
	}
	exp, err := o.Uint("exp", 1, 1<<40)
	if err != nil || exp < iat || exp-iat > uint64(MaxLifetime/time.Second) {
		return nil, ErrDelegation
	}
	d.IssuedAt, d.Expires = time.Unix(int64(iat), 0).UTC(), time.Unix(int64(exp), 0).UTC()
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
// member's credential key, and that it is valid at now. It returns the
// parsed statement.
func Verify(key ed25519.PublicKey, statement, sig []byte, now time.Time) (*Delegation, error) {
	d, err := Parse(statement)
	if err != nil {
		return nil, err
	}
	if suite.Verify(key, Label, statement, sig) != nil {
		return nil, ErrDelegation
	}
	if now.Before(d.IssuedAt.Add(-time.Minute)) || !now.Before(d.Expires) {
		return nil, ErrDelegation
	}
	return d, nil
}

// String is for debugging only and never prints keys.
func (d *Delegation) String() string {
	return "leash delegation " + d.GrantID + " v" + strconv.FormatUint(d.Version, 10) + " " + d.Scope
}
