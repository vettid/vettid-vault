// Package leashwire is the signed LEASH delegation and status statement
// of VAULT-MESSAGING §10.11 (0.12.0): the LEASH paper's §3.5 format,
// version 1, byte for byte. A delegation is RFC 8785 (JCS) JSON signed by
// the member's credential key; a status statement is JCS JSON signed by the
// member's vault (the delegation's status issuer). Both are verifiable
// without the vault; the vault itself enforces grants and never relies on
// a delegation.
//
// VettID bindings (not in the paper): the credential key as iss, the
// vault's ik as status_issuer, and the identity.rotate chain that carries a
// statement across rotations of the vault's ik.
package leashwire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Context strings and limits (§10.11, §4.1). The context strings are the
// LEASH paper's, versioned by its format rather than by the VMS suite.
const (
	Label       = "leash/v1/delegation"
	LabelStatus = "leash/v1/status"
	// Format is the statements' "v".
	Format = 1
	// MaxBytes bounds a delegation.
	MaxBytes = 8192
	// MaxStatusBytes bounds a status statement.
	MaxStatusBytes = 1024
	// MaxList bounds connections.
	MaxList = 64
	// NonceSize is the delegation nonce's length in bytes.
	NonceSize = 16
)

// Status statement limits (§10.11).
const (
	MinStatusTTL     = time.Minute
	MaxStatusTTL     = time.Hour
	DefaultStatusTTL = 15 * time.Minute
	// StatusSkew is the clock skew a verifier allows on a statement's
	// issued_at and not_after; the revocation bound is status_ttl + StatusSkew.
	StatusSkew = time.Minute
	// MaxRotations bounds the rotation chain carried with a statement.
	MaxRotations = 32
)

// Rate limit and use ranges (§10.11, §10.12).
const (
	MaxPerHour = 3600
	MaxPerDay  = 86400
	MaxUses    = 10000
)

// ErrDelegation is the only parse and verification error.
var ErrDelegation = errors.New("leashwire: invalid delegation")

// ScopeItems is the scope of an agent's share rule (§10.11).
const ScopeItems = "items.read"

// tagRE is a normalised tag (§10.8); MaxTags bounds a rule's tags.
var tagRE = regexp.MustCompile(`^[a-z0-9][a-z0-9 _-]{0,31}$`)

// opRE is a scope's op: an owner type or items.read.
var opRE = regexp.MustCompile(`^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$`)

// MaxTags bounds the tags of an items.read delegation.
const MaxTags = 16

// Scope is the delegation's scope object: the grant's op and its
// restrictions.
type Scope struct {
	Op          string
	Connections []string
	// The share rule of an items.read delegation (§10.12): its tags, match
	// and access, and the uses of each included item (0: not counted).
	Tags   []string
	Match  string
	Access string
	Uses   uint64
}

// Limits are the rate limits of the requests a grant allows without
// approval.
type Limits struct {
	PerHour uint64
	PerDay  uint64
}

// Delegation is one signed grant statement (LEASH §3.5, "Delegation").
type Delegation struct {
	// Iss is the member's credential key (§3.5.1).
	Iss ed25519.PublicKey
	// Sub is the agent's ik.
	Sub      ed25519.PublicKey
	GrantID  string
	Version  uint64
	Scope    Scope
	Approval string
	// Limits is present exactly when the grant has rate limits (every
	// auto and items.read grant).
	Limits *Limits
	// StatusIssuer is the member's vault, by its ik when the grant was
	// signed.
	StatusIssuer ed25519.PublicKey
	// StatusTTL is the lifetime of the status statements the status issuer
	// issues for this delegation.
	StatusTTL time.Duration
	// Nonce is 16 random bytes, new for each signature.
	Nonce    []byte
	IssuedAt time.Time // whole seconds
	Expires  time.Time // whole seconds; zero: the grant has no expiry (LEASH §3.2)
}

// NewNonce draws a delegation nonce from the vault's random generator.
func NewNonce() ([]byte, error) { return suite.RandomBytes(NonceSize) }

type jcsMember struct {
	name string
	val  []byte
}

// jcs writes a JSON object in RFC 8785 form: members sorted by name, no
// whitespace. Every name and value here is ASCII without characters that
// need escaping (Parse enforces it for values), so sorting by bytes is
// sorting by UTF-16 code units and strictjson.MarshalString is JCS's
// string form.
type jcs []jcsMember

func (o *jcs) str(n, v string) *jcs { return o.raw(n, strictjson.MarshalString(v)) }
func (o *jcs) b64(n string, v []byte) *jcs {
	return o.str(n, base64.StdEncoding.EncodeToString(v))
}
func (o *jcs) uint(n string, v uint64) *jcs { return o.raw(n, []byte(strconv.FormatUint(v, 10))) }
func (o *jcs) raw(n string, v []byte) *jcs  { *o = append(*o, jcsMember{n, v}); return o }

func (o jcs) bytes() []byte {
	sort.Slice(o, func(i, j int) bool { return o[i].name < o[j].name })
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, m := range o {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(strictjson.MarshalString(m.name))
		buf.WriteByte(':')
		buf.Write(m.val)
	}
	buf.WriteByte('}')
	return buf.Bytes()
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

// Marshal returns the delegation's JCS bytes (§10.11).
func (d *Delegation) Marshal() []byte {
	sc := &jcs{}
	sc.str("op", d.Scope.Op)
	if len(d.Scope.Connections) > 0 {
		sc.raw("connections", strList(d.Scope.Connections))
	}
	if len(d.Scope.Tags) > 0 {
		sc.raw("tags", strList(d.Scope.Tags)).str("match", d.Scope.Match).str("access", d.Scope.Access)
	}
	if d.Scope.Uses > 0 {
		sc.uint("uses", d.Scope.Uses)
	}
	o := &jcs{}
	o.uint("v", Format).b64("iss", d.Iss).b64("sub", d.Sub).str("grant_id", d.GrantID).uint("version", d.Version).
		raw("scope", sc.bytes()).str("approval", d.Approval)
	if d.Limits != nil {
		o.raw("limits", (&jcs{}).uint("per_hour", d.Limits.PerHour).uint("per_day", d.Limits.PerDay).bytes())
	}
	o.b64("status_issuer", d.StatusIssuer).uint("status_ttl", uint64(d.StatusTTL/time.Second)).
		b64("nonce", d.Nonce).uint("iat", uint64(d.IssuedAt.Unix()))
	if !d.Expires.IsZero() {
		o.uint("exp", uint64(d.Expires.Unix()))
	}
	return o.bytes()
}

// only requires that o has no member outside names (fail closed: a
// restriction a verifier cannot read must not be ignored).
func only(o strictjson.Object, names ...string) error {
	for k := range o {
		known := false
		for _, n := range names {
			if k == n {
				known = true
				break
			}
		}
		if !known {
			return ErrDelegation
		}
	}
	return nil
}

func ulidList(raw []json.RawMessage) ([]string, error) {
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

func parseScope(o strictjson.Object) (Scope, error) {
	var sc Scope
	so, err := o.Object("scope")
	if err != nil {
		return sc, ErrDelegation
	}
	if only(so, "op", "connections", "tags", "match", "access", "uses") != nil {
		return sc, ErrDelegation
	}
	if sc.Op, err = so.String("op"); err != nil || len(sc.Op) > 64 || !opRE.MatchString(sc.Op) {
		return sc, ErrDelegation
	}
	if raw, present, err := so.OptArray("connections"); err != nil {
		return sc, ErrDelegation
	} else if present {
		if sc.Op == ScopeItems {
			return sc, ErrDelegation
		}
		if sc.Connections, err = ulidList(raw); err != nil {
			return sc, ErrDelegation
		}
	}
	if sc.Op != ScopeItems {
		if so.Has("tags") || so.Has("match") || so.Has("access") || so.Has("uses") {
			return sc, ErrDelegation
		}
		return sc, nil
	}
	arr, err := so.Array("tags")
	if err != nil || len(arr) == 0 || len(arr) > MaxTags {
		return sc, ErrDelegation
	}
	for _, r := range arr {
		t, err := strictjson.AsString(r)
		if err != nil || !tagRE.MatchString(t) {
			return sc, ErrDelegation
		}
		sc.Tags = append(sc.Tags, t)
	}
	if sc.Match, err = so.String("match"); err != nil || sc.Match != "any" && sc.Match != "all" {
		return sc, ErrDelegation
	}
	if sc.Access, err = so.String("access"); err != nil || sc.Access != "read" {
		return sc, ErrDelegation
	}
	if sc.Uses, _, err = so.OptUint("uses", 1, MaxUses); err != nil {
		return sc, ErrDelegation
	}
	return sc, nil
}

func parseLimits(o strictjson.Object) (*Limits, error) {
	if !o.Has("limits") {
		return nil, nil
	}
	lo, err := o.Object("limits")
	if err != nil || only(lo, "per_hour", "per_day") != nil {
		return nil, ErrDelegation
	}
	l := &Limits{}
	if l.PerHour, err = lo.Uint("per_hour", 1, MaxPerHour); err != nil {
		return nil, ErrDelegation
	}
	if l.PerDay, err = lo.Uint("per_day", 1, MaxPerDay); err != nil {
		return nil, ErrDelegation
	}
	return l, nil
}

// Parse parses a delegation strictly (§10.11, "Verification"): a JSON
// object with v = 1, no duplicate member names, exactly the members of
// §10.11 with their types (no other member at the top level or in scope or
// limits), status_ttl within 60-3,600 s, and limits exactly for an auto or
// items.read grant. It does not require JCS: a verifier checks the
// signature over the bytes as received. The vault, which re-reads only
// delegations it produced, uses ParseCanonical.
func Parse(b []byte) (*Delegation, error) {
	if len(b) == 0 || len(b) > MaxBytes {
		return nil, ErrDelegation
	}
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, ErrDelegation
	}
	if only(o, "v", "iss", "sub", "grant_id", "version", "scope", "approval", "limits", "status_issuer",
		"status_ttl", "nonce", "iat", "exp") != nil {
		return nil, ErrDelegation
	}
	if v, err := o.Uint("v", Format, Format); err != nil || v != Format {
		return nil, ErrDelegation
	}
	d := &Delegation{}
	if d.Iss, err = o.Base64("iss", ed25519.PublicKeySize); err != nil {
		return nil, ErrDelegation
	}
	if d.Sub, err = o.Base64("sub", ed25519.PublicKeySize); err != nil {
		return nil, ErrDelegation
	}
	if d.GrantID, err = o.String("grant_id"); err != nil || !envelope.ValidULID(d.GrantID) {
		return nil, ErrDelegation
	}
	if d.Version, err = o.Uint("version", 1, strictjson.MaxSafeInteger); err != nil {
		return nil, ErrDelegation
	}
	if d.Scope, err = parseScope(o); err != nil {
		return nil, ErrDelegation
	}
	if d.Approval, err = o.String("approval"); err != nil || d.Approval != "ask" && d.Approval != "auto" {
		return nil, ErrDelegation
	}
	if d.Limits, err = parseLimits(o); err != nil {
		return nil, ErrDelegation
	}
	if (d.Limits != nil) != (d.Approval == "auto" || d.Scope.Op == ScopeItems) {
		return nil, ErrDelegation
	}
	if d.StatusIssuer, err = o.Base64("status_issuer", ed25519.PublicKeySize); err != nil {
		return nil, ErrDelegation
	}
	ttl, err := o.Uint("status_ttl", uint64(MinStatusTTL/time.Second), uint64(MaxStatusTTL/time.Second))
	if err != nil {
		return nil, ErrDelegation
	}
	d.StatusTTL = time.Duration(ttl) * time.Second
	if d.Nonce, err = o.Base64("nonce", NonceSize); err != nil {
		return nil, ErrDelegation
	}
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
	return d, nil
}

// ParseCanonical parses a delegation the vault produced and requires its
// JCS form.
func ParseCanonical(b []byte) (*Delegation, error) {
	d, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(d.Marshal(), b) != 1 {
		return nil, ErrDelegation // not JCS
	}
	return d, nil
}

// Sign signs the delegation's bytes with the member's credential key,
// which must be the delegation's iss.
func Sign(key ed25519.PrivateKey, delegation []byte) ([]byte, error) {
	d, err := ParseCanonical(delegation)
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PrivateKeySize || !suite.EqualPublic(key.Public().(ed25519.PublicKey), d.Iss) {
		return nil, ErrDelegation
	}
	return suite.Sign(key, Label, delegation)
}

// Verify checks a delegation alone: its form, the signature over the bytes
// as received under iss and that iss is the member key the verifier
// trusts (§10.11 step 1), and that now is before exp if present (step 2).
// Whether the grant is still in force is said by a status statement
// (VerifyPresented).
func Verify(memberKey ed25519.PublicKey, delegation, sig []byte, now time.Time) (*Delegation, error) {
	return verifyDelegation(trustKey(memberKey), delegation, sig, now)
}

func trustKey(k ed25519.PublicKey) func(ed25519.PublicKey) bool {
	return func(iss ed25519.PublicKey) bool { return suite.EqualPublic(iss, k) }
}

func verifyDelegation(trust func(iss ed25519.PublicKey) bool, delegation, sig []byte, now time.Time) (*Delegation, error) {
	d, err := Parse(delegation)
	if err != nil {
		return nil, err
	}
	// 1. sig under iss, and iss is trusted for this member.
	if suite.Verify(d.Iss, Label, delegation, sig) != nil || trust == nil || !trust(d.Iss) {
		return nil, ErrDelegation
	}
	// 2. now before exp, if present.
	if !d.Expires.IsZero() && !now.Before(d.Expires) {
		return nil, ErrDelegation
	}
	return d, nil
}

// String is for debugging only and never prints keys.
func (d *Delegation) String() string {
	return "leash delegation " + d.GrantID + " v" + strconv.FormatUint(d.Version, 10) + " " + d.Scope.Op
}

// Status is a status statement (LEASH §3.5, "Status statement"): the
// status issuer says the delegation is valid until NotAfter.
type Status struct {
	Delegation []byte // SHA-256 of the delegation's bytes
	GrantID    string
	IssuedAt   time.Time
	NotAfter   time.Time
}

// Marshal returns the statement's JCS bytes.
func (st *Status) Marshal() []byte {
	o := &jcs{}
	return o.uint("v", Format).b64("delegation", st.Delegation).str("grant_id", st.GrantID).str("status", "valid").
		uint("issued_at", uint64(st.IssuedAt.Unix())).uint("not_after", uint64(st.NotAfter.Unix())).bytes()
}

// ParseStatus parses a status statement strictly: exactly its members,
// v = 1, status "valid", and not_after after issued_at by at most an hour.
// Like Parse it does not require JCS; ParseStatusCanonical does.
func ParseStatus(b []byte) (*Status, error) {
	if len(b) == 0 || len(b) > MaxStatusBytes {
		return nil, ErrDelegation
	}
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, ErrDelegation
	}
	if only(o, "v", "delegation", "grant_id", "status", "issued_at", "not_after") != nil {
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
	return st, nil
}

// ParseStatusCanonical parses a statement the vault produced and requires
// its JCS form.
func ParseStatusCanonical(b []byte) (*Status, error) {
	st, err := ParseStatus(b)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(st.Marshal(), b) != 1 {
		return nil, ErrDelegation
	}
	return st, nil
}

// NewStatus returns the statement for a delegation the vault produced,
// issued now: valid for its status_ttl, never past the delegation's own
// exp.
func NewStatus(delegation []byte, now time.Time) (*Status, error) {
	d, err := ParseCanonical(delegation)
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
	if _, err := ParseStatusCanonical(statement); err != nil {
		return nil, err
	}
	return suite.Sign(ik, LabelStatus, statement)
}

// Presented is what an agent shows a relying party: the delegation, the
// member's signature (sig), a status statement, its signature, and the
// vault's identity.rotate statements from the delegation's status_issuer
// to the key that signed the statement (empty if it has not rotated; a
// VettID binding).
type Presented struct {
	Delegation, Sig   []byte
	Status, StatusSig []byte
	Rotations         []*handshake.Rotation
}

// VerifyPresented is VettID's reference verifier (§10.11,
// "Verification"), offline, with memberKey the credential key the relying
// party pinned for the member. See VerifyPresentedTrust.
func VerifyPresented(memberKey ed25519.PublicKey, p *Presented, now time.Time) (*Delegation, error) {
	return VerifyPresentedTrust(trustKey(memberKey), p, now)
}

// VerifyPresentedTrust runs steps 1-5 of §10.11's verification in order;
// trust says whether iss is a key the relying party trusts for this member
// (its pinned credential key, or an earlier one linked to it by rotation
// statements, §3.5.5). Steps 6 (proof of possession of sub) and 7 (the
// requested operation within scope) are the caller's. It is stricter than
// LEASH §3.5 requires, never looser: unknown members, a status_ttl outside
// 60-3,600 s, a statement longer-lived than the delegation's status_ttl,
// and a delegation without a status statement are rejected.
func VerifyPresentedTrust(trust func(iss ed25519.PublicKey) bool, p *Presented, now time.Time) (*Delegation, error) {
	if p == nil || len(p.Status) == 0 || len(p.StatusSig) == 0 {
		return nil, ErrDelegation // a status statement is required
	}
	st, err := ParseStatus(p.Status)
	if err != nil {
		return nil, err
	}
	// Steps 1 and 2.
	d, err := verifyDelegation(trust, p.Delegation, p.Sig, now)
	if err != nil {
		return nil, err
	}
	// 3. status_sig under status_issuer, or under the last key of the
	// rotation chain that starts at it.
	if len(p.Rotations) > MaxRotations {
		return nil, ErrDelegation
	}
	issuer, _, err := handshake.ResolveChain(d.StatusIssuer, p.Rotations)
	if err != nil {
		return nil, ErrDelegation
	}
	if suite.Verify(issuer, LabelStatus, p.Status, p.StatusSig) != nil {
		return nil, ErrDelegation
	}
	// 4. The statement names this delegation.
	h := sha256.Sum256(p.Delegation)
	if subtle.ConstantTimeCompare(h[:], st.Delegation) != 1 || st.GrantID != d.GrantID {
		return nil, ErrDelegation
	}
	// 5. issued_at - 60 s <= now <= not_after + 60 s.
	if now.Before(st.IssuedAt.Add(-StatusSkew)) || now.After(st.NotAfter.Add(StatusSkew)) {
		return nil, ErrDelegation
	}
	// Stricter: no statement outlives the delegation's status_ttl.
	if st.NotAfter.Sub(st.IssuedAt) > d.StatusTTL {
		return nil, ErrDelegation
	}
	return d, nil
}
