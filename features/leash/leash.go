// Package leash is LEASH for the member's agents (VAULT-MESSAGING
// §10.11): grants that give a paired agent one scope each, the decision
// behind the runtime's AgentPolicy hook (allow, refer to an app, refuse),
// agent.request for the catalog, retrieval and use of cataloged vault-held
// secrets, initial grants at pairing, and optional delegations signed
// with the member's credential key.
//
// Ported from vettid.dev's leash_handler.go and agent_handler.go: the
// per-user "attestation key" and its JWTs published to a public table are
// replaced by delegations signed with the credential key (the member's
// own key, usable only in an unlock window) that never leave the E2E
// sessions; the agent's Connection Contract (scope tokens, approval mode)
// becomes the agent's grants, enforced by the vault; secret requests,
// use-in-enclave actions and the catalog become agent.request operations
// on `cataloged` secrets. The HTTP action (a stub returning 501 in
// vettid.dev) is not offered: the enclave has no egress beyond the relay.
package leash

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/features/secrets"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/leashwire"
)

// Limits (§10.11).
const (
	MaxGrants      = 32
	MaxList        = 64
	MaxExpiry      = 365 * 24 * time.Hour
	MaxPerHour     = 3600
	MaxPerDay      = 86400
	DefaultPerHour = 60
	DefaultPerDay  = 1000
	MaxUseData     = 16384
)

// Approval modes.
const (
	Ask  = "ask"
	Auto = "auto"
)

// Scopes of the LEASH operations (agent.request).
const (
	ScopeCatalog = "secrets.catalog"
	ScopeGet     = "secrets.get"
	ScopeUse     = "secrets.use"
)

// opScope maps agent.request operations to their scopes.
var opScope = map[string]string{"catalog": ScopeCatalog, "secret.get": ScopeGet, "secret.use": ScopeUse}

// Delegable are the owner types a grant may give an agent (§10.11).
// connScoped are those whose body carries connection_id, which a grant's
// `connections` may restrict.
var (
	delegable = map[string]bool{"connection.list": true, "connection.get": true, "message.send": true, "message.list": true,
		"message.get": true, "message.read": true, "profile.get": true, "action.list": true, "action.invoke": true}
	connScoped = map[string]bool{"connection.get": true, "message.send": true, "message.list": true, "message.get": true,
		"message.read": true, "action.invoke": true}
)

// ValidScope reports whether s is a grant scope.
func ValidScope(s string) bool {
	return s == ScopeCatalog || s == ScopeGet || s == ScopeUse || delegable[s]
}

func secretScoped(scope string) bool {
	return scope == ScopeCatalog || scope == ScopeGet || scope == ScopeUse
}

// SecretSource is the vault-held secrets feature (§10.7).
type SecretSource interface {
	Catalog() []secrets.CatalogEntry
	CatalogedValue(id string) (name, value string, ok bool)
}

// KeyUser gives access to the credential key during the unlock window
// (credential.Feature.UseKey, §3.5.3).
type KeyUser interface {
	UseKey(now time.Time, ttl time.Duration) (ed25519.PrivateKey, bool)
}

// Grant is one agent's grant of one scope.
type Grant struct {
	ID          string    `json:"id"`
	AgentID     string    `json:"agent_id"`
	Version     uint64    `json:"version"`
	Scope       string    `json:"scope"`
	Approval    string    `json:"approval"`
	Connections []string  `json:"connections,omitempty"`
	Secrets     []string  `json:"secrets,omitempty"`
	PerHour     uint64    `json:"per_hour,omitempty"`
	PerDay      uint64    `json:"per_day,omitempty"`
	Expires     time.Time `json:"expires,omitempty"`
	IssuedAt    time.Time `json:"issued_at"`
	// A signed delegation (§10.11), if any.
	Delegation    []byte `json:"delegation,omitempty"`
	DelegationSig []byte `json:"delegation_sig,omitempty"`
	Key           []byte `json:"key,omitempty"`
	// Rate windows of the requests allowed without approval.
	HourStart time.Time `json:"hour_start,omitempty"`
	HourN     uint64    `json:"hour_n,omitempty"`
	DayStart  time.Time `json:"day_start,omitempty"`
	DayN      uint64    `json:"day_n,omitempty"`
	// LimitedAt is the start of the window in which leash.rate_limited
	// was last recorded (once per window).
	LimitedAt time.Time `json:"limited_at,omitempty"`
}

type data struct {
	Grants map[string]*Grant `json:"grants"`
}

// Feature implements vault.Feature, vault.AgentPolicy, vault.AgentGrantor,
// vault.DeviceRemovedObserver and vault.ConnectionRemovedObserver.
type Feature struct {
	mu      sync.Mutex
	keys    KeyUser
	secrets SecretSource
	d       data
}

// New returns the feature; keys is the credential feature, src the
// vault-held secrets.
func New(keys KeyUser, src SecretSource) *Feature {
	return &Feature{keys: keys, secrets: src, d: data{Grants: map[string]*Grant{}}}
}

var (
	apps   = []string{vault.KindApp}
	owners = []string{vault.KindApp, vault.KindDesktop}
	all    = []string{vault.KindApp, vault.KindDesktop, vault.KindAgent}
	agents = []string{vault.KindAgent}
)

// Name implements vault.Feature.
func (f *Feature) Name() string { return "leash" }

// Types implements vault.Feature.
func (f *Feature) Types() []vault.TypeSpec {
	return []vault.TypeSpec{
		{Type: "leash.grant.issue", Request: true, From: apps},
		{Type: "leash.grant.revoke", Request: true, From: owners},
		{Type: "leash.grant.list", Request: true, From: all},
		{Type: "agent.request", Request: true, From: agents, AgentPolicy: true},
	}
}

// Load implements vault.Feature.
func (f *Feature) Load(raw json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := data{}
	if err := json.Unmarshal(raw, &d); err != nil {
		return err
	}
	if d.Grants == nil {
		d.Grants = map[string]*Grant{}
	}
	f.d = d
	return nil
}

// Save implements vault.Feature.
func (f *Feature) Save() (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return json.Marshal(f.d)
}

var (
	errBad       = vault.NewError("bad_request", "")
	errNotFound  = vault.NewError("not_found", "")
	errForbidden = vault.NewError("forbidden", "")
	errLimit     = vault.NewError("limit", "")
	errConflict  = vault.NewError("conflict", "")
	errLocked    = vault.NewError("credential_locked", "")
	errInternal  = vault.NewError("internal", "")
)

// Spec is a parsed grant specification (leash.grant.issue, or one entry of
// device.pair.approve{grants}).
type Spec struct {
	Scope       string
	Approval    string
	Connections []string
	Secrets     []string
	PerHour     uint64
	PerDay      uint64
	Expires     time.Time
	Sign        bool
}

func idList(o strictjson.Object, name string) ([]string, error) {
	raw, present, err := o.OptArray(name)
	if err != nil {
		return nil, errBad
	}
	if !present {
		return nil, nil
	}
	if len(raw) == 0 || len(raw) > MaxList {
		return nil, errBad
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		s, err := strictjson.AsString(r)
		if err != nil || !envelope.ValidULID(s) || seen[s] {
			return nil, errBad
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, nil
}

// ParseSpec parses a grant specification strictly (§10.11). pairing
// refuses `sign` (grants made with a pairing approval are never signed).
func ParseSpec(o strictjson.Object, now time.Time, pairing bool) (*Spec, error) {
	sp := &Spec{Approval: Ask}
	var err error
	if sp.Scope, err = o.String("scope"); err != nil || !ValidScope(sp.Scope) {
		return nil, errBad
	}
	if a, present, err := o.OptString("approval"); err != nil || present && a != Ask && a != Auto {
		return nil, errBad
	} else if present {
		sp.Approval = a
	}
	if sp.Connections, err = idList(o, "connections"); err != nil || sp.Connections != nil && !connScoped[sp.Scope] {
		return nil, errBad
	}
	if sp.Secrets, err = idList(o, "secrets"); err != nil || sp.Secrets != nil && !secretScoped(sp.Scope) {
		return nil, errBad
	}
	ph, phSet, err := o.OptUint("per_hour", 1, MaxPerHour)
	if err != nil {
		return nil, errBad
	}
	pd, pdSet, err := o.OptUint("per_day", 1, MaxPerDay)
	if err != nil {
		return nil, errBad
	}
	if sp.Approval == Ask && (phSet || pdSet) {
		return nil, errBad // limits bound only what is allowed without approval
	}
	if sp.Approval == Auto {
		sp.PerHour, sp.PerDay = DefaultPerHour, DefaultPerDay
		if phSet {
			sp.PerHour = ph
		}
		if pdSet {
			sp.PerDay = pd
		}
		if sp.Scope == ScopeGet && sp.Secrets == nil {
			return nil, errBad // values without approval only from named secrets
		}
	}
	if s, present, err := o.OptString("expires_at"); err != nil {
		return nil, errBad
	} else if present {
		t, err := envelope.ParseTS(s)
		if err != nil || !t.After(now) || t.Sub(now) > MaxExpiry {
			return nil, errBad
		}
		sp.Expires = t.UTC()
	}
	if o.Has("sign") {
		if pairing {
			return nil, errBad
		}
		if sp.Sign, err = o.Bool("sign"); err != nil {
			return nil, errBad
		}
	}
	return sp, nil
}

// ParseInitialGrants parses device.pair.approve's grants (1–MaxGrants
// specifications, never signed).
func ParseInitialGrants(raw json.RawMessage, now time.Time) ([]*Spec, error) {
	arr, err := strictjson.AsArray(raw)
	if err != nil || len(arr) == 0 || len(arr) > MaxGrants {
		return nil, errBad
	}
	out := make([]*Spec, 0, len(arr))
	for _, r := range arr {
		o, err := strictjson.AsObject(r)
		if err != nil {
			return nil, errBad
		}
		sp, err := ParseSpec(o, now, true)
		if err != nil {
			return nil, err
		}
		out = append(out, sp)
	}
	return out, nil
}

// Request is a parsed agent.request body.
type Request struct {
	Op       string
	SecretID string
	Action   string
	Data     []byte
}

// ParseRequest parses an agent.request body strictly.
func ParseRequest(body []byte) (*Request, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	r := &Request{}
	if r.Op, err = o.String("op"); err != nil || opScope[r.Op] == "" {
		return nil, errBad
	}
	if r.Op == "catalog" {
		return r, nil
	}
	if r.SecretID, err = o.String("secret_id"); err != nil || !envelope.ValidULID(r.SecretID) {
		return nil, errBad
	}
	if r.Op == "secret.use" {
		if r.Action, err = o.String("action"); err != nil || r.Action != "hmac-sha256" {
			return nil, errBad
		}
		if r.Data, err = o.Base64("data", -1); err != nil || len(r.Data) == 0 || len(r.Data) > MaxUseData {
			return nil, errBad
		}
	}
	return r, nil
}

// --- the policy (§6.8, §10.11) ---

// scopeOf returns the scope a request needs and the members its grants'
// restrictions apply to. ok is false for a type no grant can cover.
func scopeOf(typ string, body json.RawMessage) (scope, conn, secret string, parsed, ok bool) {
	if typ == "agent.request" {
		r, err := ParseRequest(body)
		if err != nil {
			return "", "", "", false, true
		}
		return opScope[r.Op], "", r.SecretID, true, true
	}
	if !delegable[typ] {
		return "", "", "", true, false
	}
	if connScoped[typ] {
		if o, err := strictjson.ParseObject(body); err == nil {
			conn, _, _ = o.OptString("connection_id")
		}
	}
	return typ, conn, "", true, true
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

// matches reports whether g covers a request of scope with the members
// conn and secret.
func (g *Grant) matches(scope, conn, secret string, now time.Time) bool {
	if g.Scope != scope || !g.Expires.IsZero() && !now.Before(g.Expires) {
		return false
	}
	if g.Connections != nil && (conn == "" || !contains(g.Connections, conn)) {
		return false
	}
	// The catalog is filtered by `secrets`, not refused (§10.11).
	if g.Secrets != nil && scope != ScopeCatalog && (secret == "" || !contains(g.Secrets, secret)) {
		return false
	}
	return true
}

// matching returns the agent's grants covering a request, sorted by id.
func (f *Feature) matching(agent, scope, conn, secret string, now time.Time) []*Grant {
	var out []*Grant
	for _, g := range f.d.Grants {
		if g.AgentID == agent && g.matches(scope, conn, secret, now) {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// roll starts new rate windows when they have run out.
func (g *Grant) roll(now time.Time) {
	if g.HourStart.IsZero() || now.Sub(g.HourStart) >= time.Hour {
		g.HourStart, g.HourN = now, 0
	}
	if g.DayStart.IsZero() || now.Sub(g.DayStart) >= 24*time.Hour {
		g.DayStart, g.DayN = now, 0
	}
}

// AgentDecision implements vault.AgentPolicy.
func (f *Feature) AgentDecision(s *vault.Session, typ string, body json.RawMessage) vault.AgentDecision {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now()
	f.expire(now)
	agent := s.From().ID
	scope, conn, secret, parsed, ok := scopeOf(typ, body)
	if !parsed {
		return vault.AgentAllow // agent.request answers bad_request itself; nothing runs
	}
	var gs []*Grant
	if ok {
		gs = f.matching(agent, scope, conn, secret, now)
	}
	if len(gs) == 0 {
		s.Record(vault.Activity{Kind: "drop.leash_refused", DeviceID: agent, Audit: true})
		return vault.AgentDeny
	}
	for _, g := range gs {
		if g.Approval != Auto {
			continue
		}
		g.roll(now)
		if g.HourN < g.PerHour && g.DayN < g.PerDay {
			g.HourN++
			g.DayN++
			s.Record(vault.Activity{Kind: "leash.allowed", DeviceID: agent, Ref: g.ID, Audit: true})
			return vault.AgentAllow
		}
		window := g.HourStart
		if g.DayN >= g.PerDay {
			window = g.DayStart
		}
		if !g.LimitedAt.Equal(window) {
			g.LimitedAt = window
			s.Record(vault.Activity{Kind: "leash.rate_limited", DeviceID: agent, Ref: g.ID, Audit: true, Feed: true, Priority: "high"})
		}
	}
	return vault.AgentAsk
}

// --- grants ---

// expire drops expired grants (they match nothing, §10.11).
func (f *Feature) expire(now time.Time) {
	for id, g := range f.d.Grants {
		if !g.Expires.IsZero() && !now.Before(g.Expires) {
			delete(f.d.Grants, id)
		}
	}
}

func (f *Feature) count(agent string) int {
	n := 0
	for _, g := range f.d.Grants {
		if g.AgentID == agent {
			n++
		}
	}
	return n
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

// JSON is a grant's wire form (§10.11).
func (g *Grant) JSON() []byte {
	b := strictjson.NewBuilder().String("grant_id", g.ID).String("agent_id", g.AgentID).Uint("version", g.Version).
		String("scope", g.Scope).String("approval", g.Approval)
	if g.Connections != nil {
		b.Raw("connections", strList(g.Connections))
	}
	if g.Secrets != nil {
		b.Raw("secrets", strList(g.Secrets))
	}
	if g.PerHour > 0 {
		b.Uint("per_hour", g.PerHour).Uint("per_day", g.PerDay)
	}
	if !g.Expires.IsZero() {
		b.String("expires_at", envelope.FormatTS(g.Expires))
	}
	b.String("issued_at", envelope.FormatTS(g.IssuedAt))
	if g.Delegation != nil {
		b.Base64("delegation", g.Delegation).Base64("delegation_sig", g.DelegationSig).Base64("key", g.Key)
	}
	return b.Bytes()
}

func (f *Feature) listJSON(agent string) []byte {
	var gs []*Grant
	for _, g := range f.d.Grants {
		if agent == "" || g.AgentID == agent {
			gs = append(gs, g)
		}
	}
	sort.Slice(gs, func(i, j int) bool { return gs[i].ID < gs[j].ID })
	arr := []byte{'['}
	for i, g := range gs {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, g.JSON()...)
	}
	return strictjson.NewBuilder().Raw("grants", append(arr, ']')).Bytes()
}

// tell sends the agent its grants (within its access session, §6.8).
func (f *Feature) tell(s *vault.Session, agent string) {
	_ = s.Send(agent, "leash.grant.updated", f.listJSON(agent), vault.SendOptions{})
}

func syncChanged(s *vault.Session, g *Grant) {
	s.SyncEvent("leash.grant.changed", strictjson.NewBuilder().String("grant_id", g.ID).String("agent_id", g.AgentID).
		Uint("version", g.Version).Bytes())
}

func syncRevoked(s *vault.Session, g *Grant) {
	s.SyncEvent("leash.grant.revoked", strictjson.NewBuilder().String("grant_id", g.ID).String("agent_id", g.AgentID).Bytes())
}

func (sp *Spec) apply(g *Grant) {
	g.Scope, g.Approval, g.Connections, g.Secrets = sp.Scope, sp.Approval, sp.Connections, sp.Secrets
	g.PerHour, g.PerDay, g.Expires = sp.PerHour, sp.PerDay, sp.Expires
	g.Delegation, g.DelegationSig, g.Key = nil, nil, nil
	g.HourStart, g.HourN, g.DayStart, g.DayN, g.LimitedAt = time.Time{}, 0, time.Time{}, 0, time.Time{}
}

// issue handles leash.grant.issue.
func (f *Feature) issue(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	now := s.Now().UTC().Truncate(time.Millisecond)
	agentID, err := o.String("agent_id")
	if err != nil || agentID == "" {
		return nil, errBad
	}
	sp, err := ParseSpec(o, now, false)
	if err != nil {
		return nil, err
	}
	gid, hasID, err := o.OptString("grant_id")
	if err != nil || hasID && !envelope.ValidULID(gid) {
		return nil, errBad
	}
	ver, hasVer, err := o.OptUint("version", 1, strictjson.MaxSafeInteger)
	if err != nil || hasID != hasVer {
		return nil, errBad
	}
	agent, ok := s.PairedDevice(agentID)
	if !ok || agent.Kind != vault.KindAgent {
		return nil, errNotFound
	}
	var g *Grant
	if hasID {
		cur := f.d.Grants[gid]
		if cur == nil || cur.AgentID != agentID {
			return nil, errNotFound
		}
		if cur.Version != ver {
			return nil, errConflict
		}
		c := *cur
		g = &c
	} else {
		if f.count(agentID) >= MaxGrants {
			return nil, errLimit
		}
		g = &Grant{ID: s.NewID(), AgentID: agentID}
	}
	sp.apply(g)
	g.Version++
	g.IssuedAt = now
	if sp.Sign {
		if err := f.sign(s, g, agent.IK); err != nil {
			return nil, err
		}
	}
	f.d.Grants[g.ID] = g
	kind := "leash.grant.issued"
	if hasID {
		kind = "leash.grant.updated"
	}
	s.Record(vault.Activity{Kind: kind, DeviceID: agentID, Ref: g.ID, Audit: true})
	syncChanged(s, g)
	f.tell(s, agentID)
	return g.JSON(), nil
}

// sign makes the grant's delegation with the credential key, which the
// unlock window holds (§10.11).
func (f *Feature) sign(s *vault.Session, g *Grant, agentIK []byte) error {
	if f.keys == nil {
		return errLocked
	}
	key, ok := f.keys.UseKey(s.Now(), s.Settings().UnlockTTL())
	if !ok {
		return errLocked
	}
	iat := s.Now().UTC().Truncate(time.Second)
	exp := iat.Add(leashwire.MaxLifetime)
	if !g.Expires.IsZero() && g.Expires.Before(exp) {
		exp = g.Expires.Truncate(time.Second)
	}
	if exp.Before(iat) {
		exp = iat
	}
	d := &leashwire.Delegation{VaultIK: s.IdentityKey(), AgentIK: agentIK, GrantID: g.ID, Version: g.Version,
		Scope: g.Scope, Approval: g.Approval, Connections: g.Connections, Secrets: g.Secrets, IssuedAt: iat, Expires: exp}
	stmt := d.Marshal()
	sig, err := leashwire.Sign(key, stmt)
	if err != nil {
		return errInternal
	}
	g.Delegation, g.DelegationSig = stmt, sig
	g.Key = append([]byte(nil), key.Public().(ed25519.PublicKey)...)
	return nil
}

func grantID(body []byte) (string, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", errBad
	}
	id, err := o.String("grant_id")
	if err != nil || !envelope.ValidULID(id) {
		return "", errBad
	}
	return id, nil
}

// revoke deletes a grant and tells everyone concerned.
func (f *Feature) revoke(s *vault.Session, g *Grant, notifyAgent bool) {
	delete(f.d.Grants, g.ID)
	s.Record(vault.Activity{Kind: "leash.grant.revoked", DeviceID: g.AgentID, Ref: g.ID, Audit: true})
	syncRevoked(s, g)
	if notifyAgent {
		f.tell(s, g.AgentID)
	}
}

// Handle implements vault.Handler.
func (f *Feature) Handle(_ context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expire(s.Now())
	switch in.Type {
	case "leash.grant.issue":
		return f.issue(s, in.Body)
	case "leash.grant.revoke":
		id, err := grantID(in.Body)
		if err != nil {
			return nil, err
		}
		g := f.d.Grants[id]
		if g == nil {
			return nil, errNotFound
		}
		f.revoke(s, g, true)
		return nil, nil
	case "leash.grant.list":
		o, err := strictjson.ParseObject(in.Body)
		if err != nil {
			return nil, errBad
		}
		if s.From().Kind == vault.KindAgent {
			return f.listJSON(s.From().ID), nil // its own grants only
		}
		agent, _, err := o.OptString("agent_id")
		if err != nil {
			return nil, errBad
		}
		return f.listJSON(agent), nil
	case "agent.request":
		return f.request(s, in.Body)
	}
	return nil, vault.NewError("unsupported_type", "")
}

// request handles agent.request (§10.11). The policy already decided; the
// grants are checked again (a referred request runs only while covered).
func (f *Feature) request(s *vault.Session, body []byte) (json.RawMessage, error) {
	r, err := ParseRequest(body)
	if err != nil {
		return nil, err
	}
	agent := s.From().ID
	gs := f.matching(agent, opScope[r.Op], "", r.SecretID, s.Now())
	if len(gs) == 0 {
		return nil, errForbidden
	}
	switch r.Op {
	case "catalog":
		allowed := map[string]bool{}
		unrestricted := false
		for _, g := range gs {
			if g.Secrets == nil {
				unrestricted = true
			}
			for _, id := range g.Secrets {
				allowed[id] = true
			}
		}
		arr := []byte{'['}
		n := 0
		for _, e := range f.secrets.Catalog() {
			if !unrestricted && !allowed[e.ID] {
				continue
			}
			if n > 0 {
				arr = append(arr, ',')
			}
			n++
			b := strictjson.NewBuilder().String("secret_id", e.ID).String("name", e.Name).String("category", e.Category)
			if e.Description != "" {
				b.String("description", e.Description)
			}
			arr = append(arr, b.Bytes()...)
		}
		return strictjson.NewBuilder().Raw("secrets", append(arr, ']')).Bytes(), nil
	case "secret.get":
		name, value, ok := f.secrets.CatalogedValue(r.SecretID)
		if !ok {
			return nil, errNotFound
		}
		s.Record(vault.Activity{Kind: "leash.secret.read", DeviceID: agent, Ref: r.SecretID, Audit: true, Feed: true})
		return strictjson.NewBuilder().String("secret_id", r.SecretID).String("name", name).String("value", value).Bytes(), nil
	case "secret.use":
		_, value, ok := f.secrets.CatalogedValue(r.SecretID)
		if !ok {
			return nil, errNotFound
		}
		mac := hmac.New(sha256.New, []byte(value))
		mac.Write(r.Data)
		s.Record(vault.Activity{Kind: "leash.secret.used", DeviceID: agent, Ref: r.SecretID, Audit: true})
		return strictjson.NewBuilder().String("secret_id", r.SecretID).String("action", r.Action).
			Base64("result", mac.Sum(nil)).Bytes(), nil
	}
	return nil, errBad
}

// --- hooks ---

// ValidateAgentGrants implements vault.AgentGrantor.
func (f *Feature) ValidateAgentGrants(grants json.RawMessage, now time.Time) error {
	_, err := ParseInitialGrants(grants, now)
	return err
}

// AgentPaired implements vault.AgentGrantor: the initial grants take
// effect with the pairing (§6.7).
func (f *Feature) AgentPaired(s *vault.Session, agentID string, grants json.RawMessage) {
	f.mu.Lock()
	defer f.mu.Unlock()
	specs, err := ParseInitialGrants(grants, s.Now())
	if err != nil {
		return
	}
	now := s.Now().UTC().Truncate(time.Millisecond)
	for _, sp := range specs {
		if f.count(agentID) >= MaxGrants || !sp.Expires.IsZero() && !now.Before(sp.Expires) {
			continue
		}
		g := &Grant{ID: s.NewID(), AgentID: agentID, Version: 1, IssuedAt: now}
		sp.apply(g)
		f.d.Grants[g.ID] = g
		s.Record(vault.Activity{Kind: "leash.grant.issued", DeviceID: agentID, Ref: g.ID, Audit: true})
		syncChanged(s, g)
	}
	f.tell(s, agentID)
}

// DeviceRemoved implements vault.DeviceRemovedObserver: unlinking an
// agent revokes all of its grants (§7.4).
func (f *Feature) DeviceRemoved(s *vault.Session, deviceID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, g := range f.sorted() {
		if g.AgentID == deviceID {
			f.revoke(s, g, false)
		}
	}
}

// ConnectionRemoved implements vault.ConnectionRemovedObserver: the
// connection leaves every grant's `connections`; a grant left with none is
// revoked (§10.11).
func (f *Feature) ConnectionRemoved(s *vault.Session, conn string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	touched := map[string]bool{}
	for _, g := range f.sorted() {
		if !contains(g.Connections, conn) {
			continue
		}
		var keep []string
		for _, c := range g.Connections {
			if c != conn {
				keep = append(keep, c)
			}
		}
		touched[g.AgentID] = true
		if len(keep) == 0 {
			f.revoke(s, g, false)
			continue
		}
		g.Connections = keep
		g.Version++
		g.Delegation, g.DelegationSig, g.Key = nil, nil, nil // it no longer says what the grant is
		syncChanged(s, g)
	}
	for agent := range touched {
		f.tell(s, agent)
	}
}

func (f *Feature) sorted() []*Grant {
	out := make([]*Grant, 0, len(f.d.Grants))
	for _, g := range f.d.Grants {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Grants returns a copy of every grant (tests and tools).
func (f *Feature) Grants() []Grant {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Grant
	for _, g := range f.sorted() {
		out = append(out, *g)
	}
	return out
}
