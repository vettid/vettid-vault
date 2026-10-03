// Package actions is shared actions between connections (VAULT-MESSAGING
// §10.14): a fixed catalog of actions built into each release and run by
// the vault itself, natively in the vault's process, under a permission
// mode the member sets per action (default-deny, allowlist,
// prompt-each-time, default-allow). A connection learns what it may
// invoke from the member's offer; an invocation is answered with the
// action's result or a refusal.
//
// Ported from vettid.dev's action_{catalog,router,invoker,pending,
// authorization,schema}.go: the catalog, the per-action modes and the
// pending approvals are kept; profile.fields.read and secrets.share now
// make one-use grants (§10.12) instead of returning values; the votes and
// introductions entries are gone (introductions are member-initiated,
// §10.15); JSON-schema validation becomes a strict parser per action;
// invoker and result signatures are dropped (the session authenticates
// both vaults); invocations and results travel as types in the
// connection's session, which fixes the old mis-routing.
package actions

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/features/grants"
	"github.com/vettid/vettid-vault/features/profile"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Limits (§10.14).
const (
	CatalogVersion    = 1
	MaxConnections    = 256
	MaxFields         = 64
	MaxSecrets        = 64
	MaxParams         = 4096
	MaxResult         = 16384
	MaxPendingPerConn = 8
	MaxPerHour        = 60
	PendingTTL        = 24 * time.Hour
	OutgoingTTL       = 25 * time.Hour
	MaxOffers         = 64
	MaxOutgoing       = 256
	GrantUses         = 1
	GrantTTL          = 10 * time.Minute
	AuditDefault      = 20
	AuditMax          = 50
	MaxRequestFields  = 16
	MaxMemo           = 280
	MaxSats           = 2100000000000000
)

// Permission modes.
const (
	ModeDeny   = "default-deny"
	ModeList   = "allowlist"
	ModePrompt = "prompt-each-time"
	ModeAllow  = "default-allow"
)

// Sensitivities.
const (
	Normal    = "normal"
	Sensitive = "sensitive"
	Critical  = "critical"
)

// Result statuses.
const (
	StatusOK          = "ok"
	StatusDenied      = "denied"
	StatusExpired     = "expired"
	StatusUnavailable = "unavailable"
)

// Action ids of catalog version 1.
const (
	ProfileFieldsRead = "profile.fields.read"
	SecretsShare      = "secrets.share"
	AuditRecent       = "audit.recent"
	WalletAddress     = "wallet.request-address"
	WalletPayment     = "wallet.request-payment"
)

// Def is one built-in action.
type Def struct {
	ID           string
	Version      uint64
	Sensitivity  string
	Available    bool // false: answered `unavailable` (the wallet is not there yet)
	ParamSchema  string
	ResultSchema string
}

const grantsResultSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","required":["grants"],` +
	`"properties":{"grants":{"type":"array","items":{"type":"object","required":["grant_id","kind","ref","uses","expires_at"],` +
	`"properties":{"grant_id":{"type":"string"},"kind":{"type":"string"},"ref":{"type":"string"},"uses":{"type":"integer"},` +
	`"expires_at":{"type":"string"}}}}}}`

// Catalog returns catalog version 1, in a fixed order. It is built per
// call: no package-level mutable state.
func Catalog() []Def {
	return []Def{
		{ID: ProfileFieldsRead, Version: 1, Sensitivity: Sensitive, Available: true,
			ParamSchema: `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","required":["fields"],` +
				`"properties":{"fields":{"type":"array","minItems":1,"maxItems":16,"uniqueItems":true,` +
				`"items":{"type":"string","pattern":"^[a-z][a-z0-9_.-]{0,63}$"}}},"additionalProperties":false}`,
			ResultSchema: grantsResultSchema},
		{ID: SecretsShare, Version: 1, Sensitivity: Sensitive, Available: true,
			ParamSchema: `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","required":["secret_id"],` +
				`"properties":{"secret_id":{"type":"string","pattern":"^[0-7][0-9A-HJKMNP-TV-Z]{25}$"}},"additionalProperties":false}`,
			ResultSchema: grantsResultSchema},
		{ID: AuditRecent, Version: 1, Sensitivity: Normal, Available: true,
			ParamSchema: `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object",` +
				`"properties":{"limit":{"type":"integer","minimum":1,"maximum":50}},"additionalProperties":false}`,
			ResultSchema: `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","required":["entries"],` +
				`"properties":{"entries":{"type":"array","items":{"type":"object","required":["kind","at"],` +
				`"properties":{"kind":{"type":"string"},"at":{"type":"string"},"direction":{"enum":["in","out"]}}}}}}`},
		{ID: WalletAddress, Version: 1, Sensitivity: Normal, Available: false,
			ParamSchema: `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","required":["asset"],` +
				`"properties":{"asset":{"enum":["BTC"]}},"additionalProperties":false}`,
			ResultSchema: `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","required":["asset","address"],` +
				`"properties":{"asset":{"type":"string"},"address":{"type":"string"}}}`},
		{ID: WalletPayment, Version: 1, Sensitivity: Critical, Available: false,
			ParamSchema: `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","required":["asset","amount_sats"],` +
				`"properties":{"asset":{"enum":["BTC"]},"amount_sats":{"type":"integer","minimum":1,"maximum":2100000000000000},` +
				`"memo":{"type":"string","maxLength":280}},"additionalProperties":false}`,
			ResultSchema: `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","required":["status"],` +
				`"properties":{"status":{"type":"string"},"txid":{"type":"string"}}}`},
	}
}

// Lookup returns a catalog action.
func Lookup(id string) (Def, bool) {
	for _, d := range Catalog() {
		if d.ID == id {
			return d, true
		}
	}
	return Def{}, false
}

// Config is the member's configuration of one action (versioned, §10.1).
type Config struct {
	Version     uint64   `json:"version"`
	Mode        string   `json:"mode"`
	Connections []string `json:"connections,omitempty"`
	Fields      []string `json:"fields,omitempty"`
	Secrets     []string `json:"secrets,omitempty"`
}

// Offer is one action a connection offers this vault.
type Offer struct {
	ActionID string `json:"action_id"`
	Version  uint64 `json:"version"`
	Prompt   bool   `json:"prompt"`
}

// Pending is an invocation waiting for the member (prompt-each-time).
type Pending struct {
	ID       string          `json:"id"`
	Conn     string          `json:"conn"`
	ActionID string          `json:"action_id"`
	Params   json.RawMessage `json:"params"`
	Exp      time.Time       `json:"exp"`
}

// Outgoing is an invocation this vault sent, kept for its result.
type Outgoing struct {
	ID       string    `json:"id"`
	Conn     string    `json:"conn"`
	ActionID string    `json:"action_id"`
	Exp      time.Time `json:"exp"`
}

type data struct {
	Configs  map[string]*Config   `json:"configs"`  // by action_id
	Offers   map[string][]Offer   `json:"offers"`   // by connection id
	Pending  map[string]*Pending  `json:"pending"`  // by invocation_id
	Outgoing map[string]*Outgoing `json:"outgoing"` // by invocation_id
	// Seen are answered invocation ids (kept 25 h): a repeat is ignored.
	Seen map[string]time.Time `json:"seen"`
	// Hits are the invocations received per connection in the last hour.
	Hits map[string][]time.Time `json:"hits"`
}

func (d *data) init() {
	if d.Configs == nil {
		d.Configs = map[string]*Config{}
	}
	if d.Offers == nil {
		d.Offers = map[string][]Offer{}
	}
	if d.Pending == nil {
		d.Pending = map[string]*Pending{}
	}
	if d.Outgoing == nil {
		d.Outgoing = map[string]*Outgoing{}
	}
	if d.Seen == nil {
		d.Seen = map[string]time.Time{}
	}
	if d.Hits == nil {
		d.Hits = map[string][]time.Time{}
	}
}

// Feature implements vault.Feature, vault.ConnectionObserver and
// vault.ConnectionRemovedObserver.
type Feature struct {
	mu   sync.Mutex
	deps Deps
	d    data
}

// New returns the feature; deps are the features actions run through.
func New(deps Deps) *Feature {
	f := &Feature{deps: deps}
	f.d.init()
	return f
}

var (
	owners = []string{vault.KindApp, vault.KindDesktop}
	conns  = []string{vault.KindConnection}
)

// Name implements vault.Feature.
func (f *Feature) Name() string { return "actions" }

// Types implements vault.Feature.
func (f *Feature) Types() []vault.TypeSpec {
	return []vault.TypeSpec{
		{Type: "action.list", Request: true, From: owners},
		// A desktop changes what connections can obtain only with an
		// app's approval (§6.8 step-up).
		{Type: "action.configure", Request: true, From: owners, DesktopApproval: true},
		{Type: "action.invoke", Request: true, From: owners},
		{Type: "action.respond", Request: true, From: owners},
		{Type: "action.offered", From: conns},
		// The invocation between vaults is an event (§10), so it has its
		// own type: a device's action.invoke is a request.
		{Type: "action.invocation", From: conns},
		{Type: "action.result", From: conns},
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
	d.init()
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
	errConflict  = vault.NewError("conflict", "")
	errLimit     = vault.NewError("limit", "")
	errForbidden = vault.NewError("forbidden", "")
	errLocked    = vault.NewError("credential_locked", "")
	errConn      = vault.NewError("connection_unavailable", "")
)

// --- parsing ---

func ulid(o strictjson.Object, name string) (string, error) {
	v, err := o.String(name)
	if err != nil || !envelope.ValidULID(v) {
		return "", errBad
	}
	return v, nil
}

func strList(o strictjson.Object, name string, max int, valid func(string) bool) ([]string, bool, error) {
	raw, present, err := o.OptArray(name)
	if err != nil || len(raw) > max {
		return nil, false, errBad
	}
	if !present {
		return nil, false, nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, r := range raw {
		s, err := strictjson.AsString(r)
		if err != nil || !valid(s) || seen[s] {
			return nil, false, errBad
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, true, nil
}

// Configure is a parsed action.configure body.
type Configure struct {
	ActionID    string
	Mode        string
	Version     uint64 // the version it is based on, +1 (0: not given)
	Connections []string
	Fields      []string
	Secrets     []string
}

// ParseConfigure parses an action.configure body strictly and checks it
// against the catalog: modes per sensitivity, fields and secrets only for
// the actions they bound.
func ParseConfigure(body []byte) (*Configure, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	c := &Configure{}
	if c.ActionID, err = o.String("action_id"); err != nil {
		return nil, errBad
	}
	def, ok := Lookup(c.ActionID)
	if !ok {
		return nil, errNotFound
	}
	if c.Mode, err = o.String("mode"); err != nil {
		return nil, errBad
	}
	switch c.Mode {
	case ModeDeny, ModePrompt:
	case ModeList:
		if def.Sensitivity == Critical {
			return nil, errBad // a critical action is always approved by the member
		}
	case ModeAllow:
		if def.Sensitivity != Normal {
			return nil, errBad // never default-allow for sensitive or critical actions
		}
	default:
		return nil, errBad
	}
	if v, present, err := o.OptUint("version", 0, strictjson.MaxSafeInteger-1); err != nil {
		return nil, errBad
	} else if present {
		c.Version = v + 1
	}
	if c.Connections, _, err = strList(o, "connections", MaxConnections, envelope.ValidULID); err != nil {
		return nil, err
	}
	var present bool
	if c.Fields, present, err = strList(o, "fields", MaxFields, profile.ValidKey); err != nil || present && (c.ActionID != ProfileFieldsRead || len(c.Fields) == 0) {
		return nil, errBad
	}
	if c.Secrets, present, err = strList(o, "secrets", MaxSecrets, envelope.ValidULID); err != nil || present && (c.ActionID != SecretsShare || len(c.Secrets) == 0) {
		return nil, errBad
	}
	return c, nil
}

func paramsObject(o strictjson.Object, required bool) (json.RawMessage, error) {
	raw, present, err := o.OptObjectRaw("params")
	if err != nil || !present && required {
		return nil, errBad
	}
	if !present {
		return json.RawMessage(`{}`), nil
	}
	c, err := strictjson.CompactObject(raw)
	if err != nil || len(c) > MaxParams {
		return nil, errBad
	}
	return c, nil
}

// Invoke is a parsed device action.invoke body.
type Invoke struct {
	ConnectionID string
	ActionID     string
	Params       json.RawMessage
}

// ParseInvoke parses a device's action.invoke body strictly.
func ParseInvoke(body []byte) (*Invoke, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	v := &Invoke{}
	if v.ConnectionID, err = o.String("connection_id"); err != nil || v.ConnectionID == "" || len(v.ConnectionID) > 128 {
		return nil, errBad
	}
	if v.ActionID, err = o.String("action_id"); err != nil || v.ActionID == "" || len(v.ActionID) > 64 {
		return nil, errBad
	}
	if v.Params, err = paramsObject(o, false); err != nil {
		return nil, err
	}
	return v, nil
}

// Invocation is a parsed action.invocation body (from a connection).
type Invocation struct {
	InvocationID string
	ActionID     string
	Version      uint64
	Params       json.RawMessage
	// Bad: the invocation id parsed but the rest did not (answered
	// `unavailable`).
	Bad bool
}

// ParseInvocation parses a connection's action.invocation body. An error
// means not even the invocation id parsed (dropped); otherwise Bad marks
// a body to answer `unavailable`.
func ParseInvocation(body []byte) (*Invocation, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	v := &Invocation{}
	if v.InvocationID, err = ulid(o, "invocation_id"); err != nil {
		return nil, err
	}
	if v.ActionID, err = o.String("action_id"); err != nil || v.ActionID == "" || len(v.ActionID) > 64 {
		v.Bad = true
		return v, nil
	}
	if v.Version, err = o.Uint("version", 1, strictjson.MaxSafeInteger); err != nil {
		v.Bad = true
		return v, nil
	}
	if v.Params, err = paramsObject(o, true); err != nil {
		v.Bad = true
	}
	return v, nil
}

// Params are an invocation's parsed parameters.
type Params struct {
	Fields   []string
	SecretID string
	Limit    int
	Asset    string
	Sats     uint64
	Memo     string
}

// ParseParams parses an action's parameters with that action's strict
// parser (§10.14: no general schema engine).
func ParseParams(actionID string, raw []byte) (*Params, error) {
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		return nil, errBad
	}
	only := func(names ...string) error {
		for k := range o {
			ok := false
			for _, n := range names {
				ok = ok || k == n
			}
			if !ok {
				return errBad // additionalProperties: false
			}
		}
		return nil
	}
	p := &Params{}
	switch actionID {
	case ProfileFieldsRead:
		if err := only("fields"); err != nil {
			return nil, err
		}
		l, present, err := strList(o, "fields", MaxRequestFields, profile.ValidKey)
		if err != nil || !present || len(l) == 0 {
			return nil, errBad
		}
		p.Fields = l
	case SecretsShare:
		if err := only("secret_id"); err != nil {
			return nil, err
		}
		if p.SecretID, err = ulid(o, "secret_id"); err != nil {
			return nil, err
		}
	case AuditRecent:
		if err := only("limit"); err != nil {
			return nil, err
		}
		n, present, err := o.OptUint("limit", 1, AuditMax)
		if err != nil {
			return nil, errBad
		}
		p.Limit = AuditDefault
		if present {
			p.Limit = int(n)
		}
	case WalletAddress:
		if err := only("asset"); err != nil {
			return nil, err
		}
		if p.Asset, err = o.String("asset"); err != nil || p.Asset != "BTC" {
			return nil, errBad
		}
	case WalletPayment:
		if err := only("asset", "amount_sats", "memo"); err != nil {
			return nil, err
		}
		if p.Asset, err = o.String("asset"); err != nil || p.Asset != "BTC" {
			return nil, errBad
		}
		if p.Sats, err = o.Uint("amount_sats", 1, MaxSats); err != nil {
			return nil, errBad
		}
		m, _, err := o.OptString("memo")
		if err != nil || len(m) > MaxMemo {
			return nil, errBad
		}
		p.Memo = m
	default:
		return nil, errBad
	}
	return p, nil
}

// Respond is a parsed action.respond body.
type Respond struct {
	InvocationID string
	Approve      bool
}

// ParseRespond parses an action.respond body strictly.
func ParseRespond(body []byte) (*Respond, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	r := &Respond{}
	if r.InvocationID, err = ulid(o, "invocation_id"); err != nil {
		return nil, err
	}
	if r.Approve, err = o.Bool("approve"); err != nil {
		return nil, errBad
	}
	return r, nil
}

// Result is a parsed action.result body (from a connection).
type Result struct {
	InvocationID string
	Status       string
	Result       json.RawMessage
}

// ParseResult parses a connection's action.result body strictly.
func ParseResult(body []byte) (*Result, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	r := &Result{}
	if r.InvocationID, err = ulid(o, "invocation_id"); err != nil {
		return nil, err
	}
	if r.Status, err = o.String("status"); err != nil {
		return nil, errBad
	}
	raw, present, err := o.OptObjectRaw("result")
	if err != nil {
		return nil, errBad
	}
	switch r.Status {
	case StatusOK:
		if !present {
			return nil, errBad
		}
		if r.Result, err = strictjson.CompactObject(raw); err != nil || len(r.Result) > MaxResult {
			return nil, errBad
		}
	case StatusDenied, StatusExpired, StatusUnavailable:
		if present {
			return nil, errBad
		}
	default:
		return nil, errBad
	}
	return r, nil
}

// ParseOffered parses a connection's action.offered body strictly.
func ParseOffered(body []byte) ([]Offer, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	arr, err := o.Array("actions")
	if err != nil || len(arr) > MaxOffers {
		return nil, errBad
	}
	out := []Offer{}
	seen := map[string]bool{}
	for _, raw := range arr {
		e, err := strictjson.AsObject(raw)
		if err != nil {
			return nil, errBad
		}
		var of Offer
		if of.ActionID, err = e.String("action_id"); err != nil || of.ActionID == "" || len(of.ActionID) > 64 || seen[of.ActionID] {
			return nil, errBad
		}
		if of.Version, err = e.Uint("version", 1, strictjson.MaxSafeInteger); err != nil {
			return nil, errBad
		}
		if of.Prompt, err = e.Bool("prompt"); err != nil {
			return nil, errBad
		}
		seen[of.ActionID] = true
		out = append(out, of)
	}
	return out, nil
}

// Descs parses the grants of a profile.fields.read or secrets.share
// result.
func Descs(result []byte) ([]grants.Desc, error) {
	o, err := strictjson.ParseObject(result)
	if err != nil {
		return nil, errBad
	}
	arr, err := o.Array("grants")
	if err != nil || len(arr) > MaxRequestFields {
		return nil, errBad
	}
	out := make([]grants.Desc, 0, len(arr))
	for _, raw := range arr {
		e, err := strictjson.AsObject(raw)
		if err != nil {
			return nil, errBad
		}
		var d grants.Desc
		if d.GrantID, err = ulid(e, "grant_id"); err != nil {
			return nil, err
		}
		if d.Kind, err = e.String("kind"); err != nil || d.Kind != grants.KindField && d.Kind != grants.KindSecret {
			return nil, errBad
		}
		if d.Ref, err = e.String("ref"); err != nil || d.Ref == "" || len(d.Ref) > 64 {
			return nil, errBad
		}
		if d.Uses, err = e.Uint("uses", 1, grants.MaxUses); err != nil {
			return nil, errBad
		}
		ts, err := e.String("expires_at")
		if err != nil {
			return nil, errBad
		}
		if d.Expires, err = envelope.ParseTS(ts); err != nil {
			return nil, errBad
		}
		out = append(out, d)
	}
	return out, nil
}

// --- helpers ---

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (f *Feature) config(id string) *Config {
	if c := f.d.Configs[id]; c != nil {
		return c
	}
	return &Config{Mode: ModeDeny}
}

// offeredTo returns what this vault offers connection conn, in catalog
// order.
func (f *Feature) offeredTo(conn string) []Offer {
	out := []Offer{}
	for _, def := range Catalog() {
		c := f.config(def.ID)
		ok := false
		switch c.Mode {
		case ModeList:
			ok = contains(c.Connections, conn)
		case ModePrompt:
			ok = len(c.Connections) == 0 || contains(c.Connections, conn)
		case ModeAllow:
			ok = true
		}
		if ok {
			out = append(out, Offer{ActionID: def.ID, Version: def.Version, Prompt: c.Mode == ModePrompt})
		}
	}
	return out
}

func offerOf(l []Offer, id string) (Offer, bool) {
	for _, o := range l {
		if o.ActionID == id {
			return o, true
		}
	}
	return Offer{}, false
}

func offersJSON(l []Offer) []byte {
	arr := []byte{'['}
	for i, o := range l {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, strictjson.NewBuilder().String("action_id", o.ActionID).Uint("version", o.Version).Bool("prompt", o.Prompt).Bytes()...)
	}
	return strictjson.NewBuilder().Raw("actions", append(arr, ']')).Bytes()
}

func sameOffers(a, b []Offer) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func listJSON(l []string) []byte {
	arr := []byte{'['}
	for i, s := range l {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, strictjson.MarshalString(s)...)
	}
	return append(arr, ']')
}

func (f *Feature) sendResult(s *vault.Session, conn, id, status string, result json.RawMessage) {
	b := strictjson.NewBuilder().String("invocation_id", id).String("status", status)
	if status == StatusOK {
		b.Raw("result", result)
	}
	_ = s.SendToConnection(conn, "action.result", b.Bytes())
	f.d.Seen[id] = s.Now()
}

// expire does the lazy housekeeping (§10.14).
func (f *Feature) expire(s *vault.Session) {
	now := s.Now()
	for _, id := range sortedKeys(f.d.Pending) {
		if p := f.d.Pending[id]; !now.Before(p.Exp) {
			delete(f.d.Pending, id)
			f.sendResult(s, p.Conn, id, StatusExpired, nil)
		}
	}
	for id, o := range f.d.Outgoing {
		if !now.Before(o.Exp) {
			delete(f.d.Outgoing, id)
		}
	}
	for id, t := range f.d.Seen {
		if now.Sub(t) >= OutgoingTTL {
			delete(f.d.Seen, id)
		}
	}
	for c, hs := range f.d.Hits {
		var kept []time.Time
		for _, t := range hs {
			if now.Sub(t) < time.Hour {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(f.d.Hits, c)
		} else {
			f.d.Hits[c] = kept
		}
	}
}

// --- handlers ---

// Handle implements vault.Handler.
func (f *Feature) Handle(_ context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expire(s)
	switch in.Type {
	case "action.list":
		return f.list(in.Body)
	case "action.configure":
		return f.configure(s, in.Body)
	case "action.invoke":
		return f.invoke(s, in.Body)
	case "action.respond":
		return f.respond(s, in.Body)
	case "action.offered":
		offers, err := ParseOffered(in.Body)
		if err != nil {
			s.Record(vault.Activity{Kind: "drop.action_malformed", ConnectionID: s.From().ID, Audit: true})
			return nil, nil
		}
		f.d.Offers[s.From().ID] = offers
		// The owner's devices fetch them with action.list{connection_id}.
		s.SyncEvent("action.offers", strictjson.NewBuilder().String("connection_id", s.From().ID).Bytes())
		return nil, nil
	case "action.invocation":
		f.invocation(s, in.Body)
		return nil, nil
	case "action.result":
		f.result(s, in.Body)
		return nil, nil
	}
	return nil, vault.NewError("unsupported_type", "")
}

func (f *Feature) list(body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	conn, present, err := o.OptString("connection_id")
	if err != nil {
		return nil, errBad
	}
	if present {
		return offersJSON(f.d.Offers[conn]), nil
	}
	arr := []byte{'['}
	for i, def := range Catalog() {
		if i > 0 {
			arr = append(arr, ',')
		}
		c := f.config(def.ID)
		b := strictjson.NewBuilder().String("action_id", def.ID).Uint("version", def.Version).String("sensitivity", def.Sensitivity).
			Bool("available", def.Available).Raw("param_schema", []byte(def.ParamSchema)).Raw("result_schema", []byte(def.ResultSchema)).
			String("mode", c.Mode).Uint("config_version", c.Version)
		if c.Connections != nil {
			b.Raw("connections", listJSON(c.Connections))
		}
		if c.Fields != nil {
			b.Raw("fields", listJSON(c.Fields))
		}
		if c.Secrets != nil {
			b.Raw("secrets", listJSON(c.Secrets))
		}
		arr = append(arr, b.Bytes()...)
	}
	return strictjson.NewBuilder().Uint("catalog_version", CatalogVersion).Raw("actions", append(arr, ']')).Bytes(), nil
}

// configure sets an action's permission mode and bounds, re-offers to
// every affected active connection, and answers pending invocations no
// longer offered `unavailable`.
func (f *Feature) configure(s *vault.Session, body []byte) (json.RawMessage, error) {
	c, err := ParseConfigure(body)
	if err != nil {
		return nil, err
	}
	cur := f.config(c.ActionID)
	if c.Version != 0 && c.Version-1 != cur.Version {
		return nil, errConflict
	}
	active := s.Connections()
	before := map[string][]Offer{}
	for _, p := range active {
		before[p.ID] = f.offeredTo(p.ID)
	}
	next := &Config{Version: cur.Version + 1, Mode: c.Mode, Connections: c.Connections, Fields: c.Fields, Secrets: c.Secrets}
	f.d.Configs[c.ActionID] = next
	for _, id := range sortedKeys(f.d.Pending) {
		p := f.d.Pending[id]
		if _, ok := offerOf(f.offeredTo(p.Conn), p.ActionID); p.ActionID == c.ActionID && !ok {
			delete(f.d.Pending, id)
			f.sendResult(s, p.Conn, id, StatusUnavailable, nil)
		}
	}
	for _, p := range active {
		if p.State != vault.PeerActive {
			continue
		}
		if after := f.offeredTo(p.ID); !sameOffers(before[p.ID], after) {
			_ = s.SendToConnection(p.ID, "action.offered", offersJSON(after))
		}
	}
	s.SyncEvent("action.changed", strictjson.NewBuilder().String("action_id", c.ActionID).Uint("version", next.Version).Bytes())
	s.Record(vault.Activity{Kind: "action.configured", Ref: c.ActionID, Audit: true})
	return strictjson.NewBuilder().Uint("version", next.Version).Bytes(), nil
}

// ConnectionAdded implements vault.ConnectionObserver: a new connection
// gets what it is offered (§10.14).
func (f *Feature) ConnectionAdded(s *vault.Session, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l := f.offeredTo(id); len(l) > 0 {
		_ = s.SendToConnection(id, "action.offered", offersJSON(l))
	}
}

func (f *Feature) invoke(s *vault.Session, body []byte) (json.RawMessage, error) {
	v, err := ParseInvoke(body)
	if err != nil {
		return nil, err
	}
	off, ok := offerOf(f.d.Offers[v.ConnectionID], v.ActionID)
	if !ok {
		return nil, errNotFound
	}
	if len(f.d.Outgoing) >= MaxOutgoing {
		return nil, errLimit
	}
	id := s.NewID()
	b := strictjson.NewBuilder().String("invocation_id", id).String("action_id", v.ActionID).Uint("version", off.Version).Raw("params", v.Params)
	if err := s.SendToConnection(v.ConnectionID, "action.invocation", b.Bytes()); err != nil {
		return nil, errConn
	}
	f.d.Outgoing[id] = &Outgoing{ID: id, Conn: v.ConnectionID, ActionID: v.ActionID, Exp: s.Now().Add(OutgoingTTL)}
	s.Record(vault.Activity{Kind: "action.invoked", ConnectionID: v.ConnectionID, Ref: id, Direction: "out", Audit: true})
	return strictjson.NewBuilder().String("invocation_id", id).Bytes(), nil
}

// invocation handles a connection's action.invocation.
func (f *Feature) invocation(s *vault.Session, body []byte) {
	conn := s.From().ID
	v, err := ParseInvocation(body)
	if err != nil {
		s.Record(vault.Activity{Kind: "drop.action_malformed", ConnectionID: conn, Audit: true})
		return
	}
	if _, dup := f.d.Pending[v.InvocationID]; dup {
		return
	}
	if _, dup := f.d.Seen[v.InvocationID]; dup {
		return
	}
	now := s.Now()
	f.d.Hits[conn] = append(f.d.Hits[conn], now)
	s.Record(vault.Activity{Kind: "action.invoked", ConnectionID: conn, Ref: v.InvocationID, Direction: "in", Audit: true})
	unavailable := func() { f.sendResult(s, conn, v.InvocationID, StatusUnavailable, nil) }
	if v.Bad || len(f.d.Hits[conn]) > MaxPerHour {
		unavailable()
		return
	}
	def, ok := Lookup(v.ActionID)
	off, offered := offerOf(f.offeredTo(conn), v.ActionID)
	if !ok || !offered || off.Version != v.Version {
		unavailable()
		return
	}
	if _, err := ParseParams(def.ID, v.Params); err != nil {
		unavailable()
		return
	}
	if !off.Prompt {
		status, result := f.execute(s, conn, v.InvocationID, def, v.Params)
		f.sendResult(s, conn, v.InvocationID, status, result)
		return
	}
	n := 0
	for _, p := range f.d.Pending {
		if p.Conn == conn {
			n++
		}
	}
	if n >= MaxPendingPerConn {
		unavailable()
		return
	}
	p := &Pending{ID: v.InvocationID, Conn: conn, ActionID: def.ID, Params: v.Params, Exp: now.Add(PendingTTL).UTC().Truncate(time.Millisecond)}
	f.d.Pending[p.ID] = p
	s.NotifyAllDevices("action.pending", strictjson.NewBuilder().String("invocation_id", p.ID).String("connection_id", conn).
		String("action_id", def.ID).String("sensitivity", def.Sensitivity).Raw("params", p.Params).
		String("exp", envelope.FormatTS(p.Exp)).Bytes())
	s.Record(vault.Activity{Kind: "action.request", ConnectionID: conn, Ref: p.ID, Feed: true, Priority: "high"})
}

// execute runs a built-in action for connection conn (§10.14).
func (f *Feature) execute(s *vault.Session, conn, invocationID string, def Def, raw json.RawMessage) (string, json.RawMessage) {
	p, err := ParseParams(def.ID, raw)
	if err != nil || !def.Available {
		return StatusUnavailable, nil
	}
	cfg := f.config(def.ID)
	var out json.RawMessage
	switch def.ID {
	case ProfileFieldsRead, SecretsShare:
		if f.deps.Grants == nil {
			return StatusUnavailable, nil
		}
		var items []grants.Item
		if def.ID == ProfileFieldsRead {
			for _, k := range p.Fields {
				if contains(cfg.Fields, k) {
					items = append(items, grants.Item{Kind: grants.KindField, Ref: k})
				}
			}
		} else if contains(cfg.Secrets, p.SecretID) {
			items = append(items, grants.Item{Kind: grants.KindSecret, Ref: p.SecretID})
		}
		if len(items) == 0 {
			return StatusUnavailable, nil
		}
		descs, err := f.deps.Grants.IssueForAction(s, conn, invocationID, items, GrantUses, GrantTTL)
		if err != nil || len(descs) == 0 {
			return StatusUnavailable, nil
		}
		arr := []byte{'['}
		for i, d := range descs {
			if i > 0 {
				arr = append(arr, ',')
			}
			arr = append(arr, strictjson.NewBuilder().String("grant_id", d.GrantID).String("kind", d.Kind).String("ref", d.Ref).
				Uint("uses", d.Uses).String("expires_at", envelope.FormatTS(d.Expires)).Bytes()...)
		}
		out = strictjson.NewBuilder().Raw("grants", append(arr, ']')).Bytes()
	case AuditRecent:
		if f.deps.Audit == nil {
			return StatusUnavailable, nil
		}
		arr := []byte{'['}
		for i, e := range f.deps.Audit.ForConnection(conn, p.Limit) {
			if i > 0 {
				arr = append(arr, ',')
			}
			b := strictjson.NewBuilder().String("kind", e.Kind).String("at", envelope.FormatTS(e.At))
			if e.Direction != "" {
				b.String("direction", e.Direction)
			}
			arr = append(arr, b.Bytes()...)
		}
		out = strictjson.NewBuilder().Raw("entries", append(arr, ']')).Bytes()
	default:
		return StatusUnavailable, nil
	}
	if len(out) > MaxResult {
		return StatusUnavailable, nil
	}
	return StatusOK, out
}

// respond is the member's decision on a pending invocation. A critical
// action is approved only by an app within the credential's unlock
// window (§10.14).
func (f *Feature) respond(s *vault.Session, body []byte) (json.RawMessage, error) {
	r, err := ParseRespond(body)
	if err != nil {
		return nil, err
	}
	p := f.d.Pending[r.InvocationID]
	if p == nil {
		return nil, errNotFound
	}
	def, _ := Lookup(p.ActionID)
	if r.Approve && def.Sensitivity == Critical {
		if s.From().Kind != vault.KindApp {
			return nil, errForbidden
		}
		if f.deps.Keys == nil {
			return nil, errLocked
		}
		if _, ok := f.deps.Keys.UseKey(s.Now(), s.Settings().UnlockTTL()); !ok {
			return nil, errLocked // the member's phone must be there; it stays pending
		}
	}
	delete(f.d.Pending, p.ID)
	status, result := StatusDenied, json.RawMessage(nil)
	kind := "action.denied"
	if r.Approve {
		status, result = f.execute(s, p.Conn, p.ID, def, p.Params)
		kind = "action.approved"
	}
	f.sendResult(s, p.Conn, p.ID, status, result)
	s.Record(vault.Activity{Kind: kind, ConnectionID: p.Conn, Ref: p.ID, Audit: true})
	s.SyncEvent("action.decided", strictjson.NewBuilder().String("invocation_id", p.ID).Bool("approved", r.Approve).Bytes())
	return strictjson.NewBuilder().String("status", status).Bytes(), nil
}

// result handles a connection's answer to one of our invocations.
func (f *Feature) result(s *vault.Session, body []byte) {
	conn := s.From().ID
	r, err := ParseResult(body)
	if err != nil {
		s.Record(vault.Activity{Kind: "drop.action_malformed", ConnectionID: conn, Audit: true})
		return
	}
	o := f.d.Outgoing[r.InvocationID]
	if o == nil || o.Conn != conn {
		return // unknown, late or another connection's
	}
	delete(f.d.Outgoing, r.InvocationID)
	if r.Status == StatusOK && (o.ActionID == ProfileFieldsRead || o.ActionID == SecretsShare) {
		descs, err := Descs(r.Result)
		if err != nil {
			s.Record(vault.Activity{Kind: "drop.action_malformed", ConnectionID: conn, Audit: true})
			return
		}
		if f.deps.Grants != nil {
			f.deps.Grants.ReceiveFromAction(s, conn, r.InvocationID, descs)
		}
	}
	b := strictjson.NewBuilder().String("connection_id", conn).String("invocation_id", r.InvocationID).
		String("action_id", o.ActionID).String("status", r.Status)
	if r.Status == StatusOK {
		b.Raw("result", r.Result)
	}
	s.NotifyAllDevices("action.result", b.Bytes())
	s.Record(vault.Activity{Kind: "action.completed", ConnectionID: conn, Ref: r.InvocationID, Direction: "in", Audit: true})
}

// ConnectionRemoved implements vault.ConnectionRemovedObserver (§7.4).
func (f *Feature) ConnectionRemoved(_ *vault.Session, conn string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.d.Configs {
		if c.Connections == nil {
			continue
		}
		kept := []string{}
		for _, id := range c.Connections {
			if id != conn {
				kept = append(kept, id)
			}
		}
		c.Connections = kept
	}
	delete(f.d.Offers, conn)
	delete(f.d.Hits, conn)
	for id, p := range f.d.Pending {
		if p.Conn == conn {
			delete(f.d.Pending, id)
		}
	}
	for id, o := range f.d.Outgoing {
		if o.Conn == conn {
			delete(f.d.Outgoing, id)
		}
	}
}

// PendingInvocations returns the pending invocation ids (tests, tools).
func (f *Feature) PendingInvocations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return sortedKeys(f.d.Pending)
}
