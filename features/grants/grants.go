// Package grants is 1:1 sharing between connections (VAULT-MESSAGING
// §10.12): a connection asks for profile fields or cataloged vault-held
// secrets, the member decides, and the connection fetches the current
// value at most `uses` times until the grant expires or either side
// revokes it. Every fetch is checked by the member's vault and answered
// with the value sealed to a one-time key of the device that fetched, so
// the asking vault never holds the plaintext. The catalog lists the
// member's cataloged secrets (metadata only), including cataloged critical
// secrets, which can only be used (§10.13), never granted.
//
// Ported from vettid.dev's grant_handler.go (reference-based data
// requests, forVault.data.* peer events): the peer flows are events inside
// the connection's session, correlated by ids and deduplicated; values are
// sealed to the fetching device instead of travelling in the clear to the
// asking vault; alias groups become up to 16 items per request; the
// requester's "Held in trust" mirror stays.
package grants

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/features/credential"
	"github.com/vettid/vettid-vault/features/profile"
	"github.com/vettid/vettid-vault/features/secrets"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/sharewire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Limits (§10.12).
const (
	MaxItems          = 16
	MaxUses           = 100
	DefaultUses       = 1
	MinExpiresIn      = 60
	MaxExpiresIn      = 31536000
	DefaultExpiresIn  = 604800
	MaxReason         = 256
	MaxLabel          = 128
	MaxPendingPerConn = 16
	PendingTTL        = 7 * 24 * time.Hour
	MaxGiven          = 1000
	MaxReceived       = 1000
	MaxFetches        = 64
	FetchTTL          = 10 * time.Minute
	MaxCatalog        = 1000
	// Ended grants and decided requests are kept this long for listings
	// and for answering `revoked` (§10.12).
	EndedRetention = 30 * 24 * time.Hour
	// MaxRequested bounds the asking side's request records.
	MaxRequested = 1000
)

// Item kinds.
const (
	KindField  = "field"
	KindSecret = "secret"
)

// Grant states.
const (
	StateActive  = "active"
	StateUsed    = "used"
	StateExpired = "expired"
	StateRevoked = "revoked"
)

// data.value errors.
const (
	ErrNotFound    = "not_found"
	ErrRevoked     = "revoked"
	ErrExpired     = "expired"
	ErrExhausted   = "exhausted"
	ErrUnavailable = "unavailable"
)

var valueErrors = map[string]bool{ErrNotFound: true, ErrRevoked: true, ErrExpired: true, ErrExhausted: true, ErrUnavailable: true}

// FieldSource is the profile (§10.8).
type FieldSource interface {
	FieldValue(key string) (string, bool)
}

// SecretSource is the vault-held secrets (§10.7).
type SecretSource interface {
	Catalog() []secrets.CatalogEntry
	CatalogedValue(id string) (name, value string, ok bool)
}

// CriticalCatalog is the credential's catalog of critical secrets (§10.13).
type CriticalCatalog interface {
	CatalogedSecrets() []credential.Meta
}

// Item is one requested item.
type Item struct {
	Kind  string `json:"kind"`
	Ref   string `json:"ref"`
	Label string `json:"label,omitempty"`
}

// Grant is a grant given (the member's side) or received (the asking
// side's mirror).
type Grant struct {
	ID        string    `json:"id"`
	Conn      string    `json:"conn"`
	Direction string    `json:"direction"` // "given" or "received"
	RequestID string    `json:"request_id"`
	Kind      string    `json:"kind"`
	Ref       string    `json:"ref"`
	Label     string    `json:"label,omitempty"`
	Uses      uint64    `json:"uses"`
	Used      uint64    `json:"used"`
	Expires   time.Time `json:"expires"`
	State     string    `json:"state"`
	Created   time.Time `json:"created"`
	Ended     time.Time `json:"ended,omitempty"`
	// Fetched are the fetch ids answered (given side): a repeated fetch is
	// answered again without counting a use.
	Fetched []string `json:"fetched,omitempty"`
}

// Pending is a connection's request waiting for the member's decision.
type Pending struct {
	ID        string    `json:"id"`
	Conn      string    `json:"conn"`
	Items     []Item    `json:"items"`
	Uses      uint64    `json:"uses"`
	ExpiresIn uint64    `json:"expires_in"`
	Reason    string    `json:"reason,omitempty"`
	Exp       time.Time `json:"exp"`
}

// Requested is a request this vault sent.
type Requested struct {
	ID      string    `json:"id"`
	Conn    string    `json:"conn"`
	Items   []Item    `json:"items"`
	State   string    `json:"state"` // pending, granted, denied
	Created time.Time `json:"created"`
	Decided time.Time `json:"decided,omitempty"`
}

// Outstanding is a fetch or catalog request waiting for the connection's
// answer, routed to the device that asked.
type Outstanding struct {
	ID      string    `json:"id"`
	Conn    string    `json:"conn"`
	GrantID string    `json:"grant_id,omitempty"`
	Device  string    `json:"device"`
	Exp     time.Time `json:"exp"`
}

type data struct {
	Given     map[string]*Grant       `json:"given"`    // by grant_id
	Received  map[string]*Grant       `json:"received"` // by conn|grant_id
	Pending   map[string]*Pending     `json:"pending"`  // by request_id
	Requested map[string]*Requested   `json:"requested"`
	Fetches   map[string]*Outstanding `json:"fetches"`  // by fetch_id
	Catalogs  map[string]*Outstanding `json:"catalogs"` // by request_id
}

func (d *data) init() {
	if d.Given == nil {
		d.Given = map[string]*Grant{}
	}
	if d.Received == nil {
		d.Received = map[string]*Grant{}
	}
	if d.Pending == nil {
		d.Pending = map[string]*Pending{}
	}
	if d.Requested == nil {
		d.Requested = map[string]*Requested{}
	}
	if d.Fetches == nil {
		d.Fetches = map[string]*Outstanding{}
	}
	if d.Catalogs == nil {
		d.Catalogs = map[string]*Outstanding{}
	}
}

// Feature implements vault.Feature and vault.ConnectionRemovedObserver.
type Feature struct {
	mu      sync.Mutex
	fields  FieldSource
	secrets SecretSource
	crit    CriticalCatalog
	d       data
}

// New returns the feature.
func New(fields FieldSource, src SecretSource, crit CriticalCatalog) *Feature {
	f := &Feature{fields: fields, secrets: src, crit: crit}
	f.d.init()
	return f
}

var (
	owners = []string{vault.KindApp, vault.KindDesktop}
	conns  = []string{vault.KindConnection}
)

// Name implements vault.Feature.
func (f *Feature) Name() string { return "grants" }

// Types implements vault.Feature.
func (f *Feature) Types() []vault.TypeSpec {
	r := func(t string) vault.TypeSpec { return vault.TypeSpec{Type: t, Request: true, From: owners} }
	e := func(t string) vault.TypeSpec { return vault.TypeSpec{Type: t, From: conns} }
	decide := r("grant.decide")
	decide.DesktopApproval = true // it discloses data to a connection (§6.8)
	return []vault.TypeSpec{
		r("grant.request"), decide, r("grant.revoke"), r("grant.list"), r("grant.fetch"), r("grant.catalog"),
		e("data.request"), e("data.decided"), e("data.revoked"), e("data.fetch"), e("data.value"),
		e("data.catalog.get"), e("data.catalog"),
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
	errBad      = vault.NewError("bad_request", "")
	errNotFound = vault.NewError("not_found", "")
	errLimit    = vault.NewError("limit", "")
	errConn     = vault.NewError("connection_unavailable", "")
)

// --- parsing ---

func parseItems(o strictjson.Object) ([]Item, error) {
	arr, err := o.Array("items")
	if err != nil || len(arr) == 0 || len(arr) > MaxItems {
		return nil, errBad
	}
	out := make([]Item, 0, len(arr))
	for _, raw := range arr {
		io, err := strictjson.AsObject(raw)
		if err != nil {
			return nil, errBad
		}
		var it Item
		if it.Kind, err = io.String("kind"); err != nil {
			return nil, errBad
		}
		if it.Ref, err = io.String("ref"); err != nil {
			return nil, errBad
		}
		switch it.Kind {
		case KindField:
			if !profile.ValidKey(it.Ref) {
				return nil, errBad
			}
		case KindSecret:
			if !envelope.ValidULID(it.Ref) {
				return nil, errBad
			}
		default:
			return nil, errBad
		}
		l, _, err := io.OptString("label")
		if err != nil || len(l) > MaxLabel {
			return nil, errBad
		}
		it.Label = l
		out = append(out, it)
	}
	return out, nil
}

func optReason(o strictjson.Object) (string, error) {
	r, _, err := o.OptString("reason")
	if err != nil || len(r) > MaxReason {
		return "", errBad
	}
	return r, nil
}

func ulid(o strictjson.Object, name string) (string, error) {
	v, err := o.String(name)
	if err != nil || !envelope.ValidULID(v) {
		return "", errBad
	}
	return v, nil
}

func connID(o strictjson.Object) (string, error) {
	v, err := o.String("connection_id")
	if err != nil || v == "" || len(v) > 128 {
		return "", errBad
	}
	return v, nil
}

// Request is a parsed grant.request (from a device) or data.request (from
// a connection) body.
type Request struct {
	ID        string
	Conn      string
	Items     []Item
	Uses      uint64
	ExpiresIn uint64
	Reason    string
}

// ParseRequest parses a grant.request body strictly (defaults applied).
func ParseRequest(body []byte) (*Request, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	r := &Request{Uses: DefaultUses, ExpiresIn: DefaultExpiresIn}
	if r.Conn, err = connID(o); err != nil {
		return nil, err
	}
	if r.Items, err = parseItems(o); err != nil {
		return nil, err
	}
	if v, ok, err := o.OptUint("uses", 1, MaxUses); err != nil {
		return nil, errBad
	} else if ok {
		r.Uses = v
	}
	if v, ok, err := o.OptUint("expires_in", MinExpiresIn, MaxExpiresIn); err != nil {
		return nil, errBad
	} else if ok {
		r.ExpiresIn = v
	}
	if r.Reason, err = optReason(o); err != nil {
		return nil, err
	}
	return r, nil
}

// ParseDataRequest parses a data.request body strictly.
func ParseDataRequest(body []byte) (*Request, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	r := &Request{}
	if r.ID, err = ulid(o, "request_id"); err != nil {
		return nil, err
	}
	if r.Items, err = parseItems(o); err != nil {
		return nil, err
	}
	if r.Uses, err = o.Uint("uses", 1, MaxUses); err != nil {
		return nil, errBad
	}
	if r.ExpiresIn, err = o.Uint("expires_in", MinExpiresIn, MaxExpiresIn); err != nil {
		return nil, errBad
	}
	if r.Reason, err = optReason(o); err != nil {
		return nil, err
	}
	return r, nil
}

// Decision is a parsed grant.decide body.
type Decision struct {
	RequestID string
	Approve   bool
	Items     []int // nil: all
	Uses      uint64
	ExpiresIn uint64
}

// ParseDecide parses a grant.decide body strictly.
func ParseDecide(body []byte) (*Decision, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	d := &Decision{}
	if d.RequestID, err = ulid(o, "request_id"); err != nil {
		return nil, err
	}
	if d.Approve, err = o.Bool("approve"); err != nil {
		return nil, errBad
	}
	arr, ok, err := o.OptArray("items")
	if err != nil {
		return nil, errBad
	}
	if ok {
		if len(arr) == 0 || len(arr) > MaxItems {
			return nil, errBad
		}
		seen := map[uint64]bool{}
		for _, raw := range arr {
			v, err := strictjson.AsUint(raw, 0, MaxItems-1)
			if err != nil || seen[v] {
				return nil, errBad
			}
			seen[v] = true
			d.Items = append(d.Items, int(v))
		}
	}
	if d.Uses, _, err = o.OptUint("uses", 1, MaxUses); err != nil {
		return nil, errBad
	}
	if d.ExpiresIn, _, err = o.OptUint("expires_in", MinExpiresIn, MaxExpiresIn); err != nil {
		return nil, errBad
	}
	return d, nil
}

// Decided is a parsed data.decided body.
type Decided struct {
	RequestID string
	Approved  bool
	Grants    []Grant
}

// ParseDecided parses a data.decided body strictly.
func ParseDecided(body []byte) (*Decided, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	d := &Decided{}
	if d.RequestID, err = ulid(o, "request_id"); err != nil {
		return nil, err
	}
	if d.Approved, err = o.Bool("approved"); err != nil {
		return nil, errBad
	}
	arr, ok, err := o.OptArray("grants")
	if err != nil || ok != d.Approved {
		return nil, errBad
	}
	if !ok {
		return d, nil
	}
	if len(arr) == 0 || len(arr) > MaxItems {
		return nil, errBad
	}
	seen := map[string]bool{}
	for _, raw := range arr {
		g, err := strictjson.AsObject(raw)
		if err != nil {
			return nil, errBad
		}
		var gr Grant
		if gr.ID, err = ulid(g, "grant_id"); err != nil || seen[gr.ID] {
			return nil, errBad
		}
		seen[gr.ID] = true
		if gr.Kind, err = g.String("kind"); err != nil {
			return nil, errBad
		}
		if gr.Ref, err = g.String("ref"); err != nil {
			return nil, errBad
		}
		switch {
		case gr.Kind == KindField && profile.ValidKey(gr.Ref), gr.Kind == KindSecret && envelope.ValidULID(gr.Ref):
		default:
			return nil, errBad
		}
		if gr.Label, _, err = g.OptString("label"); err != nil || len(gr.Label) > MaxLabel {
			return nil, errBad
		}
		if gr.Uses, err = g.Uint("uses", 1, MaxUses); err != nil {
			return nil, errBad
		}
		ts, err := g.String("expires_at")
		if err != nil {
			return nil, errBad
		}
		if gr.Expires, err = envelope.ParseTS(ts); err != nil {
			return nil, errBad
		}
		d.Grants = append(d.Grants, gr)
	}
	return d, nil
}

// Fetch is a parsed data.fetch body.
type Fetch struct {
	FetchID string
	GrantID string
	Reply   *suite.PublicKey
}

// ParseFetch parses a data.fetch body strictly.
func ParseFetch(body []byte) (*Fetch, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	fe := &Fetch{}
	if fe.FetchID, err = ulid(o, "fetch_id"); err != nil {
		return nil, err
	}
	if fe.GrantID, err = ulid(o, "grant_id"); err != nil {
		return nil, err
	}
	if fe.Reply, err = replyKey(o); err != nil {
		return nil, err
	}
	return fe, nil
}

func replyKey(o strictjson.Object) (*suite.PublicKey, error) {
	ek, err := o.Base64("reply_key", suite.EKSize)
	if err != nil {
		return nil, errBad
	}
	k, err := suite.ParsePublicKey(ek)
	if err != nil {
		return nil, errBad
	}
	return k, nil
}

// Value is a parsed data.value body.
type Value struct {
	FetchID  string
	GrantID  string
	Sealed   []byte
	UsesLeft uint64
	Error    string
}

// ParseValue parses a data.value body strictly: a sealed value with
// uses_left, or an error.
func ParseValue(body []byte) (*Value, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	v := &Value{}
	if v.FetchID, err = ulid(o, "fetch_id"); err != nil {
		return nil, err
	}
	if v.GrantID, err = ulid(o, "grant_id"); err != nil {
		return nil, err
	}
	e, hasErr, err := o.OptString("error")
	if err != nil {
		return nil, errBad
	}
	if hasErr {
		if !valueErrors[e] || o.Has("value_sealed") || o.Has("uses_left") {
			return nil, errBad
		}
		v.Error = e
		return v, nil
	}
	if v.Sealed, err = o.Base64("value_sealed", -1); err != nil ||
		len(v.Sealed) < sharewire.EncSize+16 || len(v.Sealed) > sharewire.EncSize+sharewire.MaxValue+16 {
		return nil, errBad
	}
	if v.UsesLeft, err = o.Uint("uses_left", 0, MaxUses); err != nil {
		return nil, errBad
	}
	return v, nil
}

// CatalogEntry is one entry of a connection's catalog.
type CatalogEntry struct {
	SecretID    string
	Name        string
	Category    string
	Description string
	Critical    bool
}

func (e *CatalogEntry) json() []byte {
	b := strictjson.NewBuilder().String("secret_id", e.SecretID).String("name", e.Name).String("category", e.Category)
	if e.Description != "" {
		b.String("description", e.Description)
	}
	return b.Bool("critical", e.Critical).Bytes()
}

func catalogJSON(es []CatalogEntry) []byte {
	arr := []byte{'['}
	for i := range es {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, es[i].json()...)
	}
	return append(arr, ']')
}

// ParseCatalog parses a data.catalog body strictly.
func ParseCatalog(body []byte) (string, []CatalogEntry, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", nil, errBad
	}
	id, err := ulid(o, "request_id")
	if err != nil {
		return "", nil, err
	}
	arr, err := o.Array("secrets")
	if err != nil || len(arr) > MaxCatalog {
		return "", nil, errBad
	}
	out := make([]CatalogEntry, 0, len(arr))
	for _, raw := range arr {
		eo, err := strictjson.AsObject(raw)
		if err != nil {
			return "", nil, errBad
		}
		var e CatalogEntry
		if e.SecretID, err = ulid(eo, "secret_id"); err != nil {
			return "", nil, err
		}
		if e.Name, err = eo.String("name"); err != nil || e.Name == "" || len(e.Name) > 128 {
			return "", nil, errBad
		}
		if e.Category, err = eo.String("category"); err != nil || e.Category == "" || len(e.Category) > 32 {
			return "", nil, errBad
		}
		if e.Description, _, err = eo.OptString("description"); err != nil || len(e.Description) > 1024 {
			return "", nil, errBad
		}
		if e.Critical, err = eo.Bool("critical"); err != nil {
			return "", nil, errBad
		}
		out = append(out, e)
	}
	return id, out, nil
}

// --- JSON ---

func itemsJSON(items []Item, avail func(Item) bool) []byte {
	arr := []byte{'['}
	for i, it := range items {
		if i > 0 {
			arr = append(arr, ',')
		}
		b := strictjson.NewBuilder().String("kind", it.Kind).String("ref", it.Ref)
		if it.Label != "" {
			b.String("label", it.Label)
		}
		if avail != nil {
			b.Bool("available", avail(it))
		}
		arr = append(arr, b.Bytes()...)
	}
	return append(arr, ']')
}

func (g *Grant) json() []byte {
	b := strictjson.NewBuilder().String("grant_id", g.ID).String("connection_id", g.Conn).String("direction", g.Direction).
		String("kind", g.Kind).String("ref", g.Ref)
	if g.Label != "" {
		b.String("label", g.Label)
	}
	return b.Uint("uses", g.Uses).Uint("used", g.Used).String("expires_at", envelope.FormatTS(g.Expires)).
		String("state", g.State).String("created_at", envelope.FormatTS(g.Created)).Bytes()
}

func (p *Pending) json(avail func(Item) bool) []byte {
	b := strictjson.NewBuilder().String("request_id", p.ID).String("connection_id", p.Conn).Raw("items", itemsJSON(p.Items, avail)).
		Uint("uses", p.Uses).Uint("expires_in", p.ExpiresIn)
	if p.Reason != "" {
		b.String("reason", p.Reason)
	}
	return b.String("exp", envelope.FormatTS(p.Exp)).Bytes()
}

// --- helpers ---

func (f *Feature) available(it Item) bool {
	switch it.Kind {
	case KindField:
		_, ok := f.fields.FieldValue(it.Ref)
		return ok
	case KindSecret:
		_, _, ok := f.secrets.CatalogedValue(it.Ref)
		return ok
	}
	return false
}

func (f *Feature) value(g *Grant) (string, bool) {
	switch g.Kind {
	case KindField:
		return f.fields.FieldValue(g.Ref)
	case KindSecret:
		_, v, ok := f.secrets.CatalogedValue(g.Ref)
		return v, ok
	}
	return "", false
}

func activeConn(s *vault.Session, id string) bool {
	p, ok := s.Connection(id)
	return ok && p.State == vault.PeerActive
}

func syncChanged(s *vault.Session, g *Grant) {
	s.SyncEvent("grant.changed", strictjson.NewBuilder().String("grant_id", g.ID).String("state", g.State).Bytes())
}

func (g *Grant) end(state string, at time.Time) { g.State, g.Ended = state, at }

func countActive(m map[string]*Grant) int {
	n := 0
	for _, g := range m {
		if g.State == StateActive {
			n++
		}
	}
	return n
}

// received finds a received grant by the member's grant id.
func (f *Feature) received(grantID string) *Grant {
	for _, k := range sortedKeys(f.d.Received) {
		if g := f.d.Received[k]; g.ID == grantID {
			return g
		}
	}
	return nil
}

// expire does the lazy housekeeping (§10.12): undecided requests answered
// as denied after 7 days, fetches and catalog requests forgotten after
// 10 minutes, grants past expires_at expired, ended records pruned.
func (f *Feature) expire(s *vault.Session) {
	now := s.Now()
	for _, id := range sortedKeys(f.d.Pending) {
		p := f.d.Pending[id]
		if !now.Before(p.Exp) {
			delete(f.d.Pending, id)
			_ = s.SendToConnection(p.Conn, "data.decided", strictjson.NewBuilder().String("request_id", p.ID).Bool("approved", false).Bytes())
		}
	}
	for id, o := range f.d.Fetches {
		if !now.Before(o.Exp) {
			delete(f.d.Fetches, id)
		}
	}
	for id, o := range f.d.Catalogs {
		if !now.Before(o.Exp) {
			delete(f.d.Catalogs, id)
		}
	}
	for _, m := range []map[string]*Grant{f.d.Given, f.d.Received} {
		for id, g := range m {
			if g.State == StateActive && !now.Before(g.Expires) {
				g.end(StateExpired, g.Expires)
			}
			if g.State != StateActive && now.Sub(g.Ended) > EndedRetention {
				delete(m, id)
			}
		}
	}
	for id, r := range f.d.Requested {
		if r.State == "pending" && now.Sub(r.Created) > PendingTTL+24*time.Hour ||
			r.State != "pending" && now.Sub(r.Decided) > EndedRetention {
			delete(f.d.Requested, id)
		}
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- Handle ---

// Handle implements vault.Handler.
func (f *Feature) Handle(_ context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expire(s)
	switch in.Type {
	case "grant.request":
		return f.request(s, in.Body)
	case "grant.decide":
		return f.decide(s, in.Body)
	case "grant.fetch":
		return f.fetch(s, in.Body)
	case "grant.revoke":
		return f.revoke(s, in.Body)
	case "grant.list":
		if _, err := strictjson.ParseObject(in.Body); err != nil {
			return nil, errBad
		}
		return f.list(), nil
	case "grant.catalog":
		return f.catalog(s, in.Body)
	case "data.request":
		f.dataRequest(s, in.Body)
	case "data.decided":
		f.dataDecided(s, in.Body)
	case "data.revoked":
		f.dataRevoked(s, in.Body)
	case "data.fetch":
		f.dataFetch(s, in.Body)
	case "data.value":
		f.dataValue(s, in.Body)
	case "data.catalog.get":
		f.dataCatalogGet(s, in.Body)
	case "data.catalog":
		f.dataCatalog(s, in.Body)
	default:
		return nil, vault.NewError("unsupported_type", "")
	}
	return nil, nil
}

func malformed(s *vault.Session, conn string) {
	s.Record(vault.Activity{Kind: "drop.grant_malformed", ConnectionID: conn, Audit: true})
}

// --- the asking side ---

func (f *Feature) request(s *vault.Session, body []byte) (json.RawMessage, error) {
	r, err := ParseRequest(body)
	if err != nil {
		return nil, err
	}
	if !activeConn(s, r.Conn) {
		return nil, errNotFound
	}
	if len(f.d.Requested) >= MaxRequested {
		return nil, errLimit
	}
	id := s.NewID()
	b := strictjson.NewBuilder().String("request_id", id).Raw("items", itemsJSON(r.Items, nil)).Uint("uses", r.Uses).
		Uint("expires_in", r.ExpiresIn)
	if r.Reason != "" {
		b.String("reason", r.Reason)
	}
	if err := s.Send(r.Conn, "data.request", b.Bytes(), vault.SendOptions{}); err != nil {
		return nil, errConn
	}
	f.d.Requested[id] = &Requested{ID: id, Conn: r.Conn, Items: r.Items, State: "pending", Created: s.Now().UTC()}
	s.Record(vault.Activity{Kind: "grant.requested", ConnectionID: r.Conn, Ref: id, Direction: "out", Audit: true})
	return strictjson.NewBuilder().String("request_id", id).Bytes(), nil
}

func (f *Feature) dataDecided(s *vault.Session, body []byte) {
	conn := s.From().ID
	d, err := ParseDecided(body)
	if err != nil {
		malformed(s, conn)
		return
	}
	r := f.d.Requested[d.RequestID]
	if r == nil || r.Conn != conn || r.State != "pending" {
		return // unknown, another connection's, or already decided
	}
	r.Decided = s.Now().UTC()
	ev := strictjson.NewBuilder().String("connection_id", conn)
	if !d.Approved {
		r.State = "denied"
		s.Record(vault.Activity{Kind: "grant.denied", ConnectionID: conn, Ref: d.RequestID, Direction: "in", Audit: true})
		s.NotifyAllDevices("grant.event", ev.String("event", "denied").String("request_id", d.RequestID).Bytes())
		return
	}
	r.State = "granted"
	arr := []byte{'['}
	n := 0
	for i := range d.Grants {
		gr := d.Grants[i]
		key := conn + "|" + gr.ID
		if f.d.Received[key] != nil || countActive(f.d.Received) >= MaxReceived {
			continue
		}
		g := &Grant{ID: gr.ID, Conn: conn, Direction: "received", RequestID: d.RequestID, Kind: gr.Kind, Ref: gr.Ref,
			Label: gr.Label, Uses: gr.Uses, Expires: gr.Expires, State: StateActive, Created: s.Now().UTC().Truncate(time.Millisecond)}
		f.d.Received[key] = g
		if n > 0 {
			arr = append(arr, ',')
		}
		n++
		arr = append(arr, g.json()...)
		s.Record(vault.Activity{Kind: "grant.received", ConnectionID: conn, Ref: g.ID, Direction: "in", Audit: true})
		syncChanged(s, g)
	}
	s.NotifyAllDevices("grant.event", ev.String("event", "granted").String("request_id", d.RequestID).Raw("grants", append(arr, ']')).Bytes())
}

func (f *Feature) fetch(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	gid, err := ulid(o, "grant_id")
	if err != nil {
		return nil, err
	}
	reply, err := replyKey(o)
	if err != nil {
		return nil, err
	}
	g := f.received(gid)
	if g == nil {
		return nil, errNotFound
	}
	if len(f.d.Fetches) >= MaxFetches {
		return nil, errLimit
	}
	id := s.NewID()
	b := strictjson.NewBuilder().String("fetch_id", id).String("grant_id", gid).Base64("reply_key", reply.Bytes()).Bytes()
	if err := s.Send(g.Conn, "data.fetch", b, vault.SendOptions{}); err != nil {
		return nil, errConn
	}
	f.d.Fetches[id] = &Outstanding{ID: id, Conn: g.Conn, GrantID: gid, Device: s.From().ID, Exp: s.Now().Add(FetchTTL)}
	return strictjson.NewBuilder().String("fetch_id", id).Bytes(), nil
}

func (f *Feature) dataValue(s *vault.Session, body []byte) {
	conn := s.From().ID
	v, err := ParseValue(body)
	if err != nil {
		malformed(s, conn)
		return
	}
	o := f.d.Fetches[v.FetchID]
	if o == nil || o.Conn != conn || o.GrantID != v.GrantID {
		return // unknown, expired or answered
	}
	delete(f.d.Fetches, v.FetchID)
	now := s.Now().UTC()
	if g := f.d.Received[conn+"|"+v.GrantID]; g != nil {
		prev := g.State
		switch v.Error {
		case ErrRevoked:
			g.end(StateRevoked, now)
		case ErrExpired:
			g.end(StateExpired, now)
		case ErrExhausted:
			g.Used = g.Uses
			g.end(StateUsed, now)
		case "":
			if v.UsesLeft <= g.Uses {
				g.Used = g.Uses - v.UsesLeft
			}
			if v.UsesLeft == 0 {
				g.end(StateUsed, now)
			}
		}
		if g.State != prev {
			syncChanged(s, g)
		}
	}
	b := strictjson.NewBuilder().String("connection_id", conn).String("fetch_id", v.FetchID).String("grant_id", v.GrantID)
	if v.Error != "" {
		b.String("error", v.Error)
	} else {
		b.Base64("value_sealed", v.Sealed).Uint("uses_left", v.UsesLeft)
	}
	_ = s.Send(o.Device, "grant.value", b.Bytes(), vault.SendOptions{}) // only that device (§10.12)
}

func (f *Feature) catalog(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	conn, err := connID(o)
	if err != nil {
		return nil, err
	}
	if !activeConn(s, conn) {
		return nil, errNotFound
	}
	if len(f.d.Catalogs) >= MaxFetches {
		return nil, errLimit
	}
	id := s.NewID()
	if err := s.Send(conn, "data.catalog.get", strictjson.NewBuilder().String("request_id", id).Bytes(), vault.SendOptions{}); err != nil {
		return nil, errConn
	}
	f.d.Catalogs[id] = &Outstanding{ID: id, Conn: conn, Device: s.From().ID, Exp: s.Now().Add(FetchTTL)}
	return strictjson.NewBuilder().String("request_id", id).Bytes(), nil
}

func (f *Feature) dataCatalog(s *vault.Session, body []byte) {
	conn := s.From().ID
	id, es, err := ParseCatalog(body)
	if err != nil {
		malformed(s, conn)
		return
	}
	o := f.d.Catalogs[id]
	if o == nil || o.Conn != conn {
		return
	}
	delete(f.d.Catalogs, id)
	_ = s.Send(o.Device, "grant.catalog.result", strictjson.NewBuilder().String("connection_id", conn).String("request_id", id).
		Raw("secrets", catalogJSON(es)).Bytes(), vault.SendOptions{})
}

// --- the member's side ---

func (f *Feature) dataRequest(s *vault.Session, body []byte) {
	conn := s.From().ID
	r, err := ParseDataRequest(body)
	if err != nil {
		malformed(s, conn)
		return
	}
	if p := f.d.Pending[r.ID]; p != nil {
		if p.Conn != conn {
			s.Record(vault.Activity{Kind: "drop.grant_duplicate", ConnectionID: conn, Audit: true})
		}
		return // a repeated request_id is ignored
	}
	n := 0
	for _, p := range f.d.Pending {
		if p.Conn == conn {
			n++
		}
	}
	if n >= MaxPendingPerConn {
		s.Record(vault.Activity{Kind: "drop.grant_limit", ConnectionID: conn, Audit: true})
		return
	}
	p := &Pending{ID: r.ID, Conn: conn, Items: r.Items, Uses: r.Uses, ExpiresIn: r.ExpiresIn, Reason: r.Reason,
		Exp: s.Now().Add(PendingTTL).UTC().Truncate(time.Millisecond)}
	f.d.Pending[r.ID] = p
	s.NotifyAllDevices("grant.pending", p.json(f.available))
	s.Record(vault.Activity{Kind: "grant.requested", ConnectionID: conn, Ref: r.ID, Direction: "in", Audit: true})
	s.Record(vault.Activity{Kind: "grant.request", ConnectionID: conn, Ref: r.ID, Feed: true, Priority: "high"})
}

func (f *Feature) decide(s *vault.Session, body []byte) (json.RawMessage, error) {
	d, err := ParseDecide(body)
	if err != nil {
		return nil, err
	}
	p := f.d.Pending[d.RequestID]
	if p == nil {
		return nil, errNotFound
	}
	decided := func(approved bool) {
		s.SyncEvent("grant.request.decided", strictjson.NewBuilder().String("request_id", p.ID).Bool("approved", approved).Bytes())
	}
	if !d.Approve {
		delete(f.d.Pending, p.ID)
		_ = s.SendToConnection(p.Conn, "data.decided", strictjson.NewBuilder().String("request_id", p.ID).Bool("approved", false).Bytes())
		s.Record(vault.Activity{Kind: "grant.denied", ConnectionID: p.Conn, Ref: p.ID, Direction: "out", Audit: true})
		decided(false)
		return strictjson.NewBuilder().Raw("grants", []byte("[]")).Bytes(), nil
	}
	idx := d.Items
	if idx == nil {
		for i := range p.Items {
			idx = append(idx, i)
		}
	}
	uses, expIn := p.Uses, p.ExpiresIn
	if d.Uses > 0 {
		uses = d.Uses
	}
	if d.ExpiresIn > 0 {
		expIn = d.ExpiresIn
	}
	now := s.Now().UTC().Truncate(time.Millisecond)
	var made []*Grant
	for _, i := range idx {
		if i >= len(p.Items) {
			return nil, errBad
		}
		it := p.Items[i]
		if !f.available(it) {
			continue
		}
		made = append(made, &Grant{ID: s.NewID(), Conn: p.Conn, Direction: "given", RequestID: p.ID, Kind: it.Kind, Ref: it.Ref,
			Label: it.Label, Uses: uses, Expires: now.Add(time.Duration(expIn) * time.Second), State: StateActive, Created: now})
	}
	if len(made) == 0 {
		return nil, errBad
	}
	if countActive(f.d.Given)+len(made) > MaxGiven {
		return nil, errLimit
	}
	wire, resp := []byte{'['}, []byte{'['}
	for i, g := range made {
		if i > 0 {
			wire, resp = append(wire, ','), append(resp, ',')
		}
		b := strictjson.NewBuilder().String("grant_id", g.ID).String("kind", g.Kind).String("ref", g.Ref)
		if g.Label != "" {
			b.String("label", g.Label)
		}
		wire = append(wire, b.Uint("uses", g.Uses).String("expires_at", envelope.FormatTS(g.Expires)).Bytes()...)
		resp = append(resp, strictjson.NewBuilder().String("grant_id", g.ID).String("kind", g.Kind).String("ref", g.Ref).Bytes()...)
	}
	wire, resp = append(wire, ']'), append(resp, ']')
	if err := s.SendToConnection(p.Conn, "data.decided", strictjson.NewBuilder().String("request_id", p.ID).Bool("approved", true).
		Raw("grants", wire).Bytes()); err != nil {
		return nil, errConn
	}
	delete(f.d.Pending, p.ID)
	for _, g := range made {
		f.d.Given[g.ID] = g
		s.Record(vault.Activity{Kind: "grant.issued", ConnectionID: g.Conn, Ref: g.ID, Direction: "out", Audit: true})
		syncChanged(s, g)
	}
	decided(true)
	return strictjson.NewBuilder().Raw("grants", resp).Bytes(), nil
}

func (f *Feature) dataFetch(s *vault.Session, body []byte) {
	conn := s.From().ID
	fe, err := ParseFetch(body)
	if err != nil {
		malformed(s, conn)
		return
	}
	base := func() *strictjson.Builder {
		return strictjson.NewBuilder().String("fetch_id", fe.FetchID).String("grant_id", fe.GrantID)
	}
	refuse := func(code string) {
		s.Record(vault.Activity{Kind: "drop.grant_" + code, ConnectionID: conn, Ref: fe.GrantID, Audit: true})
		_ = s.SendToConnection(conn, "data.value", base().String("error", code).Bytes())
	}
	g := f.d.Given[fe.GrantID]
	if g == nil || g.Conn != conn {
		refuse(ErrNotFound)
		return
	}
	repeat := false
	for _, id := range g.Fetched {
		repeat = repeat || id == fe.FetchID
	}
	switch {
	case g.State == StateRevoked:
		refuse(ErrRevoked)
		return
	case g.State == StateExpired:
		refuse(ErrExpired)
		return
	case !repeat && g.Used >= g.Uses:
		refuse(ErrExhausted)
		return
	}
	v, ok := f.value(g)
	if !ok {
		refuse(ErrUnavailable)
		return
	}
	sealed, err := sharewire.SealValue(fe.Reply, g.ID, fe.FetchID, []byte(v))
	if err != nil {
		refuse(ErrUnavailable)
		return
	}
	if !repeat {
		g.Used++
		g.Fetched = append(g.Fetched, fe.FetchID)
		if g.Used >= g.Uses {
			g.end(StateUsed, s.Now().UTC())
		}
		s.Record(vault.Activity{Kind: "grant.fetched", ConnectionID: conn, Ref: g.ID, Direction: "out", Audit: true})
		syncChanged(s, g)
	}
	_ = s.SendToConnection(conn, "data.value", base().Base64("value_sealed", sealed).Uint("uses_left", g.Uses-g.Used).Bytes())
}

func (f *Feature) dataCatalogGet(s *vault.Session, body []byte) {
	conn := s.From().ID
	o, err := strictjson.ParseObject(body)
	if err != nil {
		malformed(s, conn)
		return
	}
	id, err := ulid(o, "request_id")
	if err != nil {
		malformed(s, conn)
		return
	}
	var es []CatalogEntry
	for _, e := range f.secrets.Catalog() {
		es = append(es, CatalogEntry{SecretID: e.ID, Name: e.Name, Category: e.Category, Description: e.Description})
	}
	if f.crit != nil {
		for _, m := range f.crit.CatalogedSecrets() {
			es = append(es, CatalogEntry{SecretID: m.ID, Name: m.Name, Category: m.Category, Description: m.Description, Critical: true})
		}
	}
	if len(es) > MaxCatalog {
		es = es[:MaxCatalog]
	}
	_ = s.SendToConnection(conn, "data.catalog", strictjson.NewBuilder().String("request_id", id).Raw("secrets", catalogJSON(es)).Bytes())
}

// --- both sides ---

func (f *Feature) revoke(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	id, err := ulid(o, "grant_id")
	if err != nil {
		return nil, err
	}
	g := f.d.Given[id]
	if g == nil {
		g = f.received(id)
	}
	if g == nil {
		return nil, errNotFound
	}
	if g.State == StateRevoked {
		return nil, nil
	}
	g.end(StateRevoked, s.Now().UTC())
	_ = s.SendToConnection(g.Conn, "data.revoked", strictjson.NewBuilder().String("grant_id", g.ID).Bytes())
	s.Record(vault.Activity{Kind: "grant.revoked", ConnectionID: g.Conn, Ref: g.ID, Direction: "out", Audit: true})
	syncChanged(s, g)
	return nil, nil
}

func (f *Feature) dataRevoked(s *vault.Session, body []byte) {
	conn := s.From().ID
	o, err := strictjson.ParseObject(body)
	if err != nil {
		malformed(s, conn)
		return
	}
	id, err := ulid(o, "grant_id")
	if err != nil {
		malformed(s, conn)
		return
	}
	g := f.d.Received[conn+"|"+id]
	asking := g != nil
	if g == nil {
		if gv := f.d.Given[id]; gv != nil && gv.Conn == conn {
			g = gv // the asking side relinquished it
		}
	}
	if g == nil || g.State == StateRevoked {
		return
	}
	g.end(StateRevoked, s.Now().UTC())
	s.Record(vault.Activity{Kind: "grant.revoked", ConnectionID: conn, Ref: id, Direction: "in", Audit: true, Feed: true})
	syncChanged(s, g)
	if asking {
		s.NotifyAllDevices("grant.event", strictjson.NewBuilder().String("connection_id", conn).String("event", "revoked").
			String("grant_id", id).Bytes())
	}
}

func (f *Feature) list() []byte {
	grants := func(m map[string]*Grant) []byte {
		arr := []byte{'['}
		for i, k := range sortedKeys(m) {
			if i > 0 {
				arr = append(arr, ',')
			}
			arr = append(arr, m[k].json()...)
		}
		return append(arr, ']')
	}
	pend := []byte{'['}
	for i, k := range sortedKeys(f.d.Pending) {
		if i > 0 {
			pend = append(pend, ',')
		}
		pend = append(pend, f.d.Pending[k].json(nil)...)
	}
	pend = append(pend, ']')
	req := []byte{'['}
	for i, k := range sortedKeys(f.d.Requested) {
		r := f.d.Requested[k]
		if i > 0 {
			req = append(req, ',')
		}
		req = append(req, strictjson.NewBuilder().String("request_id", r.ID).String("connection_id", r.Conn).
			Raw("items", itemsJSON(r.Items, nil)).String("state", r.State).Bytes()...)
	}
	req = append(req, ']')
	return strictjson.NewBuilder().Raw("given", grants(f.d.Given)).Raw("received", grants(f.d.Received)).
		Raw("pending", pend).Raw("requested", req).Bytes()
}

// ConnectionRemoved implements vault.ConnectionRemovedObserver: the
// connection's grants (both ways), pending requests and outstanding
// requests are dropped without notice (§7.4, §10.12).
func (f *Feature) ConnectionRemoved(_ *vault.Session, conn string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range []map[string]*Grant{f.d.Given, f.d.Received} {
		for k, g := range m {
			if g.Conn == conn {
				delete(m, k)
			}
		}
	}
	for k, p := range f.d.Pending {
		if p.Conn == conn {
			delete(f.d.Pending, k)
		}
	}
	for k, r := range f.d.Requested {
		if r.Conn == conn {
			delete(f.d.Requested, k)
		}
	}
	for _, m := range []map[string]*Outstanding{f.d.Fetches, f.d.Catalogs} {
		for k, o := range m {
			if o.Conn == conn {
				delete(m, k)
			}
		}
	}
}

// Given returns copies of the grants given (tests and tools).
func (f *Feature) Given() []Grant {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Grant
	for _, k := range sortedKeys(f.d.Given) {
		out = append(out, *f.d.Given[k])
	}
	return out
}
