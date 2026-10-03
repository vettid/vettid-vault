// Package actions is shared actions between connections (VAULT-MESSAGING
// §10.14): the member offers named actions to chosen connections; a
// connection invokes one and the member answers it, once each. The vault
// never runs code for an action: either the member answers each
// invocation (`respond`), or the vault returns a result the member fixed
// in advance (`fixed`), after the member's approval (`ask`) or at once
// (`auto`).
//
// Ported from vettid.dev's action_*.go: the fixed built-in catalog
// (profile fields, secrets, wallet, votes, introductions, audit) becomes
// member-defined actions (fields and secrets are grants, §10.12); the four
// authorization modes become a per-action allowlist plus ask/auto; JSON
// schema validation and the Ed25519 invoker and result signatures are
// dropped (apps validate params and results; the connection's E2E session
// authenticates both vaults); invocations and results are types inside
// the connection's session, which fixes vettid.dev's mis-routing of
// results to subjects the receiving vault did not listen on.
package actions

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Limits (§10.14).
const (
	MaxActions     = 64
	MaxConnections = 256
	MaxName        = 64
	MaxDescription = 1024
	MaxResult      = 16 * 1024
	MaxParams      = 4 * 1024
	MaxPending     = 8 // per connection
	PendingTTL     = 24 * time.Hour
	OutgoingTTL    = 25 * time.Hour
	MaxOffers      = 64
)

// Kinds, modes and result statuses.
const (
	KindRespond = "respond"
	KindFixed   = "fixed"
	ModeAsk     = "ask"
	ModeAuto    = "auto"

	StatusOK          = "ok"
	StatusDenied      = "denied"
	StatusExpired     = "expired"
	StatusUnavailable = "unavailable"
)

// Action is one of the member's action definitions.
type Action struct {
	ID          string          `json:"id"`
	Version     uint64          `json:"version"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Kind        string          `json:"kind"`
	Mode        string          `json:"mode"`
	Result      json.RawMessage `json:"result,omitempty"`
	Connections []string        `json:"connections"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// Offer is an action a connection offers this vault.
type Offer struct {
	ActionID    string `json:"action_id"`
	Version     uint64 `json:"version"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Pending is an invocation from a connection waiting for the member.
type Pending struct {
	ID       string          `json:"id"`
	Conn     string          `json:"conn"`
	ActionID string          `json:"action_id"`
	Params   json.RawMessage `json:"params,omitempty"`
	Exp      time.Time       `json:"exp"`
}

// Outgoing is an invocation this vault sent.
type Outgoing struct {
	ID       string    `json:"id"`
	Conn     string    `json:"conn"`
	ActionID string    `json:"action_id"`
	Exp      time.Time `json:"exp"`
}

type data struct {
	Actions map[string]*Action   `json:"actions"`
	Offers  map[string][]Offer   `json:"offers"`  // per connection
	Pending map[string]*Pending  `json:"pending"` // by invocation id
	Out     map[string]*Outgoing `json:"out"`     // by invocation id
	// Seen are the invocations received, by connection|invocation id, so
	// that a repeated invocation_id is ignored.
	Seen map[string]time.Time `json:"seen"`
}

// Feature implements vault.Feature and vault.ConnectionRemovedObserver.
type Feature struct {
	mu sync.Mutex
	d  data
}

func newData() data {
	return data{Actions: map[string]*Action{}, Offers: map[string][]Offer{}, Pending: map[string]*Pending{},
		Out: map[string]*Outgoing{}, Seen: map[string]time.Time{}}
}

// New returns the feature.
func New() *Feature { return &Feature{d: newData()} }

var (
	owners = []string{vault.KindApp, vault.KindDesktop}
	conns  = []string{vault.KindConnection}
)

// Name implements vault.Feature.
func (f *Feature) Name() string { return "actions" }

// Types implements vault.Feature.
func (f *Feature) Types() []vault.TypeSpec {
	return []vault.TypeSpec{
		// A desktop changes what connections can obtain only with an
		// app's approval (§6.8 step-up).
		{Type: "action.define", Request: true, From: owners, DesktopApproval: true},
		{Type: "action.delete", Request: true, From: owners},
		{Type: "action.list", Request: true, From: owners},
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
	d := newData()
	if err := json.Unmarshal(raw, &d); err != nil {
		return err
	}
	if d.Actions == nil {
		d.Actions = map[string]*Action{}
	}
	if d.Offers == nil {
		d.Offers = map[string][]Offer{}
	}
	if d.Pending == nil {
		d.Pending = map[string]*Pending{}
	}
	if d.Out == nil {
		d.Out = map[string]*Outgoing{}
	}
	if d.Seen == nil {
		d.Seen = map[string]time.Time{}
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
	errBad      = vault.NewError("bad_request", "")
	errNotFound = vault.NewError("not_found", "")
	errConflict = vault.NewError("conflict", "")
	errLimit    = vault.NewError("limit", "")
	errConn     = vault.NewError("connection_unavailable", "")
)

// --- parsers ---

// Define is a parsed action.define body.
type Define struct {
	ActionID    string
	Version     uint64
	Name        string
	Description string
	Kind        string
	Mode        string
	Result      json.RawMessage
	Connections []string
}

// object validates an optional JSON object member of at most max bytes
// and returns its compact form (nil when absent).
func object(o strictjson.Object, name string, max int) (json.RawMessage, error) {
	raw, present, err := o.OptObjectRaw(name)
	if err != nil {
		return nil, errBad
	}
	if !present {
		return nil, nil
	}
	c, err := strictjson.CompactObject(raw)
	if err != nil || len(c) > max {
		return nil, errBad
	}
	return c, nil
}

func ulid(o strictjson.Object, name string) (string, error) {
	s, err := o.String(name)
	if err != nil || !envelope.ValidULID(s) {
		return "", errBad
	}
	return s, nil
}

func optText(o strictjson.Object, name string, max int) (string, error) {
	v, _, err := o.OptString(name)
	if err != nil || len(v) > max {
		return "", errBad
	}
	return v, nil
}

// ParseDefine parses an action.define body strictly.
func ParseDefine(body []byte) (*Define, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	d := &Define{Mode: ModeAsk}
	id, hasID, err := o.OptString("action_id")
	if err != nil || hasID && !envelope.ValidULID(id) {
		return nil, errBad
	}
	ver, hasVer, err := o.OptUint("version", 1, strictjson.MaxSafeInteger)
	if err != nil || hasID != hasVer {
		return nil, errBad
	}
	d.ActionID, d.Version = id, ver
	if d.Name, err = o.String("name"); err != nil || d.Name == "" || len(d.Name) > MaxName {
		return nil, errBad
	}
	if d.Description, err = optText(o, "description", MaxDescription); err != nil {
		return nil, err
	}
	if d.Kind, err = o.String("kind"); err != nil || d.Kind != KindRespond && d.Kind != KindFixed {
		return nil, errBad
	}
	if m, present, err := o.OptString("mode"); err != nil || present && m != ModeAsk && m != ModeAuto {
		return nil, errBad
	} else if present {
		d.Mode = m
	}
	if d.Result, err = object(o, "result", MaxResult); err != nil {
		return nil, err
	}
	switch d.Kind {
	case KindRespond:
		if d.Mode != ModeAsk || d.Result != nil {
			return nil, errBad // the member answers each invocation
		}
	case KindFixed:
		if d.Result == nil {
			return nil, errBad
		}
	}
	arr, err := o.Array("connections")
	if err != nil || len(arr) > MaxConnections {
		return nil, errBad
	}
	seen := map[string]bool{}
	d.Connections = []string{}
	for _, r := range arr {
		c, err := strictjson.AsString(r)
		if err != nil || !envelope.ValidULID(c) || seen[c] {
			return nil, errBad
		}
		seen[c] = true
		d.Connections = append(d.Connections, c)
	}
	return d, nil
}

// Invoke is a parsed action.invoke body: from a device (ConnectionID set)
// or from a connection (InvocationID and Version set).
type Invoke struct {
	ConnectionID string
	InvocationID string
	ActionID     string
	Version      uint64
	Params       json.RawMessage
}

// ParseInvoke parses a device's action.invoke body strictly.
func ParseInvoke(body []byte) (*Invoke, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	v := &Invoke{}
	if v.ConnectionID, err = o.String("connection_id"); err != nil || v.ConnectionID == "" || len(v.ConnectionID) > 64 {
		return nil, errBad
	}
	if v.ActionID, err = ulid(o, "action_id"); err != nil {
		return nil, err
	}
	if v.Params, err = object(o, "params", MaxParams); err != nil {
		return nil, err
	}
	return v, nil
}

// ParsePeerInvoke parses a connection's action.invocation body strictly.
func ParsePeerInvoke(body []byte) (*Invoke, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	v := &Invoke{}
	if v.InvocationID, err = ulid(o, "invocation_id"); err != nil {
		return nil, err
	}
	if v.ActionID, err = ulid(o, "action_id"); err != nil {
		return nil, err
	}
	if v.Version, err = o.Uint("version", 1, strictjson.MaxSafeInteger); err != nil {
		return nil, errBad
	}
	if v.Params, err = object(o, "params", MaxParams); err != nil {
		return nil, err
	}
	return v, nil
}

// Respond is a parsed action.respond body.
type Respond struct {
	InvocationID string
	Approve      bool
	Result       json.RawMessage
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
	if r.Result, err = object(o, "result", MaxResult); err != nil {
		return nil, err
	}
	if !r.Approve && r.Result != nil {
		return nil, errBad
	}
	return r, nil
}

// Result is a parsed V↔V action.result body.
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
	if r.Result, err = object(o, "result", MaxResult); err != nil {
		return nil, err
	}
	switch r.Status {
	case StatusOK:
		if r.Result == nil {
			return nil, errBad
		}
	case StatusDenied, StatusExpired, StatusUnavailable:
		if r.Result != nil {
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
		ao, err := strictjson.AsObject(raw)
		if err != nil {
			return nil, errBad
		}
		var of Offer
		if of.ActionID, err = ulid(ao, "action_id"); err != nil || seen[of.ActionID] {
			return nil, errBad
		}
		seen[of.ActionID] = true
		if of.Version, err = ao.Uint("version", 1, strictjson.MaxSafeInteger); err != nil {
			return nil, errBad
		}
		if of.Name, err = ao.String("name"); err != nil || of.Name == "" || len(of.Name) > MaxName {
			return nil, errBad
		}
		if of.Description, err = optText(ao, "description", MaxDescription); err != nil {
			return nil, err
		}
		out = append(out, of)
	}
	return out, nil
}

// --- JSON ---

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

// JSON is an action's wire form (§10.14).
func (a *Action) JSON() []byte {
	b := strictjson.NewBuilder().String("action_id", a.ID).Uint("version", a.Version).String("name", a.Name)
	if a.Description != "" {
		b.String("description", a.Description)
	}
	b.String("kind", a.Kind).String("mode", a.Mode)
	if a.Result != nil {
		b.Raw("result", a.Result)
	}
	return b.Raw("connections", strList(a.Connections)).String("created_at", envelope.FormatTS(a.CreatedAt)).
		String("updated_at", envelope.FormatTS(a.UpdatedAt)).Bytes()
}

func offersJSON(l []Offer) []byte {
	arr := []byte{'['}
	for i, of := range l {
		if i > 0 {
			arr = append(arr, ',')
		}
		b := strictjson.NewBuilder().String("action_id", of.ActionID).Uint("version", of.Version).String("name", of.Name)
		if of.Description != "" {
			b.String("description", of.Description)
		}
		arr = append(arr, b.Bytes()...)
	}
	return strictjson.NewBuilder().Raw("actions", append(arr, ']')).Bytes()
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

func (f *Feature) sortedActions() []*Action {
	out := make([]*Action, 0, len(f.d.Actions))
	for _, a := range f.d.Actions {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (f *Feature) sortedPending() []*Pending {
	out := make([]*Pending, 0, len(f.d.Pending))
	for _, p := range f.d.Pending {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// offeredTo is the complete list of actions offered to a connection.
func (f *Feature) offeredTo(conn string) []Offer {
	out := []Offer{}
	for _, a := range f.sortedActions() {
		if contains(a.Connections, conn) {
			out = append(out, Offer{ActionID: a.ID, Version: a.Version, Name: a.Name, Description: a.Description})
		}
	}
	return out
}

// offer sends each affected active connection its complete list.
func (f *Feature) offer(s *vault.Session, affected ...[]string) {
	set := map[string]bool{}
	for _, l := range affected {
		for _, c := range l {
			set[c] = true
		}
	}
	ids := make([]string, 0, len(set))
	for c := range set {
		ids = append(ids, c)
	}
	sort.Strings(ids)
	for _, c := range ids {
		if p, ok := s.Connection(c); ok && p.State == vault.PeerActive {
			_ = s.SendToConnection(c, "action.offered", offersJSON(f.offeredTo(c)))
		}
	}
}

func (f *Feature) sendResult(s *vault.Session, conn, id, status string, result json.RawMessage) {
	b := strictjson.NewBuilder().String("invocation_id", id).String("status", status)
	if result != nil {
		b.Raw("result", result)
	}
	_ = s.SendToConnection(conn, "action.result", b.Bytes())
}

// expire answers pending invocations past their exp and forgets old
// outgoing invocations and seen ids (lazily, §10.14).
func (f *Feature) expire(s *vault.Session) {
	now := s.Now()
	for _, p := range f.sortedPending() {
		if !now.Before(p.Exp) {
			delete(f.d.Pending, p.ID)
			f.sendResult(s, p.Conn, p.ID, StatusExpired, nil)
		}
	}
	for id, o := range f.d.Out {
		if !now.Before(o.Exp) {
			delete(f.d.Out, id)
		}
	}
	for k, t := range f.d.Seen {
		if now.Sub(t) >= OutgoingTTL {
			delete(f.d.Seen, k)
		}
	}
}

// Handle implements vault.Handler.
func (f *Feature) Handle(_ context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expire(s)
	switch in.Type {
	case "action.define":
		return f.define(s, in.Body)
	case "action.delete":
		return f.remove(s, in.Body)
	case "action.list":
		return f.list(s, in.Body)
	case "action.invoke":
		return f.invoke(s, in.Body)
	case "action.invocation":
		return nil, f.peerInvoke(s, in.Body)
	case "action.respond":
		return f.respond(s, in.Body)
	case "action.offered":
		offers, err := ParseOffered(in.Body)
		if err != nil {
			return nil, err
		}
		f.d.Offers[s.From().ID] = offers
		// The owner's devices learn that the connection's offers changed
		// and fetch them with action.list{connection_id}.
		s.SyncEvent("action.offers", strictjson.NewBuilder().String("connection_id", s.From().ID).Bytes())
		return nil, nil
	case "action.result":
		return nil, f.result(s, in.Body)
	}
	return nil, vault.NewError("unsupported_type", "")
}

func (f *Feature) define(s *vault.Session, body []byte) (json.RawMessage, error) {
	d, err := ParseDefine(body)
	if err != nil {
		return nil, err
	}
	now := s.Now().UTC().Truncate(time.Millisecond)
	var a *Action
	var before []string
	if d.ActionID != "" {
		cur := f.d.Actions[d.ActionID]
		if cur == nil {
			return nil, errNotFound
		}
		if cur.Version != d.Version {
			return nil, errConflict
		}
		c := *cur
		a = &c
		before = cur.Connections
	} else {
		if len(f.d.Actions) >= MaxActions {
			return nil, errLimit
		}
		a = &Action{ID: s.NewID(), CreatedAt: now}
	}
	a.Version++
	a.Name, a.Description, a.Kind, a.Mode, a.Result, a.Connections = d.Name, d.Description, d.Kind, d.Mode, d.Result, d.Connections
	a.UpdatedAt = now
	f.d.Actions[a.ID] = a
	// Pending invocations from connections the action is no longer
	// offered to can no longer be answered (§10.14).
	for _, p := range f.sortedPending() {
		if p.ActionID == a.ID && !contains(a.Connections, p.Conn) {
			delete(f.d.Pending, p.ID)
			f.sendResult(s, p.Conn, p.ID, StatusUnavailable, nil)
		}
	}
	s.SyncEvent("action.changed", strictjson.NewBuilder().String("action_id", a.ID).Uint("version", a.Version).Bytes())
	s.Record(vault.Activity{Kind: "action.defined", Ref: a.ID, Audit: true})
	f.offer(s, before, a.Connections)
	return strictjson.NewBuilder().String("action_id", a.ID).Uint("version", a.Version).Bytes(), nil
}

func (f *Feature) remove(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	id, err := ulid(o, "action_id")
	if err != nil {
		return nil, err
	}
	a := f.d.Actions[id]
	if a == nil {
		return nil, errNotFound
	}
	delete(f.d.Actions, id)
	// Its pending invocations can no longer be answered.
	for _, p := range f.sortedPending() {
		if p.ActionID == id {
			delete(f.d.Pending, p.ID)
			f.sendResult(s, p.Conn, p.ID, StatusUnavailable, nil)
		}
	}
	s.SyncEvent("action.deleted", strictjson.NewBuilder().String("action_id", id).Bytes())
	s.Record(vault.Activity{Kind: "action.deleted", Ref: id, Audit: true})
	f.offer(s, a.Connections)
	return nil, nil
}

func (f *Feature) list(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	conn, present, err := o.OptString("connection_id")
	if err != nil || present && (conn == "" || len(conn) > 64) {
		return nil, errBad
	}
	if present {
		if _, ok := s.Connection(conn); !ok {
			return nil, errNotFound
		}
		return offersJSON(f.d.Offers[conn]), nil
	}
	arr := []byte{'['}
	for i, a := range f.sortedActions() {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, a.JSON()...)
	}
	return strictjson.NewBuilder().Raw("actions", append(arr, ']')).Bytes(), nil
}

// invoke: an owner device (or an agent through LEASH, §10.11) invokes an
// action a connection offers.
func (f *Feature) invoke(s *vault.Session, body []byte) (json.RawMessage, error) {
	v, err := ParseInvoke(body)
	if err != nil {
		return nil, err
	}
	p, ok := s.Connection(v.ConnectionID)
	if !ok || p.State != vault.PeerActive {
		return nil, errNotFound
	}
	var offer *Offer
	for i, of := range f.d.Offers[v.ConnectionID] {
		if of.ActionID == v.ActionID {
			offer = &f.d.Offers[v.ConnectionID][i]
		}
	}
	if offer == nil {
		return nil, errNotFound
	}
	id := s.NewID()
	b := strictjson.NewBuilder().String("invocation_id", id).String("action_id", v.ActionID).Uint("version", offer.Version)
	if v.Params != nil {
		b.Raw("params", v.Params)
	}
	if err := s.SendToConnection(v.ConnectionID, "action.invocation", b.Bytes()); err != nil {
		return nil, errConn
	}
	f.d.Out[id] = &Outgoing{ID: id, Conn: v.ConnectionID, ActionID: v.ActionID, Exp: s.Now().Add(OutgoingTTL)}
	s.Record(vault.Activity{Kind: "action.invoked", ConnectionID: v.ConnectionID, Ref: id, Direction: "out", Audit: true})
	return strictjson.NewBuilder().String("invocation_id", id).Bytes(), nil
}

// peerInvoke: a connection invokes one of the member's actions.
func (f *Feature) peerInvoke(s *vault.Session, body []byte) error {
	v, err := ParsePeerInvoke(body)
	if err != nil {
		return err
	}
	conn := s.From().ID
	key := conn + "|" + v.InvocationID
	if _, dup := f.d.Seen[key]; dup {
		return nil // a repeated invocation_id is ignored
	}
	if _, clash := f.d.Pending[v.InvocationID]; clash {
		return nil // another connection's pending invocation holds that id
	}
	f.d.Seen[key] = s.Now()
	s.Record(vault.Activity{Kind: "action.invoked", ConnectionID: conn, Ref: v.InvocationID, Direction: "in", Audit: true})
	a := f.d.Actions[v.ActionID]
	// Unknown, not offered to this connection or another version: not
	// told apart (§10.14).
	if a == nil || !contains(a.Connections, conn) || a.Version != v.Version {
		f.sendResult(s, conn, v.InvocationID, StatusUnavailable, nil)
		return nil
	}
	if a.Kind == KindFixed && a.Mode == ModeAuto {
		f.sendResult(s, conn, v.InvocationID, StatusOK, a.Result)
		s.Record(vault.Activity{Kind: "action.approved", ConnectionID: conn, Ref: v.InvocationID, Audit: true})
		return nil
	}
	n := 0
	for _, p := range f.d.Pending {
		if p.Conn == conn {
			n++
		}
	}
	if n >= MaxPending {
		f.sendResult(s, conn, v.InvocationID, StatusUnavailable, nil)
		return nil
	}
	p := &Pending{ID: v.InvocationID, Conn: conn, ActionID: a.ID, Params: v.Params, Exp: s.Now().Add(PendingTTL).UTC().Truncate(time.Millisecond)}
	f.d.Pending[p.ID] = p
	b := strictjson.NewBuilder().String("invocation_id", p.ID).String("connection_id", conn).String("action_id", a.ID).
		String("name", a.Name).String("kind", a.Kind)
	if p.Params != nil {
		b.Raw("params", p.Params)
	}
	s.NotifyAllDevices("action.pending", b.String("exp", envelope.FormatTS(p.Exp)).Bytes())
	s.Record(vault.Activity{Kind: "action.request", ConnectionID: conn, Ref: p.ID, Feed: true, Priority: "high"})
	return nil
}

// respond: the member answers a pending invocation.
func (f *Feature) respond(s *vault.Session, body []byte) (json.RawMessage, error) {
	r, err := ParseRespond(body)
	if err != nil {
		return nil, err
	}
	p := f.d.Pending[r.InvocationID]
	if p == nil {
		return nil, errNotFound
	}
	a := f.d.Actions[p.ActionID]
	if a == nil {
		return nil, errNotFound
	}
	// A respond action takes the member's result; a fixed one has its own.
	if r.Approve && (a.Kind == KindRespond && r.Result == nil || a.Kind == KindFixed && r.Result != nil) {
		return nil, errBad
	}
	delete(f.d.Pending, p.ID)
	if r.Approve {
		res := r.Result
		if a.Kind == KindFixed {
			res = a.Result
		}
		f.sendResult(s, p.Conn, p.ID, StatusOK, res)
		s.Record(vault.Activity{Kind: "action.approved", ConnectionID: p.Conn, Ref: p.ID, Audit: true})
	} else {
		f.sendResult(s, p.Conn, p.ID, StatusDenied, nil)
		s.Record(vault.Activity{Kind: "action.denied", ConnectionID: p.Conn, Ref: p.ID, Audit: true})
	}
	s.SyncEvent("action.decided", strictjson.NewBuilder().String("invocation_id", p.ID).Bool("approved", r.Approve).Bytes())
	return nil, nil
}

// result: a connection answers one of this vault's invocations.
func (f *Feature) result(s *vault.Session, body []byte) error {
	r, err := ParseResult(body)
	if err != nil {
		return err
	}
	conn := s.From().ID
	o := f.d.Out[r.InvocationID]
	if o == nil || o.Conn != conn {
		return nil // unknown or late: dropped
	}
	delete(f.d.Out, r.InvocationID)
	b := strictjson.NewBuilder().String("connection_id", conn).String("invocation_id", o.ID).String("action_id", o.ActionID).
		String("status", r.Status)
	if r.Result != nil {
		b.Raw("result", r.Result)
	}
	s.NotifyAllDevices("action.result", b.Bytes())
	s.Record(vault.Activity{Kind: "action.completed", ConnectionID: conn, Ref: o.ID, Direction: "in", Audit: true})
	return nil
}

// ConnectionRemoved implements vault.ConnectionRemovedObserver: the
// connection leaves every allowlist; its offers and its invocations, both
// ways, are dropped (§10.14, §7.4).
func (f *Feature) ConnectionRemoved(_ *vault.Session, conn string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.d.Actions {
		if contains(a.Connections, conn) {
			keep := []string{}
			for _, c := range a.Connections {
				if c != conn {
					keep = append(keep, c)
				}
			}
			a.Connections = keep
		}
	}
	delete(f.d.Offers, conn)
	for id, p := range f.d.Pending {
		if p.Conn == conn {
			delete(f.d.Pending, id)
		}
	}
	for id, o := range f.d.Out {
		if o.Conn == conn {
			delete(f.d.Out, id)
		}
	}
	for k := range f.d.Seen {
		if strings.HasPrefix(k, conn+"|") {
			delete(f.d.Seen, k)
		}
	}
}

// PendingInvocations returns the pending invocations (tests and tools).
func (f *Feature) PendingInvocations() []Pending {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Pending
	for _, p := range f.sortedPending() {
		out = append(out, *p)
	}
	return out
}
