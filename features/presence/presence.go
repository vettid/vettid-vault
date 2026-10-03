// Package presence is the on-demand presence ping (VAULT-MESSAGING §9.2,
// §10.17): a member's device asks its vault whether a connection is
// around; the vault pings the connection's vault, which answers with its
// member's state and a coarse last-active time only if its owner's policy
// shares presence with that connection. A refusal is silence, so it
// cannot be told apart from a locked or unreachable vault. There are no
// periodic heartbeats.
//
// Ported from vettid.dev's presence.go: the 30-second heartbeat to every
// connection, the app-active signal and the per-connection overrides
// become one policy object (state, share, except) and pings on demand.
package presence

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// States.
const (
	Available = "available"
	Busy      = "busy"
	Away      = "away"
	Invisible = "invisible"
)

// Share modes.
const (
	ShareAll  = "all"
	ShareNone = "none"
)

// Limits (§9.2, §10.17).
const (
	PingTTL        = 30 * time.Second
	ResultTTL      = time.Minute
	PingEvery      = time.Minute // pings sent per connection, pongs sent per peer
	MaxExcept      = 1024
	LastActiveStep = 5 * time.Minute
)

// Policy is the member's presence policy, versioned as one object.
type Policy struct {
	Version uint64   `json:"version"`
	State   string   `json:"state,omitempty"`
	Share   string   `json:"share,omitempty"`
	Except  []string `json:"except,omitempty"`
}

func (p Policy) state() string {
	if p.State == "" {
		return Available
	}
	return p.State
}

func (p Policy) share() string {
	if p.Share == "" {
		return ShareAll
	}
	return p.Share
}

// Shares reports whether the policy answers pings from conn.
func (p Policy) Shares(conn string) bool {
	if p.state() == Invisible {
		return false
	}
	listed := false
	for _, c := range p.Except {
		listed = listed || c == conn
	}
	return (p.share() == ShareAll) != listed
}

type ping struct {
	id, conn, device string
	sent, exp        time.Time
	result           []byte // presence.result body once the pong arrived
}

// Feature implements vault.Feature and vault.ConnectionRemovedObserver.
// Pings, pongs and their rate limits are memory only (§8.5).
type Feature struct {
	mu     sync.Mutex
	policy Policy
	pings  map[string]*ping     // by ping id
	byConn map[string]*ping     // the latest ping per connection
	ponged map[string]time.Time // the last pong sent per peer
}

// New returns the feature.
func New() *Feature {
	return &Feature{pings: map[string]*ping{}, byConn: map[string]*ping{}, ponged: map[string]time.Time{}}
}

var (
	owners = []string{vault.KindApp, vault.KindDesktop}
	conns  = []string{vault.KindConnection}
)

// Name implements vault.Feature.
func (f *Feature) Name() string { return "presence" }

// Types implements vault.Feature.
func (f *Feature) Types() []vault.TypeSpec {
	return []vault.TypeSpec{
		{Type: "presence.get", Request: true, From: owners},
		// Changes what connections can obtain: desktops with an app's
		// approval (§6.8).
		{Type: "presence.set", Request: true, From: owners, DesktopApproval: true},
		{Type: "presence.query", Request: true, From: owners},
		{Type: "presence.ping", Ephemeral: true, From: conns},
		{Type: "presence.pong", Ephemeral: true, From: conns},
	}
}

// Load implements vault.Feature.
func (f *Feature) Load(raw json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := Policy{}
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	f.policy = p
	return nil
}

// Save implements vault.Feature.
func (f *Feature) Save() (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return json.Marshal(f.policy)
}

var (
	errBad      = vault.NewError("bad_request", "")
	errNotFound = vault.NewError("not_found", "")
	errConflict = vault.NewError("conflict", "")
	errConn     = vault.NewError("connection_unavailable", "")
)

// Set is a parsed presence.set body.
type Set struct {
	Version   uint64
	State     string
	HasState  bool
	Share     string
	HasShare  bool
	Except    []string
	HasExcept bool
}

func validState(s string, own bool) bool {
	return s == Available || s == Busy || s == Away || own && s == Invisible
}

// ParseSet parses presence.set strictly.
func ParseSet(body []byte) (*Set, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	v := &Set{}
	if v.Version, err = o.Uint("version", 0, strictjson.MaxSafeInteger); err != nil {
		return nil, errBad
	}
	if v.State, v.HasState, err = o.OptString("state"); err != nil || v.HasState && !validState(v.State, true) {
		return nil, errBad
	}
	if v.Share, v.HasShare, err = o.OptString("share"); err != nil || v.HasShare && v.Share != ShareAll && v.Share != ShareNone {
		return nil, errBad
	}
	arr, present, err := o.OptArray("except")
	if err != nil || len(arr) > MaxExcept {
		return nil, errBad
	}
	if present {
		v.HasExcept = true
		v.Except = []string{}
		seen := map[string]bool{}
		for _, raw := range arr {
			c, err := strictjson.AsString(raw)
			if err != nil || c == "" || len(c) > 64 {
				return nil, errBad
			}
			if !seen[c] {
				seen[c] = true
				v.Except = append(v.Except, c)
			}
		}
		sort.Strings(v.Except)
	}
	return v, nil
}

// ParseQuery parses presence.query: {connection_id}.
func ParseQuery(body []byte) (string, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", errBad
	}
	c, err := o.String("connection_id")
	if err != nil || c == "" || len(c) > 64 {
		return "", errBad
	}
	return c, nil
}

// ParsePing parses presence.ping: {ping_id}.
func ParsePing(body []byte) (string, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", errBad
	}
	id, err := o.String("ping_id")
	if err != nil || !envelope.ValidULID(id) {
		return "", errBad
	}
	return id, nil
}

// Pong is a parsed presence.pong body.
type Pong struct {
	PingID     string
	State      string
	LastActive time.Time
}

// ParsePong parses presence.pong strictly (the caller checks last_active
// against the clock).
func ParsePong(body []byte) (*Pong, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	p := &Pong{}
	if p.PingID, err = o.String("ping_id"); err != nil || !envelope.ValidULID(p.PingID) {
		return nil, errBad
	}
	if p.State, err = o.String("state"); err != nil || !validState(p.State, false) {
		return nil, errBad
	}
	if la, present, err := o.OptString("last_active"); err != nil {
		return nil, errBad
	} else if present {
		if p.LastActive, err = envelope.ParseTS(la); err != nil {
			return nil, errBad
		}
	}
	return p, nil
}

func (f *Feature) policyJSON() []byte {
	ex := []byte{'['}
	for i, c := range f.policy.Except {
		if i > 0 {
			ex = append(ex, ',')
		}
		ex = append(ex, strictjson.MarshalString(c)...)
	}
	return strictjson.NewBuilder().Uint("version", f.policy.Version).String("state", f.policy.state()).
		String("share", f.policy.share()).Raw("except", append(ex, ']')).Bytes()
}

// Handle implements vault.Handler.
func (f *Feature) Handle(_ context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prune(s.Now())
	switch in.Type {
	case "presence.get":
		if _, err := strictjson.ParseObject(in.Body); err != nil {
			return nil, errBad
		}
		return f.policyJSON(), nil
	case "presence.set":
		return f.set(s, in.Body)
	case "presence.query":
		return f.query(s, in.Body)
	case "presence.ping":
		f.pinged(s, in.Body)
	case "presence.pong":
		f.pongReceived(s, in.Body)
	default:
		return nil, vault.NewError("unsupported_type", "")
	}
	return nil, nil
}

func (f *Feature) prune(now time.Time) {
	for id, p := range f.pings {
		if now.Sub(p.sent) >= PingEvery && now.After(p.exp) {
			delete(f.pings, id)
			if f.byConn[p.conn] == p {
				delete(f.byConn, p.conn)
			}
		}
	}
	for c, t := range f.ponged {
		if now.Sub(t) >= PingEvery {
			delete(f.ponged, c)
		}
	}
}

func (f *Feature) set(s *vault.Session, body []byte) (json.RawMessage, error) {
	v, err := ParseSet(body)
	if err != nil {
		return nil, err
	}
	if v.Version != f.policy.Version {
		return nil, errConflict
	}
	next := f.policy
	next.Except = append([]string(nil), f.policy.Except...)
	if v.HasState {
		next.State = v.State
	}
	if v.HasShare {
		next.Share = v.Share
	}
	if v.HasExcept {
		next.Except = v.Except
	}
	next.Version++
	f.policy = next
	ver := strictjson.NewBuilder().Uint("version", next.Version).Bytes()
	s.SyncEvent("presence.changed", ver)
	return ver, nil
}

func (f *Feature) resultBody(conn, pingID string, p *Pong) []byte {
	b := strictjson.NewBuilder().String("connection_id", conn).String("ping_id", pingID).String("state", p.State)
	if !p.LastActive.IsZero() {
		b.String("last_active", envelope.FormatTS(p.LastActive))
	}
	return b.Bytes()
}

func (f *Feature) query(s *vault.Session, body []byte) (json.RawMessage, error) {
	conn, err := ParseQuery(body)
	if err != nil {
		return nil, err
	}
	c, ok := s.Connection(conn)
	if !ok {
		return nil, errNotFound
	}
	if c.State != vault.PeerActive {
		return nil, errConn
	}
	now := s.Now()
	if p := f.byConn[conn]; p != nil && now.Sub(p.sent) < PingEvery {
		p.device = s.From().ID
		if p.result != nil {
			_ = s.Send(p.device, "presence.result", p.result, vault.SendOptions{Exp: now.Add(ResultTTL).UTC().Truncate(time.Millisecond), MemoryOnly: true})
		}
		return f.answer(p), nil
	}
	p := &ping{id: s.NewID(), conn: conn, device: s.From().ID, sent: now, exp: now.Add(PingTTL).UTC().Truncate(time.Millisecond)}
	if err := s.Send(conn, "presence.ping", strictjson.NewBuilder().String("ping_id", p.id).Bytes(),
		vault.SendOptions{Exp: p.exp, MemoryOnly: true}); err != nil {
		return nil, errConn
	}
	f.pings[p.id] = p
	f.byConn[conn] = p
	return f.answer(p), nil
}

func (f *Feature) answer(p *ping) json.RawMessage {
	return strictjson.NewBuilder().String("ping_id", p.id).String("exp", envelope.FormatTS(p.exp)).Bytes()
}

// pinged answers a connection's ping, or stays silent: a refusal must look
// like a locked or unreachable vault (§9.2).
func (f *Feature) pinged(s *vault.Session, body []byte) {
	conn := s.From().ID
	id, err := ParsePing(body)
	if err != nil || !f.policy.Shares(conn) {
		return
	}
	now := s.Now()
	if _, recent := f.ponged[conn]; recent {
		return
	}
	b := strictjson.NewBuilder().String("ping_id", id).String("state", f.policy.state())
	if la := s.OwnerLastActive(); !la.IsZero() {
		b.String("last_active", envelope.FormatTS(la.UTC().Truncate(LastActiveStep)))
	}
	if s.Send(conn, "presence.pong", b.Bytes(), vault.SendOptions{Exp: now.Add(PingTTL).UTC().Truncate(time.Millisecond), MemoryOnly: true}) == nil {
		f.ponged[conn] = now
	}
}

// pongReceived takes a connection's answer to one of our pings.
func (f *Feature) pongReceived(s *vault.Session, body []byte) {
	conn := s.From().ID
	now := s.Now()
	pg, err := ParsePong(body)
	if err != nil || pg.LastActive.After(now.Add(5*time.Minute)) {
		return
	}
	p := f.pings[pg.PingID]
	if p == nil || p.conn != conn || p.result != nil || now.After(p.exp) {
		return
	}
	p.result = f.resultBody(conn, p.id, pg)
	_ = s.Send(p.device, "presence.result", p.result, vault.SendOptions{Exp: now.Add(ResultTTL).UTC().Truncate(time.Millisecond), MemoryOnly: true})
}

// ConnectionRemoved implements vault.ConnectionRemovedObserver (§7.4).
func (f *Feature) ConnectionRemoved(_ *vault.Session, conn string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	kept := []string{}
	for _, c := range f.policy.Except {
		if c != conn {
			kept = append(kept, c)
		}
	}
	if len(kept) != len(f.policy.Except) {
		f.policy.Except = kept
	}
	delete(f.byConn, conn)
	delete(f.ponged, conn)
	for id, p := range f.pings {
		if p.conn == conn {
			delete(f.pings, id)
		}
	}
}
