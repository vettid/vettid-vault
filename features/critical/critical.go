// Package critical is critical-secret use by a connection
// (VAULT-MESSAGING §10.13): a connection asks the member to use one of the
// critical secrets in their Protean Credential (an Ed25519 signing key)
// for one operation; the member consents in their app with the credential
// password, for that use only, bound to the request and the payload's
// hash; the vault opens the credential, signs, rotates the CEK and wipes
// the key; the connection receives only the signature.
//
// Ported from vettid.dev's critical_secret_handler.go: the password-hash
// approval becomes a credential operation with a UTK-sealed payload
// (§3.5.3, §3.5.4) carrying request_id and payload_sha256; standing
// allowances are gone (every use needs the password); only `sign` and
// the domain-separated `auth` remain (decrypt and derive were never
// implemented); only cataloged critical secrets can be asked for.
package critical

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/features/credential"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/sharewire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Limits (§10.13).
const (
	MaxPayload    = 4096
	MaxContext    = 256
	MaxPendingIn  = 8 // per connection
	MaxOutgoing   = 64
	RequestTTL    = 24 * time.Hour
	OutgoingTTL   = 25 * time.Hour
	SeedSize      = ed25519.SeedSize
	OperationSign = "sign"
	OperationAuth = "auth"
)

// Statuses of critical-secret.result.
const (
	StatusOK          = "ok"
	StatusDenied      = "denied"
	StatusExpired     = "expired"
	StatusUnavailable = "unavailable"
	StatusUnsuitable  = "unsuitable"
)

// Incoming is a connection's pending request on the member's side.
type Incoming struct {
	ID        string    `json:"id"`
	Conn      string    `json:"conn"`
	SecretID  string    `json:"secret_id"`
	Name      string    `json:"name"`
	Operation string    `json:"operation"`
	Payload   []byte    `json:"payload"`
	Context   string    `json:"context,omitempty"`
	Exp       time.Time `json:"exp"`
}

// Outgoing is a request this vault sent, kept for its result.
type Outgoing struct {
	ID        string    `json:"id"`
	Conn      string    `json:"conn"`
	SecretID  string    `json:"secret_id"`
	Operation string    `json:"operation"`
	Payload   []byte    `json:"payload"`
	State     string    `json:"state"` // pending | done
	Status    string    `json:"status,omitempty"`
	Exp       time.Time `json:"exp"`
}

type data struct {
	In  map[string]*Incoming `json:"in"`
	Out map[string]*Outgoing `json:"out"`
	// Done remembers answered incoming request ids for a while, so that a
	// repeated request_id is ignored.
	Done map[string]time.Time `json:"done,omitempty"`
}

// Feature implements vault.Feature and vault.ConnectionRemovedObserver.
type Feature struct {
	mu   sync.Mutex
	cred *credential.Feature
	d    data
}

// New returns the feature; cred performs the uses (credential.UseSecret).
func New(cred *credential.Feature) *Feature {
	return &Feature{cred: cred, d: data{In: map[string]*Incoming{}, Out: map[string]*Outgoing{}, Done: map[string]time.Time{}}}
}

var (
	apps   = []string{vault.KindApp}
	owners = []string{vault.KindApp, vault.KindDesktop}
	conns  = []string{vault.KindConnection}
)

// Name implements vault.Feature.
func (f *Feature) Name() string { return "critical" }

// Types implements vault.Feature.
func (f *Feature) Types() []vault.TypeSpec {
	return []vault.TypeSpec{
		{Type: "critical-secret-use.request", Request: true, From: owners},
		{Type: "critical-secret-use.approve", Request: true, From: apps},
		{Type: "critical-secret-use.deny", Request: true, From: owners},
		{Type: "critical-secret-use.list", Request: true, From: owners},
		{Type: "critical-secret.use", From: conns},
		{Type: "critical-secret.result", From: conns},
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
	if d.In == nil {
		d.In = map[string]*Incoming{}
	}
	if d.Out == nil {
		d.Out = map[string]*Outgoing{}
	}
	if d.Done == nil {
		d.Done = map[string]time.Time{}
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
	errLimit    = vault.NewError("limit", "")
	errConn     = vault.NewError("connection_unavailable", "")
)

// Use is a parsed critical-secret-use.request body (D→V, with
// Connection) or critical-secret.use body (V↔V, with RequestID).
type Use struct {
	RequestID  string
	Connection string
	SecretID   string
	Operation  string
	Payload    []byte
	Context    string
}

func parseUse(o strictjson.Object) (*Use, error) {
	u := &Use{}
	var err error
	if u.SecretID, err = o.String("secret_id"); err != nil || !envelope.ValidULID(u.SecretID) {
		return nil, errBad
	}
	if u.Operation, err = o.String("operation"); err != nil || u.Operation != OperationSign && u.Operation != OperationAuth {
		return nil, errBad
	}
	if u.Payload, err = o.Base64("payload", -1); err != nil || len(u.Payload) == 0 || len(u.Payload) > MaxPayload {
		return nil, errBad
	}
	c, _, err := o.OptString("context")
	if err != nil || len(c) > MaxContext {
		return nil, errBad
	}
	u.Context = c
	return u, nil
}

// ParseRequest parses a critical-secret-use.request body strictly.
func ParseRequest(body []byte) (*Use, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	u, err := parseUse(o)
	if err != nil {
		return nil, err
	}
	if u.Connection, err = o.String("connection_id"); err != nil || u.Connection == "" || len(u.Connection) > 128 {
		return nil, errBad
	}
	return u, nil
}

// ParseUse parses a critical-secret.use body (from a connection) strictly.
func ParseUse(body []byte) (*Use, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	u, err := parseUse(o)
	if err != nil {
		return nil, err
	}
	if u.RequestID, err = o.String("request_id"); err != nil || !envelope.ValidULID(u.RequestID) {
		return nil, errBad
	}
	return u, nil
}

// Result is a parsed critical-secret.result body.
type Result struct {
	RequestID string
	Status    string
	Signature []byte
	PublicKey []byte
}

// ParseResult parses a critical-secret.result body (from a connection)
// strictly.
func ParseResult(body []byte) (*Result, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	r := &Result{}
	if r.RequestID, err = o.String("request_id"); err != nil || !envelope.ValidULID(r.RequestID) {
		return nil, errBad
	}
	if r.Status, err = o.String("status"); err != nil {
		return nil, errBad
	}
	switch r.Status {
	case StatusOK:
		if r.Signature, err = o.Base64("signature", ed25519.SignatureSize); err != nil {
			return nil, errBad
		}
		if r.PublicKey, err = o.Base64("public_key", ed25519.PublicKeySize); err != nil {
			return nil, errBad
		}
	case StatusDenied, StatusExpired, StatusUnavailable, StatusUnsuitable:
	default:
		return nil, errBad
	}
	return r, nil
}

// RequestID parses the request_id of an approve, deny body.
func RequestID(body []byte) (string, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", errBad
	}
	id, err := o.String("request_id")
	if err != nil || !envelope.ValidULID(id) {
		return "", errBad
	}
	return id, nil
}

// Handle implements vault.Handler.
func (f *Feature) Handle(_ context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expire(s)
	switch in.Type {
	case "critical-secret-use.request":
		return f.request(s, in.Body)
	case "critical-secret.use":
		return nil, f.incoming(s, in.Body)
	case "critical-secret-use.approve":
		return f.approve(s, in)
	case "critical-secret-use.deny":
		return f.deny(s, in.Body)
	case "critical-secret-use.list":
		if _, err := strictjson.ParseObject(in.Body); err != nil {
			return nil, errBad
		}
		return f.list(), nil
	case "critical-secret.result":
		return nil, f.result(s, in.Body)
	}
	return nil, vault.NewError("unsupported_type", "")
}

// expire answers expired incoming requests `expired` and forgets old
// outgoing requests and answered ids.
func (f *Feature) expire(s *vault.Session) {
	now := s.Now()
	for _, r := range f.sortedIn() {
		if !now.Before(r.Exp) {
			f.answer(s, r, StatusExpired, nil)
		}
	}
	for id, o := range f.d.Out {
		if !now.Before(o.Exp) {
			delete(f.d.Out, id)
		}
	}
	for id, t := range f.d.Done {
		if !now.Before(t) {
			delete(f.d.Done, id)
		}
	}
}

func (f *Feature) sortedIn() []*Incoming {
	out := make([]*Incoming, 0, len(f.d.In))
	for _, r := range f.d.In {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// answer sends the connection a final result and forgets the request.
func (f *Feature) answer(s *vault.Session, r *Incoming, status string, extra func(*strictjson.Builder)) {
	b := strictjson.NewBuilder().String("request_id", r.ID).String("status", status)
	if extra != nil {
		extra(b)
	}
	_ = s.SendToConnection(r.Conn, "critical-secret.result", b.Bytes())
	delete(f.d.In, r.ID)
	f.d.Done[r.ID] = s.Now().Add(OutgoingTTL)
}

// request: an owner device asks a connection's member to use a secret.
func (f *Feature) request(s *vault.Session, body []byte) (json.RawMessage, error) {
	u, err := ParseRequest(body)
	if err != nil {
		return nil, err
	}
	if p, ok := s.Connection(u.Connection); !ok || p.State != vault.PeerActive {
		return nil, errNotFound
	}
	n := 0
	for _, o := range f.d.Out {
		if o.State == "pending" {
			n++
		}
	}
	if n >= MaxOutgoing {
		return nil, errLimit
	}
	id := s.NewID()
	b := strictjson.NewBuilder().String("request_id", id).String("secret_id", u.SecretID).String("operation", u.Operation).
		Base64("payload", u.Payload)
	if u.Context != "" {
		b.String("context", u.Context)
	}
	if err := s.SendToConnection(u.Connection, "critical-secret.use", b.Bytes()); err != nil {
		return nil, errConn
	}
	f.d.Out[id] = &Outgoing{ID: id, Conn: u.Connection, SecretID: u.SecretID, Operation: u.Operation, Payload: u.Payload,
		State: "pending", Exp: s.Now().Add(OutgoingTTL).UTC()}
	s.Record(vault.Activity{Kind: "critical-secret.use.requested", ConnectionID: u.Connection, Ref: id, Direction: "out", Audit: true})
	return strictjson.NewBuilder().String("request_id", id).Bytes(), nil
}

// incoming: a connection asks this vault's member.
func (f *Feature) incoming(s *vault.Session, body []byte) error {
	u, err := ParseUse(body)
	if err != nil {
		return err
	}
	conn := s.From().ID
	if _, dup := f.d.In[u.RequestID]; dup {
		return nil
	}
	if _, done := f.d.Done[u.RequestID]; done {
		return nil
	}
	s.Record(vault.Activity{Kind: "critical-secret.use.requested", ConnectionID: conn, Ref: u.RequestID, Direction: "in", Audit: true})
	r := &Incoming{ID: u.RequestID, Conn: conn, SecretID: u.SecretID, Operation: u.Operation, Payload: u.Payload,
		Context: u.Context, Exp: s.Now().Add(RequestTTL).UTC().Truncate(time.Millisecond)}
	meta, ok := f.cred.CatalogedSecret(u.SecretID)
	pending := 0
	for _, x := range f.d.In {
		if x.Conn == conn {
			pending++
		}
	}
	if !ok || pending >= MaxPendingIn {
		// Not in the catalog (or too many pending): answered without
		// asking the member; a private or unknown secret is not told apart.
		f.answer(s, r, StatusUnavailable, nil)
		s.Record(vault.Activity{Kind: "critical-secret.use.denied", ConnectionID: conn, Ref: u.RequestID, Direction: "in", Audit: true})
		return nil
	}
	r.Name = meta.Name
	f.d.In[r.ID] = r
	h := sha256.Sum256(r.Payload)
	b := strictjson.NewBuilder().String("request_id", r.ID).String("connection_id", conn).String("secret_id", r.SecretID).
		String("name", r.Name).String("operation", r.Operation).Base64("payload", r.Payload).Base64("payload_sha256", h[:])
	if r.Context != "" {
		b.String("context", r.Context)
	}
	s.NotifyAllDevices("critical-secret-use.pending", b.String("exp", envelope.FormatTS(r.Exp)).Bytes())
	s.Record(vault.Activity{Kind: "critical-secret.use.request", ConnectionID: conn, Ref: r.ID, Feed: true, Priority: "high"})
	return nil
}

// approve: the member's consent with the password, for this use only
// (§10.13). The credential operation spends the UTK first; the sealed
// payload must name this request and this payload.
func (f *Feature) approve(s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	id, err := RequestID(in.Body)
	if err != nil {
		return nil, err
	}
	r := f.d.In[id]
	if r == nil {
		return nil, errNotFound
	}
	conn, ok := s.Connection(r.Conn)
	if !ok {
		return nil, errNotFound
	}
	want := sha256.Sum256(r.Payload)
	check := func(p *credential.Payload) error {
		if subtle.ConstantTimeCompare([]byte(p.RequestID), []byte(r.ID)) != 1 || subtle.ConstantTimeCompare(p.PayloadHash, want[:]) != 1 {
			return errBad
		}
		return nil
	}
	status := ""
	var sig, pub []byte
	use := func(value []byte, b *strictjson.Builder) {
		switch {
		case value == nil:
			status = StatusUnavailable // deleted from the credential since
		case len(value) != SeedSize:
			status = StatusUnsuitable
		default:
			key := ed25519.NewKeyFromSeed(value)
			defer suite.Wipe(key)
			msg := r.Payload
			if r.Operation == OperationAuth {
				msg = append([]byte(sharewire.LabelCriticalAuth), sharewire.AuthMessage(conn.IK, s.IdentityKey(), r.ID, r.Payload)...)
			}
			sig = ed25519.Sign(key, msg)
			pub = append([]byte(nil), key.Public().(ed25519.PublicKey)...)
			status = StatusOK
		}
		b.String("request_id", r.ID).String("status", status)
	}
	out, err := f.cred.UseSecret(s, in, r.SecretID, check, use)
	if err != nil {
		return nil, err // the request stays pending (bad_password, backoff, ...)
	}
	f.answer(s, r, status, func(b *strictjson.Builder) {
		if status == StatusOK {
			b.Base64("signature", sig).Base64("public_key", pub)
		}
	})
	kind := "critical-secret.used"
	if status != StatusOK {
		kind = "critical-secret.use.denied"
	}
	s.Record(vault.Activity{Kind: kind, ConnectionID: r.Conn, Ref: r.ID, Direction: "out", Audit: true})
	s.SyncEvent("critical-secret-use.decided", strictjson.NewBuilder().String("request_id", r.ID).Bool("approved", true).Bytes())
	return out, nil
}

func (f *Feature) deny(s *vault.Session, body []byte) (json.RawMessage, error) {
	id, err := RequestID(body)
	if err != nil {
		return nil, err
	}
	r := f.d.In[id]
	if r == nil {
		return nil, errNotFound
	}
	f.answer(s, r, StatusDenied, nil)
	s.Record(vault.Activity{Kind: "critical-secret.use.denied", ConnectionID: r.Conn, Ref: r.ID, Direction: "out", Audit: true})
	s.SyncEvent("critical-secret-use.decided", strictjson.NewBuilder().String("request_id", r.ID).Bool("approved", false).Bytes())
	return nil, nil
}

// result: the connection's answer to a request this vault sent. A
// signature is checked before it is passed on (for `auth`, over the
// message built from both identity keys as this vault has them).
func (f *Feature) result(s *vault.Session, body []byte) error {
	res, err := ParseResult(body)
	if err != nil {
		return err
	}
	conn := s.From().ID
	o := f.d.Out[res.RequestID]
	if o == nil || o.Conn != conn || o.State != "pending" {
		return nil // unknown, answered or another connection's: dropped
	}
	if res.Status == StatusOK {
		p, _ := s.Connection(conn)
		msg := o.Payload
		if o.Operation == OperationAuth {
			msg = append([]byte(sharewire.LabelCriticalAuth), sharewire.AuthMessage(s.IdentityKey(), p.IK, o.ID, o.Payload)...)
		}
		if !ed25519.Verify(res.PublicKey, msg, res.Signature) {
			s.Record(vault.Activity{Kind: "drop.critical_signature", ConnectionID: conn, Ref: o.ID, Audit: true})
			return nil
		}
	}
	o.State, o.Status = "done", res.Status
	b := strictjson.NewBuilder().String("connection_id", conn).String("request_id", o.ID).String("status", res.Status)
	if res.Status == StatusOK {
		b.Base64("signature", res.Signature).Base64("public_key", res.PublicKey)
	}
	s.NotifyAllDevices("critical-secret-use.result", b.Bytes())
	s.Record(vault.Activity{Kind: "critical-secret.use.result", ConnectionID: conn, Ref: o.ID, Direction: "in", Audit: true})
	return nil
}

func (f *Feature) list() []byte {
	in := []byte{'['}
	for i, r := range f.sortedIn() {
		if i > 0 {
			in = append(in, ',')
		}
		h := sha256.Sum256(r.Payload)
		b := strictjson.NewBuilder().String("request_id", r.ID).String("connection_id", r.Conn).String("secret_id", r.SecretID).
			String("name", r.Name).String("operation", r.Operation).Base64("payload_sha256", h[:])
		if r.Context != "" {
			b.String("context", r.Context)
		}
		in = append(in, b.String("exp", envelope.FormatTS(r.Exp)).Bytes()...)
	}
	outs := make([]*Outgoing, 0, len(f.d.Out))
	for _, o := range f.d.Out {
		outs = append(outs, o)
	}
	sort.Slice(outs, func(i, j int) bool { return outs[i].ID < outs[j].ID })
	out := []byte{'['}
	for i, o := range outs {
		if i > 0 {
			out = append(out, ',')
		}
		b := strictjson.NewBuilder().String("request_id", o.ID).String("connection_id", o.Conn).String("secret_id", o.SecretID).
			String("operation", o.Operation).String("state", o.State)
		if o.Status != "" {
			b.String("status", o.Status)
		}
		out = append(out, b.Bytes()...)
	}
	return strictjson.NewBuilder().Raw("incoming", append(in, ']')).Raw("outgoing", append(out, ']')).Bytes()
}

// ConnectionRemoved implements vault.ConnectionRemovedObserver: the
// connection's requests, both ways, are dropped without notice (§7.4).
func (f *Feature) ConnectionRemoved(_ *vault.Session, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, r := range f.d.In {
		if r.Conn == id {
			delete(f.d.In, k)
		}
	}
	for k, o := range f.d.Out {
		if o.Conn == id {
			delete(f.d.Out, k)
		}
	}
}

// Pending returns the ids of the incoming requests (tests).
func (f *Feature) Pending() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.sortedIn() {
		out = append(out, r.ID)
	}
	return out
}
