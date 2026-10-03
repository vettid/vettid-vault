// Package connauth is member authentication between connections
// (VAULT-MESSAGING §10.4, connection.authenticate.*): one vault asks a
// connection to prove that its member is present now; the member approves
// in their app, and their vault signs the challenge with the member's
// credential key (§3.5.1), which exists only inside the Protean Credential
// and is usable only during an unlock window the member opened with their
// password (§3.5.3).
//
// The §6 handshake (with the SAS) already authenticates the peer *vault*;
// this proves the *member*. The requester pins the peer's credential
// public key at the first success and reports a change.
//
// Ported from vettid.dev's connection-authenticate handlers: the identity
// key that lived in the old credential is now the credential key; the
// password travels to the vault through credential.unlock (UTK-sealed)
// rather than in the approve request; the signed string is binary and
// binds both vaults' identity keys instead of owner-space GUIDs; the
// verify-state cache becomes the per-connection state of this feature.
package connauth

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Label and limits.
const (
	Label         = "vettid/vms/2/conn-auth"
	NonceSize     = 32
	ChallengeTTL  = 10 * time.Minute
	MaxContext    = 256
	MaxPendingOut = 8 // per connection
	MaxPendingIn  = 4 // per connection
)

// Response statuses.
const (
	StatusSigned = "signed"
	StatusDenied = "denied"
)

// KeyUser gives access to the credential key during the unlock window
// (credential.Feature.UseKey, §3.5.3).
type KeyUser interface {
	UseKey(now time.Time, ttl time.Duration) (ed25519.PrivateKey, bool)
}

// Challenge is an outstanding challenge, sent or received.
type Challenge struct {
	ID      string    `json:"id"`
	Conn    string    `json:"conn"`
	Nonce   []byte    `json:"nonce"`
	Context string    `json:"context,omitempty"`
	Exp     time.Time `json:"exp"`
}

// State is the last outcome with one connection.
type State struct {
	Key        []byte    `json:"key,omitempty"` // the pinned credential key
	VerifiedAt time.Time `json:"verified_at,omitempty"`
	LastResult string    `json:"last_result,omitempty"` // "authenticated" or the failure reason
	LastAt     time.Time `json:"last_at,omitempty"`
}

type data struct {
	Out    map[string]*Challenge `json:"out"`
	In     map[string]*Challenge `json:"in"`
	States map[string]*State     `json:"states"`
	// Chain is this vault's own credential-key rotation statements, oldest
	// first (at most credwire.MaxKeyChain).
	Chain []json.RawMessage `json:"chain,omitempty"`
	// Shown is, per connection, the credential key this vault last signed
	// a response with: the key that connection pinned.
	Shown map[string][]byte `json:"shown,omitempty"`
}

// Feature implements vault.Feature and vault.ConnectionRemovedObserver.
type Feature struct {
	mu   sync.Mutex
	keys KeyUser
	d    data
}

// New returns the feature; keys is the credential feature.
func New(keys KeyUser) *Feature {
	return &Feature{keys: keys, d: data{Out: map[string]*Challenge{}, In: map[string]*Challenge{}, States: map[string]*State{},
		Shown: map[string][]byte{}}}
}

var (
	apps   = []string{vault.KindApp}
	owners = []string{vault.KindApp, vault.KindDesktop}
	conns  = []string{vault.KindConnection}
)

// Name implements vault.Feature.
func (f *Feature) Name() string { return "connauth" }

// Types implements vault.Feature.
func (f *Feature) Types() []vault.TypeSpec {
	return []vault.TypeSpec{
		{Type: "connection.authenticate.request", Request: true, From: owners},
		{Type: "connection.authenticate.approve", Request: true, From: apps},
		{Type: "connection.authenticate.deny", Request: true, From: owners},
		{Type: "connection.authenticate.list", Request: true, From: owners},
		{Type: "connection.authenticate.challenge", From: conns},
		{Type: "connection.authenticate.response", From: conns},
		{Type: "connection.authenticate.rotated", From: conns},
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
	if d.Out == nil {
		d.Out = map[string]*Challenge{}
	}
	if d.In == nil {
		d.In = map[string]*Challenge{}
	}
	if d.States == nil {
		d.States = map[string]*State{}
	}
	if d.Shown == nil {
		d.Shown = map[string][]byte{}
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
	errLocked   = vault.NewError("credential_locked", "")
	errConn     = vault.NewError("connection_unavailable", "")
)

// Message returns the signed bytes:
//
//	challenger_ik (32) || responder_ik (32) || nonce (32) || request_id (26) || context
//
// signed as Ed25519(credential key, "vettid/vms/2/conn-auth" || message).
func Message(challengerIK, responderIK, nonce []byte, requestID, ctxt string) []byte {
	m := make([]byte, 0, 32+32+NonceSize+len(requestID)+len(ctxt))
	m = append(append(append(m, challengerIK...), responderIK...), nonce...)
	return append(append(m, requestID...), ctxt...)
}

// Handle implements vault.Handler.
func (f *Feature) Handle(_ context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expire(s.Now())
	switch in.Type {
	case "connection.authenticate.request":
		return f.request(s, in.Body)
	case "connection.authenticate.challenge":
		return nil, f.challenge(s, in)
	case "connection.authenticate.approve":
		return f.approve(s, in.Body)
	case "connection.authenticate.deny":
		return f.deny(s, in.Body)
	case "connection.authenticate.response":
		return nil, f.response(s, in.Body)
	case "connection.authenticate.list":
		return f.list(), nil
	case "connection.authenticate.rotated":
		return nil, f.rotated(s, in.Body)
	}
	return nil, vault.NewError("unsupported_type", "")
}

func (f *Feature) expire(now time.Time) {
	for id, c := range f.d.Out {
		if !now.Before(c.Exp) {
			delete(f.d.Out, id)
		}
	}
	for id, c := range f.d.In {
		if !now.Before(c.Exp) {
			delete(f.d.In, id)
		}
	}
}

func count(m map[string]*Challenge, conn string) int {
	n := 0
	for _, c := range m {
		if c.Conn == conn {
			n++
		}
	}
	return n
}

func optContext(o strictjson.Object) (string, error) {
	v, _, err := o.OptString("context")
	if err != nil || len(v) > MaxContext {
		return "", errBad
	}
	return v, nil
}

// request: an owner device asks a connection's member to authenticate.
func (f *Feature) request(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	conn, err := o.String("connection_id")
	if err != nil || conn == "" {
		return nil, errBad
	}
	ctxt, err := optContext(o)
	if err != nil {
		return nil, err
	}
	if p, ok := s.Connection(conn); !ok || p.State != vault.PeerActive {
		return nil, errNotFound
	}
	if count(f.d.Out, conn) >= MaxPendingOut {
		return nil, errLimit
	}
	nonce, err := suite.RandomBytes(NonceSize)
	if err != nil {
		return nil, vault.NewError("internal", "")
	}
	c := &Challenge{ID: s.NewID(), Conn: conn, Nonce: nonce, Context: ctxt, Exp: s.Now().Add(ChallengeTTL).UTC().Truncate(time.Millisecond)}
	b := strictjson.NewBuilder().String("request_id", c.ID).Base64("nonce", nonce)
	if ctxt != "" {
		b.String("context", ctxt)
	}
	if err := s.Send(conn, "connection.authenticate.challenge", b.Bytes(), vault.SendOptions{Exp: c.Exp}); err != nil {
		return nil, errConn
	}
	f.d.Out[c.ID] = c
	s.Record(vault.Activity{Kind: "connection.authenticate.requested", ConnectionID: conn, Ref: c.ID, Direction: "out", Audit: true})
	return strictjson.NewBuilder().String("request_id", c.ID).String("exp", envelope.FormatTS(c.Exp)).Bytes(), nil
}

// ParseChallenge parses a challenge body (from a peer vault) strictly.
func ParseChallenge(body []byte) (*Challenge, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	c := &Challenge{}
	if c.ID, err = o.String("request_id"); err != nil || !envelope.ValidULID(c.ID) {
		return nil, errBad
	}
	if c.Nonce, err = o.Base64("nonce", NonceSize); err != nil {
		return nil, errBad
	}
	if c.Context, err = optContext(o); err != nil {
		return nil, err
	}
	return c, nil
}

// challenge: a connection asks our member to authenticate; the owner's
// apps and desktops are told (only an app can approve).
func (f *Feature) challenge(s *vault.Session, in *envelope.Inner) error {
	c, err := ParseChallenge(in.Body)
	if err != nil {
		return err
	}
	conn := s.From().ID
	now := s.Now()
	if _, dup := f.d.In[c.ID]; dup {
		return nil
	}
	if count(f.d.In, conn) >= MaxPendingIn {
		s.Record(vault.Activity{Kind: "drop.authenticate_limit", ConnectionID: conn, Audit: true})
		return nil
	}
	c.Conn = conn
	c.Exp = now.Add(ChallengeTTL).UTC().Truncate(time.Millisecond)
	if !in.Exp.IsZero() && in.Exp.Before(c.Exp) {
		c.Exp = in.Exp
	}
	f.d.In[c.ID] = c
	b := strictjson.NewBuilder().String("connection_id", conn).String("request_id", c.ID).String("exp", envelope.FormatTS(c.Exp))
	if c.Context != "" {
		b.String("context", c.Context)
	}
	s.NotifyDevicesWith("connection.authenticate.pending", b.Bytes(), "", vault.SendOptions{Exp: c.Exp})
	s.Record(vault.Activity{Kind: "connection.authenticate.requested", ConnectionID: conn, Ref: c.ID, Direction: "in", Audit: true,
		Feed: true, Priority: "high"})
	return nil
}

func requestID(body []byte) (string, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", errBad
	}
	id, err := o.String("request_id")
	if err != nil || id == "" {
		return "", errBad
	}
	return id, nil
}

// approve: the member signs the challenge with the credential key, which
// is usable only within the unlock window (§3.5.3).
func (f *Feature) approve(s *vault.Session, body []byte) (json.RawMessage, error) {
	id, err := requestID(body)
	if err != nil {
		return nil, err
	}
	c := f.d.In[id]
	if c == nil {
		return nil, errNotFound
	}
	peer, ok := s.Connection(c.Conn)
	if !ok || peer.State != vault.PeerActive {
		delete(f.d.In, id)
		return nil, errConn
	}
	if f.keys == nil {
		return nil, errLocked
	}
	key, ok := f.keys.UseKey(s.Now(), s.Settings().UnlockTTL())
	if !ok {
		return nil, errLocked
	}
	sig, err := suite.Sign(key, Label, Message(peer.IK, s.IdentityKey(), c.Nonce, c.ID, c.Context))
	if err != nil {
		return nil, vault.NewError("internal", "")
	}
	pub := key.Public().(ed25519.PublicKey)
	rb := strictjson.NewBuilder().String("request_id", id).String("status", StatusSigned).Base64("key", pub).
		Base64("sig", sig).String("signed_at", envelope.FormatTS(s.Now()))
	if prev := f.d.Shown[c.Conn]; len(prev) > 0 && !suite.EqualPublic(prev, pub) {
		if seg := f.segment(prev); seg != nil {
			rb.Raw("rotations", seg) // lets the requester follow rotations it missed
		}
	}
	if err := s.SendToConnection(c.Conn, "connection.authenticate.response", rb.Bytes()); err != nil {
		return nil, errConn
	}
	f.d.Shown[c.Conn] = append([]byte(nil), pub...)
	delete(f.d.In, id)
	s.Record(vault.Activity{Kind: "connection.authenticate.signed", ConnectionID: c.Conn, Ref: id, Direction: "out", Audit: true})
	s.SyncEvent("connection.authenticate.decided", strictjson.NewBuilder().String("request_id", id).Bool("approved", true).Bytes())
	return nil, nil
}

func (f *Feature) deny(s *vault.Session, body []byte) (json.RawMessage, error) {
	id, err := requestID(body)
	if err != nil {
		return nil, err
	}
	c := f.d.In[id]
	if c == nil {
		return nil, errNotFound
	}
	delete(f.d.In, id)
	_ = s.SendToConnection(c.Conn, "connection.authenticate.response",
		strictjson.NewBuilder().String("request_id", id).String("status", StatusDenied).Bytes())
	s.Record(vault.Activity{Kind: "connection.authenticate.denied", ConnectionID: c.Conn, Ref: id, Direction: "out", Audit: true})
	s.SyncEvent("connection.authenticate.decided", strictjson.NewBuilder().String("request_id", id).Bool("approved", false).Bytes())
	return nil, nil
}

// Response is a parsed connection.authenticate.response body.
type Response struct {
	RequestID string
	Status    string
	Key       []byte
	Sig       []byte
	Rotations []*credwire.KeyRotation
}

// ParseRotations parses a `rotations` array: 1–32 statements (signatures
// unchecked).
func ParseRotations(raw json.RawMessage) ([]*credwire.KeyRotation, error) {
	arr, err := strictjson.AsArray(raw)
	if err != nil || len(arr) == 0 || len(arr) > credwire.MaxKeyChain {
		return nil, errBad
	}
	out := make([]*credwire.KeyRotation, 0, len(arr))
	for _, r := range arr {
		kr, err := credwire.ParseKeyRotation(r)
		if err != nil {
			return nil, errBad
		}
		out = append(out, kr)
	}
	return out, nil
}

// ParseResponse parses a response body (from a peer vault) strictly.
func ParseResponse(body []byte) (*Response, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	r := &Response{}
	if r.RequestID, err = o.String("request_id"); err != nil || !envelope.ValidULID(r.RequestID) {
		return nil, errBad
	}
	if r.Status, err = o.String("status"); err != nil {
		return nil, errBad
	}
	switch r.Status {
	case StatusSigned:
		if r.Key, err = o.Base64("key", ed25519.PublicKeySize); err != nil {
			return nil, errBad
		}
		if r.Sig, err = o.Base64("sig", ed25519.SignatureSize); err != nil {
			return nil, errBad
		}
		sa, err := o.String("signed_at")
		if err != nil {
			return nil, errBad
		}
		if _, err := envelope.ParseTS(sa); err != nil {
			return nil, errBad
		}
		if raw, ok := o["rotations"]; ok {
			if r.Rotations, err = ParseRotations(raw); err != nil {
				return nil, err
			}
		}
	case StatusDenied:
	default:
		return nil, errBad
	}
	return r, nil
}

// response: the connection's answer to our challenge. The signature must
// verify over the challenge under the key it names; the key is pinned at
// the first success and a change is reported.
func (f *Feature) response(s *vault.Session, body []byte) error {
	r, err := ParseResponse(body)
	if err != nil {
		return err
	}
	conn := s.From().ID
	c := f.d.Out[r.RequestID]
	if c == nil || c.Conn != conn {
		return nil // §8.1: matches no pending request
	}
	delete(f.d.Out, r.RequestID)
	st := f.d.States[conn]
	if st == nil {
		st = &State{}
		f.d.States[conn] = st
	}
	now := s.Now().UTC().Truncate(time.Millisecond)
	st.LastAt = now
	reason, changed := "", false
	switch {
	case r.Status == StatusDenied:
		reason = "denied"
	default:
		peer, _ := s.Connection(conn)
		if suite.Verify(r.Key, Label, Message(s.IdentityKey(), peer.IK, c.Nonce, c.ID, c.Context), r.Sig) != nil {
			reason = "bad_signature"
			break
		}
		// A key other than the pinned one is a change unless a valid chain of
		// rotation statements leads from the pin to it (§10.4).
		if len(st.Key) > 0 && !suite.EqualPublic(st.Key, r.Key) {
			end, err := credwire.FollowChain(st.Key, r.Rotations)
			changed = err != nil || !suite.EqualPublic(end, r.Key)
		}
		st.Key, st.VerifiedAt = append([]byte(nil), r.Key...), now
	}
	st.LastResult = "authenticated"
	if reason != "" {
		st.LastResult = reason
	}
	b := strictjson.NewBuilder().String("connection_id", conn).String("request_id", c.ID).Bool("authenticated", reason == "")
	if reason != "" {
		b.String("reason", reason)
	} else {
		b.Base64("key", r.Key).Bool("key_changed", changed)
	}
	s.NotifyAllDevices("connection.authenticate.result", b.Bytes())
	kind := "connection.authenticated"
	if reason != "" {
		kind = "connection.authenticate_failed"
	}
	s.Record(vault.Activity{Kind: kind, ConnectionID: conn, Ref: c.ID, Direction: "in", Audit: true})
	return nil
}

func (f *Feature) list() json.RawMessage {
	ids := make([]string, 0, len(f.d.States))
	for id := range f.d.States {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	arr := []byte{'['}
	for i, id := range ids {
		st := f.d.States[id]
		b := strictjson.NewBuilder().String("connection_id", id)
		if len(st.Key) > 0 {
			b.Base64("key", st.Key).String("verified_at", envelope.FormatTS(st.VerifiedAt))
		}
		if st.LastResult != "" {
			b.String("last_result", st.LastResult).String("last_at", envelope.FormatTS(st.LastAt))
		}
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, b.Bytes()...)
	}
	return strictjson.NewBuilder().Raw("states", append(arr, ']')).Bytes()
}

// ConnectionRemoved implements vault.ConnectionRemovedObserver.
func (f *Feature) ConnectionRemoved(_ *vault.Session, id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.d.States, id)
	delete(f.d.Shown, id)
	for k, c := range f.d.Out {
		if c.Conn == id {
			delete(f.d.Out, k)
		}
	}
	for k, c := range f.d.In {
		if c.Conn == id {
			delete(f.d.In, k)
		}
	}
}

// chain parses the stored own statements.
func (f *Feature) chain() []*credwire.KeyRotation {
	out := make([]*credwire.KeyRotation, 0, len(f.d.Chain))
	for _, raw := range f.d.Chain {
		if r, err := credwire.ParseKeyRotation(raw); err == nil {
			out = append(out, r)
		}
	}
	return out
}

// segment returns the JSON array of own statements from the key from to
// the current key, or nil.
func (f *Feature) segment(from []byte) []byte {
	seg := credwire.ChainFrom(f.chain(), from)
	if len(seg) == 0 {
		return nil
	}
	arr := []byte{'['}
	for i, r := range seg {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, r.Marshal()...)
	}
	return append(arr, ']')
}

// CredentialKeyRotated implements credential.KeyRotationObserver: the
// statement is kept, and every active connection that pinned an earlier
// key of this member gets the chain from that key (§10.4).
func (f *Feature) CredentialKeyRotated(s *vault.Session, r *credwire.KeyRotation) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.d.Chain = append(f.d.Chain, r.Marshal())
	if n := len(f.d.Chain); n > credwire.MaxKeyChain {
		f.d.Chain = append([]json.RawMessage(nil), f.d.Chain[n-credwire.MaxKeyChain:]...)
	}
	conns := make([]string, 0, len(f.d.Shown))
	for id := range f.d.Shown {
		conns = append(conns, id)
	}
	sort.Strings(conns)
	for _, id := range conns {
		if p, ok := s.Connection(id); !ok || p.State != vault.PeerActive {
			continue
		}
		if seg := f.segment(f.d.Shown[id]); seg != nil {
			_ = s.SendToConnection(id, "connection.authenticate.rotated", strictjson.NewBuilder().Raw("rotations", seg).Bytes())
		}
	}
}

// rotated: a connection whose member's key we pinned rotated it. A chain
// that verifies from the pin moves the pin; anything else leaves the pin
// unchanged (and the next authentication under the new key reports
// key_changed).
func (f *Feature) rotated(s *vault.Session, body []byte) error {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return errBad
	}
	raw, ok := o["rotations"]
	if !ok {
		return errBad
	}
	chain, err := ParseRotations(raw)
	if err != nil {
		return err
	}
	conn := s.From().ID
	st := f.d.States[conn]
	if st == nil || len(st.Key) == 0 {
		return nil // nothing pinned
	}
	end, err := credwire.FollowChain(st.Key, chain)
	if err != nil {
		s.Record(vault.Activity{Kind: "connection.authenticate.rotation_rejected", ConnectionID: conn, Direction: "in", Audit: true})
		return nil
	}
	st.Key = end
	s.NotifyAllDevices("connection.authenticate.key", strictjson.NewBuilder().String("connection_id", conn).Base64("key", end).Bytes())
	s.Record(vault.Activity{Kind: "connection.authenticate.key_rotated", ConnectionID: conn, Direction: "in", Audit: true})
	return nil
}
