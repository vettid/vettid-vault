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
	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Limits. The wire (the signed message, the bodies, the nonce and
// context sizes, the challenge's lifetime) is vms/peerwire's.
const (
	MaxPendingOut = 8 // per connection
	MaxPendingIn  = 4 // per connection
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
	// Purpose is peerwire.PurposeSignIn, peerwire.PurposeApproval or ""
	// (0.65.0).
	Purpose string `json:"purpose,omitempty"`
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
		{Type: peerwire.TypeConnAuthChallenge, From: conns},
		{Type: peerwire.TypeConnAuthResponse, From: conns},
		{Type: peerwire.TypeConnAuthRotated, From: conns},
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
	errLocked   = vault.NewError("credential_locked", "")
	errConn     = vault.NewError("connection_unavailable", "")
)

// wire is the challenge's body.
func (c *Challenge) wire() *peerwire.ConnAuthChallenge {
	return &peerwire.ConnAuthChallenge{RequestID: c.ID, Nonce: c.Nonce, Context: c.Context, Purpose: c.Purpose}
}

// Handle implements vault.Handler.
func (f *Feature) Handle(_ context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.expire(s.Now())
	switch in.Type {
	case "connection.authenticate.request":
		return f.request(s, in.Body)
	case peerwire.TypeConnAuthChallenge:
		return nil, f.challenge(s, in)
	case "connection.authenticate.approve":
		return f.approve(s, in.Body)
	case "connection.authenticate.deny":
		return f.deny(s, in.Body)
	case peerwire.TypeConnAuthResponse:
		return nil, f.response(s, in.Body)
	case "connection.authenticate.list":
		return f.list(), nil
	case peerwire.TypeConnAuthRotated:
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
	if err != nil || len(v) > peerwire.ConnAuthMaxContext {
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
	// An owner device names only a purpose this version knows (chosen:
	// §10.4 says a receiver treats an unknown one as absent, and is
	// silent on a request's).
	purpose, ok, err := o.OptString("purpose")
	if err != nil || ok && !peerwire.KnownPurpose(purpose) {
		return nil, errBad
	}
	if p, ok := s.Connection(conn); !ok || p.State != vault.PeerActive {
		return nil, errNotFound
	}
	if count(f.d.Out, conn) >= MaxPendingOut {
		return nil, vault.LimitError("auth_challenges", MaxPendingOut)
	}
	wc, err := peerwire.NewConnAuthChallenge(s.NewID(), ctxt)
	if err != nil {
		return nil, vault.NewError("internal", "")
	}
	wc.Purpose = purpose
	c := &Challenge{ID: wc.RequestID, Conn: conn, Nonce: wc.Nonce, Context: ctxt, Purpose: purpose,
		Exp: s.Now().Add(peerwire.ConnAuthChallengeTTL).UTC().Truncate(time.Millisecond)}
	if err := s.Send(conn, peerwire.TypeConnAuthChallenge, wc.Marshal(), vault.SendOptions{Exp: c.Exp}); err != nil {
		return nil, errConn
	}
	f.d.Out[c.ID] = c
	s.Record(vault.Activity{Kind: "connection.authenticate.requested", ConnectionID: conn, Ref: c.ID, Direction: "out", Audit: true})
	return strictjson.NewBuilder().String("request_id", c.ID).String("exp", envelope.FormatTS(c.Exp)).Bytes(), nil
}

// challenge: a connection asks our member to authenticate; the owner's
// apps and desktops are told (only an app can approve).
func (f *Feature) challenge(s *vault.Session, in *envelope.Inner) error {
	wc, err := peerwire.ParseConnAuthChallenge(in.Body)
	if err != nil {
		return errBad
	}
	c := &Challenge{ID: wc.RequestID, Nonce: wc.Nonce, Context: wc.Context, Purpose: wc.Purpose}
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
	c.Exp = now.Add(peerwire.ConnAuthChallengeTTL).UTC().Truncate(time.Millisecond)
	if !in.Exp.IsZero() && in.Exp.Before(c.Exp) {
		c.Exp = in.Exp
	}
	// A received challenge is an ask (§10.4.1, 0.23.0): mute, pause, the
	// cooldown (any challenge with the same purpose, 0.65.0), the pending
	// caps and the purpose's rate bucket. A suppressed one is answered
	// `denied`, later, by the vault.
	v := s.Ask(conn, vault.Ask{Source: f.Name(), Ref: c.ID, Idents: []string{askIdent(c.Purpose)}, Pending: count(f.d.In, conn),
		Bucket: c.Purpose, BucketPending: f.countPurpose(conn, c.Purpose), Exp: c.Exp,
		AnswerType: peerwire.TypeConnAuthResponse, Answer: peerwire.DeniedConnAuth(c.ID).Marshal()})
	if !v.Passed() {
		return nil
	}
	f.d.In[c.ID] = c
	s.NotifyDevicesWith("connection.authenticate.pending", c.pendingBody(), "", vault.SendOptions{Exp: c.Exp})
	s.Record(vault.Activity{Kind: "connection.authenticate.requested", ConnectionID: conn, Ref: c.ID, Direction: "in", Audit: true,
		Feed: true, Priority: "high", AskBatch: true})
	return nil
}

// pendingBody is the body of the connection.authenticate.pending event
// (§10.4), and of the `authenticate` entry of pending.list (§10.4.2),
// which repeats it exactly.
func (c *Challenge) pendingBody() []byte {
	b := strictjson.NewBuilder().String("connection_id", c.Conn).String("request_id", c.ID).String("exp", envelope.FormatTS(c.Exp))
	if c.Context != "" {
		b.String("context", c.Context)
	}
	if c.Purpose != "" {
		b.String("purpose", c.Purpose)
	}
	return b.Bytes()
}

// OpenAsks implements vault.PendingAskSource (§10.4.2): the received
// challenges still open. It changes nothing.
func (f *Feature) OpenAsks(now time.Time) []vault.PendingAsk {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []vault.PendingAsk
	for _, c := range f.d.In {
		if now.Before(c.Exp) {
			out = append(out, vault.PendingAsk{Kind: vault.PendingAuthenticate, ID: c.ID, Exp: c.Exp, Body: c.pendingBody()})
		}
	}
	return out
}

// AskIdent is the identity for the §10.4.1 cooldown of a challenge
// without a purpose: any such challenge from the connection.
const AskIdent = "auth"

// askIdent is a challenge's cooldown identity (0.65.0): any challenge
// with the same purpose. The buckets' names are the purposes
// (vault.AskBucketSignIn, vault.AskBucketApproval, "" for none).
func askIdent(purpose string) string {
	if purpose == "" {
		return AskIdent
	}
	return AskIdent + ":" + purpose
}

// countPurpose counts the connection's received challenges with purpose
// that wait for the member.
func (f *Feature) countPurpose(conn, purpose string) int {
	n := 0
	for _, c := range f.d.In {
		if c.Conn == conn && c.Purpose == purpose {
			n++
		}
	}
	return n
}

// PendingAsks implements vault.AskSource: the connection's challenges
// waiting for the member.
func (f *Feature) PendingAsks(conn string, now time.Time) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.d.In {
		if c.Conn == conn && now.Before(c.Exp) {
			n++
		}
	}
	return n
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
	pub := key.Public().(ed25519.PublicKey)
	var seg []*credwire.KeyRotation
	if prev := f.d.Shown[c.Conn]; len(prev) > 0 && !suite.EqualPublic(prev, pub) {
		seg = f.segment(prev) // lets the requester follow rotations it missed
	}
	r, err := peerwire.SignConnAuth(key, peer.IK, s.IdentityKey(), c.wire(), s.Now(), seg)
	if err != nil {
		return nil, vault.NewError("internal", "")
	}
	if err := s.SendToConnection(c.Conn, peerwire.TypeConnAuthResponse, r.Marshal()); err != nil {
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
	_ = s.SendToConnection(c.Conn, peerwire.TypeConnAuthResponse, peerwire.DeniedConnAuth(id).Marshal())
	s.Record(vault.Activity{Kind: "connection.authenticate.denied", ConnectionID: c.Conn, Ref: id, Direction: "out", Audit: true})
	s.AskDeclinedIn(c.Conn, c.Purpose, []string{askIdent(c.Purpose)}) // §10.4.1; a sign-in's: 1 hour, no pause (0.65.0)
	s.SyncEvent("connection.authenticate.decided", strictjson.NewBuilder().String("request_id", id).Bool("approved", false).Bytes())
	return nil, nil
}

// response: the connection's answer to our challenge. The signature must
// verify over the challenge under the key it names; the key is pinned at
// the first success and a change is reported.
func (f *Feature) response(s *vault.Session, body []byte) error {
	r, err := peerwire.ParseConnAuthResponse(body)
	if err != nil {
		return errBad
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
	case r.Status == peerwire.ConnAuthDenied:
		reason = "denied"
	default:
		peer, _ := s.Connection(conn)
		if peerwire.VerifyConnAuthResponse(r, s.IdentityKey(), peer.IK, c.wire()) != nil {
			reason = "bad_signature"
			break
		}
		// A key other than the pinned one is a change unless a valid chain of
		// rotation statements leads from the pin to it (§10.4).
		changed = peerwire.PinnedKeyChanged(st.Key, r.Key, r.Rotations)
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
		// Exactly when the verified signature commits to it (0.65.0).
		if r.Purpose != "" {
			b.String("purpose", r.Purpose)
		}
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

// segment returns the own statements from the key from to the current
// key (none if empty).
func (f *Feature) segment(from []byte) []*credwire.KeyRotation {
	return credwire.ChainFrom(f.chain(), from)
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
		if seg := f.segment(f.d.Shown[id]); len(seg) > 0 {
			_ = s.SendToConnection(id, peerwire.TypeConnAuthRotated, peerwire.ConnAuthRotatedBody(seg))
		}
	}
}

// rotated: a connection whose member's key we pinned rotated it. A chain
// that verifies from the pin moves the pin; anything else leaves the pin
// unchanged (and the next authentication under the new key reports
// key_changed).
func (f *Feature) rotated(s *vault.Session, body []byte) error {
	chain, err := peerwire.ParseConnAuthRotated(body)
	if err != nil {
		return errBad
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
