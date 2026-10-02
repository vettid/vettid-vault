package vault

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// Feature is a feature area (§10): it declares its types and handles them.
// Load and Save carry its data inside DEK-encrypted state.
type Feature interface {
	Name() string
	Types() []TypeSpec
	Handler
	Load(data json.RawMessage) error
	Save() (json.RawMessage, error)
}

// Handler handles one decrypted, authorized, deduplicated inner plaintext
// (VAULT-PLAN §2: Handler(ctx, Session, Inner)). For a request type it
// returns the response body, or a *HandlerError for an error response.
type Handler interface {
	Handle(ctx context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error)
}

// TypeSpec registers one inner `type`.
type TypeSpec struct {
	Type string
	// Request types get a response with the same type (§8.1).
	Request bool
	// Ephemeral types are acked after handling, deduped in memory for
	// 10 minutes and require `exp` (§8.5). Everything else is durable.
	Ephemeral bool
	// From lists the principal kinds allowed to send this type: "app",
	// "desktop", "agent", "connection".
	From []string
}

// HandlerError is an error response (§5.3 `error`).
type HandlerError struct {
	Code    string
	Message string
}

func (e *HandlerError) Error() string { return "vault: " + e.Code }

// Errorf-free constructors for common error responses.
var (
	errNotFound   = &HandlerError{Code: "not_found"}
	errBadRequest = &HandlerError{Code: "bad_request"}
	errClaim      = &HandlerError{Code: "claim_unavailable"}
)

// NewError returns an error response with a code and a non-secret message.
func NewError(code, msg string) error { return &HandlerError{Code: code, Message: msg} }

type typeEntry struct {
	spec    TypeSpec
	handler Handler
}

func (t *typeEntry) allows(kind string) bool {
	for _, k := range t.spec.From {
		if k == kind {
			return true
		}
	}
	return false
}

func (m *Manager) addFeature(f Feature) {
	m.features = append(m.features, f)
	for _, ts := range f.Types() {
		m.register(ts, f)
	}
}

func (m *Manager) register(ts TypeSpec, h Handler) {
	if m.registry == nil {
		m.registry = map[string]*typeEntry{}
	}
	if !envelope.ValidType(ts.Type) {
		panic("vault: invalid type " + ts.Type)
	}
	if _, dup := m.registry[ts.Type]; dup {
		panic("vault: type registered twice: " + ts.Type)
	}
	m.registry[ts.Type] = &typeEntry{spec: ts, handler: h}
}

// Session is what a handler sees: the principal that sent the message and
// the effects it may cause. It is valid only during Handle.
type Session struct {
	m     *Manager
	peer  *Peer
	ctx   context.Context
	now   time.Time
	inner *envelope.Inner
}

// PeerInfo is a read-only view of a principal.
type PeerInfo struct {
	ID      string
	Kind    string
	Name    string
	State   string
	Profile json.RawMessage
}

func info(p *Peer) PeerInfo {
	return PeerInfo{ID: p.ID, Kind: p.Kind, Name: p.Name, State: p.State, Profile: p.Profile}
}

// From returns the sending principal.
func (s *Session) From() PeerInfo { return info(s.peer) }

// Now returns the processing time.
func (s *Session) Now() time.Time { return s.now }

// Connection returns a connection by id.
func (s *Session) Connection(id string) (PeerInfo, bool) {
	p, ok := s.m.st.Connections[id]
	if !ok {
		return PeerInfo{}, false
	}
	return info(p), true
}

// Connections lists the connections.
func (s *Session) Connections() []PeerInfo {
	var out []PeerInfo
	for _, p := range s.m.st.Connections {
		out = append(out, info(p))
	}
	return out
}

// ErrNoSession is returned when a principal has no usable session.
var ErrNoSession = errors.New("vault: no session with that principal")

// SendToConnection queues a durable message to an active connection, in one
// deposit under that connection's session (§9.3).
func (s *Session) SendToConnection(id, typ string, body json.RawMessage) error {
	p, ok := s.m.st.Connections[id]
	if !ok || p.State != PeerActive {
		return ErrNoSession
	}
	if s.m.sendTo(p, typ, body, s.now) == "" {
		return ErrNoSession
	}
	return nil
}

// NotifyDevices sends a durable event to every owner device except the
// sender of the current message (§9.1: side effects reach the owner's other
// devices as events).
func (s *Session) NotifyDevices(typ string, body json.RawMessage) {
	s.m.notifyDevices(typ, body, s.peer.ID, s.now)
}

// NotifyAllDevices sends a durable event to every owner device.
func (s *Session) NotifyAllDevices(typ string, body json.RawMessage) {
	s.m.notifyDevices(typ, body, "", s.now)
}

// NewID returns a fresh ULID.
func (s *Session) NewID() string { return s.m.newID(s.now) }
