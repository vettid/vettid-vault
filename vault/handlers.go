package vault

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
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
	// Volatile requests have responses that carry secret values in the
	// clear (§8.2; no type needs it today: critical values are sealed to a
	// reply key, §3.5.4): the response is never cached
	// or written to vault state, it is deposited from memory only (lost on
	// a crash), and a retransmission is executed again. Only for types
	// whose sole side effects are audit and feed entries.
	Volatile bool
	// DesktopApproval requests from a desktop are held until an owner app
	// approves them (§6.8 step-up). Apps are never held.
	DesktopApproval bool
	// AgentPolicy types are decided by the AgentPolicy feature for every
	// agent request, even though agents are listed in From (agent.request,
	// §10.11): it allows, refers to an app or refuses each one.
	AgentPolicy bool
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

func (t *typeEntry) allows(kind string) bool { return t.spec.Allows(kind) }

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
// the effects it may cause. It is valid only during Handle (or during an
// ActivitySink or ConnectionObserver callback).
type Session struct {
	m     *Manager // nil for sessions built with NewSession
	peer  *Peer    // the sender's record (core handlers); nil otherwise
	host  Host
	from  PeerInfo
	ctx   context.Context
	now   time.Time
	inner *envelope.Inner
}

// Host is what a Session acts on. The Manager implements it for the
// messages it dispatches; tests of feature packages supply their own.
// Every method is called with the vault's lock held.
type Host interface {
	VaultID() string
	Connection(id string) (PeerInfo, bool)
	Connections() []PeerInfo
	// SendToConnection queues a durable message to an active connection.
	SendToConnection(id, typ string, body json.RawMessage, now time.Time) error
	// NotifyDevices sends a durable event to every owner app and desktop
	// except the device `except` ("" for none).
	NotifyDevices(typ string, body json.RawMessage, except string, now time.Time)
	NewID(now time.Time) string
	// Record passes an activity to the audit log and the feed.
	Record(a Activity, now time.Time)
	// SetConnectionProfile replaces a connection's shared profile (§10.8).
	SetConnectionProfile(id string, profile json.RawMessage, now time.Time) error
	// RotateIdentity rotates the vault's ik and kem (§3.4) within the
	// current batch.
	RotateIdentity(now time.Time) error
	Settings() Settings
	SetSettings(Settings)
	// CompleteRecovery makes a recovering device an ordinary app and ends
	// the recovery (§11.11.5).
	CompleteRecovery(deviceID string, now time.Time) error
	// IdentityKey is the vault's current identity public key (§3.2).
	IdentityKey() ed25519.PublicKey
	// Device returns an active owner device by id that may receive
	// messages now (a desktop or agent only within its access session).
	Device(id string) (PeerInfo, bool)
	// PairedDevice returns an active owner device by id, with or without
	// an access session.
	PairedDevice(id string) (PeerInfo, bool)
	// Send sends a message to one principal (an active connection or owner
	// device) with options (an `exp`, or memory-only delivery).
	Send(to, typ string, body json.RawMessage, o SendOptions, now time.Time) error
	// NotifyDevicesWith is NotifyDevices with options.
	NotifyDevicesWith(typ string, body json.RawMessage, except string, o SendOptions, now time.Time)
	// SignICEConfig signs a call's ICE configuration with the vault's
	// identity key (§10.10); it signs nothing that does not parse as one.
	SignICEConfig(config []byte) ([]byte, error)
	// VouchCallShare signs a device's call key-exchange share with the
	// vault's identity key (callwire.VouchMessage, §10.10); it signs
	// nothing that is not a share message.
	VouchCallShare(deviceIK ed25519.PublicKey, m []byte) ([]byte, error)
	// CreateIntroInvite makes a remote connection invitation for an
	// introduction (§10.15): accepted only from expectIK, its pending
	// request marked introduced_by.
	CreateIntroInvite(ctx context.Context, expectIK []byte, introBy string, now time.Time) (inviteID, link string, err error)
	// AcceptInviteLink accepts a connection invitation link as
	// connection.invite.accept does and returns the new connection's id.
	AcceptInviteLink(ctx context.Context, link string, now time.Time) (string, error)
	// CancelInvite revokes an outstanding invitation (§6.4).
	CancelInvite(id string, now time.Time)
	// SignLeashStatus signs a LEASH status statement with the vault's
	// current identity key (§10.11); it signs nothing that does not parse
	// as one.
	SignLeashStatus(statement []byte) ([]byte, error)
	// RotationsFrom returns the vault's identity.rotate statements from
	// ik to its current identity key (none if ik is current); ok is false
	// if ik is not on its chain.
	RotationsFrom(ik []byte) (chain []json.RawMessage, ok bool)
	// OwnerLastActive is the latest LastActiveAt of the vault's active app
	// and desktop devices (not agents); zero if none (§9.2).
	OwnerLastActive() time.Time
}

// SendOptions qualify one outbound message.
type SendOptions struct {
	// Exp is the message's `exp` (§5.3); required for ephemeral types
	// (§8.5). Zero for none.
	Exp time.Time
	// MemoryOnly deposits the message from memory after the batch's flush,
	// behind queued deposits to the same mailbox, once and best effort: it
	// never reaches vault state (ephemeral types such as call.ice, §8.5).
	MemoryOnly bool
}

// NewSession returns a session for a message from `from`, acting on h. It
// is how feature tests drive handlers; the Manager builds its own.
func NewSession(ctx context.Context, h Host, from PeerInfo, now time.Time, in *envelope.Inner) *Session {
	return &Session{host: h, from: from, ctx: ctx, now: now, inner: in}
}

// PeerInfo is a read-only view of a principal.
type PeerInfo struct {
	ID      string
	Kind    string
	Name    string
	State   string
	IK      []byte // its current identity key
	Profile json.RawMessage
	// Recovering: an app registered by recovery that has not yet
	// authenticated with the credential password (§11.11.5).
	Recovering bool
}

func info(p *Peer) PeerInfo {
	if p == nil {
		return PeerInfo{}
	}
	return PeerInfo{ID: p.ID, Kind: p.Kind, Name: p.Name, State: p.State, IK: append([]byte(nil), p.IK...), Profile: p.Profile, Recovering: p.Recovering}
}

// From returns the sending principal (zero for vault-internal activity).
func (s *Session) From() PeerInfo { return s.from }

// Now returns the processing time.
func (s *Session) Now() time.Time { return s.now }

// Context returns the request context.
func (s *Session) Context() context.Context {
	if s.ctx == nil {
		return context.Background()
	}
	return s.ctx
}

// VaultID returns the vault id.
func (s *Session) VaultID() string { return s.host.VaultID() }

// Connection returns a connection by id.
func (s *Session) Connection(id string) (PeerInfo, bool) { return s.host.Connection(id) }

// Connections lists the connections, sorted by id.
func (s *Session) Connections() []PeerInfo { return s.host.Connections() }

// ErrNoSession is returned when a principal has no usable session.
var ErrNoSession = errors.New("vault: no session with that principal")

// SendToConnection queues a durable message to an active connection, in one
// deposit under that connection's session (§9.3).
func (s *Session) SendToConnection(id, typ string, body json.RawMessage) error {
	return s.host.SendToConnection(id, typ, body, s.now)
}

// NotifyDevices sends a durable event to every owner device except the
// sender of the current message (§9.1: side effects reach the owner's other
// devices as events).
func (s *Session) NotifyDevices(typ string, body json.RawMessage) {
	s.host.NotifyDevices(typ, body, s.from.ID, s.now)
}

// NotifyAllDevices sends a durable event to every owner device.
func (s *Session) NotifyAllDevices(typ string, body json.RawMessage) {
	s.host.NotifyDevices(typ, body, "", s.now)
}

// NotifyDevicesWith sends an event to every owner app and desktop except
// `except` ("" for none), with options.
func (s *Session) NotifyDevicesWith(typ string, body json.RawMessage, except string, o SendOptions) {
	s.host.NotifyDevicesWith(typ, body, except, o, s.now)
}

// Send sends a message to one principal: an active connection or an
// active owner device.
func (s *Session) Send(to, typ string, body json.RawMessage, o SendOptions) error {
	return s.host.Send(to, typ, body, o, s.now)
}

// Device returns an active owner device that may receive messages now.
func (s *Session) Device(id string) (PeerInfo, bool) { return s.host.Device(id) }

// PairedDevice returns an active owner device, with or without an access
// session (§6.8).
func (s *Session) PairedDevice(id string) (PeerInfo, bool) { return s.host.PairedDevice(id) }

// IdentityKey returns the vault's current identity public key.
func (s *Session) IdentityKey() ed25519.PublicKey { return s.host.IdentityKey() }

// SignICEConfig signs an ICE configuration (callwire format) with the
// vault's identity key.
func (s *Session) SignICEConfig(config []byte) ([]byte, error) { return s.host.SignICEConfig(config) }

// CreateIntroInvite makes an introduction's invitation (§10.15).
func (s *Session) CreateIntroInvite(expectIK []byte, introBy string) (string, string, error) {
	return s.host.CreateIntroInvite(s.Context(), expectIK, introBy, s.now)
}

// AcceptInviteLink accepts a connection invitation link (§6.4).
func (s *Session) AcceptInviteLink(link string) (string, error) {
	return s.host.AcceptInviteLink(s.Context(), link, s.now)
}

// CancelInvite revokes an outstanding invitation.
func (s *Session) CancelInvite(id string) { s.host.CancelInvite(id, s.now) }

// SignLeashStatus signs a LEASH status statement with the vault's ik.
func (s *Session) SignLeashStatus(statement []byte) ([]byte, error) {
	return s.host.SignLeashStatus(statement)
}

// RotationsFrom returns the vault's rotation chain from ik.
func (s *Session) RotationsFrom(ik []byte) ([]json.RawMessage, bool) { return s.host.RotationsFrom(ik) }

// OwnerLastActive returns when an owner app or desktop was last active
// (§9.2 presence).
func (s *Session) OwnerLastActive() time.Time { return s.host.OwnerLastActive() }

// VouchCallShare signs a device's call key-exchange share (§10.10).
func (s *Session) VouchCallShare(deviceIK ed25519.PublicKey, m []byte) ([]byte, error) {
	return s.host.VouchCallShare(deviceIK, m)
}

// InnerID returns the id of the message being handled ("" outside Handle).
func (s *Session) InnerID() string {
	if s.inner == nil {
		return ""
	}
	return s.inner.ID
}

// SyncEvent sends sync.event{kind, members...} to the owner's other
// devices (§10.1). members is a JSON object or nil.
func (s *Session) SyncEvent(kind string, members []byte) {
	b := []byte(`{"kind":`)
	b = append(b, strictjson.MarshalString(kind)...)
	if len(members) > 2 {
		b = append(append(b, ','), members[1:]...)
	} else {
		b = append(b, '}')
	}
	s.NotifyDevices("sync.event", b)
}

// NewID returns a fresh ULID.
func (s *Session) NewID() string { return s.host.NewID(s.now) }

// Record records an activity in the audit log and/or the feed (§10.9).
func (s *Session) Record(a Activity) { s.host.Record(a, s.now) }

// SetConnectionProfile replaces a connection's shared profile (§10.8).
func (s *Session) SetConnectionProfile(id string, profile json.RawMessage) error {
	return s.host.SetConnectionProfile(id, profile, s.now)
}

// RotateIdentity rotates the vault's ik and kem (§3.4); the batch's flush
// persists it.
func (s *Session) RotateIdentity() error { return s.host.RotateIdentity(s.now) }

// CompleteRecovery ends the recovery of the sending device (§11.11.5).
func (s *Session) CompleteRecovery() error { return s.host.CompleteRecovery(s.from.ID, s.now) }

// Settings returns the owner's settings (§10.8).
func (s *Session) Settings() Settings { return s.host.Settings() }

// Activity is something that happened in the vault, for the audit log and
// the feed (§10.9). It never carries content, secret values or keys.
type Activity struct {
	Kind         string
	ConnectionID string
	DeviceID     string
	Ref          string
	Direction    string // "in", "out" or ""
	Audit        bool   // record in the audit log
	Feed         bool   // create a feed item
	Priority     string // feed priority ("" = normal)
}

// ActivitySink is implemented by features that keep activity (the audit
// log and the feed).
type ActivitySink interface {
	RecordActivity(s *Session, a Activity)
}

// ConnectionObserver is implemented by features that act when a
// connection becomes active (profile.update on activation, §9.3).
type ConnectionObserver interface {
	ConnectionAdded(s *Session, connectionID string)
}

// CredentialGate is implemented by the credential feature: a vault without
// a credential is restricted (§3.5.7).
type CredentialGate interface {
	// CredentialReady: the vault has a credential and its holder (§3.5.9).
	CredentialReady() bool
	// CredentialExists: the vault has a credential, held or not (a vault
	// with a credential can be recovered, §11.11.1).
	CredentialExists() bool
}

// allowedWithoutCredential are the types a restricted vault still accepts
// (§3.5.7).
var allowedWithoutCredential = map[string]bool{"vault.status": true, "vault.lock": true, "vault.delete": true, "credential.utk.get": true,
	"credential.create": true, "credential.version": true, "relay.token.issued": true, "relay.token.refresh": true,
	"relay.address.update": true}

// hasGate reports whether a credential feature is present.
func (m *Manager) hasGate() bool {
	for _, f := range m.features {
		if _, ok := f.(CredentialGate); ok {
			return true
		}
	}
	return false
}

// credentialReady reports whether no gate restricts the vault.
func (m *Manager) credentialReady() bool {
	for _, f := range m.features {
		if g, ok := f.(CredentialGate); ok && !g.CredentialReady() {
			return false
		}
	}
	return true
}

// credentialExists reports whether the vault has a credential (or no gate).
func (m *Manager) credentialExists() bool {
	for _, f := range m.features {
		if g, ok := f.(CredentialGate); ok && !g.CredentialExists() {
			return false
		}
	}
	return true
}

// SettingsObserver is implemented by features that act on a settings
// change (the credential drops its kept copy when backup is turned off).
type SettingsObserver interface {
	SettingsChanged(s *Session, next Settings)
}

// ConnectionRemovedObserver is implemented by features that keep data per
// connection and act when a connection is removed or blocked (§7.4).
type ConnectionRemovedObserver interface {
	ConnectionRemoved(s *Session, connectionID string)
}

// AgentDecision is an AgentPolicy's answer for one request.
type AgentDecision int

// Agent decisions.
const (
	AgentDeny  AgentDecision = iota // forbidden
	AgentAllow                      // within the agent's grants
	AgentAsk                        // held for an owner app's approval (§6.8)
)

// AgentPolicy is the LEASH hook (§6.8, §10.11): it decides an agent's
// request of an owner type (one that desktops may send) that the type's
// own roles do not give agents, and every agent request of a type marked
// TypeSpec.AgentPolicy. Without an AgentPolicy feature, agents get nothing
// beyond their listed types. App-only types are never offered to it.
// AgentDecision may record what it allowed (rate counting, audit); it is
// also asked again, when an app approves a referred request, whether a
// grant still covers it.
type AgentPolicy interface {
	AgentDecision(s *Session, typ string, body json.RawMessage) AgentDecision
}

// AgentGrantor is implemented by the LEASH feature: an agent's initial
// grants come with its pairing approval (device.pair.approve{grants},
// §6.7, §10.3). PrepareAgentGrants checks and signs them at the approval
// (for the agent's identity key; a *HandlerError such as
// credential_locked is answered as is) and returns what AgentPaired
// installs in the flush that completes the pairing.
type AgentGrantor interface {
	PrepareAgentGrants(s *Session, agentIK []byte, grants json.RawMessage) (json.RawMessage, error)
	AgentPaired(s *Session, agentID string, prepared json.RawMessage)
}

// AgentCoverage is optionally implemented by the AgentPolicy feature: when
// an app approves a referred agent request, it says whether a grant still
// covers it, without counting it as a new request (§6.8).
type AgentCoverage interface {
	AgentCovered(s *Session, typ string, body json.RawMessage) bool
}

// AppOnlyForms is optionally implemented by a feature whose step-up types
// have forms only an app may send (a critical item's credential operation
// or an agent's share rule, §10.7, §10.12): the runtime refuses such a
// request from a desktop with forbidden instead of holding it (§6.8).
type AppOnlyForms interface {
	AppOnly(typ string, body json.RawMessage) bool
}

// DeviceRemovedObserver is implemented by features that keep data per
// owner device and act when a device is unlinked (§7.4: an agent's LEASH
// grants are revoked).
type DeviceRemovedObserver interface {
	DeviceRemoved(s *Session, deviceID string)
}

// HandshakeProfiler supplies the vault's self-asserted hs.init profile and
// invite hint name (§6.2, §6.4): its display name only.
type HandshakeProfiler interface {
	DisplayName() string
}

// Zeroizer is implemented by features that hold secrets in memory outside
// their saved state (the credential unlock window, §3.5.3); the vault calls
// it when it locks or zeroizes.
type Zeroizer interface {
	Zeroize()
}

// Allows reports whether a principal kind may send a type (§10.1).
func (t TypeSpec) Allows(kind string) bool {
	for _, k := range t.From {
		if k == kind {
			return true
		}
	}
	return false
}
