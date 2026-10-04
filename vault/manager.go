// Package vault is the vault runtime (VAULT-PLAN phase V2): one Manager
// per unlocked vault (decision D4) that holds the DEK-encrypted state,
// collects from the vault's mailbox, routes every message by sender,
// recipient kid and the session that decrypts it (§13.6), runs the
// handshakes (§6), the delivery rules (§8) and the token registry (§7),
// and dispatches to feature handlers by inner `type` (§10).
//
// Nothing in this package logs. Errors are sentinels or carry only
// non-secret context.
package vault

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Errors.
var (
	ErrLocked     = errors.New("vault: locked")
	ErrSplitBrain = errors.New("vault: newer state written by another instance; locked")
	ErrBadPIN     = errors.New("vault: bad PIN")
	ErrBackoff    = errors.New("vault: unlock backoff in effect")
	ErrRollback   = errors.New("vault: state rollback detected")
	ErrHeader     = errors.New("vault: sealed header invalid")
	ErrState      = errors.New("vault: state invalid")
	ErrExists     = errors.New("vault: vault exists")
	ErrMissing    = errors.New("vault: vault missing")
	ErrCrash      = errors.New("vault: simulated crash")
	ErrRelease    = errors.New("vault: sealed to another release")
)

// Options configure a Manager.
type Options struct {
	Store  store.Store
	Sealer Sealer
	// Relay, if nil, is a ClientRelay built from the state's relay URL and
	// key with HTTP as transport.
	Relay func(baseURL string, key ed25519.PrivateKey) Relay
	HTTP  *http.Client
	Now   func() time.Time
	// WebSocket selects WebSocket collect instead of long-poll (§12.2).
	WebSocket bool
	// PollWait overrides the long-poll wait (tests).
	PollWait time.Duration
	// Features are the feature handlers (§10). Core types are built in.
	Features []Feature
	// ConnectionStandingTTL caps the lifetime of standing tokens issued to
	// connections below the 30-day default (tests use it to exercise
	// expiry and reconnects).
	ConnectionStandingTTL time.Duration
	Hooks                 Hooks
	// Release is the running release (§11.10); the header this manager
	// reads and writes is the one sealed to it, through Sealer.
	Release Release
	// DeviceAttest verifies an app's device_attest at pairing (§6.7,
	// §11.7) against the challenge and returns the binding. If nil, apps
	// pair without a binding and cannot unlock over the alternate channel
	// (development).
	DeviceAttest func(d *altchan.DeviceAttest, challenge [32]byte, now time.Time) (json.RawMessage, error)
	// Lifecycle receives lifecycle events for the parent (§11.5).
	Lifecycle func(LifecycleEvent)
}

// LifecycleEvent is reported to the parent, which writes it to the vault
// table (§11.5). It is advisory and holds no secrets.
type LifecycleEvent struct {
	Event        string // enrolled, unlocked, locked, moved
	VaultID      string
	Release      string // moved: the target release; otherwise the running one
	VaultVersion string // the release that reports
	StateVersion int
}

// Hooks let tests and supervisors observe or interrupt processing.
type Hooks struct {
	// AfterFlush runs after a batch's state flush and before its acks. An
	// error stops processing there, like a crash: nothing is acked and the
	// in-memory state is discarded.
	AfterFlush func() error
	// DropDeposit, if it returns true for an outbox deposit, drops it as if
	// it were lost (fault injection for best-effort notices).
	DropDeposit func(e *OutboxEntry) bool
}

// Manager is one unlocked vault.
type Manager struct {
	mu   sync.Mutex
	opt  Options
	now  func() time.Time
	keys *keyset

	st        *State
	hdr       *Header
	dek       []byte
	stateVer  store.Version
	headerVer store.Version
	relay     Relay
	limits    Limits
	collector Collector

	sessions map[string]*handshake.Keyring
	inbound  map[string]*handshake.PendingInit
	awaiting map[string]*handshake.Responder
	outgoing map[string]*handshake.Initiator

	registry map[string]*typeEntry
	features []Feature

	ephemeralSeen map[string]time.Time
	rates         map[string]*rateWindow
	requests      map[string]string // our outstanding request inner id -> peer id
	requestTypes  map[string]string // ... -> type
	// volatile holds deposits that must never reach vault state (responses
	// carrying secret values, TypeSpec.Volatile); drained after the
	// durable outbox, dropped on failure or lock.
	volatile []*OutboxEntry
	dirty    bool

	// pairAccess carries device.pair.approve's session_seconds into
	// approveInbound (§6.8).
	pairAccess *pendingAccess
	// replaceAfter is the recovered app whose recovery completed in the
	// current handler: the other apps are removed after it returns
	// (§11.11.5). alarms are host alarms reported after the flush (§11.5).
	replaceAfter string
	alarms       []string
	// deletePending: a deletion was marked in this batch; it is finished
	// after the flush (§12.5).
	deletePending bool
	deleteRequest string

	locked      bool
	lockPending bool
	lockReason  string
	started     bool
	hadFailures bool // the header recorded failures before this unlock
	holdsDEK    bool // counted in unlocked
}

type pendingAccess struct {
	inbound string
	seconds uint64
	by      string
	session bool            // grant an access session of seconds
	grants  json.RawMessage // an agent's initial LEASH grants (§10.11)
}

// unlocked counts the managers in this process that hold a DEK.
var unlocked atomic.Int64

// Unlocked returns how many managers in this process hold a DEK. The
// enclave's supervisor must always report 0: vaults run in their own
// processes (VAULT-MESSAGING §12.4).
func Unlocked() int64 { return unlocked.Load() }

// keyset holds the vault's private keys in usable form.
type keyset struct {
	relay   ed25519.PrivateKey
	ik      ed25519.PrivateKey
	kem     *suite.PrivateKey
	retired []*suite.PrivateKey
}

func (k *keyset) destroy() {
	if k == nil {
		return
	}
	suite.Wipe(k.relay)
	suite.Wipe(k.ik)
	if k.kem != nil {
		k.kem.Destroy()
	}
	for _, r := range k.retired {
		r.Destroy()
	}
}

func (o *Options) defaults() {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Relay == nil {
		h, now := o.HTTP, o.Now
		o.Relay = func(base string, key ed25519.PrivateKey) Relay { return NewClientRelay(base, key, h, now) }
	}
}

// CreateParams create a new vault.
type CreateParams struct {
	Options
	VaultID     string // "" = random 128-bit id
	UserGUID    string
	PIN         string
	KDF         KDFParams
	RelayURL    string
	Provisional bool
	// App is the first app, bound at enrollment (§11.3). Optional.
	App *EnrollApp
	// Release fields of the first header (§11.10): the manifest serial
	// seen at enrollment and the verified sealing key (§11.10.7).
	ManifestSerial  uint64
	SealKeyVerified *SealKeyRecord
	// Replace, if set, overwrites an existing vault's objects at these
	// versions instead of creating them (§11.3 re-enrollment of a
	// provisional vault older than 24 h).
	Replace *Replace
}

// Replace names the versions of the objects a re-enrollment overwrites
// ("" for an object that does not exist).
type Replace struct {
	State, Header store.Version
}

// EnrollApp is the first app's public enrollment data (§11.3).
type EnrollApp struct {
	Name      string
	IK        ed25519.PublicKey
	KEM       *suite.PublicKey
	Relay     PeerRelay
	OpenToken string // open token for the app's mailbox, ≤ 10 min
	RequestID string
	// Attestation is the verified device-attestation binding (§11.7).
	Attestation json.RawMessage
	// Attest, if set, returns the attestation document carried in
	// vault.enrolled for the exact vault_bundle bytes (nonce = the app's
	// nonce, user_data = SHA-256("vettid/vms/2/vault" || vault_bundle)).
	Attest func(vaultBundle []byte) ([]byte, error)
}

// Create creates a vault: keys, mailbox registration, DEK-encrypted state
// and sealed header written create-only. The vault is returned unlocked.
func Create(ctx context.Context, p CreateParams) (*Manager, error) {
	p.Options.defaults()
	now := p.Now()
	if p.VaultID == "" {
		b, err := suite.RandomBytes(16)
		if err != nil {
			return nil, err
		}
		p.VaultID = hex.EncodeToString(b)
	}
	if !store.ValidKey(store.StateKey(p.VaultID)) || !validRelease(p.Release) || p.RelayURL == "" || p.Store == nil || p.Sealer == nil {
		return nil, errors.New("vault: invalid create parameters")
	}
	seeds := make([][]byte, 4) // relay, ik, kem, wake
	for i := range seeds {
		s, err := suite.RandomBytes(32)
		if err != nil {
			return nil, err
		}
		seeds[i] = s
	}
	pepper, err := suite.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	st := &State{
		V: 1, VaultID: p.VaultID, UserGUID: p.UserGUID,
		Relay:        RelayState{URL: p.RelayURL, Seed: seeds[0]},
		IdentitySeed: seeds[1], KEMSeed: seeds[2], WakeSeed: seeds[3],
		SealedRelease: p.Release.PCR0, AnnouncedRelease: p.Release.PCR0,
	}
	st.init()
	hdr := &Header{V: 1, VaultID: p.VaultID, UserGUID: p.UserGUID, Provisional: p.Provisional, CreatedAt: now.UTC(),
		KDF: p.KDF, Pepper: pepper, SealedRelease: p.Release.PCR0, ManifestSerial: p.ManifestSerial,
		SealKeyVerified: p.SealKeyVerified}
	dek, err := deriveDEK(p.PIN, p.KDF, pepper, p.VaultID)
	if err != nil {
		return nil, err
	}
	m := newManager(p.Options, st, hdr, dek)
	if err := m.loadKeys(); err != nil {
		return nil, err
	}
	st.Relay.Mailbox = mailboxOf(m.keys.relay)
	m.relay = p.Relay(p.RelayURL, m.keys.relay)
	if m.limits, err = m.relay.Register(ctx); err != nil {
		m.zeroize()
		return nil, err
	}
	if p.App != nil {
		if err := m.enrollApp(ctx, p.App, now); err != nil {
			m.zeroize()
			return nil, err
		}
	}
	if r := p.Replace; r != nil {
		m.stateVer, m.headerVer = r.State, r.Header
	}
	if err := m.persist(ctx, p.Replace == nil); err != nil {
		m.zeroize()
		return nil, err
	}
	m.drainOutbox(ctx) // vault.enrolled goes out after the create-only write (§11.3)
	if err := m.flushIfDirty(ctx); err != nil {
		m.zeroize()
		return nil, err
	}
	return m, nil
}

func validRelease(r Release) bool {
	return r.PCR0 != "" && store.ValidKey("x/"+r.PCR0) && !strings.Contains(r.PCR0, "/")
}

// UnlockParams unlock an existing vault directly with a PIN (development
// and tests; the enclave uses UnlockAlt).
type UnlockParams struct {
	Options
	VaultID string
	PIN     string
	// Client-anchored rollback minimums (§13.2).
	MinStateSeq  uint64
	MinHeaderSeq uint64
}

// UnlockResult reports the sequence numbers the app stores (§11.4).
type UnlockResult struct {
	StateSeq  uint64
	HeaderSeq uint64
}

// backoffDelays after 3 consecutive failures (§11.8).
var backoffDelays = []time.Duration{30 * time.Second, time.Minute, 5 * time.Minute, 15 * time.Minute, 60 * time.Minute}

func backoffFor(failures int) time.Duration {
	if failures < 3 {
		return 0
	}
	i := failures - 3
	if i >= len(backoffDelays) {
		i = len(backoffDelays) - 1
	}
	return backoffDelays[i]
}

// Unlock opens a vault with a PIN only: the header, backoff, DEK and the
// rollback checks of §13.2, without device or release checks. A failed PIN
// is counted in the header (header_seq increments); failures never wipe
// the vault.
func Unlock(ctx context.Context, p UnlockParams) (*Manager, UnlockResult, error) {
	m, out := UnlockAlt(ctx, AltUnlockParams{Options: p.Options, VaultID: p.VaultID, PIN: p.PIN,
		MinStateSeq: p.MinStateSeq, MinHeaderSeq: p.MinHeaderSeq, pinOnly: true})
	res := UnlockResult{StateSeq: out.StateSeq, HeaderSeq: out.HeaderSeq}
	if out.OK {
		return m, res, nil
	}
	return nil, res, out.err()
}

func newManager(o Options, st *State, hdr *Header, dek []byte) *Manager {
	m := &Manager{
		opt: o, now: o.Now, st: st, hdr: hdr, dek: dek,
		sessions: map[string]*handshake.Keyring{}, inbound: map[string]*handshake.PendingInit{},
		awaiting: map[string]*handshake.Responder{}, outgoing: map[string]*handshake.Initiator{},
		ephemeralSeen: map[string]time.Time{}, rates: map[string]*rateWindow{}, requests: map[string]string{}, requestTypes: map[string]string{},
	}
	if dek != nil {
		m.holdsDEK = true
		unlocked.Add(1)
	}
	m.registerCore()
	for _, f := range o.Features {
		m.addFeature(f)
		if raw, ok := st.Features[f.Name()]; ok {
			_ = f.Load(raw)
		}
	}
	return m
}

func (st *State) init() {
	if st.Devices == nil {
		st.Devices = map[string]*Peer{}
	}
	if st.Connections == nil {
		st.Connections = map[string]*Peer{}
	}
	if st.Invites == nil {
		st.Invites = map[string]*Invite{}
	}
	if st.Inbound == nil {
		st.Inbound = map[string]*InboundHS{}
	}
	if st.Awaiting == nil {
		st.Awaiting = map[string]*AwaitingHS{}
	}
	if st.Outgoing == nil {
		st.Outgoing = map[string]*OutgoingHS{}
	}
	if st.SeenMsgIDs == nil {
		st.SeenMsgIDs = map[string]time.Time{}
	}
	if st.SeenInner == nil {
		st.SeenInner = map[string]time.Time{}
	}
	if st.Responses == nil {
		st.Responses = map[string]CachedResponse{}
	}
	if st.Features == nil {
		st.Features = map[string]json.RawMessage{}
	}
	if st.Blocks == nil {
		st.Blocks = map[string]*Block{}
	}
	if st.AccessRequests == nil {
		st.AccessRequests = map[string]*AccessRequest{}
	}
	if st.Held == nil {
		st.Held = map[string]*HeldRequest{}
	}
}

func (m *Manager) loadKeys() error {
	k := &keyset{}
	var err error
	if len(m.st.Relay.Seed) != 32 || len(m.st.IdentitySeed) != 32 {
		return ErrState
	}
	k.relay = ed25519.NewKeyFromSeed(m.st.Relay.Seed)
	k.ik = ed25519.NewKeyFromSeed(m.st.IdentitySeed)
	if k.kem, err = suite.NewPrivateKey(m.st.KEMSeed); err != nil {
		return ErrState
	}
	for _, r := range m.st.RetiredKEMs {
		rk, err := suite.NewPrivateKey(r.Seed)
		if err != nil {
			return ErrState
		}
		k.retired = append(k.retired, rk)
	}
	m.keys = k
	return nil
}

// restoreLive rebuilds sessions and in-flight handshakes from state.
func (m *Manager) restoreLive() error {
	for _, p := range m.allPeers() {
		kr, err := handshake.ImportKeyring(p.Sessions)
		if err != nil {
			return ErrState
		}
		m.sessions[p.ID] = kr
	}
	for id, ib := range m.st.Inbound {
		pi, err := handshake.RestorePending(ib.Pending)
		if err != nil {
			return ErrState
		}
		m.inbound[id] = pi
	}
	for id, aw := range m.st.Awaiting {
		r, err := handshake.RestoreResponder(aw.Resp)
		if err != nil {
			return ErrState
		}
		m.awaiting[id] = r
	}
	for id, og := range m.st.Outgoing {
		i, err := handshake.RestoreInitiator(og.Init, m.keys.ik)
		if err != nil {
			return ErrState
		}
		m.outgoing[id] = i
	}
	return nil
}

// exportLive writes live sessions and handshakes back into state.
func (m *Manager) exportLive() {
	for _, p := range m.allPeers() {
		if kr, ok := m.sessions[p.ID]; ok {
			p.Sessions = kr.Export()
		}
	}
	for id, pi := range m.inbound {
		if s, err := pi.Export(); err == nil {
			m.st.Inbound[id].Pending = s
		}
	}
	for id, r := range m.awaiting {
		if s, err := r.Export(); err == nil {
			m.st.Awaiting[id].Resp = s
		}
	}
	for id, i := range m.outgoing {
		if s, err := i.Export(); err == nil {
			m.st.Outgoing[id].Init = s
		}
	}
	for _, f := range m.features {
		if raw, err := f.Save(); err == nil && raw != nil {
			m.st.Features[f.Name()] = raw
		}
	}
}

func (m *Manager) allPeers() []*Peer {
	out := make([]*Peer, 0, len(m.st.Devices)+len(m.st.Connections))
	for _, p := range m.st.Devices {
		out = append(out, p)
	}
	for _, p := range m.st.Connections {
		out = append(out, p)
	}
	return out
}

// persist flushes state. create = the first write (create-only objects).
func (m *Manager) persist(ctx context.Context, create bool) error {
	m.exportLive()
	m.prune()
	m.st.StateSeq++
	pt, err := json.Marshal(m.st)
	if err != nil {
		m.st.StateSeq--
		return err
	}
	blob, err := encryptState(m.dek, m.st.VaultID, m.st.StateSeq, pt)
	suite.Wipe(pt)
	if err != nil {
		m.st.StateSeq--
		return err
	}
	ifMatch := m.stateVer
	if create {
		ifMatch = ""
	}
	v, err := m.opt.Store.Put(ctx, store.StateKey(m.st.VaultID), blob, ifMatch)
	if errors.Is(err, store.ErrConflict) {
		m.splitBrain()
		return ErrSplitBrain
	}
	if err != nil {
		m.st.StateSeq--
		return err
	}
	m.stateVer = v
	m.dirty = false
	// The header follows the state to the same state_seq (§13.2). If this
	// write fails the state leads the header by one write, which is allowed.
	m.hdr.StateSeq = m.st.StateSeq
	if create {
		m.headerVer = ""
	}
	return m.writeHeader(ctx)
}

func (m *Manager) writeHeader(ctx context.Context) error {
	m.syncUnlockKeys()
	if m.st != nil {
		m.hdr.HasCredential = m.credentialExists() && m.hasGate()
	}
	m.hdr.HeaderSeq++
	b, err := sealHeader(ctx, m.opt.Sealer, m.hdr)
	if err != nil {
		return err
	}
	v, err := m.opt.Store.Put(ctx, store.HeaderKey(m.hdr.VaultID, m.hdr.SealedRelease), b, m.headerVer)
	if errors.Is(err, store.ErrConflict) {
		m.splitBrain()
		return ErrSplitBrain
	}
	if err != nil {
		return err
	}
	m.headerVer = v
	return nil
}

// syncUnlockKeys keeps the header's unlock keys equal to the active apps
// (§6.7: added in the same flush as the device record; §7.4: removed on
// unlink), plus the first app while its enrollment handshake is pending
// (§11.3). The header's attestation bindings are authoritative: an app
// already listed keeps its binding (the iOS counter advances there).
func (m *Manager) syncUnlockKeys() {
	if m.st == nil {
		return
	}
	prev := map[string]json.RawMessage{}
	for _, k := range m.hdr.UnlockKeys {
		prev[string(k.IK)] = k.Attestation
	}
	binding := func(ik []byte, fallback json.RawMessage) json.RawMessage {
		if b, ok := prev[string(ik)]; ok && len(b) > 0 {
			return b
		}
		return fallback
	}
	var keys []UnlockKey
	for _, p := range m.st.Devices {
		if p.Recovering && !m.hdr.isRecoveryKey(p.IK) {
			continue // its recovery was cancelled (§11.11.4)
		}
		if p.Kind == KindApp && p.State == PeerActive {
			keys = append(keys, UnlockKey{DeviceID: p.ID, IK: p.IK, KEM: p.KEM, Attestation: binding(p.IK, p.Attestation)})
		}
	}
	if inv := m.st.Invites[m.st.VaultID]; inv != nil && inv.EnrollIK != nil && !inv.Used && m.now().Before(inv.Exp) {
		keys = append(keys, UnlockKey{DeviceID: enrollDeviceID, IK: inv.EnrollIK, KEM: inv.EnrollKEM, Attestation: binding(inv.EnrollIK, inv.EnrollAttest)})
	}
	if r := m.hdr.Recovery; r != nil && r.State == RecoveryRegistered && r.App != nil {
		present := false
		for _, k := range keys {
			present = present || suite.EqualPublic(k.IK, r.App.IK)
		}
		if !present {
			keys = append(keys, UnlockKey{DeviceID: recoveryDeviceID, IK: r.App.IK, KEM: r.App.KEM, Attestation: binding(r.App.IK, r.App.Attestation)})
		}
	}
	sortUnlockKeys(keys)
	m.hdr.UnlockKeys = keys
}

// enrollDeviceID names the first app's unlock key until its enrollment
// handshake creates the device record.
const enrollDeviceID = "enroll"

// splitBrain is the §12.3 guard: another writer advanced the state. Zeroize
// immediately, without flushing or acking.
func (m *Manager) splitBrain() {
	m.zeroize()
}

// zeroize wipes the DEK and every key, and marks the manager locked.
func (m *Manager) zeroize() {
	m.locked = true
	if m.holdsDEK {
		m.holdsDEK = false
		unlocked.Add(-1)
	}
	if d, ok := m.opt.Sealer.(interface{ Destroy() }); ok {
		d.Destroy() // a KMS sealer's cached data key
	}
	suite.Wipe(m.dek)
	m.dek = nil
	for _, f := range m.features {
		if z, ok := f.(Zeroizer); ok {
			z.Zeroize()
		}
	}
	m.keys.destroy()
	m.keys = nil
	for _, kr := range m.sessions {
		kr.Destroy()
	}
	m.sessions = map[string]*handshake.Keyring{}
	for _, e := range m.volatile {
		suite.Wipe(e.Payload)
	}
	m.volatile = nil
	for _, pi := range m.inbound {
		pi.Discard()
	}
	for _, r := range m.awaiting {
		r.Abort()
	}
	for _, i := range m.outgoing {
		i.Abort()
	}
	m.inbound, m.awaiting, m.outgoing = nil, nil, nil
	if m.st != nil {
		suite.Wipe(m.st.Relay.Seed)
		suite.Wipe(m.st.IdentitySeed)
		suite.Wipe(m.st.KEMSeed)
		suite.Wipe(m.st.WakeSeed)
		for _, r := range m.st.RetiredKEMs {
			suite.Wipe(r.Seed)
		}
	}
	m.st = nil
	if m.collector != nil {
		_ = m.collector.Close()
		m.collector = nil
	}
}

// Locked reports whether the vault is locked (by request, split brain or
// error).
func (m *Manager) Locked() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.locked
}

// Audit returns a copy of the audit log (dropped and refused messages). It
// holds no secrets.
func (m *Manager) Audit() []AuditEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st == nil {
		return nil
	}
	return append([]AuditEntry(nil), m.st.Audit...)
}

// VaultID returns the vault id.
func (m *Manager) VaultID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st == nil {
		return ""
	}
	return m.st.VaultID
}

// Lock locks the vault on the owner's request (§12.3): flush, send
// vault.locking to the owner's devices, stop collecting, zeroize.
func (m *Manager) Lock(ctx context.Context) error { return m.LockReason(ctx, "") }

// LockReason is Lock with a reason in vault.locking ("recovery",
// §11.11.1; "" for none).
func (m *Manager) LockReason(ctx context.Context, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if reason == LockDelete {
		return m.deleteLocked(ctx, "host")
	}
	m.lockReason = reason
	return m.lockLocked(ctx)
}

// LockDelete as a lock reason deletes the running vault (§12.5): the
// host's deletion (account cancellation) with the full semantics.
const LockDelete = "delete"

// Delete deletes the running vault (§12.5) on the host's authority.
func (m *Manager) Delete(ctx context.Context) error { return m.LockReason(ctx, LockDelete) }

func (m *Manager) deleteLocked(ctx context.Context, via string) error {
	if m.locked {
		return ErrLocked
	}
	m.beginDelete(via, m.now())
	m.deletePending = false
	if err := m.persist(ctx, false); err != nil {
		if errors.Is(err, ErrSplitBrain) {
			return err
		}
		// Not marked: finish anyway; erasing needs no marker.
	}
	return m.finishDelete(ctx)
}

func (m *Manager) lockLocked(ctx context.Context) error {
	if m.locked {
		return nil
	}
	// Deliver what is queued first (an interrupted batch may have left
	// deposits, such as an hs.fin, in the outbox), then flush.
	m.drainOutbox(ctx)
	m.record(Activity{Kind: "vault.locked", Audit: true}, m.now())
	err := m.persist(ctx, false)
	if errors.Is(err, ErrSplitBrain) {
		return err
	}
	m.sendLocking(ctx)
	vid := m.st.VaultID
	m.zeroize()
	m.report("locked", vid, m.opt.Release.PCR0)
	return err
}

func (m *Manager) report(event, vaultID, release string) {
	if m.opt.Lifecycle != nil {
		m.opt.Lifecycle(LifecycleEvent{Event: event, VaultID: vaultID, Release: release,
			VaultVersion: m.opt.Release.PCR0, StateVersion: StateVersion})
	}
}

// StateVersion is the vault-state format version reported in lifecycle
// events (§11.5).
const StateVersion = 1

// Crash discards the in-memory vault without flushing (tests: process
// death).
func (m *Manager) Crash() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.zeroize()
}
