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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/vettid/vettid-vault/vault/counter"
	"github.com/vettid/vettid-vault/vms/recovery"
	"net/http"
	"sort"
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
	// OwnerCheckClock, if set, is the clock the daily owner check compares
	// (§3.6; tests move it past a deadline while messages keep the real
	// time). Nil: Now.
	OwnerCheckClock func() time.Time
	// IdleWatchEvery is how often Run's own timer looks at the idle lock
	// beside the collect loop (§3.6.8; 0: IdleWatchDefault). For tests.
	IdleWatchEvery time.Duration
	// AskRand, if set, draws the delay of a suppressed ask's neutral
	// answer (§10.4.1): a uniform value in [0, n). Nil: crypto/rand.
	AskRand func(n int64) int64
	// AndroidSigners are the Android signers the running release pins,
	// with their classes (0.27.0, §11.7.1): what the vault reports for
	// its signer binding. The enclave decides what is pinned; this is
	// for naming.
	AndroidSigners []SignerPin
	// Push is the channel's push gateway (0.24.0, §14); nil: the release
	// has none and push.register is answered unavailable.
	Push PushGateway
	// PushTiming overrides the wake rules' numbers (tests).
	PushTiming *PushTiming
	// Transfers is the instance's admission of blob transfers (the
	// supervisor's, by memory, §10.5.1); nil: only the vault's own limit
	// of attwire.VaultTransfers.
	Transfers TransferGate
	// AttachTick overrides the attachment runner's period (tests).
	AttachTick time.Duration
	// AttachClock, if set, is the clock of the attachment windows and
	// backoffs (§10.5.1; tests move it while messages keep the real time).
	AttachClock func() time.Time
	// AttachLimits, if set, replaces release A's attachment limits (tests).
	AttachLimits *AttachLimits
	// Counter is the recovery attempt counter's bucket (0.33.0, release
	// R, §11.14.4); nil: unreachable. HeavyPermit takes the supervisor's
	// permit for the recovery wrap's heavy derivation and returns its
	// release (§11.14.3); nil: always given (development, tests).
	Counter     counter.Bucket
	HeavyPermit func(ctx context.Context) (release func(), ok bool)
	// RecoveryWaitUnit and RecoveryQuiet are the release constants
	// recovery_wait_unit_seconds and recovery_quiet_seconds (§11.10.8);
	// zero: 24 h and 72 h.
	RecoveryWaitUnit time.Duration
	RecoveryQuiet    time.Duration
	// RecoveryCounterLock is the counter's lock period of token, success
	// and close records, the measured channel's (releasecfg.CounterLock,
	// VAULT-MESSAGING 0.33.2 §11.14.4: staging a day, production 100
	// years); zero: 100 years.
	RecoveryCounterLock time.Duration
	// RecoveryNotOffered is the inverse of the measured release
	// constant recovery_offered (§11.14.13); it only drops
	// recovery_offered from a transfer bundle's capabilities (§11.10.9).
	// Zero: offered (development, tests).
	RecoveryNotOffered bool
	// TimeScale is the running release's time scale (VAULT-MESSAGING
	// 0.43.0 §11.10.8, STAGING-TIME-SCALE): the enclave's measured value,
	// 1 outside staging and development (releasecfg.Config.TimeScale).
	// It divides the waits of timescale.go when each starts, and is
	// reported in vault.status and a transfer bundle. Zero: 1.
	TimeScale uint64
	// MarkDeleting asks the parent to record a deletion whose marking
	// flush is stored (0.51.0, §12.5 "Mark at the host",
	// VAULT-HOST-PROTOCOL §5.6) and returns nil on its ok; the vault
	// retries it for 2 minutes and delivers nothing of step 2 before.
	// Nil fails closed: the deletion is never recorded and the vault ends
	// locked. NoHostMark is the explicit choice of a vault without a host
	// (development, tests).
	MarkDeleting func(ctx context.Context, vaultID string) error
	// DeleteRetry overrides a deletion's retry schedules (tests).
	DeleteRetry *DeleteRetry
}

// LifecycleEvent is reported to the parent, which writes it to the vault
// table (§11.5). It is advisory and holds no secrets.
type LifecycleEvent struct {
	Event        string // enrolled, unlocked, locked, moved, app_key, ...
	VaultID      string
	Release      string // moved: the target release; otherwise the running one
	VaultVersion string // the release that reports
	StateVersion int
	// AppKey and AppKeySeq are the vault's current app key (SPKI DER) and
	// its change count (0.15.0, §11.5): on enrolled, unlocked, locked and
	// app_key; nil and 0 for a vault without one.
	AppKey    []byte
	AppKeySeq uint64
	// CredentialBackup is the vault's backup bit (0.16.0, §11.5): on
	// enrolled, unlocked, locked and credential_backup; nil when not
	// reported.
	CredentialBackup *bool
	// Name is the name request of account_name (0.18.0, §11.5); nil on
	// every other event.
	Name *NameChange
	// Release R (§11.5, §11.14.2): Next says on unlocked and locked whether
	// the header has a `next` part (nil: not reported) and HeaderSeq is
	// that header's header_seq (also the step-1 write's on app_key_next);
	// NextCleared marks an app_key event that repeats the current key and
	// only clears app_key_next.
	Next        *bool
	HeaderSeq   uint64
	NextCleared bool
	// CancelledRecoveryID (0.49.0, §11.5) is the recovery that the unlock
	// behind the event ended: on that unlock's unlocked event, or on its
	// moved event when it completed a release move (which emits no
	// unlocked); empty on every other event.
	CancelledRecoveryID string
}

// EventAppKeyNext reports the next app key of a replacement in progress
// with its first header write (release R, §11.5, §11.14.2).
const EventAppKeyNext = "app_key_next"

// EventCredentialBackup reports a changed backup bit (0.16.0, §11.5).
const EventCredentialBackup = "credential_backup"

// EventAppKey reports a changed app key (a transfer or a recovery
// replaced the app, §11.5, 0.15.0), after the flush that wrote it.
const EventAppKey = "app_key"

// Hooks let tests and supervisors observe or interrupt processing.
type Hooks struct {
	// AfterFlush runs after a batch's state flush and before its acks. An
	// error stops processing there, like a crash: nothing is acked and the
	// in-memory state is discarded.
	AfterFlush func() error
	// DropDeposit, if it returns true for an outbox deposit, drops it as if
	// it were lost (fault injection for best-effort notices).
	DropDeposit func(e *OutboxEntry) bool
	// AttachStep, if it returns an error at a step of the attachment
	// runner ("thumb": an object written, its flush not yet made;
	// "prepared", "stored": the content's flush made, the blob not yet
	// deleted), crashes the vault there (fault injection, §10.5.1 write
	// order).
	AttachStep func(step string) error
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
	awaiting map[string]*handshake.Responder
	// reqEpochs are the established, not yet active epochs of Requests
	// (§6.3, 0.10.3).
	reqEpochs map[string]*handshake.Epoch
	outgoing  map[string]*handshake.Initiator

	registry map[string]*typeEntry
	features []Feature
	// featureNames are the registered features' names (0.26.0, §11.10.8).
	featureNames map[string]bool

	ephemeralSeen map[string]time.Time
	rates         map[string]*rateWindow
	requests      map[string]string // our outstanding request inner id -> peer id
	requestTypes  map[string]string // ... -> type
	// volatile holds deposits that must never reach vault state (responses
	// carrying secret values, TypeSpec.Volatile); drained after the
	// durable outbox, dropped on failure or lock.
	volatile []*OutboxEntry
	dirty    bool

	// transferAfter is the transfer request the current handler approved:
	// the transfer completes after the handler returns (§6.7.1), outside
	// the credential feature's lock.
	transferAfter string
	// replaceAfter is the recovered app whose recovery completed in the
	// current handler: the other apps are removed after it returns
	// (§11.11.5). alarms are host alarms reported after the flush (§11.5).
	replaceAfter string
	alarms       []string
	// appKeyChanged: the header's app key changed in this batch; reported
	// to the host after the flush (§11.5).
	appKeyChanged bool
	// nameReport: a name request stored in this batch; reported as
	// account_name after the flush (0.18.0, §11.5).
	nameReport *NameChange
	// backupChanged: the header's credential_backup changed; reported
	// after the flush (0.16.0, §11.5).
	backupChanged bool
	// deletePending: a deletion was marked in this batch; it is finished
	// after the flush (§12.5).
	deletePending bool
	deleteRequest string
	// markStored: a header that records Deleting is stored (0.51.0,
	// §12.5: the host's mark and step 2 wait for it).
	markStored bool
	// markOK: step 1 is complete, the host's ok included (completeMark);
	// until then a marked vault delivers nothing (holdForMark).
	markOK bool

	locked      bool
	lockPending bool
	lockReason  string
	// unlockID names this opening of the vault (VAULT-MESSAGING 0.29.0
	// §10.2 "Locks", release L): 16 random bytes as 32 lowercase hex,
	// made when the Manager is made (every enroll, unlock or recovery
	// open makes one), kept in memory only, never in the state or the
	// header. It ends with the Manager, so every earlier value is stale
	// after any lock, restart or move. Not a secret.
	unlockID string
	// unlockedBy: the app whose unlock started this manager (its device
	// id; "" for a PIN-only unlock or an app without a device record
	// yet), audited on vault.unlocked (0.23.2, §10.9).
	unlockedBy string
	// lockBy: the owner device whose vault.lock is pending, audited on
	// vault.locked (0.23.2); "" for every other lock.
	lockBy string
	// The idle lock's look at this opening (§3.6.8 "After an unlock"):
	// idleOpened once it was taken; idleGrace is one hour from an unlock
	// that came when the idle lock's time had already passed (zero
	// otherwise). Memory only: every opening has its own.
	idleOpened  bool
	idleGrace   time.Time
	started     bool
	hadFailures bool // the header recorded failures before this unlock
	holdsDEK    bool // counted in unlocked
	// ocCred caches whether the vault has a credential, for the owner
	// check (refreshOwnerCred).
	ocCred bool
	// push sends the registration's wakes (0.24.0, §14.2); pushGen
	// changes with every registration so that late outcomes of an older
	// one are ignored.
	push    *pusher
	pushGen uint64
	// att is the attachment runner while the vault runs (§10.5.1).
	att *attRunner
	// attWrites counts the runner's store writes in flight (finishDelete
	// waits for them before it erases).
	attWrites sync.WaitGroup

	// Release R (§11.14.1, §11.14.2): the unlock key and the phone's
	// secret since the unlock (memory only, never written), a DEK
	// replacement whose step 1 is stored, the reasons of those promoted in
	// this batch, and the lifecycle news for the parent: app_key_next sent
	// with a step 1, a `next` part with an app key dropped.
	unlockKey    []byte
	unlockSecret []byte
	repl         *replacement
	replaced     []string
	nextCleared  bool
	// rec is the recovery runtime: the counter, the last status read, the
	// presence retry (§11.14.4, §11.14.5).
	rec recoveryRuntime
	// presentAfterFlush: an event that marks the member present (a
	// completed transfer) waits for its state write (§11.14.5).
	presentAfterFlush bool
	// replInHandler: the current handler stored step 1 of a replacement.
	replInHandler bool
	// transferSecret is a transfer's new phone's unlock secret from its
	// hs.init, in memory only until the approval (§11.14.10).
	transferSecret []byte
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
	VaultID  string // "" = random 128-bit id
	UserGUID string
	PIN      string
	// UnlockSecret is the phone's unlock secret (release R, §11.14.1).
	UnlockSecret []byte
	KDF          KDFParams
	RelayURL     string
	Provisional  bool
	// App is the first app, bound at enrollment (§11.3). Optional.
	App *EnrollApp
	// Account is the enroll queue message's account snapshot (0.18.0,
	// §11.5, §11.13), stored before the first flush. The enclave refuses
	// an enrollment without a valid one; development vaults may omit it.
	Account []byte
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
	// APIKey is the app key (SPKI DER, 0.15.0): the header's app key,
	// app_key_seq 1.
	APIKey []byte
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
		DeviceTokensMarked: true, // every device token is minted with owner_device (§7.1)
	}
	st.init()
	hdr := &Header{V: 1, VaultID: p.VaultID, UserGUID: p.UserGUID, Provisional: p.Provisional, CreatedAt: now.UTC(),
		KDF: p.KDF, Pepper: pepper, SealedRelease: p.Release.PCR0, ManifestSerial: p.ManifestSerial,
		SealKeyVerified: p.SealKeyVerified}
	if p.Provisional {
		// The enrollment window, divided by the time scale (0.43.0, S13).
		hdr.EnrollUntil = hdr.CreatedAt.Add(p.Options.scale(EnrollWindow))
	}
	if p.App != nil && len(p.App.APIKey) > 0 {
		hdr.AppKey, hdr.AppKeySeq = append([]byte(nil), p.App.APIKey...), 1
	}
	// Release R (§11.14.1): a random DEK, wrapped under the unlock key of
	// the PIN and the phone's secret, and the counter key (§11.14.3).
	uk, err := deriveUnlockKey(p.PIN, p.UnlockSecret, p.KDF, pepper, p.VaultID)
	if err != nil {
		return nil, err
	}
	dek, err := suite.RandomBytes(recovery.SecretSize)
	if err != nil {
		return nil, err
	}
	hdr.V, hdr.DEKVersion = HeaderVersion, 1
	if hdr.DEKWrap, err = recovery.WrapDEK(uk, dek, p.VaultID, 1); err != nil {
		return nil, err
	}
	if hdr.SecretCheck, err = recovery.SecretCheck(pepper, p.VaultID, p.UnlockSecret); err != nil {
		return nil, err
	}
	if hdr.Rec.CounterKey, err = suite.RandomBytes(recovery.SecretSize); err != nil {
		return nil, err
	}
	m := newManager(p.Options, st, hdr, dek)
	m.unlockKey, m.unlockSecret = uk, append([]byte(nil), p.UnlockSecret...)
	if err := m.loadKeys(); err != nil {
		return nil, err
	}
	st.Relay.Mailbox = mailboxOf(m.keys.relay)
	m.relay = p.Relay(p.RelayURL, m.keys.relay)
	if m.limits, err = m.relay.Register(ctx); err != nil {
		m.zeroize()
		return nil, err
	}
	if len(p.Account) > 0 && !m.applyAccount(p.Account, now) {
		m.zeroize()
		return nil, ErrAccount
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
	VaultID      string
	PIN          string
	UnlockSecret []byte
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
	m, out := UnlockAlt(ctx, AltUnlockParams{Options: p.Options, VaultID: p.VaultID, PIN: p.PIN, UnlockSecret: p.UnlockSecret,
		MinStateSeq: p.MinStateSeq, MinHeaderSeq: p.MinHeaderSeq, pinOnly: true})
	res := UnlockResult{StateSeq: out.StateSeq, HeaderSeq: out.HeaderSeq}
	if out.OK {
		return m, res, nil
	}
	return nil, res, out.err()
}

// newUnlockID makes an unlock_id: 16 bytes from crypto/rand, as 32
// lowercase hex characters (§10.2 "Locks").
func newUnlockID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (Go 1.24)
	return hex.EncodeToString(b[:])
}

// UnlockID returns the name of this opening of the vault (§10.2 "Locks"),
// for the enroll, unlock and recovery-open results.
func (m *Manager) UnlockID() string { return m.unlockID }

func newManager(o Options, st *State, hdr *Header, dek []byte) *Manager {
	m := &Manager{
		opt: o, now: o.Now, st: st, hdr: hdr, dek: dek,
		sessions: map[string]*handshake.Keyring{}, reqEpochs: map[string]*handshake.Epoch{},
		awaiting: map[string]*handshake.Responder{}, outgoing: map[string]*handshake.Initiator{},
		ephemeralSeen: map[string]time.Time{}, rates: map[string]*rateWindow{}, requests: map[string]string{}, requestTypes: map[string]string{},
		unlockID: newUnlockID(),
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
	m.clearDeadHolder() // §3.5.9 (0.52.0): a holder naming no live app is none
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
	if st.Awaiting == nil {
		st.Awaiting = map[string]*AwaitingHS{}
	}
	if st.Outgoing == nil {
		st.Outgoing = map[string]*OutgoingHS{}
	}
	if st.Requests == nil {
		st.Requests = map[string]*Request{}
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
	// In-flight handshakes and requests that do not restore (made by an
	// earlier release, before 0.10.3) are dropped: they would fail anyway,
	// and the vault must still unlock.
	for id, aw := range m.st.Awaiting {
		r, err := handshake.RestoreResponder(aw.Resp)
		if err != nil {
			delete(m.st.Awaiting, id)
			m.audit(m.now(), "handshake_not_restored", aw.PeerID)
			continue
		}
		m.awaiting[id] = r
	}
	for id, og := range m.st.Outgoing {
		i, err := handshake.RestoreInitiator(og.Init, m.keys.ik)
		if err != nil {
			delete(m.st.Outgoing, id)
			m.audit(m.now(), "handshake_not_restored", og.PeerID)
			continue
		}
		m.outgoing[id] = i
	}
	for id, r := range m.st.Requests {
		e, err := handshake.ImportEpoch(r.Epoch)
		if err != nil || r.Peer == nil {
			delete(m.st.Requests, id)
			m.audit(m.now(), "handshake_not_restored", "")
			continue
		}
		m.reqEpochs[id] = e
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
	for id, e := range m.reqEpochs {
		if r := m.st.Requests[id]; r != nil {
			r.Epoch = e.Export()
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
	// Step 2 of a DEK replacement (§11.14.2): the state under DEK_1.
	dek, ver := m.dek, m.hdr.DEKVersion
	if r := m.repl; r != nil {
		dek, ver = r.dek1, r.next.DEKVersion
	}
	blob, err := encryptState(dek, ver, m.st.VaultID, m.st.StateSeq, pt)
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
	if err := m.promote(); err != nil { // step 3, written below
		return err
	}
	// The header follows the state to the same state_seq (§13.2). If this
	// write fails the state leads the header by one write, which is allowed.
	m.hdr.StateSeq = m.st.StateSeq
	if create {
		m.headerVer = ""
	}
	if err := m.writeHeader(ctx); err != nil {
		return err
	}
	if m.presentAfterFlush {
		// After the event's state write (§11.14.5); not recorded: sent
		// again at the next unlock or owner check.
		m.presentAfterFlush = false
		if !m.markPresent(ctx, m.now()) {
			m.st.PresentPending = true
			m.dirty = true
		}
	}
	return nil
}

func (m *Manager) writeHeader(ctx context.Context) error { return m.writeHeaderWith(ctx, true) }

// writeHeaderWith writes the header; features false keeps the credential
// bits as they are (a DEK replacement's step 1 runs inside the credential
// feature's handler, which holds its lock).
func (m *Manager) writeHeaderWith(ctx context.Context, features bool) error {
	m.syncUnlockKeys()
	if m.st != nil && features {
		m.hdr.HasCredential = m.credentialExists() && m.hasGate()
		// §3.3, §11.5 (0.16.0): the backup bit, and an event when it
		// changes on a running vault (reported after the write).
		b := m.hdr.HasCredential && m.backupCopy()
		if m.hdr.CredentialBackup == nil || *m.hdr.CredentialBackup != b {
			if m.hdr.CredentialBackup != nil || m.started {
				m.backupChanged = true
			}
			m.hdr.CredentialBackup = &b
		}
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
	if m.hdr.Deleting {
		m.markStored = true
	}
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
	// Release R (§11.14.6): a registered phone is no unlock key; a
	// recovered phone is one from the completion until its pairing (its
	// invite), and a transfer's or recovery's new phone is in the `next`
	// part until step 3 (findUnlockKey).
	for _, inv := range m.st.Invites {
		// Kept until the phone pairs, past the invite's expiry: a lost
		// ok is resumed by this phone's unlock (owner decision of
		// 2026-10-16, §11.14.6).
		if inv.CreatedBy == inviteByRecovery && inv.EnrollIK != nil {
			present := false
			for _, k := range keys {
				present = present || suite.EqualPublic(k.IK, inv.EnrollIK)
			}
			if !present {
				keys = append(keys, UnlockKey{DeviceID: recoveryDeviceID, IK: inv.EnrollIK, KEM: inv.EnrollKEM, Attestation: binding(inv.EnrollIK, inv.EnrollAttest)})
			}
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
	m.attStop()
	if m.push != nil {
		m.push.stop()
		m.push = nil
	}
	if m.holdsDEK {
		m.holdsDEK = false
		unlocked.Add(-1)
	}
	if d, ok := m.opt.Sealer.(interface{ Destroy() }); ok {
		d.Destroy() // a KMS sealer's cached data key
	}
	suite.Wipe(m.dek)
	m.dek = nil
	suite.Wipe(m.unlockKey)
	suite.Wipe(m.unlockSecret)
	m.unlockKey, m.unlockSecret = nil, nil
	m.repl.wipe()
	m.repl = nil
	suite.Wipe(m.transferSecret)
	m.transferSecret = nil
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
	for _, e := range m.reqEpochs {
		e.Destroy()
	}
	for _, r := range m.awaiting {
		r.Abort()
	}
	for _, i := range m.outgoing {
		i.Abort()
	}
	m.reqEpochs, m.awaiting, m.outgoing = nil, nil, nil
	if m.st != nil && m.st.Attach != nil {
		// k_att, blob keys and held thumbnails (§10.5.1).
		for _, e := range m.st.Attach.Entries {
			e.wipe()
		}
	}
	if m.st != nil {
		if m.st.PendingUnlink != nil {
			m.st.PendingUnlink.wipe() // the kept send key (§11.14.10); stored under the DEK
		}
		suite.Wipe(m.st.Relay.Seed)
		suite.Wipe(m.st.IdentitySeed)
		suite.Wipe(m.st.KEMSeed)
		suite.Wipe(m.st.WakeSeed)
		if m.st.Push != nil {
			suite.Wipe(m.st.Push.WakeSeed)
		}
		if m.st.PushPending != nil {
			suite.Wipe(m.st.PushPending.WakeSeed)
		}
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

// FeatureEntries returns the names of the features.<name> entries in the
// vault's state, ascending (tests and tools; 0.26.0, §11.10.8: an image
// creates no entry for a feature it does not register and carries one it
// meets unchanged).
func (m *Manager) FeatureEntries() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st == nil {
		return nil
	}
	out := make([]string, 0, len(m.st.Features))
	for n := range m.st.Features {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
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
	m.lockBy = "" // the host's lock, not a device's (0.23.2)
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
		// The state may not be marked: finishDelete still writes the
		// header's mark and asks the host before anything of step 2
		// (0.51.0), and erasing needs no marker.
	}
	return m.finishDelete(ctx)
}

func (m *Manager) lockLocked(ctx context.Context) error {
	if m.locked {
		return nil
	}
	if m.st != nil && m.st.Deleting != nil {
		return m.lockDeleting(ctx)
	}
	// Deliver what is queued first (an interrupted batch may have left
	// deposits, such as an hs.fin, in the outbox), then flush.
	m.drainOutbox(ctx)
	// A device's vault.lock names the device (0.23.2, §10.9); a lock
	// with a reason (owner check, recovery) or by the host has none.
	by := ""
	if m.lockReason == "" {
		by = m.lockBy
	}
	ref := ""
	if m.lockReason == LockIdle {
		ref = LockIdle // §10.9 (0.29.0, release L): the idle lock, §3.6.8
	}
	m.record(Activity{Kind: "vault.locked", DeviceID: by, Ref: ref, Audit: true}, m.now())
	err := m.persist(ctx, false)
	if errors.Is(err, ErrSplitBrain) {
		return err
	}
	m.pushLockWake(m.sendLocking(ctx)) // §14.2 trigger 3, before zeroizing
	vid := m.st.VaultID
	m.zeroize()
	m.report("locked", vid, m.opt.Release.PCR0)
	return err
}

// lockDeleting locks a vault whose deletion is marked and whose step 2 has
// not run (a marking flush that failed, a lock that came first; 0.51.0,
// §12.5): nothing of the deletion leaves, neither the outbox (its notices)
// nor vault.locking. The mark is flushed if it is not stored, and the
// next unlock finishes the deletion.
func (m *Manager) lockDeleting(ctx context.Context) error {
	var err error
	if m.dirty || !m.markStored {
		err = m.persist(ctx, false)
		if errors.Is(err, ErrSplitBrain) {
			return err
		}
	}
	vid := m.st.VaultID
	m.zeroize()
	m.report("locked", vid, m.opt.Release.PCR0)
	return err
}

func (m *Manager) report(event, vaultID, release string) {
	if m.opt.Lifecycle != nil {
		ev := LifecycleEvent{Event: event, VaultID: vaultID, Release: release,
			VaultVersion: m.opt.Release.PCR0, StateVersion: StateVersion}
		if event == "locked" || event == EventAppKey || event == "unlocked" || event == "enrolled" {
			ev.AppKey, ev.AppKeySeq = m.AppKey()
		}
		if event == "locked" || event == EventCredentialBackup || event == "unlocked" || event == "enrolled" {
			ev.CredentialBackup = m.CredentialBackup()
		}
		if (event == "locked" || event == "unlocked") && m.hdr != nil {
			next := m.hdr.Next != nil
			ev.Next, ev.HeaderSeq = &next, m.hdr.HeaderSeq
		}
		m.opt.Lifecycle(ev)
	}
}

// AppKey returns the vault's app key and its change count (0.15.0).
// It reads the header, which a lock leaves in place.
func (m *Manager) AppKey() ([]byte, uint64) {
	if m.hdr == nil || len(m.hdr.AppKey) == 0 {
		return nil, 0
	}
	return append([]byte(nil), m.hdr.AppKey...), m.hdr.AppKeySeq
}

// CredentialBackup returns the header's backup bit (nil before 0.16.0).
func (m *Manager) CredentialBackup() *bool {
	if m.hdr == nil || m.hdr.CredentialBackup == nil {
		return nil
	}
	b := *m.hdr.CredentialBackup
	return &b
}

// RecoveryRefusal reports whether a running vault would refuse a recovery
// (0.16.0, §11.11.1): "no_credential", "no_backup" or "". It decides from
// its own state, before anything is locked.
func (m *Manager) RecoveryRefusal() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked || m.st == nil {
		return ""
	}
	switch {
	case !m.hasGate() || !m.credentialExists():
		return "no_credential"
	case !m.backupCopy():
		return "no_backup"
	}
	return ""
}

// setAppKey makes key the vault's app key (a transfer's or a recovery's
// new app, §6.7.1, §11.11.5): app_key_seq + 1, written with the batch's
// header and reported after the flush.
func (m *Manager) setAppKey(key []byte) {
	m.hdr.AppKey = append([]byte(nil), key...)
	m.hdr.AppKeySeq++
	m.appKeyChanged = true
	m.dirty = true
}

// reportAppKey reports a changed app key after the flush that stored it.
func (m *Manager) reportAppKey() {
	if m.st == nil {
		return
	}
	if m.appKeyChanged {
		m.appKeyChanged = false
		m.nextCleared = false // app_key clears app_key_next by its seq
		m.report(EventAppKey, m.st.VaultID, m.opt.Release.PCR0)
	}
	if m.nextCleared {
		// A dropped replacement (§11.14.2): the current key again, with
		// next_cleared.
		m.nextCleared = false
		if m.opt.Lifecycle != nil {
			ev := lifecycle(m.opt, EventAppKey, m.st.VaultID, m.opt.Release.PCR0)
			ev.AppKey, ev.AppKeySeq = m.AppKey()
			ev.NextCleared, ev.HeaderSeq = true, m.hdr.HeaderSeq
			if ev.AppKey != nil {
				m.opt.Lifecycle(ev)
			}
		}
	}
	if m.backupChanged {
		m.backupChanged = false
		m.report(EventCredentialBackup, m.st.VaultID, m.opt.Release.PCR0)
	}
	m.reportName()
}

// StateVersion is the vault-state format version reported in lifecycle
// events (§11.5).
const StateVersion = 2 // release R: format 0x02 (§11.14.1, §11.5)

// Crash discards the in-memory vault without flushing (tests: process
// death).
func (m *Manager) Crash() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.zeroize()
}
