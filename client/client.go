// Package client is the reference client for a vault's owner devices: an
// app, desktop or agent (VAULT-MESSAGING §6.7, §9.1, §11.3). It enrolls or
// pairs with a vault, keeps the session (including vault-initiated rekeys),
// exchanges requests, responses and events, and handles token refresh and
// identity rotation. It is used by vaultctl and the end-to-end tests, and is
// the model for the app clients (VAULT-PLAN phase V6).
//
// State (Save/Load) contains private keys: store it encrypted or with
// restrictive permissions.
package client

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/invite"
	"github.com/vettid/vettid-vault/vms/nitro"
	"github.com/vettid/vettid-vault/vms/suite"
)

const devicePairRejected = "device.pair.rejected"

// Errors.
var (
	ErrNotPaired = errors.New("client: not paired with a vault")
	ErrProtocol  = errors.New("client: unexpected message from the vault")
	ErrToken     = errors.New("client: token invalid")
	// ErrPairRejected: the owner rejected this pairing or transfer on the
	// phone (device.pair.rejected, VAULT-MESSAGING §6.7, 0.10.5).
	ErrPairRejected = errors.New("client: pairing rejected on the phone")
	// ErrRefused: the vault's mailbox answered a deposit of this device
	// token_revoked, the refused relay key of §6.7.1. Terminal (§8.6):
	// the device sends nothing more to that mailbox, keeps collecting
	// its own (a device.unlinked may be waiting) and does not erase its
	// state on this answer alone; it counts toward offering an erase.
	ErrRefused = errors.New("client: refused by the vault's mailbox (token_revoked)")
	// ErrOutboxDropped wraps a relay error that made Poll drop an
	// outbox entry for good (a client error other than 429).
	ErrOutboxDropped = errors.New("client: outbox deposit refused")
	// ErrHandshakeUnsent: the hs.fin of this device's pairing could not
	// be deposited, so the vault cannot complete the handshake.
	ErrHandshakeUnsent = errors.New("client: hs.fin could not be deposited")
	// ErrRunning: Run was called while it already runs, or Poll while
	// Run runs.
	ErrRunning = errors.New("client: Run is already running")
)

// Config configures a Device.
type Config struct {
	Role     string // "app", "desktop" or "agent"
	Name     string
	RelayURL string // the device's own relay
	HTTP     *http.Client
	Now      func() time.Time
	// PollWait is the long-poll wait used while waiting (default 2 s).
	PollWait time.Duration
	// Trust pins the Nitro root and manifest keys for the alternate
	// channel (§11.2). With Trust set, vault.enrolled must carry a valid
	// attestation for the pending enrollment.
	Trust *Trust
	// Persist, if set, saves the device state (what Save returns) after
	// the messages of a collected batch are handled and before any of
	// them is acknowledged, as VAULT-MESSAGING §8.3 has devices do with
	// their local storage. If it returns an error, Poll returns that
	// error and acknowledges none of the batch, so the relay delivers it
	// again. The deposits that handling makes (a rekey's hs.resp, a
	// pairing's hs.fin, relay.token.issued and relay.token.refresh)
	// wait in the state's outbox until Persist has saved them and are
	// deposited after it, before the acks. Poll calls Persist without
	// the device's lock held and never twice at once; Persist may call
	// the Device's methods, though not Poll or the waiting calls. The
	// state slice is wiped when Persist returns: copy it to keep it.
	// Persist covers what the client records while handling (keys and
	// sessions, tokens, device.paired, the msg_ids seen); the responses
	// and events it hands to the caller stay in memory as before, so
	// what the caller makes of them is the caller's to save.
	//
	// Nothing a batch brought reaches the caller before the batch is
	// saved: its responses and events are held back from the waiting
	// calls until a Persist succeeds, and a pairing's SAS is returned
	// only once its hs.fin is saved and deposited. After a Persist
	// error the next Poll calls Persist again before collecting.
	// Terminal deposit errors from the outbox are returned by Poll
	// (ErrRefused, ErrOutboxDropped); see flushOutboxLocked for the
	// outbox's rules.
	//
	// Nil: each message is acknowledged right after it is handled, its
	// deposits are made at once, and the state is saved only when the
	// caller calls Save. In both modes a deposit to the vault's mailbox
	// answered token_revoked makes the device refused (ErrRefused,
	// Refused): it sends nothing more to that mailbox (§8.6).
	Persist func(state []byte) error
	// RunError, if set, receives each error of a Poll that Run makes
	// (a Persist error, a collect error, ErrRefused, ErrOutboxDropped).
	// Run keeps collecting after it, with a backoff.
	RunError func(error)
}

// State is the device's persistent state.
type State struct {
	Role      string `json:"role"`
	Name      string `json:"name"`
	RelayURL  string `json:"relay_url"`
	IKSeed    []byte `json:"ik_seed"`
	KEMSeed   []byte `json:"kem_seed"`
	RelaySeed []byte `json:"relay_seed"`

	VaultID  string       `json:"vault_id,omitempty"`
	DeviceID string       `json:"device_id,omitempty"`
	Vault    *VaultRecord `json:"vault,omitempty"`

	Outgoing *handshake.InitiatorState  `json:"outgoing,omitempty"`
	Awaiting []handshake.ResponderState `json:"awaiting,omitempty"`
	Seen     map[string]time.Time       `json:"seen,omitempty"`
	// IssuedExp is the expiry of the standing token we last gave the vault.
	IssuedExp time.Time `json:"issued_exp,omitempty"`
	// Alt is the alternate-channel state (§11.10.6, §13.2).
	Alt *AltState `json:"alt,omitempty"`
	// Credential is this app's copy of the Protean Credential (§3.5): the
	// sealed blob, useless without the vault's CEK and the password.
	Credential *CredentialCopy `json:"credential,omitempty"`
	// UTKs is this app's pool of one-time transaction keys (§3.5.4).
	UTKs []UTK `json:"utks,omitempty"`
	// Recovery is set while this app recovers a vault (§11.11).
	Recovery *RecoveryState `json:"recovery,omitempty"`
	// AppKey is the app key's P-256 scalar (0.15.0, §11.12.2; an app
	// holds it in hardware, this reference client in its state).
	AppKey []byte `json:"app_key,omitempty"`
	// UserGUID is the member's id from the redeem or the recovery claim
	// (0.15.0), or a transfer's device.paired (0.17.0): the sealed
	// requests carry it.
	UserGUID string `json:"user_guid,omitempty"`
	// AttestChain is the certificate chain of this app's Android device
	// key, as sent at its last attestation (Android Keystore keeps it
	// with the key). 0.27.0 (§11.7.1): it is sent again with each unlock
	// until the vault has recorded this app's signer (SignerBound).
	AttestChain [][]byte `json:"attest_chain,omitempty"`
	SignerBound bool     `json:"signer_bound,omitempty"`
	// PhoneKey stands in for the phone key, the Android Keystore's
	// non-exportable HMAC key (release R, §11.14.1; this reference client
	// holds it in its state), with the vault id its secrets name and the
	// epoch of the current secret (1 at enrollment, a transfer and a
	// recovery; one higher at each pin.change and vault.secret.renew).
	PhoneKey    []byte `json:"phone_key,omitempty"`
	SecretVault string `json:"secret_vault,omitempty"`
	Epoch       uint64 `json:"epoch,omitempty"`
	// Outbox holds the deposits to the vault made while a batch was
	// handled with Config.Persist set, until the relay accepts them.
	Outbox []OutboxEntry `json:"outbox,omitempty"`
	// Paired is what device.paired told this device (Paired).
	Paired *Paired `json:"paired,omitempty"`
	// PairingPending: this device started a handshake (pairing,
	// enrollment, recovery) and has not had its device.paired or
	// device.pair.rejected yet. A device.paired arriving otherwise, once
	// the device has its id, is dropped (§6.7).
	PairingPending bool `json:"pairing_pending,omitempty"`
}

// Paired is what device.paired told this device (VAULT-MESSAGING §6.7,
// the §10.3 row), recorded when the message is handled and kept in the
// state, so that a device restarted after a crash can still read it.
// The standing token it carried is in the vault record.
type Paired struct {
	DeviceID string `json:"device_id"`
	Role     string `json:"role,omitempty"`
	VaultID  string `json:"vault_id,omitempty"`
	// Release and ReleaseNumber are what the message named. The floor
	// for unlocks is Alt's Release and ReleaseNumber, which device.paired
	// raises and never lowers: callers take the floor from Alt.
	Release       string `json:"release,omitempty"`
	ReleaseNumber uint64 `json:"release_number,omitempty"`
	// SessionExpiresAt is the end of the first access session, when the
	// owner approved the pairing of a desktop or agent with one (§6.8);
	// zero without one.
	SessionExpiresAt time.Time `json:"session_expires_at"`
	// Transfer, CredentialVersion and UserGUID: a transfer's new app
	// only (§6.7.1).
	Transfer          bool   `json:"transfer,omitempty"`
	CredentialVersion uint64 `json:"credential_version,omitempty"`
	UserGUID          string `json:"user_guid,omitempty"`
	// ReceivedAt is when the device handled device.paired (its clock).
	ReceivedAt time.Time `json:"received_at"`
}

// OutboxEntry is one deposit to the vault waiting in State.Outbox: an
// envelope already sealed, deposited on the vault token held when it
// is sent.
type OutboxEntry struct {
	// Kind: "hs.fin", "hs.resp", "token" (a standing token for the
	// vault: relay.token.issued or a relay.token.refresh reply),
	// "refresh" (a relay.token.refresh request) or "".
	Kind     string    `json:"kind,omitempty"`
	RelayURL string    `json:"relay_url"`
	Mailbox  string    `json:"mailbox"`
	Payload  []byte    `json:"payload"`
	Created  time.Time `json:"created"`

	seq uint64 // in memory: the order it was queued in (Device.nextSeq)
}

// outboxMaxAge bounds how long an outbox entry is retried: a vault
// refuses durable messages whose ts is more than 16 days old (§8.4).
// outboxCap bounds the outbox: past it, the oldest entry is dropped.
const (
	outboxMaxAge = 16 * 24 * time.Hour
	outboxCap    = 64
	// maxRetryAfter bounds a relay's retry_after (seconds).
	maxRetryAfter = 3600
)

// VaultRecord is what the device knows about its vault.
type VaultRecord struct {
	IK       []byte                 `json:"ik"`
	KEM      []byte                 `json:"kem"`
	RelayURL string                 `json:"relay_url"`
	Mailbox  string                 `json:"mailbox"`
	RelayPK  []byte                 `json:"relay_pk"`
	Token    string                 `json:"token,omitempty"`
	TokenExp time.Time              `json:"token_exp,omitempty"`
	Sessions handshake.KeyringState `json:"sessions"`
	Suite    uint8                  `json:"suite"`
}

// Device is one owner device.
type Device struct {
	mu  sync.Mutex
	cfg Config
	st  *State

	// leashStatus caches an agent's LEASH status statements by grant id
	// (memory only; refreshed before they expire, §10.11).
	leashStatus map[string]*cachedStatus
	leashGrants json.RawMessage // the latest leash.grant.updated body

	ik       ed25519.PrivateKey
	kem      *suite.PrivateKey
	relayKey ed25519.PrivateKey
	own      *relayclient.Client

	keyring  *handshake.Keyring
	ini      *handshake.Initiator
	sas      string // the SAS of the last pairing handshake (0.10.3)
	hsFailed bool   // the last hs.resp aborted the handshake
	awaiting []*handshake.Responder
	events   []*envelope.Inner
	pending  *pendingUnlock
	lastUTK  UTK

	// sem (capacity 1) serializes every Poll (collect, handle, Persist,
	// deposits, acks) and every outbox flush; taking it honours the
	// caller's context.
	sem chan struct{}
	// wake is closed and replaced (mu held) at the end of every Poll and
	// when Run stops: waiting calls wait on it while Run collects.
	wake chan struct{}
	// running: Run collects; runDone is closed when it stops.
	running bool
	runDone chan struct{}
	// batching is set (with mu held) while a batch is handled for
	// Persist: deposits go to the outbox instead of the relay.
	batching bool
	// nextSeq numbers outbox entries as they are queued; savedSeq is the
	// highest a successful Persist (or the loaded state) holds: only
	// entries up to it are deposited, so that nothing leaves before it
	// is saved. Entries are found by their number, never by position,
	// so removing some (startPairing) cannot shift what a flush tried.
	nextSeq, savedSeq uint64
	// dirty: a handled batch is not saved yet (its Persist failed); the
	// next Poll calls Persist again before collecting. held keeps the
	// responses and events of unsaved batches from the waiting calls.
	dirty bool
	held  []*envelope.Inner
	// outboxFails counts consecutive transient outbox failures;
	// outboxNext is when the outbox may be tried again (§8.6 backoff).
	outboxFails int
	outboxNext  time.Time
	// finErr: this pairing's hs.fin left the outbox without being
	// deposited. refused: the vault's mailbox answered token_revoked.
	finErr  error
	refused error
	// persistErr is the last Persist error while the device is dirty.
	persistErr error
}

func (c *Config) defaults() {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 60 * time.Second}
	}
	if c.PollWait == 0 {
		c.PollWait = 2 * time.Second
	}
	c.RelayURL = strings.TrimRight(c.RelayURL, "/")
}

// New creates a device with fresh keys and registers its mailbox.
func New(ctx context.Context, cfg Config) (*Device, error) {
	d, err := Generate(cfg)
	if err != nil {
		return nil, err
	}
	if _, err := d.own.Register(ctx); err != nil {
		return nil, err
	}
	return d, nil
}

// Generate creates a device with fresh keys without registering its
// mailbox (in-process tests; New registers).
func Generate(cfg Config) (*Device, error) {
	cfg.defaults()
	st := &State{Role: cfg.Role, Name: cfg.Name, RelayURL: cfg.RelayURL}
	for _, p := range []*[]byte{&st.IKSeed, &st.KEMSeed, &st.RelaySeed} {
		b, err := suite.RandomBytes(32)
		if err != nil {
			return nil, err
		}
		*p = b
	}
	return open(cfg, st)
}

// Load restores a device from Save output.
func Load(cfg Config, data []byte) (*Device, error) {
	cfg.defaults()
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	if cfg.Role == "" {
		cfg.Role, cfg.Name = st.Role, st.Name
	}
	if cfg.RelayURL == "" {
		cfg.RelayURL = st.RelayURL
	}
	return open(cfg, &st)
}

func open(cfg Config, st *State) (*Device, error) {
	if st.Seen == nil {
		st.Seen = map[string]time.Time{}
	}
	d := &Device{cfg: cfg, st: st, sem: make(chan struct{}, 1), wake: make(chan struct{}),
		ik: ed25519.NewKeyFromSeed(st.IKSeed), relayKey: ed25519.NewKeyFromSeed(st.RelaySeed)}
	var err error
	if d.kem, err = suite.NewPrivateKey(st.KEMSeed); err != nil {
		return nil, err
	}
	d.own = d.relayClient(st.RelayURL)
	for i := range st.Outbox {
		d.nextSeq++
		st.Outbox[i].seq = d.nextSeq
	}
	d.savedSeq = d.nextSeq
	d.keyring = &handshake.Keyring{}
	if st.Vault != nil {
		if d.keyring, err = handshake.ImportKeyring(st.Vault.Sessions); err != nil {
			return nil, err
		}
	}
	if st.Outgoing != nil {
		if d.ini, err = handshake.RestoreInitiator(*st.Outgoing, d.ik); err != nil {
			return nil, err
		}
	}
	for _, a := range st.Awaiting {
		r, err := handshake.RestoreResponder(a)
		if err != nil {
			return nil, err
		}
		d.awaiting = append(d.awaiting, r)
	}
	return d, nil
}

func (d *Device) relayClient(url string) *relayclient.Client {
	c := relayclient.New(url, d.relayKey)
	c.HTTP, c.Now = d.cfg.HTTP, d.cfg.Now
	return c
}

// Save returns the device state (secret).
func (d *Device) Save() ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.export()
	return json.Marshal(d.st)
}

func (d *Device) export() {
	if d.st.Vault != nil {
		d.st.Vault.Sessions = d.keyring.Export()
	}
	d.st.Outgoing = nil
	if d.ini != nil {
		if s, err := d.ini.Export(); err == nil {
			d.st.Outgoing = &s
		}
	}
	d.st.Awaiting = nil
	for _, r := range d.awaiting {
		if s, err := r.Export(); err == nil {
			d.st.Awaiting = append(d.st.Awaiting, s)
		}
	}
}

// RelayAddr returns the device's relay address.
func (d *Device) RelayAddr() handshake.RelayAddr {
	pk := d.relayKey.Public().(ed25519.PublicKey)
	return handshake.RelayAddr{URL: d.st.RelayURL, Mailbox: relayauth.MailboxID(pk), PK: pk}
}

// IdentityKey returns the device's ik.
func (d *Device) IdentityKey() ed25519.PublicKey { return d.ik.Public().(ed25519.PublicKey) }

// KEMKey returns the device's static KEM key.
func (d *Device) KEMKey() *suite.PublicKey { return d.kem.Public() }

// VaultID returns the vault id once known.
func (d *Device) VaultID() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.st.VaultID
}

// Paired returns what device.paired told this device, and false before
// it arrived. After AwaitPaired it holds that message's fields, e.g. the
// first access session's end (Paired.SessionExpiresAt).
func (d *Device) Paired() (Paired, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.st.Paired == nil {
		return Paired{}, false
	}
	return *d.st.Paired, true
}

// DeviceID returns the id the vault assigned (from device.paired).
func (d *Device) DeviceID() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.st.DeviceID
}

// OpenToken mints a one-shot open token for the device's mailbox, for the
// vault's first deposit at enrollment (§7.1: ≤ 10 min).
func (d *Device) OpenToken() (string, error) {
	return d.own.MintOpenToken(d.st.RelayURL, 10*time.Minute, "")
}

// VaultMailbox returns the relay URL and mailbox id of the vault this
// device is paired with ("" before pairing).
func (d *Device) VaultMailbox() (url, mailbox string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.st.Vault == nil {
		return "", ""
	}
	return d.st.Vault.RelayURL, d.st.Vault.Mailbox
}

func (d *Device) vaultPeerAddr() (url, mailbox string, pk ed25519.PublicKey) {
	v := d.st.Vault
	return v.RelayURL, v.Mailbox, v.RelayPK
}

// mintForVault issues a standing token for the vault (sub = vault relay key).
func (d *Device) mintForVault() (string, error) {
	_, _, pk := d.vaultPeerAddr()
	ttl := 30 * 24 * time.Hour
	tok, err := d.own.MintToken(relayauth.EncodeKey(pk), d.st.RelayURL, relayclient.TokenOptions{TTL: ttl})
	if err == nil {
		d.st.IssuedExp = d.cfg.Now().Add(ttl - time.Minute)
	}
	return tok, err
}

// heldFromVault validates a token the vault issued to this device.
func (d *Device) heldFromVault(tok string) (time.Time, error) {
	v := d.st.Vault
	msg, err := relayauth.VerifyToken(tok, v.RelayPK)
	if err != nil {
		return time.Time{}, ErrToken
	}
	c, err := relayauth.ParseClaims(msg)
	if err != nil || c.Iss != v.Mailbox || c.Sub != relayauth.EncodeKey(d.relayKey.Public().(ed25519.PublicKey)) {
		return time.Time{}, ErrToken
	}
	return c.Exp, nil
}

func (d *Device) setVaultFromPrincipal(pr handshake.Principal) {
	d.st.Vault = &VaultRecord{IK: pr.IK, KEM: pr.KEM.Bytes(), RelayURL: pr.Relay.URL, Mailbox: pr.Relay.Mailbox, RelayPK: pr.Relay.PK}
}

func (d *Device) policy() handshake.Policy { return handshake.PolicyVaultToDevice }

// AwaitEnrolled waits for vault.enrolled (§11.3), sealed to this device's
// KEM key and deposited on its open token, and pins the vault bundle. Dev
// builds carry no attestation; real apps verify it here (phase V3/V6).
func (d *Device) AwaitEnrolled(ctx context.Context) error {
	_, err := d.waitFor(ctx, func(in *envelope.Inner) bool { return in.Type == "vault.enrolled" })
	return err
}

// CompleteEnrollment runs the first app's handshake (purpose app, ctx =
// vault id) and waits for device.paired.
func (d *Device) CompleteEnrollment(ctx context.Context) error {
	d.mu.Lock()
	if d.st.Vault == nil || d.st.Vault.Token == "" {
		d.mu.Unlock()
		return ErrNotPaired
	}
	err := d.startInit(handshake.PurposeApp, d.st.VaultID, d.st.Vault.Token, nil)
	d.mu.Unlock()
	if err != nil {
		return err
	}
	// The hs.fin first: if it is refused for good, the vault never sends
	// device.paired (ErrHandshakeUnsent, ErrRefused).
	if _, err := d.awaitHandshake(ctx); err != nil {
		return err
	}
	return d.awaitPaired(ctx)
}

// Pair starts pairing from a QR / link shown by an already paired app
// (§6.7). The vault answers hs.init at once; Pair completes the handshake
// (hs.fin) and returns the SAS to compare (0.10.3). Then call AwaitPaired,
// which waits for the owner's approval (device.paired).
func (d *Device) Pair(ctx context.Context, link string) (string, error) {
	return d.PairAttested(ctx, link, nil)
}

// PairAttested is Pair for an app with a device attestation key: hs.init
// carries device_attest over the challenge DevattChallenge(hs.init id, "",
// hs.init ts) (§6.7, §11.7).
func (d *Device) PairAttested(ctx context.Context, link string, att Attester) (string, error) {
	if err := d.startPairing(ctx, link, att); err != nil {
		return "", err
	}
	return d.awaitHandshake(ctx)
}

// awaitHandshake waits until the vault's hs.resp completed the handshake
// and returns its SAS.
func (d *Device) awaitHandshake(ctx context.Context) (string, error) {
	var sas string
	var err error
	done := func() bool {
		if d.ini != nil {
			return false
		}
		finErr, finQueued := d.finErr, d.queued("hs.fin")
		switch {
		case d.hsFailed || d.sas == "":
			err = ErrProtocol
		case finErr != nil:
			err = finErr
		case finQueued:
			return false
		default:
			// The hs.fin is deposited (with Config.Persist: after the
			// batch that made it was saved), so the vault can finish the
			// handshake the SAS belongs to.
			sas = d.sas
		}
		return true
	}
	if werr := d.waitUntil(ctx, done); werr != nil {
		return "", werr
	}
	return sas, err
}

func (d *Device) startPairing(ctx context.Context, link string, att Attester) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.refused != nil {
		// Before anything else: fetching the claim would spend the
		// owner's single-use link, and opening it would replace the vault
		// record, whose mailbox may still hold the device.unlinked a
		// refused device acts on (§8.6). A re-pairing uses a new Device.
		return d.refused
	}
	q, err := invite.ParseLink(link)
	if err != nil {
		return err
	}
	want := map[string]invite.Kind{"app": invite.KindApp, "desktop": invite.KindDesktop, "agent": invite.KindAgent}[d.st.Role]
	if q.Kind != want {
		return ErrProtocol
	}
	blob, err := d.relayClient(q.Relay).GetClaim(ctx, q.ClaimID)
	if err != nil {
		return err
	}
	b, err := invite.OpenBundle(blob, q, d.cfg.Now())
	if err != nil {
		return err
	}
	d.setVaultFromPrincipal(b.Vault)
	profile := strictjson.NewBuilder().String("name", d.st.Name).Bytes()
	var da *altchan.DeviceAttest
	var id string
	now := d.cfg.Now().UTC().Truncate(time.Millisecond)
	if att != nil && d.st.Role == "app" {
		if id, err = envelope.NewULID(now); err != nil {
			return err
		}
		ch, err := altchan.DevattChallenge(id, "", envelope.FormatTS(now))
		if err != nil {
			return err
		}
		if da, err = att.Attest(ch); err != nil {
			return err
		}
		d.keepChain(da)
	}
	var apiKey []byte
	if d.st.Role == "app" {
		// An app pairs only as a transfer's new app: its hs.init carries
		// its app key (0.15.0, §6.2, §6.7.1).
		if _, apiKey, err = d.appKeyLocked(); err != nil {
			return err
		}
	}
	return d.startInitWith(handshake.Purpose(d.st.Role), b.InviteID, b.Token, profile, da, id, now, apiKey)
}

// AwaitPaired waits for device.paired, which the vault sends at the
// owner's approval with the device's standing token (§6.7, 0.10.3), or
// device.pair.rejected, the owner's rejection (0.10.5), which ends the
// wait with ErrPairRejected.
func (d *Device) AwaitPaired(ctx context.Context) error { return d.awaitPaired(ctx) }

func (d *Device) awaitPaired(ctx context.Context) error {
	in, err := d.waitFor(ctx, func(in *envelope.Inner) bool {
		return in.Type == "device.paired" || in.Type == devicePairRejected
	})
	if err != nil {
		return err
	}
	if in.Type == devicePairRejected {
		return ErrPairRejected
	}
	// handle recorded the device id, vault id and release.
	if _, err := strictjson.ParseObject(in.Body); err != nil {
		return ErrProtocol
	}
	return nil
}

// startInit sends hs.init to the vault on depositToken.
func (d *Device) startInit(purpose handshake.Purpose, ctxID, depositToken string, profile json.RawMessage) error {
	return d.startInitWith(purpose, ctxID, depositToken, profile, nil, "", d.cfg.Now(), nil)
}

func (d *Device) startInitWith(purpose handshake.Purpose, ctxID, depositToken string, profile json.RawMessage, da *altchan.DeviceAttest, id string, now time.Time,
	apiKey []byte) error {
	if d.refused != nil {
		// This device's relay key is refused by the vault's mailbox, and a
		// re-pairing must use a new relay key (§6.7): a new Device.
		return d.refused
	}
	// An earlier pairing's hs.fin still waiting must neither fail nor
	// delay this one.
	d.removeOutbox(func(o OutboxEntry) bool { return o.Kind == "hs.fin" })
	// Nothing from an earlier handshake on this Device (an aborted hs.resp,
	// its SAS, a dropped hs.fin) carries over to this one.
	d.sas, d.hsFailed, d.finErr = "", false, nil
	v := d.st.Vault
	ek, err := suite.ParsePublicKey(v.KEM)
	if err != nil {
		return err
	}
	tok, err := d.mintForVault()
	if err != nil {
		return err
	}
	var secret []byte
	if apiKey != nil && purpose == handshake.PurposeApp {
		// A transfer's new phone (release R, §11.14.10): a new phone key,
		// and its secret of epoch 1 in the hs.init.
		if err := d.newPhoneKeyLocked(d.st.VaultID); err != nil {
			return err
		}
		secret = d.unlockSecretLocked(1)
	}
	ini, err := handshake.NewInitiator(handshake.InitiatorConfig{
		Purpose: purpose, Ctx: ctxID, Identity: d.ik, StaticKEM: d.kem.Public(), Relay: d.RelayAddr(),
		Token: tok, Profile: profile, ResponderIK: v.IK, ResponderEK: ek, ResponderRelayKey: v.RelayPK,
		Policy: d.policy(), Now: now, ID: id, DeviceAttest: da, APIKey: apiKey, UnlockSecret: secret,
	})
	if err != nil {
		return err
	}
	if _, err := d.relayClient(v.RelayURL).Deposit(context.Background(), v.Mailbox, depositToken, ini.Envelope()); err != nil {
		return err
	}
	d.ini = ini
	d.st.PairingPending = true
	return nil
}

// Response is a decoded response.
type Response struct {
	Inner *envelope.Inner
}

// OK reports whether the response status is ok.
func (r *Response) OK() bool { return r.Inner.Status == envelope.StatusOK }

// ErrorCode returns the error code of an error response.
func (r *Response) ErrorCode() string {
	if r.Inner.Error == nil {
		return ""
	}
	return r.Inner.Error.Code
}

// Body returns the response body.
func (r *Response) Body() json.RawMessage { return r.Inner.Body }

// Send seals a message to the vault in the current epoch and deposits it.
// It returns the inner id.
func (d *Device) Send(ctx context.Context, typ string, body json.RawMessage) (string, error) {
	return d.SendWithID(ctx, "", typ, body)
}

// SendWithID is Send with a caller-chosen inner id (a retransmission reuses
// the id, §5.3).
func (d *Device) SendWithID(ctx context.Context, id, typ string, body json.RawMessage) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sendLocked(ctx, id, typ, body, "", "")
}

func (d *Device) sendLocked(ctx context.Context, id, typ string, body json.RawMessage, re, status string) (string, error) {
	return d.sendFull(ctx, id, typ, body, re, status, time.Time{})
}

func (d *Device) sendFull(ctx context.Context, id, typ string, body json.RawMessage, re, status string, exp time.Time) (string, error) {
	v := d.st.Vault
	if v == nil || v.Token == "" || d.keyring.Current() == nil {
		return "", ErrNotPaired
	}
	now := d.cfg.Now()
	if id == "" {
		var err error
		if id, err = envelope.NewULID(now); err != nil {
			return "", err
		}
	}
	in := &envelope.Inner{ID: id, Type: typ, TS: now, Exp: exp, Body: body, Re: re, Status: status}
	raw, err := d.keyring.Current().Seal(in)
	if err != nil {
		return "", err
	}
	if err := d.depositVault(ctx, outboxKind(typ, re), v.RelayURL, v.Mailbox, v.Token, raw); err != nil {
		return "", err
	}
	return id, nil
}

// Request sends a request and waits for its response (§8.1).
func (d *Device) Request(ctx context.Context, typ string, body json.RawMessage) (*Response, error) {
	id, err := d.Send(ctx, typ, body)
	if err != nil {
		return nil, err
	}
	return d.AwaitResponse(ctx, id)
}

// AwaitResponse waits for the response to request id.
func (d *Device) AwaitResponse(ctx context.Context, id string) (*Response, error) {
	in, err := d.waitFor(ctx, func(in *envelope.Inner) bool { return in.Re == id })
	if err != nil {
		return nil, err
	}
	return &Response{Inner: in}, nil
}

// WaitEvent waits for an event of the given type (and optional predicate
// on its body), returning it. Events seen earlier are searched first.
func (d *Device) WaitEvent(ctx context.Context, typ string, pred func(json.RawMessage) bool) (*envelope.Inner, error) {
	return d.waitFor(ctx, func(in *envelope.Inner) bool {
		return in.Type == typ && in.Re == "" && (pred == nil || pred(in.Body))
	})
}

// Events returns and clears the buffered events.
func (d *Device) Events() []*envelope.Inner {
	d.mu.Lock()
	defer d.mu.Unlock()
	ev := d.events
	d.events = nil
	return ev
}

// waitFor waits until match accepts a received message, which is
// removed from the buffer and returned.
func (d *Device) waitFor(ctx context.Context, match func(*envelope.Inner) bool) (*envelope.Inner, error) {
	var got *envelope.Inner
	err := d.waitUntil(ctx, func() bool {
		for i, ev := range d.events {
			if match(ev) {
				d.events = append(d.events[:i:i], d.events[i+1:]...)
				got = ev
				return true
			}
		}
		return false
	})
	return got, err
}

// waitUntil waits until done (called with mu held) reports true. While
// Run collects, it waits for Run's Polls (VAULT-MESSAGING §8.1: one
// collector, which dispatches); otherwise it collects itself, as before
// Run existed. Either way done is checked again after every Poll, and a
// waiter that had to wait for another's Poll checks it again before
// collecting, so it never long-polls for a message already buffered.
func (d *Device) waitUntil(ctx context.Context, done func() bool) error {
	fails := 0
	for {
		d.mu.Lock()
		if done() {
			d.mu.Unlock()
			return nil
		}
		if d.running {
			wake, stopped := d.wake, d.runDone
			d.mu.Unlock()
			select {
			case <-wake:
			case <-stopped:
			case <-ctx.Done():
				return d.ctxErr(ctx)
			}
			continue
		}
		d.mu.Unlock()
		if err := d.ctxErr(ctx); err != nil {
			return err
		}
		hit := false
		err := d.poll(ctx, func() bool {
			hit = done()
			return hit || d.running
		})
		if hit {
			return nil
		}
		if err == nil || ctx.Err() != nil {
			fails = 0
			continue
		}
		// A failed Poll (relay or Persist error): back off as Run does.
		fails++
		t := time.NewTimer(outboxBackoff(fails))
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return d.ctxErr(ctx)
		}
	}
}

// acquire takes sem, or returns the context's error.
func (d *Device) acquire(ctx context.Context) error {
	select {
	case d.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *Device) release() { <-d.sem }

// wakeLocked wakes the waiting calls. d.mu is held.
func (d *Device) wakeLocked() {
	close(d.wake)
	d.wake = make(chan struct{})
}

// Run collects from the device's mailbox and dispatches what arrives
// until ctx ends, and returns ctx's error (ErrRunning if it already
// runs). While it runs, the waiting calls (Request, AwaitResponse,
// WaitEvent, Op, LeashPresent, the pairing waits) wait for its Polls
// instead of collecting themselves, so concurrent callers do not take
// each other's messages (§8.1). Each Poll is a long poll of
// Config.PollWait. A Poll error goes to Config.RunError, and Run polls
// again after a backoff (full jitter from 0.25 s, doubling, capped at
// 30 s), which a successful Poll resets: after a Persist error that is
// the retry, and a refused device keeps collecting (§8.6). When Run
// stops, waiting calls go back to collecting themselves.
func (d *Device) Run(ctx context.Context) error {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return ErrRunning
	}
	d.running, d.runDone = true, make(chan struct{})
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.running = false
		close(d.runDone)
		d.wakeLocked()
		d.mu.Unlock()
	}()
	fails := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := d.poll(ctx, nil)
		if err == nil {
			fails = 0
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if f := d.cfg.RunError; f != nil {
			f(err)
		}
		fails++
		t := time.NewTimer(outboxBackoff(fails))
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		}
	}
}

// Poll collects once from the device's mailbox and processes what arrived.
// With Config.Persist set, it first deposits what waits in the outbox,
// then handles the batch, calls Persist, deposits the batch's outbox
// entries and acknowledges the batch; a Persist error is returned and
// leaves the batch unacknowledged. Polls never overlap: a Poll waits for
// the one in progress (or for ctx to end).
// While Run runs, Poll returns ErrRunning: Run is the one collector.
func (d *Device) Poll(ctx context.Context) error {
	d.mu.Lock()
	running := d.running
	d.mu.Unlock()
	if running {
		return ErrRunning
	}
	return d.poll(ctx, nil)
}

// poll is Poll; skip (called with mu held, once sem is taken) ends it
// early without collecting, for a waiter whose message arrived during
// the Poll it waited for.
func (d *Device) poll(ctx context.Context, skip func() bool) error {
	if err := d.acquire(ctx); err != nil {
		return err
	}
	defer d.release()
	if skip != nil {
		d.mu.Lock()
		ok := skip()
		d.mu.Unlock()
		if ok {
			return nil
		}
	}
	defer func() {
		d.mu.Lock()
		d.wakeLocked()
		d.mu.Unlock()
	}()
	if d.cfg.Persist != nil {
		return d.pollPersist(ctx)
	}
	ferr := d.flushOutboxLocked(ctx) // a state saved under Persist may still hold some
	msgs, err := d.own.Collect(ctx, d.cfg.PollWait, 32)
	if err != nil {
		return errors.Join(ferr, err)
	}
	d.mu.Lock()
	before := d.refused
	d.mu.Unlock()
	for _, m := range msgs {
		// Unlocked by defer, so that a panic in handle unwinds through
		// poll's deferred wake and release instead of deadlocking.
		func() {
			d.mu.Lock()
			defer d.mu.Unlock()
			d.handle(ctx, m)
		}()
		_ = d.own.Ack(ctx, m.MsgID)
	}
	d.mu.Lock()
	if before == nil && d.refused != nil {
		// A deposit made while handling (a rekey's hs.resp, a token)
		// was refused in this Poll.
		ferr = errors.Join(ferr, d.refused)
	}
	d.mu.Unlock()
	return ferr
}

// pollPersist is Poll with Config.Persist: save before acknowledging
// (§8.3). A message of the batch that is collected again, after a
// Persist error or a crash between Persist and the acks, is skipped by
// the msg_id dedupe (State.Seen, saved with the batch's effects) and
// acknowledged after the next Persist.
//
// After a Persist error the device is dirty: the next Poll calls Persist
// again first, before collecting, so the batch's deposits (a pairing's
// hs.fin) need not wait for the relay to deliver the batch again. Until
// a batch is saved, its responses and events are held back from the
// waiting calls, so nothing is reported to the caller that a crash
// could still undo.
//
// The returned error joins the Persist error, the collect error and the
// outbox's terminal deposit errors (ErrRefused, ErrOutboxDropped);
// transient deposit failures are retried later and not returned.
func (d *Device) pollPersist(ctx context.Context) error {
	d.mu.Lock()
	dirty := d.dirty
	d.mu.Unlock()
	if dirty {
		if err := d.saveLocked(); err != nil {
			return err
		}
	}
	ferr := d.flushOutboxLocked(ctx)
	msgs, err := d.own.Collect(ctx, d.cfg.PollWait, 32)
	if err != nil {
		return errors.Join(ferr, err)
	}
	if len(msgs) == 0 {
		return ferr
	}
	fresh := d.handleBatch(ctx, msgs)
	// A batch of messages already handled and saved (a redelivery after
	// a crash between Persist and the acks) changes nothing to save.
	if fresh {
		if err := d.saveLocked(); err != nil {
			return errors.Join(ferr, err)
		}
		ferr = errors.Join(ferr, d.flushOutboxLocked(ctx))
	}
	for _, m := range msgs {
		// Acked also when its answer was refused (§8.6 "A refused answer
		// does not block the mailbox").
		_ = d.own.Ack(ctx, m.MsgID)
	}
	return ferr
}

// handleBatch handles a batch for Persist, unless all of it is already
// handled and saved, and reports whether it handled any. The device
// lock is released and batching reset by defer, so a panic in handle
// unwinds cleanly. The caller holds sem.
func (d *Device) handleBatch(ctx context.Context, msgs []relayclient.Message) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	fresh := false
	for _, m := range msgs {
		_, seen := d.st.Seen[m.MsgID]
		fresh = fresh || !seen
	}
	if !fresh {
		return false
	}
	d.batching, d.dirty = true, true
	defer func() { d.batching = false }()
	for _, m := range msgs {
		d.handle(ctx, m)
	}
	return true
}

// saveLocked calls Persist with the state; sem is held. On success
// the outbox entries it holds may be deposited and the held responses
// and events reach the waiting calls; on failure the device stays dirty.
func (d *Device) saveLocked() error {
	d.mu.Lock()
	d.export()
	state, err := json.Marshal(d.st)
	queued := d.nextSeq
	d.mu.Unlock()
	if err != nil {
		return err
	}
	err = d.cfg.Persist(state)
	suite.Wipe(state)
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		d.dirty = true
		d.persistErr = fmt.Errorf("client: persist: %w", err)
		return d.persistErr
	}
	d.dirty, d.persistErr = false, nil
	d.savedSeq = queued
	d.events = append(d.events, d.held...)
	d.held = nil
	return nil
}

// emit hands a handled message to the waiting calls, or holds it while
// its batch is not saved. d.mu is held.
func (d *Device) emit(in *envelope.Inner) {
	if d.batching || d.dirty {
		d.held = append(d.held, in)
		return
	}
	d.events = append(d.events, in)
}

// PersistError returns the last Persist error while what the device has
// handled is not saved (nil once a Persist succeeds). The waiting calls
// also return it, joined to their context's error, when their context
// ends while it is set.
func (d *Device) PersistError() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.persistErr
}

// ctxErr is ctx's error, joined to the last Persist error if what the
// device handled is not saved: a caller whose wait ended learns why
// nothing arrived.
func (d *Device) ctxErr(ctx context.Context) error {
	err := ctx.Err()
	if err == nil {
		return nil
	}
	if perr := d.PersistError(); perr != nil {
		return errors.Join(err, perr)
	}
	return err
}

// Refused returns the ErrRefused error once the vault's mailbox has
// answered a deposit of this device token_revoked (nil before). It stays
// set for the life of this Device.
func (d *Device) Refused() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.refused
}

// outboxKind classifies a message for the outbox (OutboxEntry.Kind).
func outboxKind(typ, re string) string {
	switch {
	case typ == "relay.token.issued", typ == "relay.token.refresh" && re != "":
		return "token"
	case typ == "relay.token.refresh":
		return "refresh"
	}
	return ""
}

// depositVault deposits an envelope into the vault's mailbox, or, while
// a batch is handled for Persist, puts it in the outbox. After the
// mailbox answered token_revoked it sends nothing and returns that
// refusal (§8.6). d.mu is held.
func (d *Device) depositVault(ctx context.Context, kind, relayURL, mailbox, token string, payload []byte) error {
	if d.refused != nil {
		return d.refused
	}
	if d.batching {
		d.queueLocked(OutboxEntry{Kind: kind, RelayURL: relayURL, Mailbox: mailbox,
			Payload: append([]byte(nil), payload...), Created: d.cfg.Now()})
		return nil
	}
	_, err := d.relayClient(relayURL).Deposit(ctx, mailbox, token, payload)
	if relayclient.IsCode(err, "token_revoked") {
		d.refused = fmt.Errorf("%w: %w", ErrRefused, err)
		return d.refused
	}
	return err
}

// queueLocked appends an entry to the outbox. A "token" or "refresh"
// entry replaces the waiting ones of its kind: only the newest standing
// token for the vault, and one refresh request, are worth sending. Past
// outboxCap entries the oldest is dropped. d.mu is held.
func (d *Device) queueLocked(e OutboxEntry) {
	if e.Kind == "token" || e.Kind == "refresh" {
		d.removeOutbox(func(o OutboxEntry) bool { return o.Kind == e.Kind })
	}
	d.nextSeq++
	e.seq = d.nextSeq
	d.st.Outbox = append(d.st.Outbox, e)
	for len(d.st.Outbox) > outboxCap {
		if d.st.Outbox[0].Kind == "hs.fin" {
			d.finErr = ErrHandshakeUnsent
		}
		d.st.Outbox = d.st.Outbox[1:]
	}
}

// removeOutbox removes the entries drop selects. d.mu is held.
func (d *Device) removeOutbox(drop func(OutboxEntry) bool) {
	var kept []OutboxEntry
	for _, o := range d.st.Outbox {
		if !drop(o) {
			kept = append(kept, o)
		}
	}
	d.st.Outbox = kept
}

// dropOutboxLocked empties the outbox (the vault record is gone).
func (d *Device) dropOutboxLocked() {
	d.removeOutbox(func(OutboxEntry) bool { return true })
}

// queued reports whether an outbox entry of the kind waits. d.mu is held.
func (d *Device) queued(kind string) bool {
	for _, o := range d.st.Outbox {
		if o.Kind == kind {
			return true
		}
	}
	return false
}

// flushOutboxLocked deposits the saved outbox entries in order (an entry from
// a batch whose Persist failed waits for the next successful one), on
// the vault token held now, and returns the terminal errors.
//
//   - Accepted: the entry leaves the outbox.
//   - Refused with token_revoked: the device is refused (ErrRefused,
//     Refused) and every entry is dropped; nothing more is sent (§8.6).
//   - Refused with another client error than 429: the entry is dropped,
//     the error returned wrapped in ErrOutboxDropped.
//   - 429, 5xx or a transport error: it and the rest stay, and the
//     outbox is not tried again before a backoff (full jitter from
//     0.25 s doubling, capped at 30 s, or the relay's retry_after if
//     longer; §8.6).
//   - Dropped without a deposit: an entry older than outboxMaxAge, or
//     one whose relay URL or mailbox is no longer the vault record's
//     (or with no vault record).
//
// A dropped hs.fin fails the pairing's awaitHandshake (ErrHandshakeUnsent
// or the refusal). A removal is saved with the next Persist, so an entry
// deposited just before a crash is deposited again: the vault drops the
// second hs.resp or hs.fin of a handshake it has finished and dedupes
// the rest by their inner id (§8.2). sem is held.
func (d *Device) flushOutboxLocked(ctx context.Context) error {
	now := d.cfg.Now()
	d.mu.Lock()
	var out []OutboxEntry
	for _, e := range d.st.Outbox {
		if e.seq <= d.savedSeq {
			out = append(out, e)
		}
	}
	if len(out) == 0 || now.Before(d.outboxNext) {
		d.mu.Unlock()
		return nil
	}
	var url, mailbox, tok string
	if v := d.st.Vault; v != nil {
		url, mailbox, tok = v.RelayURL, v.Mailbox, v.Token
	}
	refused := d.refused
	d.mu.Unlock()
	var errs []error
	// finErrs: why a tried hs.fin was dropped, by entry number.
	finErrs := map[uint64]error{}
	drop := func(e OutboxEntry, err error) {
		if e.Kind == "hs.fin" {
			finErrs[e.seq] = ErrHandshakeUnsent
			if errors.Is(err, ErrRefused) {
				finErrs[e.seq] = err
			} else if err != nil {
				finErrs[e.seq] = fmt.Errorf("%w: %w", ErrHandshakeUnsent, err)
			}
		}
	}
	i, sent, backoff := 0, false, time.Duration(0)
loop:
	for ; i < len(out); i++ {
		e := out[i]
		if refused != nil || tok == "" || e.RelayURL != url || e.Mailbox != mailbox || now.Sub(e.Created) > outboxMaxAge {
			drop(e, refused)
			continue
		}
		_, err := d.relayClient(e.RelayURL).Deposit(ctx, e.Mailbox, tok, e.Payload)
		var re *relayclient.Error
		switch {
		case err == nil:
			sent = true
		case relayclient.IsCode(err, "token_revoked"):
			refused = fmt.Errorf("%w: %w", ErrRefused, err)
			errs = append(errs, refused)
			drop(e, refused)
		case errors.As(err, &re) && re.Status >= 400 && re.Status < 500 && re.Status != http.StatusTooManyRequests:
			errs = append(errs, fmt.Errorf("%w (%s): %w", ErrOutboxDropped, e.Kind, err))
			drop(e, err)
		default:
			backoff = retryAfter(err)
			break loop
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	// Remove the entries tried (sent or dropped), by number: the outbox
	// may have changed meanwhile. A dropped hs.fin fails its pairing
	// only if it is still waiting (a new pairing removes an older one).
	tried := map[uint64]bool{}
	for _, e := range out[:i] {
		tried[e.seq] = true
	}
	for _, e := range d.st.Outbox {
		if err := finErrs[e.seq]; err != nil && tried[e.seq] {
			d.finErr = err
		}
	}
	d.removeOutbox(func(o OutboxEntry) bool { return tried[o.seq] })
	if refused != nil {
		if d.refused == nil {
			d.refused = refused
		}
		d.dropOutboxLocked()
	}
	switch {
	case i < len(out): // a transient failure
		d.outboxFails++
		wait := outboxBackoff(d.outboxFails)
		if backoff > wait {
			wait = backoff
		}
		d.outboxNext = now.Add(wait)
	case sent:
		d.outboxFails, d.outboxNext = 0, time.Time{}
	}
	return errors.Join(errs...)
}

// retryAfter is a relay error's retry_after, at most maxRetryAfter
// seconds (0 without one).
func retryAfter(err error) time.Duration {
	var re *relayclient.Error
	if !errors.As(err, &re) || re.RetryAfter <= 0 {
		return 0
	}
	return time.Duration(min(re.RetryAfter, maxRetryAfter)) * time.Second
}

// outboxBackoff is the wait after n consecutive transient failures:
// full jitter over 0.25 s × 2ⁿ⁻¹, capped at 30 s (§8.6).
func outboxBackoff(n int) time.Duration {
	c := 250 * time.Millisecond << min(n-1, 7)
	if c > 30*time.Second {
		c = 30 * time.Second
	}
	return rand.N(c) + 1
}

// Deliver processes one message as if collected (in-process tests).
// With Config.Persist it is handled as a batch of one: saved (the error,
// if any, is PersistError, and the next Poll saves again), then its
// deposits are made.
func (d *Device) Deliver(ctx context.Context, m relayclient.Message) {
	if d.cfg.Persist == nil {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.handle(ctx, m)
		return
	}
	if err := d.acquire(ctx); err != nil {
		return
	}
	defer d.release()
	func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.batching, d.dirty = true, true
		defer func() { d.batching = false }()
		d.handle(ctx, m)
	}()
	if d.saveLocked() == nil {
		_ = d.flushOutboxLocked(ctx)
	}
}

// testHandleHook, set only by tests, runs at the start of handle.
var testHandleHook func(relayclient.Message)

// handle processes one collected message. Classification is by sender and
// recipient kid only (§13.6).
func (d *Device) handle(ctx context.Context, m relayclient.Message) {
	if testHandleHook != nil {
		testHandleHook(m)
	}
	if _, seen := d.st.Seen[m.MsgID]; seen {
		return
	}
	now := d.cfg.Now()
	d.st.Seen[m.MsgID] = now
	for k, t := range d.st.Seen {
		if now.Sub(t) > 16*24*time.Hour {
			delete(d.st.Seen, k)
		}
	}
	sender, ok := relayauth.DecodeKey(m.Sender)
	if !ok {
		return
	}
	env, err := envelope.Parse(m.Payload)
	if err != nil {
		return
	}
	v := d.st.Vault
	if env.Mode() == envelope.ModeSealed {
		switch {
		case env.RecipientKid().Equal(d.kem.Public().Kid()):
			d.handleEnrolled(env, sender)
		case d.ini != nil && env.RecipientKid().Equal(d.ini.EphKid()):
			d.handleResp(ctx, m.Payload, sender)
		}
		return
	}
	if v == nil || !suite.EqualPublic(sender, v.RelayPK) {
		return // §6.3: only the vault's relay key may send to a device
	}
	in, ep, err := d.keyring.Open(env, now)
	if err != nil {
		for i, r := range d.awaiting {
			rk, sk := r.Kids()
			if env.RecipientKid().Equal(rk) && env.SenderKid().Equal(sk) {
				fr, err := r.HandleFin(m.Payload, sender, now)
				if err == nil {
					d.keyring.Activate(fr.Epoch, now)
					d.awaiting = append(d.awaiting[:i:i], d.awaiting[i+1:]...)
				}
				return
			}
		}
		return
	}
	if in.Type == handshake.TypeInit {
		d.handleRekey(ctx, m.Payload, in, ep, sender, now)
		return
	}
	if err := in.CheckTime(now, in.Exp.IsZero()); err != nil {
		return
	}
	switch in.Type {
	case devicePairRejected:
		// §6.7 (0.10.5): only while pairing, under the handshake's epoch.
		// The device stops waiting and drops the handshake state and the
		// request token; it sends nothing back (the token is denylisted).
		if in.Re != "" || d.st.DeviceID != "" {
			return
		}
		d.keyring = &handshake.Keyring{}
		d.st.Vault, d.sas, d.st.PairingPending = nil, "", false
		d.dropOutboxLocked()
	case "device.paired":
		// §6.7 "Late and duplicate": the vault sends it once per pairing.
		// Once this device has its id, one arriving without a handshake
		// of this device waiting for it (a replay under a new msg_id, or a
		// late one) is dropped: it changes no token, id or release.
		if d.st.DeviceID != "" && !d.st.PairingPending {
			return
		}
		d.st.PairingPending = false
		// The device's standing token (§10.3, 0.10.3) replaces the request
		// token of the pairing's hs.resp, before maintain() looks at it.
		if o, err := strictjson.ParseObject(in.Body); err == nil {
			if tok, ok, _ := o.OptString("token"); ok {
				if exp, err := d.heldFromVault(tok); err == nil {
					d.st.Vault.Token, d.st.Vault.TokenExp = tok, exp
				}
			}
			// A transferred app learns the member's user_guid here
			// (§6.7.1, 0.17.0); it has no redeem or claim.
			if tr, err := o.Bool("transfer"); err == nil && tr {
				if g, ok, _ := o.OptString("user_guid"); ok && validUserGUID(g) {
					d.st.UserGUID = g
				}
			}
			// The device id, vault id and release are recorded here,
			// not by AwaitPaired, so that Config.Persist saves them with
			// the token before device.paired is acknowledged.
			d.st.DeviceID, _ = o.String("device_id")
			if v, _ := o.String("vault_id"); v != "" {
				d.st.VaultID = v
			}
			// The release the vault runs under (§10.3), the floor for
			// unlocks (Alt): raised, never lowered.
			if r, ok, _ := o.OptString("release"); ok && len(r) == 96 {
				if n, _, err := o.OptUint("release_number", 1, strictjson.MaxSafeInteger); err == nil && n > 0 {
					if a := d.alt(); n > a.ReleaseNumber {
						a.Release, a.ReleaseNumber = r, n
					}
				}
			}
			d.st.Paired = pairedFrom(o, now)
		}
	case "relay.token.issued":
		d.storeVaultToken(in.Body)
	case "relay.token.refresh":
		if in.Re == "" {
			tok, err := d.mintForVault()
			if err == nil {
				body := strictjson.NewBuilder().String("kind", "standing").String("token", tok).Bytes()
				_, _ = d.sendLocked(ctx, "", in.Type, body, in.ID, envelope.StatusOK)
			}
			return
		}
		d.storeVaultToken(in.Body)
	case "identity.rotate":
		d.followRotation(in.Body)
	case "leash.grant.updated":
		if in.Re == "" {
			d.leashGrants = append(json.RawMessage(nil), in.Body...) // the agent's current grants (§10.11); d.mu is held
		}
	}
	d.emit(in)
	d.maintain(ctx, now)
}

func (d *Device) handleEnrolled(env *envelope.Envelope, sender ed25519.PublicKey) {
	padded, _, err := envelope.OpenSealed(env, d.kem)
	if err != nil {
		return
	}
	in, err := envelope.DecodeInner(padded, envelope.ModeSealed)
	if err != nil || in.Type != "vault.enrolled" {
		return
	}
	o, err := strictjson.ParseObject(in.Body)
	if err != nil {
		return
	}
	bundle, err := o.Base64("vault_bundle", -1)
	if err != nil {
		return
	}
	bo, err := strictjson.ParseObject(bundle)
	if err != nil {
		return
	}
	if v, err := bo.Uint("v", 1, 1); err != nil || v != 1 {
		return
	}
	if s, err := bo.Uint("suite", 2, 2); err != nil || s != 2 {
		return
	}
	pr, err := handshake.ParsePrincipal(bo)
	if err != nil || !suite.EqualPublic(sender, pr.Relay.PK) {
		return
	}
	if !d.checkEnrolledAttestation(o, bundle) {
		return
	}
	vid, err := o.String("vault_id")
	if err != nil {
		return
	}
	tok, err := o.String("token")
	if err != nil {
		return
	}
	d.setVaultFromPrincipal(pr)
	exp, err := d.heldFromVault(tok)
	if err != nil {
		d.st.Vault = nil
		return
	}
	d.st.Vault.Token, d.st.Vault.TokenExp = tok, exp
	d.st.VaultID = vid
	if a := d.st.Alt; a != nil && a.EnrollNonce != nil {
		// §11.3 "App state": the release and state_seq.
		if len(a.EnrollPCRs) >= 96 {
			a.Release, a.ReleaseNumber = a.EnrollPCRs[:96], a.EnrollNumber
		}
		if ss, err := o.Uint("state_seq", 0, strictjson.MaxSafeInteger); err == nil && ss > a.StateSeq {
			a.StateSeq = ss
		}
		a.EnrollNonce, a.EnrollPCRs, a.EnrollNumber = nil, "", 0
	}
	d.emit(in)
}

// checkEnrolledAttestation verifies vault.enrolled's attestation (§11.3):
// nonce = the app's nonce, user_data = SHA-256("vettid/vms/2/vault" ||
// vault_bundle), and the PCRs of the enclave the request was sealed to.
// Without Trust (development) a missing attestation is accepted.
func (d *Device) checkEnrolledAttestation(o strictjson.Object, bundle []byte) bool {
	t := d.cfg.Trust
	if t == nil {
		return true
	}
	a := d.st.Alt
	if a == nil || a.EnrollNonce == nil {
		return false
	}
	doc, err := o.Base64("attestation", -1)
	if err != nil {
		return false
	}
	nd, err := nitro.Verify(doc, t.NitroRoots)
	if err != nil {
		return false
	}
	ud := altchan.VaultUserData(bundle)
	ms := nd.Measurements()
	return nd.CheckNonce(a.EnrollNonce) == nil && nd.CheckUserData(ud[:]) == nil &&
		suite.Equal([]byte(ms.PCR0+ms.PCR1+ms.PCR2), []byte(a.EnrollPCRs)) &&
		nd.CheckFresh(d.cfg.Now(), MaxAttestationAge, attestationSkew) == nil
}

func (d *Device) handleResp(ctx context.Context, raw []byte, sender ed25519.PublicKey) {
	now := d.cfg.Now()
	res, err := d.ini.HandleResp(raw, sender, now)
	if err != nil {
		if _, xerr := d.ini.Export(); errors.Is(xerr, handshake.ErrDone) {
			d.ini, d.hsFailed = nil, true
		}
		return
	}
	d.ini, d.sas = nil, res.SAS
	if res.Resp.Token != "" {
		if exp, err := d.heldFromVault(res.Resp.Token); err == nil {
			d.st.Vault.Token, d.st.Vault.TokenExp = res.Resp.Token, exp
		}
	}
	if res.Epoch.Suite() > d.st.Vault.Suite {
		d.st.Vault.Suite = res.Epoch.Suite()
	}
	d.keyring.Activate(res.Epoch, now)
	v := d.st.Vault
	if err := d.depositVault(ctx, "hs.fin", v.RelayURL, v.Mailbox, v.Token, res.Fin); err != nil {
		// The vault cannot finish this handshake: awaitHandshake fails
		// instead of returning a SAS.
		if errors.Is(err, ErrRefused) {
			d.finErr = err
		} else {
			d.finErr = fmt.Errorf("%w: %w", ErrHandshakeUnsent, err)
		}
	}
}

// handleRekey answers a vault-initiated rekey (§6.5).
func (d *Device) handleRekey(ctx context.Context, raw []byte, in *envelope.Inner, ep *handshake.Epoch, sender ed25519.PublicKey, now time.Time) {
	if d.keyring.Current() != ep {
		return
	}
	pi, err := handshake.AcceptRekey(raw, in, ep, now)
	if err != nil {
		return
	}
	v := d.st.Vault
	resp, env, err := pi.Respond(handshake.ResponderConfig{
		Identity: d.ik, Policy: d.policy(), PinnedSuite: v.Suite, CollectSender: sender,
		RecordRelayKey: v.RelayPK, KnownInitiatorIK: v.IK, Now: now,
	})
	if err != nil {
		return
	}
	if err := d.depositVault(ctx, "hs.resp", v.RelayURL, v.Mailbox, v.Token, env); err != nil {
		resp.Abort()
		return
	}
	d.awaiting = append(d.awaiting, resp)
}

func (d *Device) storeVaultToken(body json.RawMessage) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return
	}
	tok, err := o.String("token")
	if err != nil {
		return
	}
	if kind, _, _ := o.OptString("kind"); kind != "" && kind != "standing" {
		return
	}
	if exp, err := d.heldFromVault(tok); err == nil && exp.After(d.st.Vault.TokenExp) {
		d.st.Vault.Token, d.st.Vault.TokenExp = tok, exp
	}
}

func (d *Device) followRotation(body json.RawMessage) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return
	}
	r, err := handshake.ParseRotation(o["rotation"])
	if err != nil {
		return
	}
	final, kem, err := handshake.ResolveChain(d.st.Vault.IK, []*handshake.Rotation{r})
	if err != nil {
		return
	}
	d.st.Vault.IK, d.st.Vault.KEM = final, kem.Bytes()
}

// maintain refreshes tokens in both directions (§7.2).
func (d *Device) maintain(ctx context.Context, now time.Time) {
	v := d.st.Vault
	if v == nil || d.keyring.Current() == nil {
		return
	}
	if !d.st.IssuedExp.IsZero() && d.st.IssuedExp.Sub(now) < 10*24*time.Hour {
		if tok, err := d.mintForVault(); err == nil {
			body := strictjson.NewBuilder().String("kind", "standing").String("token", tok).Bytes()
			_, _ = d.sendLocked(ctx, "", "relay.token.issued", body, "", "")
		}
	}
	if v.TokenExp.Sub(now) < 3*24*time.Hour && now.Before(v.TokenExp) {
		_, _ = d.sendLocked(ctx, "", "relay.token.refresh", json.RawMessage(`{}`), "", "")
	}
}

// pairedFrom reads device.paired's fields (§10.3). A member that is
// missing or malformed is left zero.
func pairedFrom(o strictjson.Object, now time.Time) *Paired {
	p := &Paired{ReceivedAt: now.UTC()}
	p.DeviceID, _ = o.String("device_id")
	p.Role, _, _ = o.OptString("role")
	p.VaultID, _, _ = o.OptString("vault_id")
	if r, ok, _ := o.OptString("release"); ok && len(r) == 96 {
		if n, _, err := o.OptUint("release_number", 1, strictjson.MaxSafeInteger); err == nil {
			p.Release, p.ReleaseNumber = r, n
		}
	}
	if s, ok, _ := o.OptString("session_expires_at"); ok {
		if t, err := envelope.ParseTS(s); err == nil {
			p.SessionExpiresAt = t
		}
	}
	if tr, err := o.Bool("transfer"); err == nil && tr {
		p.Transfer = true
		p.CredentialVersion, _, _ = o.OptUint("credential_version", 0, strictjson.MaxSafeInteger)
		if g, ok, _ := o.OptString("user_guid"); ok && validUserGUID(g) {
			p.UserGUID = g
		}
	}
	return p
}

// validUserGUID checks a user_guid from device.paired (§6.7.1, 0.17.0):
// 1–128 printable ASCII characters, so that it fits the unlock's signing
// string (§11.4).
func validUserGUID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
