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
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/invite"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Errors.
var (
	ErrNotPaired = errors.New("client: not paired with a vault")
	ErrProtocol  = errors.New("client: unexpected message from the vault")
	ErrToken     = errors.New("client: token invalid")
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
}

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

	ik       ed25519.PrivateKey
	kem      *suite.PrivateKey
	relayKey ed25519.PrivateKey
	own      *relayclient.Client

	keyring  *handshake.Keyring
	ini      *handshake.Initiator
	awaiting []*handshake.Responder
	events   []*envelope.Inner
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
	cfg.defaults()
	st := &State{Role: cfg.Role, Name: cfg.Name, RelayURL: cfg.RelayURL}
	for _, p := range []*[]byte{&st.IKSeed, &st.KEMSeed, &st.RelaySeed} {
		b, err := suite.RandomBytes(32)
		if err != nil {
			return nil, err
		}
		*p = b
	}
	d, err := open(cfg, st)
	if err != nil {
		return nil, err
	}
	if _, err := d.own.Register(ctx); err != nil {
		return nil, err
	}
	return d, nil
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
	d := &Device{cfg: cfg, st: st,
		ik: ed25519.NewKeyFromSeed(st.IKSeed), relayKey: ed25519.NewKeyFromSeed(st.RelaySeed)}
	var err error
	if d.kem, err = suite.NewPrivateKey(st.KEMSeed); err != nil {
		return nil, err
	}
	d.own = d.relayClient(st.RelayURL)
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
	return d.awaitPaired(ctx)
}

// Pair starts pairing from a QR / link shown by an already paired app
// (§6.7). It returns the SAS to compare; then call AwaitPaired.
func (d *Device) Pair(ctx context.Context, link string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	q, err := invite.ParseLink(link)
	if err != nil {
		return "", err
	}
	want := map[string]invite.Kind{"app": invite.KindApp, "desktop": invite.KindDesktop, "agent": invite.KindAgent}[d.st.Role]
	if q.Kind != want {
		return "", ErrProtocol
	}
	blob, err := d.relayClient(q.Relay).GetClaim(ctx, q.ClaimID)
	if err != nil {
		return "", err
	}
	b, err := invite.OpenBundle(blob, q, d.cfg.Now())
	if err != nil {
		return "", err
	}
	d.setVaultFromPrincipal(b.Vault)
	profile := strictjson.NewBuilder().String("name", d.st.Name).Bytes()
	if err := d.startInit(handshake.Purpose(d.st.Role), b.InviteID, b.Token, profile); err != nil {
		return "", err
	}
	return d.ini.SAS(), nil
}

// AwaitPaired waits for the vault's hs.resp (after the owner approves),
// completes the handshake and waits for device.paired.
func (d *Device) AwaitPaired(ctx context.Context) error { return d.awaitPaired(ctx) }

func (d *Device) awaitPaired(ctx context.Context) error {
	in, err := d.waitFor(ctx, func(in *envelope.Inner) bool { return in.Type == "device.paired" })
	if err != nil {
		return err
	}
	o, err := strictjson.ParseObject(in.Body)
	if err != nil {
		return ErrProtocol
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.st.DeviceID, _ = o.String("device_id")
	if v, _ := o.String("vault_id"); v != "" {
		d.st.VaultID = v
	}
	return nil
}

// startInit sends hs.init to the vault on depositToken.
func (d *Device) startInit(purpose handshake.Purpose, ctxID, depositToken string, profile json.RawMessage) error {
	v := d.st.Vault
	ek, err := suite.ParsePublicKey(v.KEM)
	if err != nil {
		return err
	}
	tok, err := d.mintForVault()
	if err != nil {
		return err
	}
	ini, err := handshake.NewInitiator(handshake.InitiatorConfig{
		Purpose: purpose, Ctx: ctxID, Identity: d.ik, StaticKEM: d.kem.Public(), Relay: d.RelayAddr(),
		Token: tok, Profile: profile, ResponderIK: v.IK, ResponderEK: ek, ResponderRelayKey: v.RelayPK,
		Policy: d.policy(), Now: d.cfg.Now(),
	})
	if err != nil {
		return err
	}
	if _, err := d.relayClient(v.RelayURL).Deposit(context.Background(), v.Mailbox, depositToken, ini.Envelope()); err != nil {
		return err
	}
	d.ini = ini
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
	in := &envelope.Inner{ID: id, Type: typ, TS: now, Body: body, Re: re, Status: status}
	raw, err := d.keyring.Current().Seal(in)
	if err != nil {
		return "", err
	}
	if _, err := d.relayClient(v.RelayURL).Deposit(ctx, v.Mailbox, v.Token, raw); err != nil {
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

// waitFor processes the mailbox until match accepts a received message,
// which is removed from the buffer and returned.
func (d *Device) waitFor(ctx context.Context, match func(*envelope.Inner) bool) (*envelope.Inner, error) {
	for {
		d.mu.Lock()
		for i, ev := range d.events {
			if match(ev) {
				d.events = append(d.events[:i:i], d.events[i+1:]...)
				d.mu.Unlock()
				return ev, nil
			}
		}
		d.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := d.Poll(ctx); err != nil && ctx.Err() == nil {
			var re *relayclient.Error
			if !errors.As(err, &re) {
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

// Poll collects once from the device's mailbox and processes what arrived.
func (d *Device) Poll(ctx context.Context) error {
	msgs, err := d.own.Collect(ctx, d.cfg.PollWait, 32)
	if err != nil {
		return err
	}
	for _, m := range msgs {
		d.mu.Lock()
		d.handle(ctx, m)
		d.mu.Unlock()
		_ = d.own.Ack(ctx, m.MsgID)
	}
	return nil
}

// handle processes one collected message. Classification is by sender and
// recipient kid only (§13.6).
func (d *Device) handle(ctx context.Context, m relayclient.Message) {
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
				e, _, err := r.HandleFin(m.Payload, sender, now)
				if err == nil {
					d.keyring.Activate(e, now)
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
	}
	d.events = append(d.events, in)
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
	vo, err := bo.Object("vault")
	if err != nil {
		return
	}
	pr, err := handshake.ParsePrincipal(vo)
	if err != nil || !suite.EqualPublic(sender, pr.Relay.PK) {
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
	d.events = append(d.events, in)
}

func (d *Device) handleResp(ctx context.Context, raw []byte, sender ed25519.PublicKey) {
	now := d.cfg.Now()
	res, err := d.ini.HandleResp(raw, sender, now)
	if err != nil {
		if _, xerr := d.ini.Export(); errors.Is(xerr, handshake.ErrDone) {
			d.ini = nil
		}
		return
	}
	d.ini = nil
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
	_, _ = d.relayClient(v.RelayURL).Deposit(ctx, v.Mailbox, v.Token, res.Fin)
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
	if _, err := d.relayClient(v.RelayURL).Deposit(ctx, v.Mailbox, v.Token, env); err != nil {
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
