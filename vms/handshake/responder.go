package handshake

import (
	"crypto/ed25519"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// KeyLookup returns the static KEM private key (current or retired) whose
// kid is kid, or nil. It must return at most one key: a receiver never
// trial-decrypts under other keys (§4.4).
type KeyLookup func(kid suite.Kid) *suite.PrivateKey

// PendingInit is a decrypted, validated hs.init awaiting the responder's
// decision (approval for pairing and connections, §6.4, §6.7).
type PendingInit struct {
	mu    sync.Mutex
	env   []byte
	inner *envelope.Inner
	body  *Init
	ks    []byte
	th1   [32]byte
	sas   string
	used  bool
}

// OpenInit decrypts a sealed-mode hs.init (every purpose except rekey). The
// static key is chosen by recipient_kid through lookup; when the sender
// names itself (non-zero sender_kid), the kid must be that of from.kem.
func OpenInit(raw []byte, lookup KeyLookup, now time.Time) (*PendingInit, error) {
	env, err := envelope.Parse(raw)
	if err != nil {
		return nil, err
	}
	if env.Mode() != envelope.ModeSealed {
		return nil, envelope.ErrWrongMode
	}
	sk := lookup(env.RecipientKid())
	if sk == nil {
		return nil, ErrNoKey
	}
	padded, exp, err := envelope.OpenSealed(env, sk)
	if err != nil {
		return nil, err
	}
	defer suite.Wipe(padded)
	in, err := envelope.DecodeInner(padded, envelope.ModeSealed)
	if err != nil {
		return nil, err
	}
	if in.Type != TypeInit {
		return nil, ErrType
	}
	if err := in.CheckTime(now, true); err != nil {
		return nil, err
	}
	body, err := ParseInit(in.Body)
	if err != nil {
		return nil, err
	}
	if body.Purpose == PurposeRekey {
		return nil, ErrPurpose // rekeys travel in session mode
	}
	if sk := env.SenderKid(); !sk.IsAnonymous() && !sk.Equal(body.From.KEM.Kid()) {
		return nil, ErrSenderKid
	}
	ks, err := exp.Export(suite.LabelHsKs, suite.KeySize)
	if err != nil {
		return nil, err
	}
	return newPending(raw, in, body, ks)
}

// OpenRekeyInit decrypts a session-mode hs.init with purpose rekey under the
// session's current epoch; K_s is that epoch's rk (§6.2). Rekeys are
// accepted only under the current epoch, whose rk is the only one kept.
func OpenRekeyInit(raw []byte, current *Epoch, now time.Time) (*PendingInit, error) {
	if current == nil {
		return nil, ErrConfig
	}
	env, err := envelope.Parse(raw)
	if err != nil {
		return nil, err
	}
	if env.Mode() != envelope.ModeSession {
		return nil, envelope.ErrWrongMode
	}
	in, err := current.Open(env)
	if err != nil {
		return nil, err
	}
	if in.Type != TypeInit {
		return nil, ErrType
	}
	if err := in.CheckTime(now, true); err != nil {
		return nil, err
	}
	body, err := ParseInit(in.Body)
	if err != nil {
		return nil, err
	}
	if body.Purpose != PurposeRekey {
		return nil, ErrPurpose
	}
	if body.Ctx != EpochCtx(current.ID()) {
		return nil, ErrCtx
	}
	ks, err := current.rkCopy()
	if err != nil {
		return nil, err
	}
	return newPending(raw, in, body, ks)
}

func newPending(raw []byte, in *envelope.Inner, body *Init, ks []byte) (*PendingInit, error) {
	p := &PendingInit{env: append([]byte(nil), raw...), inner: in, body: body, ks: ks}
	p.th1 = Th1(p.env)
	var err error
	if p.sas, err = SAS(ks, p.th1); err != nil {
		suite.Wipe(ks)
		return nil, err
	}
	return p, nil
}

// Init returns the hs.init body. `profile` in it is self-asserted (§6.4).
func (p *PendingInit) Init() *Init { return p.body }

// Inner returns the hs.init inner plaintext.
func (p *PendingInit) Inner() *envelope.Inner { return p.inner }

// SAS returns the short authentication string (§6.3).
func (p *PendingInit) SAS() string { return p.sas }

// Th1 returns th1.
func (p *PendingInit) Th1() [32]byte { return p.th1 }

// Discard wipes the pending state (rejection, expiry).
func (p *PendingInit) Discard() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.used = true
	suite.Wipe(p.ks)
	p.ks = nil
}

// ResponderConfig configures hs.resp. Calling Respond is the approval: the
// runtime MUST NOT call it before the owner approves a pairing (§6.7) or a
// remote invite (§6.4).
type ResponderConfig struct {
	Identity       ed25519.PrivateKey // ik_R
	Token          string
	ReconnectToken string
	Rotations      []*Rotation // reconnect: own rotations since the last epoch
	PinnedSuite    uint8
	Policy         Policy

	// CollectSender is the relay `sender` of the hs.init deposit. It MUST
	// equal from.relay.pk (§6.3).
	CollectSender ed25519.PublicKey
	// RecordRelayKey is the relay key on record for the peer. Required for
	// rekey and reconnect, where the sender must also equal it (§6.3,
	// §6.6).
	RecordRelayKey ed25519.PublicKey
	// KnownInitiatorIK is the stored ik of the peer. Required for rekey
	// (from.ik must equal it) and reconnect (from.ik must be reached from it
	// through a valid rotation chain, §6.6).
	KnownInitiatorIK ed25519.PublicKey
	// ExpectedCtx, if set, must equal hs.init ctx. Required for reconnect:
	// EpochCtx of the stored last epoch id (§6.6).
	ExpectedCtx string

	ID  string
	Now time.Time
}

// Responder is the responder side after hs.resp, awaiting hs.fin.
type Responder struct {
	mu       sync.Mutex
	sched    *Schedule
	verifyIK ed25519.PublicKey
	sender   ed25519.PublicKey
	suiteID  uint8
	policy   Policy
	done     bool
}

// Respond checks the initiator against the record (rekey, reconnect),
// negotiates the suite, and builds hs.resp sealed to the initiator's
// ephemeral key, with sig_R over th. It returns the state that awaits
// hs.fin, and hs.resp ready to deposit.
func (p *PendingInit) Respond(cfg ResponderConfig) (*Responder, []byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used {
		return nil, nil, ErrDone
	}
	if len(cfg.Identity) != ed25519.PrivateKeySize || cfg.Policy == (Policy{}) {
		return nil, nil, ErrConfig
	}
	verifyIK, err := p.checkInitiator(cfg)
	if err != nil {
		return nil, nil, err
	}
	chosen, err := suite.Negotiate(p.body.Suites, cfg.PinnedSuite)
	if err != nil {
		return nil, nil, err
	}
	id, now, err := innerMeta(cfg.ID, cfg.Now)
	if err != nil {
		return nil, nil, err
	}
	sealer, err := envelope.NewSealer(p.body.Eph, suite.Anonymous)
	if err != nil {
		return nil, nil, err
	}
	ke, err := sealer.Export(suite.LabelHsKe, suite.KeySize)
	if err != nil {
		return nil, nil, err
	}
	defer suite.Wipe(ke)
	th := Th(p.env, sealer.Header())
	sched, err := DeriveSchedule(p.ks, ke, p.th1, th)
	if err != nil {
		return nil, nil, err
	}
	sig, err := SignResp(cfg.Identity, th)
	if err != nil {
		sched.Destroy()
		return nil, nil, err
	}
	resp := &Resp{Token: cfg.Token, ReconnectToken: cfg.ReconnectToken, Suite: int(chosen), Rotations: cfg.Rotations, Sig: sig}
	rb, err := resp.Marshal(p.body.Purpose)
	if err != nil {
		sched.Destroy()
		return nil, nil, err
	}
	padded, err := envelope.EncodeInner(&envelope.Inner{ID: id, Type: TypeResp, TS: now, Body: rb}, envelope.ModeSealed)
	if err != nil {
		sched.Destroy()
		return nil, nil, err
	}
	defer suite.Wipe(padded)
	out, err := sealer.Seal(padded)
	if err != nil {
		sched.Destroy()
		return nil, nil, err
	}
	p.used = true
	suite.Wipe(p.ks)
	p.ks = nil
	return &Responder{sched: sched, verifyIK: verifyIK, sender: p.body.From.Relay.PK, suiteID: chosen, policy: cfg.Policy}, out, nil
}

// checkInitiator applies §6.3 and §6.6 and returns the key sig_I must
// verify under.
func (p *PendingInit) checkInitiator(cfg ResponderConfig) (ed25519.PublicKey, error) {
	b := p.body
	// §6.3: the collect sender MUST equal from.relay.pk for hs.init.
	if !suite.EqualPublic(cfg.CollectSender, b.From.Relay.PK) {
		return nil, ErrSender
	}
	if cfg.ExpectedCtx != "" && cfg.ExpectedCtx != b.Ctx {
		return nil, ErrCtx
	}
	switch b.Purpose {
	case PurposeRekey:
		if !suite.EqualPublic(cfg.CollectSender, cfg.RecordRelayKey) {
			return nil, ErrSender
		}
		if !suite.EqualPublic(b.From.IK, cfg.KnownInitiatorIK) {
			return nil, ErrIdentity
		}
		return b.From.IK, nil
	case PurposeReconnect:
		// §6.6: accept only if the sender is the relay key on record (the
		// reconnect token's sub), from.ik is the stored ik or reached from
		// it by a valid chain, and (in HandleFin) sig_I verifies under it.
		if cfg.ExpectedCtx == "" {
			return nil, ErrConfig
		}
		if !suite.EqualPublic(cfg.CollectSender, cfg.RecordRelayKey) {
			return nil, ErrSender
		}
		final, kem, err := ResolveChain(cfg.KnownInitiatorIK, b.Rotations)
		if err != nil {
			return nil, err
		}
		if !suite.EqualPublic(final, b.From.IK) {
			return nil, ErrIdentity
		}
		if kem != nil && !kem.Equal(b.From.KEM) {
			return nil, ErrIdentity
		}
		return b.From.IK, nil
	default:
		// New peer or device: trust on first use, under approval and SAS.
		return b.From.IK, nil
	}
}

// Kids returns (recipient_kid, sender_kid) that hs.fin carries, so the
// runtime can route it to this pending responder.
func (r *Responder) Kids() (recipient, sender suite.Kid) {
	return r.sched.KidI2R, r.sched.KidR2I
}

// Abort destroys the pending state.
func (r *Responder) Abort() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.done = true
	r.sched.Destroy()
}

// HandleFin processes hs.fin: it decrypts it with the pending epoch's i2r
// key, verifies sig_I, and only then activates the epoch (§6.3). On any
// failure the pending state is kept, so that a forged message cannot
// cancel a genuine handshake; the runtime leaves the message unacked.
func (r *Responder) HandleFin(raw []byte, collectSender ed25519.PublicKey, now time.Time) (*Epoch, *envelope.Inner, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		return nil, nil, ErrDone
	}
	if !suite.EqualPublic(collectSender, r.sender) {
		return nil, nil, ErrSender
	}
	env, err := envelope.Parse(raw)
	if err != nil {
		return nil, nil, err
	}
	if env.Mode() != envelope.ModeSession {
		return nil, nil, envelope.ErrWrongMode
	}
	// A not-yet-active epoch, used only to decrypt and check hs.fin.
	pending := newEpoch(r.sched, RoleResponder, r.suiteID, r.policy, now)
	in, err := pending.Open(env)
	if err != nil {
		pending.Destroy()
		return nil, nil, err
	}
	if in.Type != TypeFin {
		pending.Destroy()
		return nil, nil, ErrType
	}
	if err := in.CheckTime(now, true); err != nil {
		pending.Destroy()
		return nil, nil, err
	}
	sig, err := ParseFin(in.Body)
	if err != nil {
		pending.Destroy()
		return nil, nil, err
	}
	if err := VerifyFin(r.verifyIK, r.sched.Th, sig); err != nil {
		pending.Destroy()
		return nil, nil, ErrSigFin
	}
	r.done = true
	r.sched.Destroy()
	return pending, in, nil
}
