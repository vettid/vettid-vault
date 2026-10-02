package handshake

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// EpochCtx encodes an epoch id as hs.init `ctx` for rekey and reconnect
// (standard base64, §5.3).
func EpochCtx(id [suite.EpochIDSize]byte) string { return base64.StdEncoding.EncodeToString(id[:]) }

// InitiatorConfig configures an hs.init.
type InitiatorConfig struct {
	Purpose Purpose
	// Ctx is the invite id, pairing id or connection reference. For rekey
	// it is set to EpochCtx(Current.ID()) when empty; for reconnect it must
	// be EpochCtx of the stored last epoch id.
	Ctx string

	Identity  ed25519.PrivateKey // ik_I
	StaticKEM *suite.PublicKey   // from.kem: the initiator's static ek
	Relay     RelayAddr          // from.relay

	Token          string
	ReconnectToken string
	Suites         []int // default [2]
	Profile        json.RawMessage
	Rotations      []*Rotation // reconnect: own rotations since the last epoch
	AppAttest      json.RawMessage

	// AnonymousSender sets hs.init sender_kid to all-zero instead of the
	// kid of StaticKEM (§6.2).
	AnonymousSender bool

	ResponderIK       ed25519.PublicKey // pinned ik_R, or the stored ik for rekey/reconnect
	ResponderEK       *suite.PublicKey  // ek_R (not used for rekey)
	ResponderRelayKey ed25519.PublicKey // relay key on record for R: the expected collect sender of hs.resp

	Current     *Epoch // rekey only: the epoch hs.init travels in; K_s = its rk
	PinnedSuite uint8
	Policy      Policy

	// Inner metadata. Zero values are generated (ULID, current time).
	ID    string
	FinID string
	Now   time.Time
}

// Initiator is the initiator side of one handshake.
type Initiator struct {
	mu   sync.Mutex
	cfg  InitiatorConfig
	body *Init
	eph  *suite.PrivateKey
	env  []byte
	th1  [32]byte
	ks   []byte
	sas  string
	done bool
}

func innerMeta(id string, now time.Time) (string, time.Time, error) {
	if now.IsZero() {
		now = time.Now()
	}
	if id == "" {
		var err error
		if id, err = envelope.NewULID(now); err != nil {
			return "", now, err
		}
	}
	return id, now, nil
}

// NewInitiator builds and seals hs.init. It generates a fresh ephemeral KEM
// key for forward secrecy (§6.5).
func NewInitiator(cfg InitiatorConfig) (*Initiator, error) {
	if len(cfg.Identity) != ed25519.PrivateKeySize || cfg.StaticKEM == nil ||
		len(cfg.ResponderIK) != ed25519.PublicKeySize || len(cfg.ResponderRelayKey) != ed25519.PublicKeySize {
		return nil, ErrConfig
	}
	if cfg.Suites == nil {
		cfg.Suites = []int{int(suite.Suite2)}
	}
	if cfg.Policy == (Policy{}) {
		return nil, ErrConfig
	}
	rekey := cfg.Purpose == PurposeRekey
	if rekey {
		if cfg.Current == nil {
			return nil, ErrConfig
		}
		want := EpochCtx(cfg.Current.ID())
		if cfg.Ctx == "" {
			cfg.Ctx = want
		} else if cfg.Ctx != want {
			return nil, ErrCtx
		}
	} else if cfg.ResponderEK == nil || cfg.Current != nil {
		return nil, ErrConfig
	}
	id, now, err := innerMeta(cfg.ID, cfg.Now)
	if err != nil {
		return nil, err
	}
	cfg.ID, cfg.Now = id, now

	eph, err := suite.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	body := &Init{
		Purpose: cfg.Purpose,
		Ctx:     cfg.Ctx,
		From: Principal{
			IK:    cfg.Identity.Public().(ed25519.PublicKey),
			KEM:   cfg.StaticKEM,
			Relay: cfg.Relay,
		},
		Eph:            eph.Public(),
		Token:          cfg.Token,
		ReconnectToken: cfg.ReconnectToken,
		Suites:         cfg.Suites,
		Profile:        cfg.Profile,
		Rotations:      cfg.Rotations,
		AppAttest:      cfg.AppAttest,
	}
	bj, err := body.Marshal()
	if err != nil {
		eph.Destroy()
		return nil, err
	}
	in := &envelope.Inner{ID: cfg.ID, Type: TypeInit, TS: cfg.Now, Body: bj}

	i := &Initiator{cfg: cfg, body: body, eph: eph}
	if rekey {
		// §6.2: on rekey, hs.init travels in session mode under the current
		// epoch, and K_s is that epoch's rk.
		if i.ks, err = cfg.Current.rkCopy(); err != nil {
			eph.Destroy()
			return nil, err
		}
		if i.env, err = cfg.Current.Seal(in); err != nil {
			i.Abort()
			return nil, err
		}
	} else {
		padded, err := envelope.EncodeInner(in, envelope.ModeSealed)
		if err != nil {
			eph.Destroy()
			return nil, err
		}
		senderKid := cfg.StaticKEM.Kid()
		if cfg.AnonymousSender {
			senderKid = suite.Anonymous
		}
		env, exp, err := envelope.SealSealed(cfg.ResponderEK, senderKid, padded)
		suite.Wipe(padded)
		if err != nil {
			eph.Destroy()
			return nil, err
		}
		i.env = env
		if i.ks, err = exp.Export(suite.LabelHsKs, suite.KeySize); err != nil {
			i.Abort()
			return nil, err
		}
	}
	i.th1 = Th1(i.env)
	if i.sas, err = SAS(i.ks, i.th1); err != nil {
		i.Abort()
		return nil, err
	}
	return i, nil
}

// Envelope returns hs.init, ready to deposit.
func (i *Initiator) Envelope() []byte { return append([]byte(nil), i.env...) }

// SAS returns the short authentication string, which depends only on
// hs.init (§6.3).
func (i *Initiator) SAS() string { return i.sas }

// Th1 returns th1, which also decides simultaneous rekeys (§6.5).
func (i *Initiator) Th1() [32]byte { return i.th1 }

// EphKid returns the kid that hs.resp will carry as recipient_kid.
func (i *Initiator) EphKid() suite.Kid { return i.body.Eph.Kid() }

// Body returns the hs.init body.
func (i *Initiator) Body() *Init { return i.body }

// Abort destroys the handshake state. Any later HandleResp fails.
func (i *Initiator) Abort() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.abortLocked()
}

func (i *Initiator) abortLocked() {
	i.done = true
	if i.eph != nil {
		i.eph.Destroy()
		i.eph = nil
	}
	suite.Wipe(i.ks)
	i.ks = nil
}

// Result is the outcome of a completed handshake on the initiator side.
type Result struct {
	// Epoch is the new, active epoch. For a rekey, activate it in the
	// session's Keyring (which retires the previous epoch's send key).
	Epoch *Epoch
	// Fin is hs.fin, sealed in the new epoch, ready to deposit.
	Fin []byte
	// Resp is the decrypted hs.resp body (tokens, chosen suite).
	Resp *Resp
	// ResponderIK is the key sig_R verified under: the pinned key, or the
	// key a reconnect's rotation chain leads to. Store it.
	ResponderIK ed25519.PublicKey
	// ResponderKEM is the KEM key announced by the last rotation, if any.
	ResponderKEM *suite.PublicKey
	// Inner is the hs.resp inner plaintext.
	Inner *envelope.Inner
}

// HandleResp processes hs.resp. collectSender is the relay `sender` of the
// deposit; it must be R's relay key on record (§6.3). sig_R is verified
// before any epoch key is used.
//
// A message that does not decrypt under eph (wrong sender, malformed,
// wrong key) is rejected and the handshake stays pending, so unauthenticated
// junk cannot cancel it. Once a message has decrypted, any failure, and in
// particular a sig_R that does not verify, aborts the handshake (§6.3:
// "MUST abort") and destroys its state.
func (i *Initiator) HandleResp(raw []byte, collectSender ed25519.PublicKey, now time.Time) (*Result, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.done {
		return nil, ErrDone
	}
	res, decrypted, err := i.handleResp(raw, collectSender, now)
	if err != nil {
		if decrypted {
			i.abortLocked()
		}
		return nil, err
	}
	i.abortLocked() // success also ends the state: wipe eph and K_s
	return res, nil
}

func (i *Initiator) handleResp(raw []byte, collectSender ed25519.PublicKey, now time.Time) (*Result, bool, error) {
	if !suite.EqualPublic(collectSender, i.cfg.ResponderRelayKey) {
		return nil, false, ErrSender
	}
	env, err := envelope.Parse(raw)
	if err != nil {
		return nil, false, err
	}
	if env.Mode() != envelope.ModeSealed {
		return nil, false, envelope.ErrWrongMode
	}
	if !env.SenderKid().IsAnonymous() {
		return nil, false, ErrSenderKid
	}
	padded, exp, err := envelope.OpenSealed(env, i.eph)
	if err != nil {
		return nil, false, err
	}
	defer suite.Wipe(padded)
	res, err := i.completeResp(env, padded, exp, now)
	return res, true, err
}

func (i *Initiator) completeResp(env *envelope.Envelope, padded []byte, exp suite.Exporter, now time.Time) (*Result, error) {
	ke, err := exp.Export(suite.LabelHsKe, suite.KeySize)
	if err != nil {
		return nil, err
	}
	defer suite.Wipe(ke)
	in, err := envelope.DecodeInner(padded, envelope.ModeSealed)
	if err != nil {
		return nil, err
	}
	if in.Type != TypeResp {
		return nil, ErrType
	}
	if err := in.CheckTime(now, true); err != nil {
		return nil, err
	}
	resp, err := ParseResp(in.Body, i.cfg.Purpose)
	if err != nil {
		return nil, err
	}
	if err := suite.CheckChosen(resp.Suite, i.cfg.Suites, i.cfg.PinnedSuite); err != nil {
		return nil, err
	}
	verifyIK := i.cfg.ResponderIK
	var newKEM *suite.PublicKey
	if i.cfg.Purpose == PurposeReconnect {
		if verifyIK, newKEM, err = ResolveChain(i.cfg.ResponderIK, resp.Rotations); err != nil {
			return nil, err
		}
	}
	th := Th(i.env, env.Header())
	sched, err := DeriveSchedule(i.ks, ke, i.th1, th)
	if err != nil {
		return nil, err
	}
	defer sched.Destroy()
	// §6.3: I MUST verify sig_R before using any epoch key.
	if err := VerifyResp(verifyIK, th, resp.Sig); err != nil {
		return nil, ErrSigResp
	}
	epoch := newEpoch(sched, RoleInitiator, uint8(resp.Suite), i.cfg.Policy, now)
	sigI, err := SignFin(i.cfg.Identity, th)
	if err != nil {
		epoch.Destroy()
		return nil, err
	}
	fb, err := MarshalFin(sigI)
	if err != nil {
		epoch.Destroy()
		return nil, err
	}
	finID, finNow, err := innerMeta(i.cfg.FinID, now)
	if err != nil {
		epoch.Destroy()
		return nil, err
	}
	fin, err := epoch.Seal(&envelope.Inner{ID: finID, Type: TypeFin, TS: finNow, Body: fb})
	if err != nil {
		epoch.Destroy()
		return nil, err
	}
	return &Result{Epoch: epoch, Fin: fin, Resp: resp, ResponderIK: verifyIK, ResponderKEM: newKEM, Inner: in}, nil
}
