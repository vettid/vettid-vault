package handshake

import (
	"crypto/ed25519"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Snapshots let the vault runtime persist sessions and in-flight handshakes
// in DEK-encrypted vault state (§3.3) and restore them after a lock or
// restart. Every snapshot holds secret key material: store it only inside
// encrypted state, and never log it (the types redact themselves).

// EpochState is the persistent form of an Epoch.
type EpochState struct {
	suite.Redacted
	ID               []byte    `json:"id"`
	Role             Role      `json:"role"`
	Suite            uint8     `json:"suite"`
	Policy           Policy    `json:"policy"`
	Created          time.Time `json:"created"`
	SendKey          []byte    `json:"send_key,omitempty"` // nil once retired
	SendSenderKid    []byte    `json:"send_sender_kid"`
	SendRecipientKid []byte    `json:"send_recipient_kid"`
	RecvKey          []byte    `json:"recv_key"`
	RecvKid          []byte    `json:"recv_kid"`
	RecvSenderKid    []byte    `json:"recv_sender_kid"`
	RK               []byte    `json:"rk,omitempty"` // nil once retired
	LastSeq          uint64    `json:"last_seq"`
	Sent             uint64    `json:"sent"`
	Received         uint64    `json:"received"`
}

func cp(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

func kidOf(b []byte) (suite.Kid, error) {
	var k suite.Kid
	if len(b) != suite.KidSize {
		return k, ErrConfig
	}
	copy(k[:], b)
	return k, nil
}

// Export returns the epoch's persistent state.
func (e *Epoch) Export() EpochState {
	e.mu.Lock()
	defer e.mu.Unlock()
	return EpochState{
		ID: cp(e.id[:]), Role: e.role, Suite: e.suiteID, Policy: e.policy, Created: e.created,
		SendKey: cp(e.sendKey), SendSenderKid: cp(e.sendSenderKid[:]), SendRecipientKid: cp(e.sendRecipientKid[:]),
		RecvKey: cp(e.recvKey), RecvKid: cp(e.recvKid[:]), RecvSenderKid: cp(e.recvSenderKid[:]),
		RK: cp(e.rk), LastSeq: e.lastSeq, Sent: e.sent, Received: e.received,
	}
}

// ImportEpoch restores an epoch.
func ImportEpoch(s EpochState) (*Epoch, error) {
	if len(s.ID) != suite.EpochIDSize || len(s.RecvKey) != suite.KeySize ||
		(s.SendKey != nil && len(s.SendKey) != suite.KeySize) || (s.RK != nil && len(s.RK) != suite.KeySize) ||
		(s.Role != RoleInitiator && s.Role != RoleResponder) || suite.Check(int(s.Suite), 0) != nil {
		return nil, ErrConfig
	}
	e := &Epoch{role: s.Role, suiteID: s.Suite, policy: s.Policy, created: s.Created,
		sendKey: cp(s.SendKey), recvKey: cp(s.RecvKey), rk: cp(s.RK),
		lastSeq: s.LastSeq, sent: s.Sent, received: s.Received}
	copy(e.id[:], s.ID)
	var err error
	if e.sendSenderKid, err = kidOf(s.SendSenderKid); err != nil {
		return nil, err
	}
	if e.sendRecipientKid, err = kidOf(s.SendRecipientKid); err != nil {
		return nil, err
	}
	if e.recvKid, err = kidOf(s.RecvKid); err != nil {
		return nil, err
	}
	if e.recvSenderKid, err = kidOf(s.RecvSenderKid); err != nil {
		return nil, err
	}
	return e, nil
}

// KeyringState is the persistent form of a Keyring.
type KeyringState struct {
	Current *EpochState    `json:"current,omitempty"`
	Retired []RetiredState `json:"retired,omitempty"`
}

// RetiredState is a retired epoch (receive key only) and its expiry.
type RetiredState struct {
	Epoch EpochState `json:"epoch"`
	Until time.Time  `json:"until"`
}

// Export returns the keyring's persistent state.
func (k *Keyring) Export() KeyringState {
	k.mu.Lock()
	defer k.mu.Unlock()
	var s KeyringState
	if k.current != nil {
		c := k.current.Export()
		s.Current = &c
	}
	for _, r := range k.retired {
		s.Retired = append(s.Retired, RetiredState{Epoch: r.e.Export(), Until: r.until})
	}
	return s
}

// ImportKeyring restores a keyring.
func ImportKeyring(s KeyringState) (*Keyring, error) {
	k := &Keyring{}
	if s.Current != nil {
		e, err := ImportEpoch(*s.Current)
		if err != nil {
			return nil, err
		}
		k.current = e
	}
	for _, r := range s.Retired {
		e, err := ImportEpoch(r.Epoch)
		if err != nil {
			return nil, err
		}
		k.retired = append(k.retired, retiredEpoch{e: e, until: r.Until})
	}
	return k, nil
}

// InitiatorState is the persistent form of an Initiator awaiting hs.resp.
// The identity key is not included: pass it to RestoreInitiator.
type InitiatorState struct {
	suite.Redacted
	Purpose           Purpose `json:"purpose"`
	Suites            []int   `json:"suites"`
	PinnedSuite       uint8   `json:"pinned_suite"`
	Policy            Policy  `json:"policy"`
	ResponderIK       []byte  `json:"responder_ik"`
	ResponderRelayKey []byte  `json:"responder_relay_key"`
	EphSeed           []byte  `json:"eph_seed"`
	Env               []byte  `json:"env"`
	Ks                []byte  `json:"ks"`
	NI                []byte  `json:"n_i,omitempty"` // the SAS nonce (0.10.3)
	Th1               []byte  `json:"th1"`
	Body              []byte  `json:"body"`
}

// Export returns the initiator's persistent state, or ErrDone after it
// completed or aborted.
func (i *Initiator) Export() (InitiatorState, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.done || i.eph == nil {
		return InitiatorState{}, ErrDone
	}
	seed, err := i.eph.Seed()
	if err != nil {
		return InitiatorState{}, err
	}
	body, err := i.body.Marshal()
	if err != nil {
		return InitiatorState{}, err
	}
	return InitiatorState{
		Purpose: i.cfg.Purpose, Suites: append([]int(nil), i.cfg.Suites...), PinnedSuite: i.cfg.PinnedSuite,
		Policy: i.cfg.Policy, ResponderIK: cp(i.cfg.ResponderIK), ResponderRelayKey: cp(i.cfg.ResponderRelayKey),
		EphSeed: seed, Env: cp(i.env), Ks: cp(i.ks), NI: cp(i.nI), Th1: cp(i.th1[:]), Body: body,
	}, nil
}

// RestoreInitiator rebuilds an Initiator awaiting hs.resp.
func RestoreInitiator(s InitiatorState, identity ed25519.PrivateKey) (*Initiator, error) {
	if len(identity) != ed25519.PrivateKeySize || len(s.Th1) != 32 || len(s.Ks) != suite.KeySize ||
		len(s.ResponderIK) != ed25519.PublicKeySize || len(s.ResponderRelayKey) != ed25519.PublicKeySize {
		return nil, ErrConfig
	}
	eph, err := suite.NewPrivateKey(s.EphSeed)
	if err != nil {
		return nil, err
	}
	body, err := ParseInit(s.Body)
	if err != nil || !body.Eph.Equal(eph.Public()) || body.Purpose.HasSAS() && !CheckSASCommit(body.SASCommit, s.NI) {
		eph.Destroy()
		return nil, ErrConfig
	}
	i := &Initiator{
		cfg: InitiatorConfig{Purpose: s.Purpose, Suites: s.Suites, PinnedSuite: s.PinnedSuite, Policy: s.Policy,
			Identity: identity, ResponderIK: cp(s.ResponderIK), ResponderRelayKey: cp(s.ResponderRelayKey)},
		body: body, eph: eph, env: cp(s.Env), ks: cp(s.Ks), nI: cp(s.NI),
	}
	copy(i.th1[:], s.Th1)
	return i, nil
}

// PendingState is the persistent form of a PendingInit awaiting approval.
type PendingState struct {
	suite.Redacted
	Env   []byte `json:"env"`
	Inner []byte `json:"inner"` // the hs.init inner plaintext JSON
	Ks    []byte `json:"ks"`
}

// Export returns the pending hs.init's persistent state.
func (p *PendingInit) Export() (PendingState, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used {
		return PendingState{}, ErrDone
	}
	mode := envelope.ModeSealed
	if p.body.Purpose == PurposeRekey {
		mode = envelope.ModeSession
	}
	in, err := p.inner.Marshal(mode)
	if err != nil {
		return PendingState{}, err
	}
	return PendingState{Env: cp(p.env), Inner: in, Ks: cp(p.ks)}, nil
}

// RestorePending rebuilds a PendingInit.
func RestorePending(s PendingState) (*PendingInit, error) {
	if len(s.Ks) != suite.KeySize {
		return nil, ErrConfig
	}
	mode := envelope.ModeSealed
	in, err := envelope.ParseInner(s.Inner, mode)
	if err != nil {
		if in, err = envelope.ParseInner(s.Inner, envelope.ModeSession); err != nil {
			return nil, ErrConfig
		}
	}
	body, err := ParseInit(in.Body)
	if err != nil {
		return nil, err
	}
	return newPending(s.Env, in, body, cp(s.Ks))
}

// ResponderState is the persistent form of a Responder awaiting hs.fin.
type ResponderState struct {
	suite.Redacted
	Ks, Ke, PRK, KI2R, KR2I, RK []byte
	Th1, Th                     []byte
	KidI2R, KidR2I              []byte
	EpochID                     []byte
	VerifyIK                    []byte  `json:"verify_ik"`
	Sender                      []byte  `json:"sender"`
	Suite                       uint8   `json:"suite"`
	Policy                      Policy  `json:"policy"`
	Purpose                     Purpose `json:"purpose,omitempty"`
	SASCommit                   []byte  `json:"sas_commit,omitempty"` // from hs.init (0.10.3)
	NR                          []byte  `json:"n_r,omitempty"`        // our SAS nonce (0.10.3)
}

// Export returns the responder's persistent state.
func (r *Responder) Export() (ResponderState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		return ResponderState{}, ErrDone
	}
	s := r.sched
	return ResponderState{
		Ks: cp(s.Ks), Ke: cp(s.Ke), PRK: cp(s.PRK), KI2R: cp(s.KI2R), KR2I: cp(s.KR2I), RK: cp(s.RK),
		Th1: cp(s.Th1[:]), Th: cp(s.Th[:]), KidI2R: cp(s.KidI2R[:]), KidR2I: cp(s.KidR2I[:]), EpochID: cp(s.EpochID[:]),
		VerifyIK: cp(r.verifyIK), Sender: cp(r.sender), Suite: r.suiteID, Policy: r.policy,
		Purpose: r.purpose, SASCommit: cp(r.commit), NR: cp(r.nR),
	}, nil
}

// RestoreResponder rebuilds a Responder awaiting hs.fin.
func RestoreResponder(s ResponderState) (*Responder, error) {
	for _, b := range [][]byte{s.Ks, s.Ke, s.PRK, s.KI2R, s.KR2I, s.RK, s.Th1, s.Th} {
		if len(b) != 32 {
			return nil, ErrConfig
		}
	}
	if len(s.EpochID) != suite.EpochIDSize || len(s.VerifyIK) != ed25519.PublicKeySize || len(s.Sender) != ed25519.PublicKeySize {
		return nil, ErrConfig
	}
	if !s.Purpose.Valid() || s.Purpose.HasSAS() && (len(s.SASCommit) != SASNonceSize || len(s.NR) != SASNonceSize) {
		return nil, ErrConfig
	}
	sc := &Schedule{Ks: cp(s.Ks), Ke: cp(s.Ke), PRK: cp(s.PRK), KI2R: cp(s.KI2R), KR2I: cp(s.KR2I), RK: cp(s.RK)}
	copy(sc.Th1[:], s.Th1)
	copy(sc.Th[:], s.Th)
	copy(sc.EpochID[:], s.EpochID)
	var err error
	if sc.KidI2R, err = kidOf(s.KidI2R); err != nil {
		return nil, err
	}
	if sc.KidR2I, err = kidOf(s.KidR2I); err != nil {
		return nil, err
	}
	return &Responder{sched: sc, verifyIK: cp(s.VerifyIK), sender: cp(s.Sender), suiteID: s.Suite, policy: s.Policy,
		purpose: s.Purpose, commit: cp(s.SASCommit), nR: cp(s.NR)}, nil
}

// AcceptRekey builds a PendingInit from a session-mode hs.init that the
// runtime already opened (through its Keyring) under epoch e. It applies
// the same checks as OpenRekeyInit without decrypting twice: purpose rekey,
// ctx equal to e's id, and K_s = e's rk. e must be the current epoch.
func AcceptRekey(raw []byte, in *envelope.Inner, e *Epoch, now time.Time) (*PendingInit, error) {
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
	if body.Ctx != EpochCtx(e.ID()) {
		return nil, ErrCtx
	}
	ks, err := e.rkCopy()
	if err != nil {
		return nil, err
	}
	return newPending(raw, in, body, ks)
}

// Purpose returns the handshake purpose of the initiator.
func (i *Initiator) Purpose() Purpose { return i.cfg.Purpose }
