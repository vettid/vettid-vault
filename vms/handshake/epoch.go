package handshake

import (
	"sync"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Role is this side's role in the handshake that created an epoch.
type Role uint8

const (
	RoleInitiator Role = 1
	RoleResponder Role = 2
)

// Policy bounds an epoch (§6.5). An epoch is due for rekey after MaxAge,
// or after MaxMessages sent or received (0: no message bound).
type Policy struct {
	MaxAge      time.Duration
	MaxMessages uint64
}

var (
	// PolicyVaultToVault: 24 h or 10,000 messages in either direction.
	PolicyVaultToVault = Policy{MaxAge: 24 * time.Hour, MaxMessages: 10000}
	// PolicyVaultToDevice: 7 days (and on every unlock, which the runtime
	// triggers).
	PolicyVaultToDevice = Policy{MaxAge: 7 * 24 * time.Hour}
)

// ReceiveKeyRetention is how long receive keys of previous epochs are kept
// after a new epoch activates (§6.5): the relay TTL plus a margin.
const ReceiveKeyRetention = 16 * 24 * time.Hour

// Epoch is one active session epoch: a send and a receive direction, each
// with its key and kids, plus the rekey secret rk. It is safe for
// concurrent use and redacts itself when formatted.
type Epoch struct {
	suite.Redacted
	mu sync.Mutex

	id      [suite.EpochIDSize]byte
	role    Role
	suiteID uint8
	policy  Policy
	created time.Time

	sendKey          []byte
	sendSenderKid    suite.Kid // header sender_kid when sending
	sendRecipientKid suite.Kid // header recipient_kid when sending
	recvKey          []byte
	recvKid          suite.Kid // recipient_kid of messages to us
	recvSenderKid    suite.Kid // sender_kid of messages to us
	rk               []byte

	lastSeq  uint64 // last seq sent
	sent     uint64
	received uint64
}

// newEpoch builds an epoch from a schedule. Direction i2r uses k_i2r with
// recipient_kid = kid_i2r and sender_kid = kid_r2i; r2i mirrors it (§6.3).
func newEpoch(s *Schedule, role Role, suiteID uint8, policy Policy, now time.Time) *Epoch {
	e := &Epoch{id: s.EpochID, role: role, suiteID: suiteID, policy: policy, created: now,
		rk: append([]byte(nil), s.RK...)}
	i2rKey := append([]byte(nil), s.KI2R...)
	r2iKey := append([]byte(nil), s.KR2I...)
	if role == RoleInitiator {
		e.sendKey, e.sendRecipientKid, e.sendSenderKid = i2rKey, s.KidI2R, s.KidR2I
		e.recvKey, e.recvKid, e.recvSenderKid = r2iKey, s.KidR2I, s.KidI2R
	} else {
		e.sendKey, e.sendRecipientKid, e.sendSenderKid = r2iKey, s.KidR2I, s.KidI2R
		e.recvKey, e.recvKid, e.recvSenderKid = i2rKey, s.KidI2R, s.KidR2I
	}
	return e
}

// ID returns the epoch id.
func (e *Epoch) ID() [suite.EpochIDSize]byte { return e.id }

// Role returns this side's role in the handshake that created the epoch.
func (e *Epoch) Role() Role { return e.role }

// Suite returns the negotiated suite.
func (e *Epoch) Suite() uint8 { return e.suiteID }

// RecvKid returns the recipient_kid that messages to this side carry.
func (e *Epoch) RecvKid() suite.Kid { return e.recvKid }

// Created returns the activation time.
func (e *Epoch) Created() time.Time { return e.created }

// Counts returns the numbers of messages sent and received.
func (e *Epoch) Counts() (sent, received uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sent, e.received
}

// NeedsRekey reports whether the epoch has reached its policy limit
// (§6.5). The side that hits the limit initiates the rekey. Sending in the
// epoch remains possible until the new epoch activates, so that a peer that
// is locked does not block delivery.
func (e *Epoch) NeedsRekey(now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.policy.MaxAge > 0 && now.Sub(e.created) >= e.policy.MaxAge {
		return true
	}
	m := e.policy.MaxMessages
	return m > 0 && (e.sent >= m || e.received >= m)
}

// CanSend reports whether the epoch still holds its send key.
func (e *Epoch) CanSend() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sendKey != nil
}

// rkCopy returns a copy of rk, the K_s of the next rekey (§6.2).
func (e *Epoch) rkCopy() ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.rk == nil {
		return nil, ErrEpochRetired
	}
	return append([]byte(nil), e.rk...), nil
}

// Seal encrypts an inner plaintext in session mode. It assigns in.Seq, the
// per-epoch, per-direction counter starting at 1 (§5.3). The same in.ID
// may be sealed again for a retransmission; every call produces a new
// envelope with a fresh nonce.
func (e *Epoch) Seal(in *envelope.Inner) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sendKey == nil {
		return nil, ErrEpochRetired
	}
	in.Seq = e.lastSeq + 1
	padded, err := envelope.EncodeInner(in, envelope.ModeSession)
	if err != nil {
		in.Seq = 0
		return nil, err
	}
	defer suite.Wipe(padded)
	env, err := envelope.SealSession(e.sendKey, e.sendSenderKid, e.sendRecipientKid, padded)
	if err != nil {
		in.Seq = 0
		return nil, err
	}
	e.lastSeq++
	e.sent++
	return env, nil
}

// Open decrypts a session-mode envelope addressed to this epoch: its
// recipient_kid and sender_kid must be this epoch's receive kids (compared
// in constant time), the AEAD must verify, and the inner plaintext must
// parse strictly.
func (e *Epoch) Open(env *envelope.Envelope) (*envelope.Inner, error) {
	if env.Mode() != envelope.ModeSession {
		return nil, envelope.ErrWrongMode
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.recvKey == nil {
		return nil, ErrEpochRetired
	}
	if !env.RecipientKid().Equal(e.recvKid) || !env.SenderKid().Equal(e.recvSenderKid) {
		return nil, envelope.ErrKid
	}
	padded, err := envelope.OpenSession(env, e.recvKey)
	if err != nil {
		return nil, err
	}
	defer suite.Wipe(padded)
	in, err := envelope.DecodeInner(padded, envelope.ModeSession)
	if err != nil {
		return nil, err
	}
	e.received++
	return in, nil
}

// retireSend deletes the send key and rk when a newer epoch activates
// (§6.5). The receive key stays for ReceiveKeyRetention.
func (e *Epoch) retireSend() {
	e.mu.Lock()
	defer e.mu.Unlock()
	suite.Wipe(e.sendKey)
	suite.Wipe(e.rk)
	e.sendKey, e.rk = nil, nil
}

// Destroy wipes every key of the epoch.
func (e *Epoch) Destroy() {
	e.mu.Lock()
	defer e.mu.Unlock()
	suite.Wipe(e.sendKey)
	suite.Wipe(e.recvKey)
	suite.Wipe(e.rk)
	e.sendKey, e.recvKey, e.rk = nil, nil, nil
}

// Keyring holds a session's current epoch and the receive keys of
// previous epochs. It is safe for concurrent use.
type Keyring struct {
	mu      sync.Mutex
	current *Epoch
	retired []retiredEpoch
}

type retiredEpoch struct {
	e     *Epoch
	until time.Time
}

// Activate makes e the current epoch. The previous epoch's send key and rk
// are deleted at once; its receive key is kept for ReceiveKeyRetention.
func (k *Keyring) Activate(e *Epoch, now time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.current != nil {
		k.current.retireSend()
		k.retired = append(k.retired, retiredEpoch{e: k.current, until: now.Add(ReceiveKeyRetention)})
	}
	k.current = e
	k.pruneLocked(now)
}

// Current returns the current epoch (nil if none).
func (k *Keyring) Current() *Epoch {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.current
}

// Prune destroys retired receive keys past their retention.
func (k *Keyring) Prune(now time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.pruneLocked(now)
}

func (k *Keyring) pruneLocked(now time.Time) {
	kept := k.retired[:0]
	for _, r := range k.retired {
		if now.After(r.until) {
			r.e.Destroy()
			continue
		}
		kept = append(kept, r)
	}
	for i := len(kept); i < len(k.retired); i++ {
		k.retired[i] = retiredEpoch{}
	}
	k.retired = kept
}

// lookup selects the one epoch whose receive kid matches. Every candidate
// is compared, in constant time, so the lookup does not reveal which
// position matched.
func (k *Keyring) lookup(kid suite.Kid, now time.Time) *Epoch {
	var found *Epoch
	if k.current != nil && kid.Equal(k.current.recvKid) {
		found = k.current
	}
	for _, r := range k.retired {
		if !now.After(r.until) && kid.Equal(r.e.recvKid) && found == nil {
			found = r.e
		}
	}
	return found
}

// Open routes a session-mode envelope by recipient_kid to the current or a
// retained epoch and decrypts it there. No other epoch is tried (§4.4).
func (k *Keyring) Open(env *envelope.Envelope, now time.Time) (*envelope.Inner, *Epoch, error) {
	k.mu.Lock()
	e := k.lookup(env.RecipientKid(), now)
	k.mu.Unlock()
	if e == nil {
		return nil, nil, envelope.ErrKid
	}
	in, err := e.Open(env)
	if err != nil {
		return nil, nil, err
	}
	return in, e, nil
}

// Destroy wipes every epoch in the keyring.
func (k *Keyring) Destroy() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.current != nil {
		k.current.Destroy()
		k.current = nil
	}
	for _, r := range k.retired {
		r.e.Destroy()
	}
	k.retired = nil
}
