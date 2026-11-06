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

// MarkActivated sets the activation time to now and restarts the epoch's
// message counts: a new connection's or device's first epoch counts from
// its activation at approval, not from hs.fin (§6.5, 0.10.3).
func (e *Epoch) MarkActivated(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.created = now
	e.sent, e.received = 0, 0
}

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

// retireSendOnly deletes the send key and keeps rk: a responder's
// confirmed epoch while not current (0.86.0, §6.3.1) can still be rekeyed
// from, but no longer sent in.
func (e *Epoch) retireSendOnly() {
	e.mu.Lock()
	defer e.mu.Unlock()
	suite.Wipe(e.sendKey)
	e.sendKey = nil
}

// HasRK reports whether the epoch still holds its rekey secret.
func (e *Epoch) HasRK() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rk != nil
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

// Keyring holds a session's current epoch, the receive keys of previous
// epochs and (0.86.0, §6.3.1) an initiator's pending epoch. A previous
// epoch may keep more than its receive key for a while: a responder's
// confirmed epoch keeps its rk, and the epoch an initiator activated
// without confirmation superseded keeps its send key and rk, for a
// revert. It is safe for concurrent use.
type Keyring struct {
	mu      sync.Mutex
	current *Epoch
	pending *Epoch
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

// Kept says what a superseded epoch keeps besides its receive key.
type Kept uint8

const (
	KeepReceive Kept = iota // receive key only (§6.5)
	KeepRK                  // and rk: a responder's confirmed epoch (§6.3.1)
	KeepSend                // and the send key and rk: an epoch a reverting initiator may go back to (§6.3.1 "Deployment")
)

// ActivateKeeping makes e the current epoch as Activate does, but the
// previous epoch keeps what kept says until until (0.86.0, §6.3.1).
func (k *Keyring) ActivateKeeping(e *Epoch, now, until time.Time, kept Kept) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if c := k.current; c != nil {
		switch kept {
		case KeepReceive:
			c.retireSend()
			until = now.Add(ReceiveKeyRetention)
		case KeepRK:
			c.retireSendOnly()
		}
		k.retired = append(k.retired, retiredEpoch{e: c, until: until})
	}
	k.current = e
	k.pruneLocked(now)
}

// SetPending records e as the initiator's pending epoch (§6.3.1): it opens
// messages but is not current. An earlier pending epoch is abandoned.
func (k *Keyring) SetPending(e *Epoch, now time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.abandonPendingLocked(now)
	k.pending = e
}

// Pending returns the pending epoch (nil if none).
func (k *Keyring) Pending() *Epoch {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.pending
}

// ConfirmPending makes the pending epoch current (§6.3.1): the previous
// current epoch is retired as Activate retires it. It returns the epoch,
// or nil if none was pending.
func (k *Keyring) ConfirmPending(now time.Time) *Epoch {
	k.mu.Lock()
	defer k.mu.Unlock()
	e := k.pending
	if e == nil {
		return nil
	}
	k.pending = nil
	if k.current != nil {
		k.current.retireSend()
		k.retired = append(k.retired, retiredEpoch{e: k.current, until: now.Add(ReceiveKeyRetention)})
	}
	k.current = e
	k.pruneLocked(now)
	return e
}

// AbandonPending abandons the pending epoch (§6.3.1): its receive key is
// kept 16 days as a previous epoch's, nothing else.
func (k *Keyring) AbandonPending(now time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.abandonPendingLocked(now)
}

func (k *Keyring) abandonPendingLocked(now time.Time) {
	if k.pending == nil {
		return
	}
	k.pending.retireSend()
	k.retired = append(k.retired, retiredEpoch{e: k.pending, until: now.Add(ReceiveKeyRetention)})
	k.pending = nil
}

// Reinstate makes the superseded epoch id current again (a revert,
// §6.3.1 "Deployment"; §3.4.1): the current epoch loses its send key and
// rk at once and keeps its receive key 16 days from now, as a previous
// epoch's, so that a later message under it is still authenticated (the
// caller decides what it is). It reports false, changing nothing, unless
// id is a superseded epoch that kept its send key.
func (k *Keyring) Reinstate(id [suite.EpochIDSize]byte, now time.Time) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	for i, r := range k.retired {
		if r.e.id != id || !r.e.CanSend() || !r.e.HasRK() {
			continue
		}
		cur := k.current
		k.current = r.e
		k.retired = append(k.retired[:i], k.retired[i+1:]...)
		if cur != nil {
			cur.retireSend()
			k.retired = append(k.retired, retiredEpoch{e: cur, until: now.Add(ReceiveKeyRetention)})
		}
		return true
	}
	return false
}

// Release ends what the superseded epoch id kept beyond its receive key:
// its send key and rk are deleted, and its receive key is kept until
// until, or its earlier end.
func (k *Keyring) Release(id [suite.EpochIDSize]byte, until time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for i := range k.retired {
		r := &k.retired[i]
		if r.e.id == id {
			r.e.retireSend()
			if until.Before(r.until) {
				r.until = until
			}
		}
	}
}

// Retain sets when the superseded epoch id's keys end.
func (k *Keyring) Retain(id [suite.EpochIDSize]byte, until time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for i := range k.retired {
		if k.retired[i].e.id == id {
			k.retired[i].until = until
		}
	}
}

// DestroyEpoch destroys the epoch id wherever it is (current, pending or
// superseded) and forgets it.
func (k *Keyring) DestroyEpoch(id [suite.EpochIDSize]byte) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.current != nil && k.current.id == id {
		k.current.Destroy()
		k.current = nil
	}
	if k.pending != nil && k.pending.id == id {
		k.pending.Destroy()
		k.pending = nil
	}
	kept := k.retired[:0]
	for _, r := range k.retired {
		if r.e.id == id {
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

// Find returns the epoch id (current, pending, or superseded and still
// kept), or nil.
func (k *Keyring) Find(id [suite.EpochIDSize]byte) *Epoch {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.current != nil && k.current.id == id {
		return k.current
	}
	if k.pending != nil && k.pending.id == id {
		return k.pending
	}
	for _, r := range k.retired {
		if r.e.id == id {
			return r.e
		}
	}
	return nil
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
	if k.pending != nil && kid.Equal(k.pending.recvKid) && found == nil {
		found = k.pending
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
	if k.pending != nil {
		k.pending.Destroy()
		k.pending = nil
	}
	for _, r := range k.retired {
		r.e.Destroy()
	}
	k.retired = nil
}

// OpenSent decrypts a session-mode envelope this side sealed under the
// epoch (its send kids and send key): the runtime reads back an outbox
// entry it has not yet deposited (VAULT-MESSAGING 0.86.3 §3.4.1, a
// message sealed under an epoch an ik link then demoted, sealed again
// under the next one).
func (e *Epoch) OpenSent(env *envelope.Envelope) (*envelope.Inner, error) {
	if env.Mode() != envelope.ModeSession {
		return nil, envelope.ErrWrongMode
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sendKey == nil {
		return nil, ErrEpochRetired
	}
	if !env.RecipientKid().Equal(e.sendRecipientKid) || !env.SenderKid().Equal(e.sendSenderKid) {
		return nil, envelope.ErrKid
	}
	padded, err := envelope.OpenSession(env, e.sendKey)
	if err != nil {
		return nil, err
	}
	defer suite.Wipe(padded)
	return envelope.DecodeInner(padded, envelope.ModeSession)
}
