package vault

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/recovery"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Transfer from release R (VAULT-MESSAGING 0.33.0 §11.14.10): the new
// phone's secret from its hs.init, the approval's DEK replacement in three
// writes, and the old phone's notice held until the new phone's first
// unlock from storage, while its deposit token lives.

// PendingUnlink is the old app's device.unlinked{transferred}, kept in
// the state from the approval until it is delivered (§11.14.10).
//
// Owner decision 2026-10-23 (vettid.org #404): it is kept for as long as
// its deposit token lives, not for a fixed 7 days, and it is sealed at
// delivery, not at the approval. A notice sealed at the approval would be
// refused by the old phone once its ts is more than 16 days old (§8.4,
// durable types); one sealed at delivery has a fresh ts. For that the
// vault keeps the sending half of the old app's session epoch (Epoch: the
// send key and kids and the send counter; no receive key, no rekey
// secret), under the DEK like every session key, and zeroizes it when the
// notice is sent or deleted. The deposit token is the standing token the
// old app issued to the vault; the old app renews it at the approval, so
// it has up to the full 30 days (§7.2).
type PendingUnlink struct {
	RelayURL   string    `json:"relay_url"`
	Mailbox    string    `json:"mailbox"`
	Token      string    `json:"token"`
	TokenExp   time.Time `json:"token_exp"`
	TransferID string    `json:"transfer_id"`
	DEKVersion uint64    `json:"dek_version"`
	At         time.Time `json:"at"`
	// Epoch is the sending half of the old app's session epoch at the
	// approval (handshake.ExportSendOnly). Absent in a notice held by a
	// release before this one, which kept only Payload.
	Epoch *handshake.EpochState `json:"epoch,omitempty"`
	// Payload is the notice sealed at the approval. It is what a release
	// before this one sends (and the only thing it can read), and what
	// this release sends for a notice that has no Epoch.
	Payload []byte `json:"payload"`
	// Queued is the outbox entry that deposits the notice now, until the
	// relay answers: an unlock that finds it queued queues no second copy.
	Queued string `json:"queued,omitempty"`
	// Marked: the approval that held the notice also wrote the transfer's
	// owed mark (State.RotationOwed). A notice held by a release before the
	// mark existed has none, and is treated as owing a rotation
	// (§11.14.10 "The owed mark").
	Marked bool `json:"marked,omitempty"`
}

// until is when a held notice is deleted unsent: when its deposit token
// expires, and at most StandingMax (30 days) after the approval
// (§11.14.10 "at most 30 days after the approval"). The cap holds against
// a token with a longer or no expiry from a faulty or hostile old app
// (heldToken does not bound exp), so the kept send key never outlives it.
func (pu *PendingUnlink) until() time.Time {
	limit := pu.At.Add(StandingMax)
	if !pu.TokenExp.IsZero() && pu.TokenExp.Before(limit) {
		return pu.TokenExp
	}
	return limit
}

// expired reports whether the held notice can no longer be delivered: its
// token has expired.
func (pu *PendingUnlink) expired(now time.Time) bool {
	return !now.Before(pu.until())
}

// wipe zeroizes the kept send key and the sealed payload.
func (pu *PendingUnlink) wipe() {
	if pu.Epoch != nil {
		suite.Wipe(pu.Epoch.SendKey)
		pu.Epoch.SendKey = nil
	}
	suite.Wipe(pu.Payload)
	pu.Payload = nil
}

// approveTransferR is the vault's part of an approval (§11.14.10 step 2):
// the permit, the current wrap opened with the approval's pair and a new
// opener, and step 1 of the DEK replacement with the new phone's unlock
// key and app key in the `next` part. busy and retry leave the transfer
// open with nothing spent but the UTK.
func (m *Manager) approveTransferR(ctx context.Context, r *Request, pin string, pw []byte, backup bool, now time.Time) error {
	if len(m.transferSecret) != recovery.SecretSize {
		return errNotFound // the vault locked since the hs.init: the transfer starts again
	}
	rel0, ok := m.permit(ctx, 0)
	if !ok {
		return errBusy
	}
	rel := sync.OnceFunc(rel0)
	defer rel()
	var rk []byte
	if m.armed() && backup {
		k, err := m.openWrap(m.hdr.Rec.Wrap, pin, pw)
		if err != nil {
			return errRetry
		}
		rk = k
		defer suite.Wipe(rk)
	}
	kdf := m.hdr.KDF
	salt, err := suite.RandomBytes(16)
	if err != nil {
		return errUnavailable
	}
	kdf.Salt = salt
	rep, err := m.nextFor(ReplaceTransfer, pin, m.transferSecret, kdf, nil, now)
	if err != nil {
		return errUnavailable
	}
	if rk != nil {
		if rep.next.Wrap, err = reopen(m.hdr.Rec.Wrap, rk, m.hdr.VaultID, rep.dek1, rep.next.DEKVersion); err != nil {
			rep.wipe()
			return errUnavailable
		}
	}
	p := r.Peer
	rep.next.App = &UnlockKey{DeviceID: p.ID, IK: p.IK, KEM: p.KEM, Attestation: p.Attestation}
	if len(p.APIKey) > 0 {
		rep.next.AppKey, rep.next.AppKeySeq = append([]byte(nil), p.APIKey...), m.hdr.AppKeySeq+1
	}
	if t := m.st.Transfer; t != nil {
		rep.next.TransferID = t.ID
	}
	rep.promoteFn = m.replacementPromoteFn(rep.next)
	rel() // the permit covers the derivations only
	if err := m.beginReplace(ctx, rep); err != nil {
		return err
	}
	suite.Wipe(m.transferSecret)
	m.transferSecret = nil
	return nil
}

// holdUnlink keeps the old app's device.unlinked{transferred,
// transfer_id} in the state (§11.14.10): the sending half of its session
// epoch, to seal the notice at delivery, and, for a release before this
// one that reads the state, the notice sealed now.
func (m *Manager) holdUnlink(old *Peer, transferID string, dekVersion uint64, now time.Time) {
	kr := m.sessions[old.ID]
	if kr == nil || kr.Current() == nil || old.Standing.Token == "" {
		return
	}
	if prev := m.st.PendingUnlink; prev != nil {
		// A second transfer before the first one's notice went out
		// (§11.14.10 keeps one pending unlink): the earlier notice is
		// dropped and its kept send key zeroized. No audit kind exists
		// for a dropped notice (§10.9), so none is recorded.
		m.st.PendingUnlink = nil
		prev.wipe()
	}
	cur := kr.Current()
	raw, err := cur.Seal(m.unlinkInner(transferID, now))
	if err != nil {
		return
	}
	// Exported after that seal, so the notice sealed at delivery takes the
	// next seq; nothing else is sealed in this epoch afterwards (the old
	// app is removed in this flush, and its session destroyed).
	ep, err := cur.ExportSendOnly()
	if err != nil {
		suite.Wipe(raw)
		return
	}
	m.st.PendingUnlink = &PendingUnlink{RelayURL: old.Relay.URL, Mailbox: old.Relay.Mailbox, Token: old.Standing.Token,
		TokenExp: old.Standing.Exp, TransferID: transferID, DEKVersion: dekVersion, At: now.UTC(), Epoch: &ep, Payload: raw, Marked: true}
	m.dirty = true
}

// unlinkInner is the notice's plaintext at now.
func (m *Manager) unlinkInner(transferID string, now time.Time) *envelope.Inner {
	body := strictjson.NewBuilder().String("reason", "transferred").String("transfer_id", transferID).Bytes()
	return &envelope.Inner{ID: m.newID(now), Type: "device.unlinked", TS: now, Body: body}
}

// sendPendingUnlink queues the deposit of the held notice (the new phone
// has unlocked from storage at the transfer's dek_version or later, a
// recovery completed, or the vault's keys rotate), whatever its age, while
// its token lives. It is sealed now, with a fresh ts, in the old app's
// epoch, whose kept send counter moves on in the same state (a notice held
// by an earlier release, without the epoch, goes as it was sealed). The
// notice stays held until the relay settles it (unlinkOutcome): accepted,
// or refused for good; any other answer leaves it for the next unlock
// (§11.14.10 "What settles the notice", "If the notice is not accepted").
// While one deposit is queued no second copy is queued.
func (m *Manager) sendPendingUnlink(now time.Time) {
	pu := m.st.PendingUnlink
	if pu == nil {
		return
	}
	if pu.expired(now) {
		m.dropPendingUnlink() // deleted unsent: the token cannot deposit any more
		return
	}
	if pu.Queued != "" && m.outboxQueued(pu.Queued) {
		return
	}
	payload := pu.Payload
	if pu.Epoch != nil {
		e, err := handshake.ImportSendOnly(*pu.Epoch)
		if err != nil {
			m.dropPendingUnlink() // a damaged epoch: deleted unsent, as an expired one
			return
		}
		raw, err := e.Seal(m.unlinkInner(pu.TransferID, now))
		if err != nil {
			e.Destroy()
			return
		}
		ep, err := e.ExportSendOnly() // the counter after this seal
		e.Destroy()
		if err != nil {
			suite.Wipe(raw)
			return
		}
		suite.Wipe(pu.Epoch.SendKey)
		pu.Epoch = &ep
		payload = raw
	} else {
		payload = append([]byte(nil), payload...)
	}
	e := &OutboxEntry{Op: OpDeposit, RelayURL: pu.RelayURL, Mailbox: pu.Mailbox, Token: pu.Token, Payload: payload,
		BestEffort: true, Unlink: pu.TransferID}
	m.queueDeposit(e, now)
	pu.Queued = e.ID
}

// outboxQueued reports whether the outbox entry id is still to be done.
func (m *Manager) outboxQueued(id string) bool {
	for _, e := range m.st.Outbox {
		if e.ID == id {
			return !e.Done
		}
	}
	return false
}

// dropPendingUnlink deletes the held notice and zeroizes its kept send key.
func (m *Manager) dropPendingUnlink() {
	if pu := m.st.PendingUnlink; pu != nil {
		m.st.PendingUnlink = nil
		m.dirty = true
		pu.wipe()
	}
}

// unlinkOutcome applies the relay's answer to the deposit of a held notice
// (§11.14.10 "What settles the notice"): accepted (its 201), or refused for
// good (the token expired or revoked, the mailbox gone), the notice is
// settled and deleted, and a transfer's owed rotation is made in the state
// write that follows; a timeout, an unreachable relay, a 5xx or any other
// refusal leave it held, for the next unlock to deposit again.
func (m *Manager) unlinkOutcome(e *OutboxEntry, err error, now time.Time) {
	pu := m.st.PendingUnlink
	if pu == nil || pu.Queued != e.ID {
		return // an earlier transfer's notice, or one already settled
	}
	m.dirty = true
	switch code := RelayCode(err); {
	case err == nil:
		m.record(Activity{Kind: "device.unlinked_sent", Ref: pu.TransferID, Audit: true}, now)
	case code == CodeTokenExpired || code == CodeTokenRevoked || code == CodeMailboxUnknown:
	default:
		pu.Queued = ""
		return
	}
	m.dropPendingUnlink()
	if m.st.Deleting != nil {
		return // a deletion's step 2 drains the outbox: nothing rotates (§12.5)
	}
	if o := m.st.RotationOwed; o != nil && o.Transfer != "" {
		m.retryOwedRotation(now)
		// The rotation's notices go out only after the state write that
		// holds it (§3.4, §11.14.2): they are unstored until then (queue),
		// and the drain writes the state when it has finished
		// (settledWrite), then sends them.
		m.settledWrite = true
	}
}

// pendingUnlinkAtUnlock sends the held notice when the vault's current
// app has unlocked from the stored objects under the transfer's
// dek_version or a later one. The held credential key rotation statement
// goes first, under its own transfer's dek_version (§11.14.10 "The rest,
// after the new phone's first unlock"). A notice held by a release before
// the owed mark existed gets the mark it would have had.
func (m *Manager) pendingUnlinkAtUnlock(now time.Time) {
	ver := m.dekVersion()
	if h := m.st.HeldKeyRotation; h != nil && ver >= h.DEKVersion {
		m.sendHeldKeyRotations(now)
	}
	if pu := m.st.PendingUnlink; pu != nil && ver >= pu.DEKVersion {
		if !pu.Marked {
			pu.Marked = true
			m.owe(pu.TransferID, pu.DEKVersion, pu.At)
		}
		m.sendPendingUnlink(now)
	}
}

// dekVersion is the DEK version the state is written under.
func (m *Manager) dekVersion() uint64 {
	if m.repl != nil {
		return m.repl.next.DEKVersion
	}
	return m.hdr.DEKVersion
}

// owe records a transfer's owed mark (§11.14.10 "The owed mark"), next to
// a recovery's if one is owed.
func (m *Manager) owe(transferID string, dekVersion uint64, at time.Time) {
	o := m.st.RotationOwed
	if o == nil {
		o = &RotationOwed{}
		m.st.RotationOwed = o
	}
	o.Transfer, o.DEKVersion, o.At = transferID, dekVersion, at.UTC()
	m.dirty = true
}

// transferRotationWaits reports whether a transfer's owed rotation still
// waits (§11.14.10 "The rest, after the new phone's first unlock"): for an
// unlock under its DEK version, or for the old phone's notice, which can
// still be delivered, before day 7 after the approval.
func (m *Manager) transferRotationWaits(o *RotationOwed, now time.Time) bool {
	if m.dekVersion() < o.DEKVersion {
		return true
	}
	pu := m.st.PendingUnlink
	if pu == nil || pu.expired(now) {
		return false // no notice to wait for: settled
	}
	return now.Before(o.At.Add(TransferRotateAnyway))
}

// TransferRotateAnyway is how long after a transfer's approval its
// rotation waits for the old phone's notice: from then, the next unlock
// rotates with or without it (§11.14.10 "If the notice is not accepted",
// the old app's day-7 check).
const TransferRotateAnyway = 7 * 24 * time.Hour

// expirePendingUnlink deletes a held notice whose token has expired
// (housekeeping), and zeroizes its kept send key.
func (m *Manager) expirePendingUnlink(now time.Time) {
	if pu := m.st.PendingUnlink; pu != nil && pu.expired(now) {
		m.dropPendingUnlink()
	}
}

// recoveredPhonePaired completes the hand-over to a recovered phone at its
// first handshake (§11.14.6): the credential's holder and the signer
// binding move to it, and (0.52.0, §3.5.9) the same flush removes every
// other app, so that it is the vault's only app.
func (m *Manager) recoveredPhonePaired(p *Peer, now time.Time) {
	wasDigest, wasClass := m.vaultSigner(p.ID)
	if rs := m.st.RecoveredSigner; len(rs) == 2 {
		wasDigest, wasClass = rs[0], rs[1]
		m.st.RecoveredSigner = nil
	}
	p.Recovering = false
	m.signerMoved(wasDigest, wasClass, p, now)
	m.replaceApps(p.ID, now) // device.unlinked{reason: "replaced"}
	sess := m.session(now)
	for _, f := range m.features {
		if o, ok := f.(TransferObserver); ok {
			o.TransferCompleted(sess, "", p.ID)
		}
	}
	for _, id := range sortedKeys(m.st.Invites) {
		inv, sortedOK := m.st.Invites[id]
		if !sortedOK {
			continue // removed earlier in this loop
		}
		if inv.CreatedBy == inviteByRecovery && suite.EqualPublic(inv.EnrollIK, p.IK) {
			delete(m.st.Invites, id)
		}
	}
	m.record(Activity{Kind: "recovery.device_paired", DeviceID: p.ID, Audit: true, Feed: true}, now)
	m.notifyDevices("sync.event", strictjson.NewBuilder().String("kind", "device.paired").String("device_id", p.ID).
		String("role", p.Kind).Bytes(), p.ID, now)
}

// HeldKeyRotation is the credential key's rotation statement K0→K1 made at
// a transfer's approval (§11.14.10 "The credential key, at the approval"):
// written with the step-2 state, and sent to the connections that pinned
// the earlier key only at the first unlock from storage under DEKVersion or
// a later one, before device.unlinked{transferred}; a recovery or a later
// rotation sends it first. A state that was not stored, or was restored to
// an earlier one, never holds it, so "The move didn't finish" needs no step
// to undo it. Statements is the chain in order: a second transfer approved
// before the first one's statement went out adds its own.
type HeldKeyRotation struct {
	TransferID string            `json:"transfer_id"`
	DEKVersion uint64            `json:"dek_version"`
	Statements []json.RawMessage `json:"statements"`
}

// KeyRotationHost is implemented by the runtime (§11.14.10): it holds the
// credential key's rotation statements of a transfer's approval in the
// state, and gives them up to a rotation that sends them first.
type KeyRotationHost interface {
	HoldKeyRotation(statement []byte, now time.Time) error
	TakeHeldKeyRotations(now time.Time) [][]byte
	KeyRotationHeld() bool
}

// KeyRotationSender is implemented by the credential feature: it sends
// held rotation statements, in order, to the connections that pinned an
// earlier credential key (§10.4). The runtime calls it outside the
// feature's handlers. It must not call back into the runtime's holding.
type KeyRotationSender interface {
	SendKeyRotations(s *Session, statements [][]byte)
}

// HoldKeyRotation keeps a credential key rotation statement made at a
// transfer's approval, after ApproveTransfer, until the new phone's first
// unlock from storage (§11.14.10). If the handler then fails, it is not
// kept.
func (s *Session) HoldKeyRotation(statement []byte) error {
	h, ok := s.host.(KeyRotationHost)
	if !ok {
		return errUnavailable
	}
	return h.HoldKeyRotation(statement, s.now)
}

// TakeHeldKeyRotations returns the statements still held, oldest first,
// and stops holding them: the caller sends them before its own rotation
// statement (§11.14.10 "The owed mark").
func (s *Session) TakeHeldKeyRotations() [][]byte {
	h, ok := s.host.(KeyRotationHost)
	if !ok {
		return nil
	}
	return h.TakeHeldKeyRotations(s.now)
}

// KeyRotationHeld reports whether a credential key rotation statement is
// still held (§11.14.10): a signature under the current credential key may
// then not be followed by a connection that pinned the earlier key.
func (s *Session) KeyRotationHeld() bool {
	h, ok := s.host.(KeyRotationHost)
	return ok && h.KeyRotationHeld()
}

func (h managerHost) KeyRotationHeld() bool { return h.m.st.HeldKeyRotation != nil }

func (h managerHost) HoldKeyRotation(statement []byte, now time.Time) error {
	return h.m.holdKeyRotation(statement)
}

// TakeHeldKeyRotations gives a handler the held chain (credential.rotate);
// if the handler fails, the chain is held again.
func (h managerHost) TakeHeldKeyRotations(time.Time) [][]byte {
	m := h.m
	if m.st.HeldKeyRotation != nil && !m.heldInHandler {
		m.heldInHandler, m.heldBefore = true, m.st.HeldKeyRotation
	}
	return m.takeHeldKeyRotations()
}

// holdKeyRotation adds a statement to the held chain, for the approved
// transfer of the current handler, at the DEK version its step 2 writes.
func (m *Manager) holdKeyRotation(statement []byte) error {
	t := m.st.Transfer
	if t == nil || t.State != TransferApproved || len(statement) == 0 {
		return errNotFound
	}
	ver := m.hdr.DEKVersion
	if m.repl != nil {
		ver = m.repl.next.DEKVersion
	}
	prev := m.st.HeldKeyRotation
	if !m.heldInHandler {
		m.heldInHandler, m.heldBefore = true, prev
	}
	next := &HeldKeyRotation{TransferID: t.ID, DEKVersion: ver}
	if prev != nil {
		next.Statements = append(next.Statements, prev.Statements...)
	}
	next.Statements = append(next.Statements, append(json.RawMessage(nil), statement...))
	m.st.HeldKeyRotation = next
	m.dirty = true
	return nil
}

// takeHeldKeyRotations clears the held chain and returns it.
func (m *Manager) takeHeldKeyRotations() [][]byte {
	h := m.st.HeldKeyRotation
	if h == nil {
		return nil
	}
	m.st.HeldKeyRotation = nil
	m.dirty = true
	out := make([][]byte, 0, len(h.Statements))
	for _, st := range h.Statements {
		out = append(out, []byte(st))
	}
	return out
}

// sendHeldKeyRotations sends the held chain to the connections that pinned
// an earlier credential key (through the credential feature) and stops
// holding it, in the same state write as what follows: the deposits are
// queued in the outbox ahead of anything sent after them.
func (m *Manager) sendHeldKeyRotations(now time.Time) {
	stmts := m.takeHeldKeyRotations()
	if len(stmts) == 0 {
		return
	}
	sess := m.session(now)
	for _, f := range m.features {
		if ks, ok := f.(KeyRotationSender); ok {
			ks.SendKeyRotations(sess, stmts)
		}
	}
}
