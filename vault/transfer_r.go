package vault

import (
	"context"
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
		TokenExp: old.Standing.Exp, TransferID: transferID, DEKVersion: dekVersion, At: now.UTC(), Epoch: &ep, Payload: raw}
	m.dirty = true
}

// unlinkInner is the notice's plaintext at now.
func (m *Manager) unlinkInner(transferID string, now time.Time) *envelope.Inner {
	body := strictjson.NewBuilder().String("reason", "transferred").String("transfer_id", transferID).Bytes()
	return &envelope.Inner{ID: m.newID(now), Type: "device.unlinked", TS: now, Body: body}
}

// sendPendingUnlink deposits the held notice (the new phone has unlocked
// from storage at the transfer's dek_version or later, or a recovery
// completed) and deletes it, whatever its age, while its token lives. It
// is sealed now, with a fresh ts, in the old app's epoch (a notice held
// by an earlier release, without the epoch, goes as it was sealed).
func (m *Manager) sendPendingUnlink(now time.Time) {
	pu := m.st.PendingUnlink
	if pu == nil {
		return
	}
	m.st.PendingUnlink = nil
	m.dirty = true
	defer pu.wipe()
	if pu.expired(now) {
		return // deleted unsent: the token cannot deposit any more
	}
	payload := pu.Payload
	if pu.Epoch != nil {
		e, err := handshake.ImportSendOnly(*pu.Epoch)
		if err != nil {
			return // a damaged epoch: deleted unsent, as an expired one
		}
		raw, err := e.Seal(m.unlinkInner(pu.TransferID, now))
		e.Destroy()
		if err != nil {
			return
		}
		payload = raw
	} else {
		payload = append([]byte(nil), payload...)
	}
	m.queueDeposit(&OutboxEntry{Op: OpDeposit, RelayURL: pu.RelayURL, Mailbox: pu.Mailbox, Token: pu.Token, Payload: payload, BestEffort: true}, now)
	m.record(Activity{Kind: "device.unlinked_sent", Ref: pu.TransferID, Audit: true}, now)
}

// pendingUnlinkAtUnlock sends the held notice when the vault's current
// app has unlocked from the stored objects under the transfer's
// dek_version or a later one.
func (m *Manager) pendingUnlinkAtUnlock(now time.Time) {
	pu := m.st.PendingUnlink
	if pu == nil {
		return
	}
	ver := m.hdr.DEKVersion
	if m.repl != nil {
		ver = m.repl.next.DEKVersion
	}
	if ver >= pu.DEKVersion {
		m.sendPendingUnlink(now)
	}
}

// expirePendingUnlink deletes a held notice whose token has expired
// (housekeeping), and zeroizes its kept send key.
func (m *Manager) expirePendingUnlink(now time.Time) {
	if pu := m.st.PendingUnlink; pu != nil && pu.expired(now) {
		m.st.PendingUnlink = nil
		m.dirty = true
		pu.wipe()
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
	for id, inv := range m.st.Invites {
		if inv.CreatedBy == inviteByRecovery && suite.EqualPublic(inv.EnrollIK, p.IK) {
			delete(m.st.Invites, id)
		}
	}
	m.record(Activity{Kind: "recovery.device_paired", DeviceID: p.ID, Audit: true, Feed: true}, now)
	m.notifyDevices("sync.event", strictjson.NewBuilder().String("kind", "device.paired").String("device_id", p.ID).
		String("role", p.Kind).Bytes(), p.ID, now)
}
