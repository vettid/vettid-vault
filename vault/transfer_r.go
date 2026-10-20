package vault

import (
	"context"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/recovery"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Transfer from release R (VAULT-MESSAGING 0.33.0 §11.14.10): the new
// phone's secret from its hs.init, the approval's DEK replacement in three
// writes, and the old phone's notice held until the new phone's first
// unlock from storage, for at most 7 days.

// PendingUnlinkTTL bounds how long the old phone's notice is kept.
const PendingUnlinkTTL = 7 * 24 * time.Hour

// PendingUnlink is the old app's device.unlinked{transferred}, sealed at
// the approval to its session and kept in the state until it may be sent.
type PendingUnlink struct {
	RelayURL   string    `json:"relay_url"`
	Mailbox    string    `json:"mailbox"`
	Token      string    `json:"token"`
	TokenExp   time.Time `json:"token_exp"`
	Payload    []byte    `json:"payload"`
	TransferID string    `json:"transfer_id"`
	DEKVersion uint64    `json:"dek_version"`
	At         time.Time `json:"at"`
	// Until is when the notice is deleted unsent: At plus PendingUnlinkTTL
	// divided by the time scale (0.43.0, STAGING-TIME-SCALE S11). Zero in
	// a notice held by a release before the scale: At + PendingUnlinkTTL,
	// so a notice held before the vault moved keeps its 7 days.
	Until time.Time `json:"until,omitzero"`
}

// expired reports whether the held notice is past its deletion time.
func (pu *PendingUnlink) expired(now time.Time) bool {
	until := pu.Until
	if until.IsZero() {
		until = pu.At.Add(PendingUnlinkTTL)
	}
	return now.After(until)
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

// holdUnlink seals the old app's device.unlinked{transferred, transfer_id}
// to its session now and keeps it in the state (§11.14.10).
func (m *Manager) holdUnlink(old *Peer, transferID string, dekVersion uint64, now time.Time) {
	kr := m.sessions[old.ID]
	if kr == nil || kr.Current() == nil || old.Standing.Token == "" {
		return
	}
	body := strictjson.NewBuilder().String("reason", "transferred").String("transfer_id", transferID).Bytes()
	in := &envelope.Inner{ID: m.newID(now), Type: "device.unlinked", TS: now, Body: body}
	raw, err := kr.Current().Seal(in)
	if err != nil {
		return
	}
	m.st.PendingUnlink = &PendingUnlink{RelayURL: old.Relay.URL, Mailbox: old.Relay.Mailbox, Token: old.Standing.Token,
		TokenExp: old.Standing.Exp, Payload: raw, TransferID: transferID, DEKVersion: dekVersion, At: now.UTC(),
		Until: now.UTC().Add(m.opt.scale(PendingUnlinkTTL))}
	m.dirty = true
}

// sendPendingUnlink deposits the held notice (the new phone has unlocked
// from storage at the transfer's dek_version or later, or a recovery
// completed) and deletes it.
func (m *Manager) sendPendingUnlink(now time.Time) {
	pu := m.st.PendingUnlink
	if pu == nil {
		return
	}
	m.st.PendingUnlink = nil
	m.dirty = true
	if !now.Before(pu.TokenExp) && !pu.TokenExp.IsZero() || pu.expired(now) {
		return // deleted unsent
	}
	m.queueDeposit(&OutboxEntry{Op: OpDeposit, RelayURL: pu.RelayURL, Mailbox: pu.Mailbox, Token: pu.Token, Payload: pu.Payload, BestEffort: true}, now)
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

// expirePendingUnlink deletes a held notice older than 7 days (scaled) or whose
// token has expired (housekeeping).
func (m *Manager) expirePendingUnlink(now time.Time) {
	if pu := m.st.PendingUnlink; pu != nil && (pu.expired(now) || !pu.TokenExp.IsZero() && !now.Before(pu.TokenExp)) {
		m.st.PendingUnlink = nil
		m.dirty = true
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
