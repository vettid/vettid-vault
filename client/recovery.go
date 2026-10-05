package client

import (
	"context"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// Recovery (VAULT-MESSAGING §11.11) from the new app's side: register with
// the code from the portal's QR, unlock with the PIN, run the first
// handshake, then authenticate with the credential password.

// RecoveryState is what a recovering app keeps.
type RecoveryState struct {
	RecoveryID string `json:"recovery_id"`
	RequestID  string `json:"request_id,omitempty"` // the pending register request
	// CredentialBackup is the vault's credential.backup setting from the
	// unlock result (§11.11.5 step 1, 0.10.6); nil until then, or from a
	// vault that does not send it.
	CredentialBackup *bool `json:"credential_backup,omitempty"`
}

// RecoveryCredentialBackup reports, for a recovering app after its PIN
// unlock, whether the vault keeps a copy of the credential (§11.11.5 step
// 1, 0.10.6): with known and !backup the app does not ask for the password
// (credential.recover cannot succeed) and goes straight to
// CredentialReset or deleting the vault (step 4). known is false before
// the unlock or for a vault that does not say (then ask for the password;
// credential.recover answers credential_lost if there is no copy).
func (d *Device) RecoveryCredentialBackup() (backup, known bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.st.Recovery == nil || d.st.Recovery.CredentialBackup == nil {
		return false, false
	}
	return *d.st.Recovery.CredentialBackup, true
}

// BuildRecoveryRegister builds vault.recovery.register (§11.11.3) for the
// enclave e, attesting a fresh device key with the request's challenge.
func (d *Device) BuildRecoveryRegister(userGUID string, qr *altchan.RecoveryCode, e *Enclave, att Attester) (*Request, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.st.Vault != nil {
		return nil, ErrProtocol // already paired with a vault
	}
	now := d.cfg.Now()
	rid, err := envelope.NewULID(now)
	if err != nil {
		return nil, err
	}
	ts := now.UTC().Truncate(time.Millisecond)
	ch, err := altchan.DevattChallenge(rid, qr.VaultID, envelope.FormatTS(ts))
	if err != nil {
		return nil, err
	}
	da, err := att.Attest(ch)
	if err != nil {
		return nil, err
	}
	ra := d.RelayAddr()
	body, err := (&altchan.RecoveryRegisterRequest{UserGUID: userGUID, VaultID: qr.VaultID, RequestID: rid,
		RecoveryID: qr.RecoveryID, Code: qr.Code, IK: d.IdentityKey(), KEM: d.kem.Public(),
		Relay: altchan.RelayAddr{URL: ra.URL, Mailbox: ra.Mailbox, PK: ra.PK}, Name: d.st.Name, Attest: da}).Marshal()
	if err != nil {
		return nil, err
	}
	env, err := altchan.SealRequest(e.Descriptor.ETK, altchan.TypeRecoveryRegister, rid, ts, body)
	if err != nil {
		return nil, err
	}
	d.st.VaultID = qr.VaultID
	d.st.Recovery = &RecoveryState{RecoveryID: qr.RecoveryID, RequestID: rid}
	return &Request{RequestID: rid, ETKKid: e.Descriptor.Kid.String(), Envelope: env}, nil
}

// OpenRecoveryResult reads vault.recovery.result from the response slot.
func (d *Device) OpenRecoveryResult(raw []byte) (*altchan.RecoveryResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.st.Recovery == nil || d.st.Recovery.RequestID == "" {
		return nil, ErrNoPending
	}
	body, err := altchan.OpenResult(raw, d.kem, altchan.TypeRecoveryResult, d.st.Recovery.RequestID)
	if err != nil {
		return nil, ErrResult
	}
	return altchan.ParseRecoveryResult(body)
}

// adoptBundle pins the vault from the recovered app's unlock result.
func (d *Device) adoptBundle(bundle []byte) error {
	bo, err := strictjson.ParseObject(bundle)
	if err != nil {
		return ErrResult
	}
	if v, err := bo.Uint("v", 1, 1); err != nil || v != 1 {
		return ErrResult
	}
	if s, err := bo.Uint("suite", 2, 2); err != nil || s != 2 {
		return ErrResult
	}
	pr, err := handshake.ParsePrincipal(bo)
	if err != nil {
		return ErrResult
	}
	d.setVaultFromPrincipal(pr)
	return nil
}

// CompleteRecoveryHandshake runs the recovered app's first handshake
// (purpose app, ctx = recovery id) after its PIN unlock and waits for
// device.paired.
func (d *Device) CompleteRecoveryHandshake(ctx context.Context) error {
	d.mu.Lock()
	if d.st.Vault == nil || d.st.Vault.Token == "" || d.st.Recovery == nil {
		d.mu.Unlock()
		return ErrNotPaired
	}
	err := d.startInit(handshake.PurposeApp, d.st.Recovery.RecoveryID, d.st.Vault.Token, nil)
	d.mu.Unlock()
	if err != nil {
		return err
	}
	return d.awaitPaired(ctx)
}
