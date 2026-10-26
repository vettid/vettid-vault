package client

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/devattest"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/manifest"
	"github.com/vettid/vettid-vault/vms/recovery"
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

// RecoveryCredentialBackup reports the credential_backup member of a
// recovering app's unlock result (§11.11.5 step 1, 0.10.6). Since 0.16.0 it
// is always true (a vault without a backup copy refuses that unlock with
// no_backup); apps MAY ignore it. known is false before the unlock.
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
	d.keepChain(da)
	_, apiKey, err := d.appKeyLocked()
	if err != nil {
		return nil, err
	}
	ra := d.RelayAddr()
	body, err := (&altchan.RecoveryRegisterRequest{APIKey: apiKey, UserGUID: userGUID, VaultID: qr.VaultID, RequestID: rid,
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
	return &Request{RequestID: rid, ETKKid: e.Descriptor.Kid.String(), Envelope: env, AppKey: apiKey}, nil
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
	return d.CompleteRecoveryHandshakeAs(ctx, "")
}

// CompleteRecoveryHandshakeAs is CompleteRecoveryHandshake with ctx = an
// earlier recovery_id this phone registered for ("": the current one):
// after a lost ok whose unlock finished an earlier registration's open,
// the invitation is that registration's (VAULT-MESSAGING 0.63.2 §11.14.6
// "Pairing").
func (d *Device) CompleteRecoveryHandshakeAs(ctx context.Context, recoveryID string) error {
	d.mu.Lock()
	if d.st.Vault == nil || d.st.Vault.Token == "" || d.st.Recovery == nil {
		d.mu.Unlock()
		return ErrNotPaired
	}
	if recoveryID == "" {
		recoveryID = d.st.Recovery.RecoveryID
	}
	err := d.startInit(handshake.PurposeApp, recoveryID, d.st.Vault.Token, nil)
	d.mu.Unlock()
	if err != nil {
		return err
	}
	// The hs.fin first: if it is refused for good, the vault never sends
	// device.paired (ErrHandshakeUnsent, ErrRefused).
	if _, err := d.awaitHandshake(ctx); err != nil {
		return err
	}
	return d.awaitPaired(ctx)
}

// BuildRecoveryOpen builds vault.recovery.open (0.33.0, release R,
// §11.14.6) for the registered phone: the PIN and the password together,
// the phone's unlock secret (a new phone key, epoch 1, made at the first
// open of this recovery), an open token for its mailbox, a device
// assertion, and the signature of the device key. m is the verified
// manifest.
func (d *Device) BuildRecoveryOpen(userGUID, pin, password string, e *Enclave, m *manifest.Manifest, att Attester) (*Request, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.st.Recovery == nil {
		return nil, ErrNoPending
	}
	if d.st.PhoneKey == nil || d.st.SecretVault != d.st.VaultID {
		if err := d.newPhoneKeyLocked(d.st.VaultID); err != nil {
			return nil, err
		}
	}
	now := d.cfg.Now()
	rid, err := envelope.NewULID(now)
	if err != nil {
		return nil, err
	}
	ts := now.UTC().Truncate(time.Millisecond)
	tss := envelope.FormatTS(ts)
	ch, err := altchan.DevattChallenge(rid, d.st.VaultID, tss)
	if err != nil {
		return nil, err
	}
	as, err := att.Assert(devattest.ForChallenge(ch))
	if err != nil {
		return nil, err
	}
	tok, err := d.own.MintOpenToken(d.st.RelayURL, 10*time.Minute, "")
	if err != nil {
		return nil, err
	}
	_, apiKey, err := d.appKeyLocked()
	if err != nil {
		return nil, err
	}
	us := d.unlockSecretLocked(d.st.Epoch)
	pw, ok := recovery.NormalizePassword([]byte(password))
	if !ok {
		return nil, ErrProtocol
	}
	secrets, err := recovery.Secrets(pin, pw)
	if err != nil {
		return nil, err
	}
	sig, err := recovery.OpenSigningString(recovery.OpenFields{UserGUID: userGUID, VaultID: d.st.VaultID, RequestID: rid,
		RecoveryID: d.st.Recovery.RecoveryID, TS: tss, ETKKid: e.Descriptor.Kid.String(), Secrets: secrets, Token: []byte(tok),
		Manifest: m.Bytes, UnlockSecret: us})
	if err != nil {
		return nil, err
	}
	req := &altchan.RecoveryOpenRequest{UserGUID: userGUID, VaultID: d.st.VaultID, RequestID: rid, RecoveryID: d.st.Recovery.RecoveryID,
		DeviceIK: d.IdentityKey(), PIN: pin, Password: pw, UnlockSecret: us, Token: tok, Assertion: as,
		ManifestSHA256: manifest.SHA256Hex(m.Bytes), ManifestSerial: m.Serial, Sig: ed25519.Sign(d.ik, []byte(sig))}
	body, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	env, err := altchan.SealRequest(e.Descriptor.ETK, altchan.TypeRecoveryOpen, rid, ts, body)
	if err != nil {
		return nil, err
	}
	d.st.Recovery.RequestID = rid
	return &Request{RequestID: rid, ETKKid: e.Descriptor.Kid.String(), Envelope: env, ManifestSHA256: req.ManifestSHA256, AppKey: apiKey}, nil
}

// OpenRecoveryOpenResult reads vault.recovery.open.result; on ok it pins
// the vault from the bundle and keeps the token, so that the phone can run
// its first handshake (CompleteRecoveryHandshake).
func (d *Device) OpenRecoveryOpenResult(raw []byte) (*altchan.RecoveryOpenResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.st.Recovery == nil || d.st.Recovery.RequestID == "" {
		return nil, ErrNoPending
	}
	body, err := altchan.OpenResult(raw, d.kem, altchan.TypeRecoveryOpenResult, d.st.Recovery.RequestID)
	if err != nil {
		return nil, ErrResult
	}
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, ErrResult
	}
	r, err := altchan.ParseRecoveryOpenResult(o)
	if err != nil {
		return nil, ErrResult
	}
	if r.OK {
		if err := d.adoptBundle(r.VaultBundle); err != nil {
			return nil, err
		}
		d.st.Vault.Token = r.Token
		a := d.alt()
		a.StateSeq = r.StateSeq
		d.unlockID = ""
		if altchan.ValidUnlockID(r.UnlockID) { // "" from S21/S22 (release R without L)
			d.unlockID = r.UnlockID
		}
	}
	return r, nil
}
