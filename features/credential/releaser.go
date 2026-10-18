package credential

import (
	"encoding/json"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/recovery"
)

// Release R's credential operations (VAULT-MESSAGING 0.33.0 §11.14.9).

// createArmWait is how long credential.create waits for the heavy
// derivation's permit before it leaves arming to the next owner check.
const createArmWait = 60 * time.Second

// verifyPair verifies the PIN and the password as an owner check does
// (§3.6.1 steps 3–7): the blob, the PIN under the §11.8 backoff, the
// password under its backoff; a bad_pin or bad_password is a failed check.
func (f *Feature) verifyPair(s *vault.Session, e *Envelope, p *Payload) (*Inner, func(), error) {
	if err := f.checkBlob(s, e.Blob); err != nil {
		return nil, nil, err
	}
	if err := s.VerifyPIN(string(p.PIN)); err != nil {
		if vault.IsCode(err, "bad_pin") {
			s.OwnerCheckFailed("pin")
		}
		return nil, nil, err
	}
	cek, inner, err := f.openChecked(s, e.Blob, p.Password)
	if err != nil {
		if err == errPassword {
			s.OwnerCheckFailed("password")
		}
		return nil, nil, err
	}
	return inner, func() { cek.Destroy(); inner.Wipe() }, nil
}

// changeSecret is pin.change and vault.secret.renew (§11.14.9): the pair
// verified as in an owner check, the new PIN (6–32 digits) and the next
// epoch's secret (32 bytes) checked, then the vault's change (a new
// generation for pin.change, a new opener for a renew; the DEK replaced)
// before the CEK rotates. Neither marks the member present.
func (f *Feature) changeSecret(s *vault.Session, typ string, e *Envelope, p *Payload) (json.RawMessage, error) {
	inner, done, err := f.verifyPair(s, e, p)
	if err != nil {
		return nil, err
	}
	defer done()
	if len(p.NewSecret) != altchan.UnlockSecretSize || typ == TypePINChange && !validPIN(string(p.NewPIN)) {
		return nil, errBad
	}
	c := vault.SecretChange{Reason: vault.ReplaceRenew, PIN: string(p.PIN), Password: p.Password, NewUnlockSecret: p.NewSecret,
		BackupCopy: f.backupLocked()}
	if typ == TypePINChange {
		c.Reason, c.NewPIN = vault.ReplacePIN, string(p.NewPIN)
	}
	if err := s.ChangeSecrets(c); err != nil {
		return nil, err
	}
	blob, err := f.rotateCEK(s, inner, p.Password)
	if err != nil {
		return nil, err
	}
	b := strictjson.NewBuilder().Base64("credential", blob).Uint("version", f.st.Version).Raw("utks", f.replenish(s))
	if typ == TypePINChange {
		b.Bool("epoch_advanced", true)
		s.Record(vault.Activity{Kind: "vault.pin_changed", Audit: true, Feed: true})
	} else {
		s.Record(vault.Activity{Kind: "device.secret_renewed", Audit: true, Feed: true})
	}
	return b.Bytes(), nil
}

// passwordChange is credential.password.change from release R
// (§11.14.9): the blob is checked, then the PIN is verified and the
// password opens the blob, in verifyPair's order (VAULT-MESSAGING 0.44.0
// §11.14.9 "A lost answer": an old blob is stale_credential before any
// secret is tested, so a retry after a lost answer counts nothing; a
// wrong PIN with the current blob is a failed owner check); the
// new password must meet §11.14.7, the generation is closed and the next
// armed, and the DEK replaced, before the content is sealed under the
// new password.
func (f *Feature) passwordChange(s *vault.Session, e *Envelope, p *Payload) (json.RawMessage, error) {
	if err := f.checkBlob(s, e.Blob); err != nil {
		return nil, err
	}
	if err := s.VerifyPIN(string(p.PIN)); err != nil {
		// A wrong PIN, tested after the blob passed, is a failed owner
		// check, as in verifyPair (owner decision 2026-10-18); a stale or
		// cloned blob never reaches this test and counts nothing.
		if vault.IsCode(err, "bad_pin") {
			s.OwnerCheckFailed("pin")
		}
		return nil, err
	}
	cek, inner, err := f.openChecked(s, e.Blob, p.Password)
	if err != nil {
		return nil, err
	}
	defer cek.Destroy()
	defer inner.Wipe()
	if r := recovery.CheckNewPassword(p.NewPassword, string(p.PIN)); r != "" {
		return nil, vault.WeakPasswordError(r)
	}
	if err := s.ChangeSecrets(vault.SecretChange{Reason: vault.ReplacePassword, PIN: string(p.PIN), Password: p.Password,
		NewPassword: p.NewPassword, BackupCopy: f.backupLocked()}); err != nil {
		return nil, err
	}
	inner.PasswordChangedAt = s.Now().UTC().Truncate(time.Millisecond)
	out, err := f.respond(s, inner, p.NewPassword, nil)
	if err != nil {
		return nil, err
	}
	s.Record(vault.Activity{Kind: "credential.password_changed", Audit: true})
	return out, nil
}

// RecoverFromBackup implements vault.RecoveryCredential (§11.14.6 step 6):
// the vault's backup copy opened with the password the recovery proved,
// every critical item re-keyed and the CEK rotated (every earlier blob is
// dead), every pool dropped; the recovered phone becomes the holder when
// its first handshake completes (TransferCompleted). An open clone alarm
// must still end with a rotation by the new holder (§3.5.9).
func (f *Feature) RecoverFromBackup(s *vault.Session, password []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.st.CEKSeed == nil || f.st.Blob == nil {
		return errCredRequired
	}
	cek, inner, err := f.openChecked(s, f.st.Blob, password) // the vault's own copy: no holder check
	if err != nil {
		return err
	}
	defer cek.Destroy()
	defer inner.Wipe()
	commit, err := f.rekeyItems(s, inner)
	if err != nil {
		return err
	}
	f.endWindow()
	if _, err := f.rotateCEK(s, inner, password); err != nil {
		return err
	}
	commit()
	for id := range f.st.Pools {
		f.dropPool(id)
	}
	f.st.Holder = ""
	if a := f.st.Alarm; a != nil && a.State == AlarmFrozen {
		a.State = AlarmRotationRequired
		f.alarmEvent(s, a)
	}
	s.Record(vault.Activity{Kind: "credential.recovered", Audit: true, Feed: true})
	return nil
}
