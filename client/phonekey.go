package client

import (
	"github.com/vettid/vettid-vault/vms/recovery"
	"github.com/vettid/vettid-vault/vms/suite"
)

// newPhoneKeyLocked makes a new phone key (enrollment, a transfer's new
// phone, a recovery) for vault id (or "" when the app does not know it
// yet), at epoch 1.
func (d *Device) newPhoneKeyLocked(vaultID string) error {
	k, err := suite.RandomBytes(32)
	if err != nil {
		return err
	}
	suite.Wipe(d.st.PhoneKey)
	d.st.PhoneKey, d.st.SecretVault, d.st.Epoch = k, vaultID, 1
	return nil
}

// unlockSecretLocked computes the unlock secret of epoch e (§11.14.1).
func (d *Device) unlockSecretLocked(e uint64) []byte {
	if d.st.PhoneKey == nil {
		return nil
	}
	return recovery.PhoneUnlockSecret(d.st.PhoneKey, d.st.SecretVault, e)
}

// UnlockSecret returns the current epoch's unlock secret, and NextUnlockSecret
// the next epoch's (pin.change, vault.secret.renew).
func (d *Device) UnlockSecret() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.unlockSecretLocked(d.st.Epoch)
}

// NextUnlockSecret is the secret of the epoch after the current one.
func (d *Device) NextUnlockSecret() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.unlockSecretLocked(d.st.Epoch + 1)
}

// AdvanceEpoch moves to the next epoch once the vault answered a change
// of secret (pin.change, vault.secret.renew).
func (d *Device) AdvanceEpoch() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.st.Epoch++
}
