//go:build !vettid_channel_prod && !vettid_channel_staging

package enclave

import "time"

// devRecoveryNow is the recovery's clock in builds without a channel (the
// development stack and tests): Config.RecoveryNow when set. A release
// image (a channel build) never contains it (recoveryclock_release.go;
// check-tcb, VAULT-MESSAGING 0.33.0 §11.14.14).
func (c *Core) devRecoveryNow() time.Time {
	if c.cfg.RecoveryNow != nil {
		return c.cfg.RecoveryNow()
	}
	return c.now()
}

func (c *Core) recoveryNow() time.Time { return c.devRecoveryNow() }
