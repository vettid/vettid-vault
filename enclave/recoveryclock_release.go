//go:build vettid_channel_prod || vettid_channel_staging

package enclave

import "time"

// recoveryNow is the enclave's clock in a release image: no test clock can
// be set (VAULT-MESSAGING 0.33.0 §11.14.14).
func (c *Core) recoveryNow() time.Time { return c.now() }
