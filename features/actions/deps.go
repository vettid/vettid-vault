package actions

import (
	"crypto/ed25519"
	"time"
)

// Deps are the features the built-in actions run through (§10.14). The
// interfaces are defined by the implementation; nil fields disable the
// actions that need them.
type Deps struct {
	Grants  any // the grants feature (one-use grants for profile.fields.read, secrets.share)
	Audit   any // the audit feature (audit.recent)
	Keys    KeyUser
	Profile any
	Secrets any
}

// KeyUser gives access to the credential unlock window (critical actions).
type KeyUser interface {
	UseKey(now time.Time, ttl time.Duration) (ed25519.PrivateKey, bool)
}
