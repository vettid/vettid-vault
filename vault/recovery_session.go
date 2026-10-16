package vault

import (
	"context"
	"time"
)

// RecoveryHost is what the credential feature needs of the runtime for
// release R's recovery (§11.14.3, §11.14.5, §11.14.9). The Manager
// implements it.
type RecoveryHost interface {
	ChangeSecrets(ctx context.Context, c SecretChange, now time.Time) error
	RecoveryArm(ctx context.Context, pin string, pw []byte, wait time.Duration, backup bool, now time.Time) string
	OwnerCheckRecovery(ctx context.Context, pin string, pw []byte, wait time.Duration, backup bool, now time.Time) (state string, present bool)
}

func (h managerHost) ChangeSecrets(ctx context.Context, c SecretChange, now time.Time) error {
	return h.m.changeSecrets(ctx, c, now)
}

func (h managerHost) RecoveryArm(ctx context.Context, pin string, pw []byte, wait time.Duration, backup bool, now time.Time) string {
	return h.m.arm(ctx, pin, pw, wait, backup, now)
}

func (h managerHost) OwnerCheckRecovery(ctx context.Context, pin string, pw []byte, wait time.Duration, backup bool, now time.Time) (string, bool) {
	return h.m.ownerCheckRecovery(ctx, pin, pw, wait, backup, now)
}

func (s *Session) recHost() (RecoveryHost, bool) {
	h, ok := s.host.(RecoveryHost)
	return h, ok
}

// ChangeSecrets runs a change of PIN, password or phone secret up to and
// including step 1 of its DEK replacement (§11.14.9). Its errors (busy,
// counter_unavailable, retry) mean nothing changed; the caller must then
// change nothing of its own.
func (s *Session) ChangeSecrets(c SecretChange) error {
	h, ok := s.recHost()
	if !ok {
		return errUnavailable
	}
	return h.ChangeSecrets(s.Context(), c, s.now)
}

// RecoveryArm arms recovery after the PIN and the password were verified
// in one request, waiting up to wait for the heavy-derivation permit, and
// returns recovery.state (§11.14.3).
func (s *Session) RecoveryArm(pin string, pw []byte, wait time.Duration, backup bool) string {
	h, ok := s.recHost()
	if !ok {
		return RecoveryNeedsCheck
	}
	return h.RecoveryArm(s.Context(), pin, pw, wait, backup, s.now)
}

// OwnerCheckRecovery is a passed owner check's part for recovery: presence,
// the counter's attempts in the audit log, arming (§3.6.1 step 8).
func (s *Session) OwnerCheckRecovery(pin string, pw []byte, wait time.Duration, backup bool) (state string, present bool) {
	h, ok := s.recHost()
	if !ok {
		return RecoveryNeedsCheck, false
	}
	return h.OwnerCheckRecovery(s.Context(), pin, pw, wait, backup, s.now)
}
