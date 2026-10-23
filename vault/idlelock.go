package vault

import "time"

// The idle lock (VAULT-MESSAGING 0.29.0 §3.6.8, release L; VAULT-LOCK §4,
// decisions L10–L14, approved by the owner 2026-10-12). The owner check is
// the one signal that is the member; a vault whose check is overdue by
// idle_lock.after_seconds locks itself, by the enclave's clock, whatever
// the hold says. It is the one lock a host cannot suppress (§13.3).
//
//   - When: the time is later than owner_check.deadline +
//     idle_lock.after_seconds, compared at every request and every collect
//     cycle (ownerCheckTick), as the hold is.
//   - The setting: 3,600–2,592,000 s, default 604,800, no "never"; the app
//     only; a shorter value applies at once (and may lock at once), a
//     longer one from the next successful check (OwnerCheck.IdleAfter is
//     the value in force at the last check).
//   - After an unlock already past that time: the rule applies from one
//     hour after the unlock, so the member can pass the check.
//   - A call in progress delays it until the call ends.
//   - A vault without a credential has no deadline and no idle lock.
//
// Both durations are divided by the staging time scale when the time is
// computed (STAGING-TIME-SCALE S3, S4); the setting keeps real units.

// Idle-lock constants (§3.6.8, §10.8).
const (
	DefaultIdleLockAfter = 7 * 24 * time.Hour
	MinIdleLockAfter     = time.Hour
	MaxIdleLockAfter     = 30 * 24 * time.Hour
	IdleLockAfterUnlock  = time.Hour
	LockIdle             = "idle" // vault.locking reason, vault.locked ref (§3.6.8, §10.9)
)

// IdleLockAfter is the setting idle_lock.after_seconds (§10.8).
func (s Settings) IdleLockAfter() time.Duration {
	if s.IdleLockSeconds == 0 {
		return DefaultIdleLockAfter
	}
	return time.Duration(s.IdleLockSeconds) * time.Second
}

// CallActivity is implemented by the calls feature: whether a call is in
// progress (§10.10), which delays the idle lock until it ends (§3.6.8).
type CallActivity interface {
	CallInProgress(now time.Time) bool
}

// idleLockAfter is the setting in force (§3.6.8): the current value when
// it is shorter than the one at the last successful check, that one
// otherwise, so that a longer value waits for the next check. A record
// from before release L has no value at its check; the default stands in
// for it, so an upgrade cannot buy time either.
func (m *Manager) idleLockAfter() time.Duration {
	cur := m.st.Settings.IdleLockAfter()
	at := DefaultIdleLockAfter
	if rec := m.st.OwnerCheck; rec != nil && rec.IdleAfter != 0 {
		at = time.Duration(rec.IdleAfter) * time.Second
	}
	return min(cur, at)
}

// idleLockAt is when the vault locks itself if no check is passed, on the
// owner check's clock; ok false for a vault without a running check (no
// credential). It is idle_lock_at in vault.status and vault.held.
func (m *Manager) idleLockAt(now time.Time) (time.Time, bool) {
	if !m.ownerCheckRunning() {
		return time.Time{}, false
	}
	at := m.st.OwnerCheck.Deadline.Add(m.opt.scale(m.idleLockAfter()))
	if !m.idleOpened {
		// The first look after this opening: an unlock already past the
		// time gets one hour from the unlock (§3.6.8 "After an unlock").
		m.idleOpened = true
		if t := m.ocTime(now); !t.Before(at) {
			m.idleGrace = t.Add(m.opt.scale(IdleLockAfterUnlock))
		}
	}
	if at.Before(m.idleGrace) {
		at = m.idleGrace
	}
	return at, true
}

// idleLockTick locks the vault after the batch when the time of the idle
// lock has passed and no call is in progress (§3.6.8). Run from
// ownerCheckTick.
func (m *Manager) idleLockTick(now time.Time) {
	at, ok := m.idleLockAt(now)
	if !ok || m.lockPending || m.ocTime(now).Before(at) || m.callInProgress(now) {
		return
	}
	m.lockPending, m.lockReason = true, LockIdle
}

func (m *Manager) callInProgress(now time.Time) bool {
	for _, f := range m.features {
		if c, ok := f.(CallActivity); ok && c.CallInProgress(now) {
			return true
		}
	}
	return false
}
