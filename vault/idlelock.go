package vault

import (
	"context"
	"time"
)

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
	// IdleLockCallMax bounds the wait for a call in progress: a call ends
	// within 12 hours (§10.10), so the idle lock waits at most that long
	// past its time, however calls follow one another. Not scaled
	// (STAGING-TIME-SCALE N14).
	IdleLockCallMax = 12 * time.Hour
	// IdleWatchDefault is the period of Run's idle-lock timer: at most 30 s,
	// as the collect cycle (§3.6.8).
	IdleWatchDefault = 30 * time.Second
	// idleLockFlush bounds the idle lock's final flush and notices when
	// the timer locks: a host that stalls them cannot keep the vault
	// open; lockLocked zeroizes whatever the flush does.
	idleLockFlush = 60 * time.Second
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
	t := m.ocTime(now)
	if !ok || m.lockPending || t.Before(at) {
		return
	}
	// A call in progress delays it, at most IdleLockCallMax past its time
	// (a call ends within 12 hours, §10.10): calls one after another
	// cannot keep the vault open.
	if t.Before(at.Add(IdleLockCallMax)) && m.callInProgress(now) {
		return
	}
	m.lockPending, m.lockReason = true, LockIdle
}

// idleWatch is Run's own idle-lock timer (§3.6.8): every IdleWatchEvery,
// whatever the collect loop does (blocked in a collect, retrying after
// relay errors), it looks at the idle lock and, when it is due, locks the
// vault itself and ends a blocked collect. The idle lock is the one lock
// a host cannot suppress (§13.3), so it must not depend on the relay.
func (m *Manager) idleWatch(ctx context.Context) {
	every := m.opt.IdleWatchEvery
	if every <= 0 {
		every = IdleWatchDefault
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if m.idleWatchOnce() {
			return
		}
	}
}

// idleWatchOnce runs one look; true once the vault is locked.
func (m *Manager) idleWatchOnce() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked || m.st == nil {
		return true
	}
	m.refreshOwnerCred()
	m.idleLockTick(m.now())
	if !m.lockPending || m.lockReason != LockIdle {
		return false
	}
	lctx, cancel := context.WithTimeout(context.Background(), idleLockFlush)
	_ = m.lockLocked(lctx) // zeroizes whatever the flush does
	cancel()
	if m.collector != nil {
		_ = m.collector.Close() // a collect the host holds open ends now
		m.collector = nil
	}
	return true
}

func (m *Manager) callInProgress(now time.Time) bool {
	for _, f := range m.features {
		if c, ok := f.(CallActivity); ok && c.CallInProgress(now) {
			return true
		}
	}
	return false
}
