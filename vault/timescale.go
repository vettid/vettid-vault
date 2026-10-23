package vault

import "time"

// The staging time scale (VAULT-MESSAGING 0.43.0 §11.10.8,
// STAGING-TIME-SCALE §3, §5.1; owner decision 2026-10-18). The release
// constant time_scale divides the waits of 1 hour or more that
// STAGING-TIME-SCALE §2.1 lists and that the vault runs, when each timer
// starts:
//
//   - S1  the owner check's interval (startClock, settingsOwnerCheck);
//   - S5  the recovery code's delay (RecoveryRequest);
//   - S6  the recovery code's validity (RecoveryRequest, and after a wait
//     in RecoveryOpen);
//   - S8  the counter unavailable for 24 h (recoveryHousekeeping);
//   - S11 the pending unlink kept 7 days (holdUnlink);
//   - S13 the provisional enrollment window (Create, enrollApp).
//
// S7 (the quiet period) is stated in the staging channel file itself;
// S3 and S4, the idle lock past the deadline and the hour after an unlock
// (0.29.0, release L), are scaled in idleLockAt.
// Nothing else is scaled: rate limits, backoff ladders, cryptographic
// freshness, token lifetimes, the recovery wait unit, timers between
// vaults, durations the member chooses, retention (§2.2).
//
// The absolute time is kept, so a timer started under one scale ends at
// the time it was given (§3 rule 2, §5.5). Settings keep their real units
// (§3 rule 3).

// MaxTimeScale is the largest scale a development build may run with
// (releasecfg.MaxDevTimeScale; the release channels allow 1, or 1 and 24).
const MaxTimeScale = 86400

// Scale divides d by the time scale n, rounded up to a whole second
// (§3 rule 1). n 0 or 1 is real time and returns d unchanged.
func Scale(d time.Duration, n uint64) time.Duration {
	if n <= 1 || d <= 0 {
		return d
	}
	if n > MaxTimeScale {
		n = MaxTimeScale
	}
	div := time.Duration(n) * time.Second
	return (d + div - 1) / div * time.Second
}

// timeScale is the running release's scale: Options.TimeScale, 1 when
// unset.
func (o *Options) timeScale() uint64 {
	if o.TimeScale <= 1 {
		return 1
	}
	if o.TimeScale > MaxTimeScale {
		return MaxTimeScale
	}
	return o.TimeScale
}

// scale divides a wait of §2.1 by the running release's scale.
func (o *Options) scale(d time.Duration) time.Duration { return Scale(d, o.timeScale()) }
