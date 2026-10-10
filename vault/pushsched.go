package vault

import (
	"math/rand/v2"
	"time"
)

// PushTiming are the numbers of the wake rules (VAULT-MESSAGING §14.1,
// §14.2). Zero fields take the defaults; tests shorten them.
type PushTiming struct {
	// Debounce: a trigger less than this after the last wake is deferred
	// until this after it, and triggers meanwhile merge (5 s).
	Debounce time.Duration
	// Window is the rolling window of the caps (1 h).
	Window time.Duration
	// HourCap wakes per Window (30); past it, one per OverCapEvery
	// (10 min) until the count falls below it.
	HourCap      int
	OverCapEvery time.Duration
	// ExemptCap: wakes for vault.locking, credential.alarm and urgent
	// feed items skip the cap up to this many per Window (10).
	ExemptCap int
	// Retries are the waits after a 5xx, a timeout or no connection (5 s,
	// 30 s, 120 s, each ±Jitter); then the wake is dropped.
	Retries []time.Duration
	Jitter  float64
	// RetryAfter is the wait after a 429 without retry_after (60 s); a
	// retry_after is honoured up to MaxRetryAfter (3,600 s).
	RetryAfter    time.Duration
	MaxRetryAfter time.Duration
	// LockBudget bounds the wake for vault.locking (3 s): one attempt,
	// never delaying a lock longer.
	LockBudget time.Duration
	// RegisterTimeout bounds POST /v1/register (10 s, no retry);
	// WakeTimeout one wake attempt (10 s).
	RegisterTimeout time.Duration
	WakeTimeout     time.Duration
}

// DefaultPushTiming is §14.2.
var DefaultPushTiming = PushTiming{
	Debounce: 5 * time.Second, Window: time.Hour, HourCap: 30, OverCapEvery: 10 * time.Minute, ExemptCap: 10,
	Retries: []time.Duration{5 * time.Second, 30 * time.Second, 120 * time.Second}, Jitter: 0.2,
	RetryAfter: time.Minute, MaxRetryAfter: time.Hour, LockBudget: 3 * time.Second,
	RegisterTimeout: 10 * time.Second, WakeTimeout: 10 * time.Second,
}

func (t PushTiming) withDefaults() PushTiming {
	d := DefaultPushTiming
	if t.Debounce > 0 {
		d.Debounce = t.Debounce
	}
	if t.Window > 0 {
		d.Window = t.Window
	}
	if t.HourCap > 0 {
		d.HourCap = t.HourCap
	}
	if t.OverCapEvery > 0 {
		d.OverCapEvery = t.OverCapEvery
	}
	if t.ExemptCap > 0 {
		d.ExemptCap = t.ExemptCap
	}
	if t.Retries != nil {
		d.Retries = append([]time.Duration(nil), t.Retries...)
	}
	if t.Jitter >= 0 && t.Jitter < 1 && (t.Jitter > 0 || t.Retries != nil) {
		d.Jitter = t.Jitter
	}
	if t.RetryAfter > 0 {
		d.RetryAfter = t.RetryAfter
	}
	if t.MaxRetryAfter > 0 {
		d.MaxRetryAfter = t.MaxRetryAfter
	}
	if t.LockBudget > 0 {
		d.LockBudget = t.LockBudget
	}
	if t.RegisterTimeout > 0 {
		d.RegisterTimeout = t.RegisterTimeout
	}
	if t.WakeTimeout > 0 {
		d.WakeTimeout = t.WakeTimeout
	}
	return d
}

// wakeResult is the outcome of one wake attempt (§14.2 "Outcomes").
type wakeResult int

const (
	wakeSent        wakeResult = iota // 202
	wakeRateLimited                   // 429
	wakeFailed                        // 5xx, a timeout, no connection
	wakeGone                          // token_gone, token_invalid, blob_invalid
)

// wakeSched decides when the one registration's pending wake goes out
// (§14.2 "Debounce and limits"). It is pure: the caller passes the time.
// Everything is in memory and starts empty at unlock and at every new
// registration.
type wakeSched struct {
	t PushTiming

	pending bool // a wake is waiting (triggers merge into it)
	exempt  bool // ... and one of its triggers skips the hourly cap
	counted bool // ... and it was already sent once (a retry)

	inflight   bool
	curExempt  bool
	curCounted bool

	last       time.Time // the last wake's first attempt
	notBefore  time.Time // a 429's retry_after or a retry's wait
	retries    int       // failed attempts of the wake being retried
	hour       []time.Time
	exemptHour []time.Time
}

func newWakeSched(t PushTiming) wakeSched { return wakeSched{t: t} }

// trigger records a deposit that wakes (exempt: vault.locking,
// credential.alarm, an urgent feed item).
func (s *wakeSched) trigger(exempt bool) {
	s.pending = true
	s.exempt = s.exempt || exempt
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// count returns the entries of l within the window ending at t.
func (s *wakeSched) count(l []time.Time, t time.Time) int {
	n := 0
	for _, x := range l {
		if t.Sub(x) < s.t.Window {
			n++
		}
	}
	return n
}

func (s *wakeSched) prune(now time.Time) {
	keep := func(l []time.Time) []time.Time {
		i := 0
		for i < len(l) && now.Sub(l[i]) >= s.t.Window {
			i++
		}
		return l[i:]
	}
	s.hour, s.exemptHour = keep(s.hour), keep(s.exemptHour)
}

// next returns when the pending wake may be sent; ok is false when none
// is pending or one is in flight.
func (s *wakeSched) next(now time.Time) (time.Time, bool) {
	if !s.pending || s.inflight {
		return time.Time{}, false
	}
	s.prune(now)
	at := now
	if !s.last.IsZero() {
		at = later(at, s.last.Add(s.t.Debounce))
	}
	at = later(at, s.notBefore)
	if s.counted || s.count(s.hour, at) < s.t.HourCap {
		return at, true
	}
	if s.exempt && s.count(s.exemptHour, at) < s.t.ExemptCap {
		return at, true
	}
	// Past the cap: one wake per OverCapEvery, or as soon as the hour's
	// count falls below the cap, whichever comes first.
	in := s.hour[len(s.hour)-s.count(s.hour, at):]
	fall := in[len(in)-s.t.HourCap].Add(s.t.Window)
	every := s.last.Add(s.t.OverCapEvery)
	if every.Before(fall) {
		fall = every
	}
	return later(at, fall), true
}

// start marks the pending wake sent at now: a first attempt counts toward
// the caps and moves the debounce.
func (s *wakeSched) start(now time.Time) {
	s.inflight, s.curExempt, s.curCounted = true, s.exempt, s.counted
	if !s.counted {
		s.last = now
		s.hour = append(s.hour, now)
		if s.exempt {
			s.exemptHour = append(s.exemptHour, now)
		}
	}
	s.pending, s.exempt, s.counted = false, false, false
}

// done applies the attempt's outcome at now; retryAfter is a 429's wait
// (0: the default).
func (s *wakeSched) done(now time.Time, r wakeResult, retryAfter time.Duration) {
	s.inflight = false
	again := func(wait time.Duration) {
		s.pending, s.counted = true, true
		s.exempt = s.exempt || s.curExempt
		s.notBefore = now.Add(wait)
	}
	switch r {
	case wakeSent:
		s.retries, s.notBefore = 0, time.Time{}
	case wakeRateLimited:
		if retryAfter <= 0 {
			retryAfter = s.t.RetryAfter
		}
		again(min(retryAfter, s.t.MaxRetryAfter))
	case wakeFailed:
		if s.retries < len(s.t.Retries) {
			d := s.t.Retries[s.retries]
			s.retries++
			again(jitter(d, s.t.Jitter))
			return
		}
		// Dropped after the last retry; triggers that arrived while it
		// was in flight wait as a new wake.
		s.retries, s.notBefore = 0, time.Time{}
	case wakeGone:
		*s = newWakeSched(s.t)
	}
}

// jitter spreads d by ±f (not secret: math/rand).
func jitter(d time.Duration, f float64) time.Duration {
	if f <= 0 {
		return d
	}
	return time.Duration(float64(d) * (1 + f*(2*rand.Float64()-1)))
}
