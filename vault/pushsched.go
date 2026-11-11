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
	// CallCap: (C2) call wakes (trigger 5) per Window (20). A call wake
	// is not debounced and counts toward neither HourCap nor ExemptCap;
	// past CallCap trigger 5 is an ordinary trigger.
	CallCap int
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
	Debounce: 5 * time.Second, Window: time.Hour, HourCap: 30, OverCapEvery: 10 * time.Minute, ExemptCap: 10, CallCap: 20,
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
	if t.CallCap > 0 {
		d.CallCap = t.CallCap
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

	pending bool // an ordinary wake is waiting (triggers merge into it)
	exempt  bool // ... and one of its triggers skips the hourly cap
	counted bool // ... and it was already sent once (a retry)

	// (C2) calls: the calls whose offers wait for a call wake (trigger
	// 5); checked: each was found still ringing since it was added, and
	// the wake may go now (a look is made again after any wait);
	// callRetry: they are the retry of a call wake (not counted again,
	// not held by the call cap), waiting until callNotBefore.
	calls         []string
	checked       bool
	callRetry     bool
	callNotBefore time.Time

	inflight   bool
	curExempt  bool
	curCounted bool
	curCalls   []string // the calls of a call wake in flight
	curPending bool     // ... and the ordinary triggers merged into it

	last         time.Time // the last ordinary wake's first attempt
	notBefore    time.Time // an ordinary retry's wait (a 429's included)
	limitedUntil time.Time // a 429's retry_after: it holds call wakes too
	retries      int       // failed attempts of the wake being retried
	hour         []time.Time
	exemptHour   []time.Time
	callHour     []time.Time
}

func newWakeSched(t PushTiming) wakeSched { return wakeSched{t: t} }

// trigger records a deposit that wakes (exempt: vault.locking,
// credential.alarm, an urgent feed item).
func (s *wakeSched) trigger(exempt bool) {
	s.pending = true
	s.exempt = s.exempt || exempt
}

// triggerCall records the deposit of a call's offer to the app (§14.2
// trigger 5): a call wake, sent as soon as no wake is in flight while the
// call still rings.
func (s *wakeSched) triggerCall(callID string) {
	for _, c := range s.calls {
		if c == callID {
			return
		}
	}
	s.calls = append(s.calls, callID)
	s.checked = false
}

// callsToCheck returns the waiting calls whose ringing is to be looked at
// before a wake goes out (nil when checked).
func (s *wakeSched) callsToCheck() []string {
	if s.checked || len(s.calls) == 0 {
		return nil
	}
	return append([]string(nil), s.calls...)
}

// keepCalls keeps the waiting calls that still ring (ringing, as the
// caller found them out of the lock): a call answered, declined, ended,
// timed out or superseded meanwhile gets no wake and is not counted. A
// call added since the look is kept, to be looked at next. A call wake's
// retry whose calls all ended is over: its retry count and wait go.
func (s *wakeSched) keepCalls(ringing map[string]bool) {
	defer func() {
		if len(s.calls) == 0 && s.callRetry {
			s.callRetry, s.callNotBefore, s.retries = false, time.Time{}, 0
		}
	}()
	kept := s.calls[:0]
	all := true
	for _, c := range s.calls {
		live, looked := ringing[c]
		if !looked {
			all = false
		}
		if live || !looked {
			kept = append(kept, c)
		}
	}
	s.calls = kept
	s.checked = all
}

// callWake reports whether the waiting wake goes out as a call wake at t:
// a call waits, and the call cap is not reached or it is a retry (part of
// its wake: the caps do not hold it back).
func (s *wakeSched) callWake(t time.Time) bool {
	return len(s.calls) > 0 && (s.callRetry || s.count(s.callHour, t) < s.t.CallCap)
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
	s.hour, s.exemptHour, s.callHour = keep(s.hour), keep(s.exemptHour), keep(s.callHour)
}

// next returns when the pending wake may be sent; ok is false when none
// is pending or one is in flight.
func (s *wakeSched) next(now time.Time) (time.Time, bool) {
	if (!s.pending && len(s.calls) == 0) || s.inflight {
		return time.Time{}, false
	}
	s.prune(now)
	if len(s.calls) > 0 {
		if s.callWake(now) {
			// (C2) Not deferred by the debounce, nor by an ordinary wake's
			// retry: as soon as nothing is in flight, after a 429's wait
			// and its own retry's wait. A wake that waits is looked at
			// again before it goes.
			at := later(now, s.limitedUntil)
			if s.callRetry {
				at = later(at, s.callNotBefore)
			}
			if at.After(now) {
				s.checked = false
			}
			return at, true
		}
		// Past the call cap: an ordinary trigger.
		s.pending, s.calls = true, nil
	}
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
	s.curCalls, s.curPending = nil, false
	if s.callWake(now) {
		// (C2) A call wake counts toward its own cap only, and moves
		// neither the debounce nor the over-cap rhythm of ordinary wakes;
		// the ordinary triggers waiting merge into it (and come back if it
		// is retried and its calls end).
		s.curCalls, s.curPending = s.calls, s.pending
		if !s.callRetry {
			s.callHour = append(s.callHour, now)
		}
	} else if !s.counted {
		s.last = now
		s.hour = append(s.hour, now)
		if s.exempt {
			s.exemptHour = append(s.exemptHour, now)
		}
	}
	s.pending, s.exempt, s.counted = false, false, false
	s.calls, s.checked, s.callRetry, s.callNotBefore = nil, false, false, time.Time{}
}

// done applies the attempt's outcome at now; retryAfter is a 429's wait
// (0: the default).
func (s *wakeSched) done(now time.Time, r wakeResult, retryAfter time.Duration) {
	s.inflight = false
	again := func(wait time.Duration) {
		if len(s.curCalls) > 0 {
			// A call wake's retry stays a call wake, for the calls that
			// still ring when it goes (looked at again); the ordinary
			// triggers merged into it wait as an ordinary wake beside it.
			for _, c := range s.curCalls {
				s.triggerCall(c)
			}
			s.callRetry, s.callNotBefore = true, now.Add(wait)
			if s.curPending {
				s.pending = true
				s.counted = s.counted || s.curCounted
				s.exempt = s.exempt || s.curExempt
			}
			return
		}
		s.pending, s.counted = true, true
		s.exempt = s.exempt || s.curExempt
		s.notBefore = now.Add(wait)
	}
	switch r {
	case wakeSent:
		s.retries, s.notBefore, s.limitedUntil = 0, time.Time{}, time.Time{}
	case wakeRateLimited:
		if retryAfter <= 0 {
			retryAfter = s.t.RetryAfter
		}
		d := min(retryAfter, s.t.MaxRetryAfter)
		s.limitedUntil = now.Add(d)
		again(d)
	case wakeFailed:
		if s.retries < len(s.t.Retries) {
			d := s.t.Retries[s.retries]
			s.retries++
			again(jitter(d, s.t.Jitter))
			return
		}
		// Dropped after the last retry; triggers that arrived while it
		// was in flight wait as a new wake.
		s.retries, s.notBefore, s.callNotBefore = 0, time.Time{}, time.Time{}
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
