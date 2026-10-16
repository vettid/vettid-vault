package counter

import (
	"time"

	"github.com/vettid/vettid-vault/vms/recovery"
)

// Decisions (§11.14.5, §11.14.6). They are pure: the counter's listings in,
// a verdict out.

// Verdicts.
const (
	VerdictTest   = "test"   // the guess may be tested
	VerdictClosed = "closed" // the generation is closed
	VerdictQuiet  = "quiet"  // the member was present within the quiet period, or never recorded
	VerdictWait   = "wait"   // a wait runs
	VerdictExhaus = "exhausted"
)

// ConfirmWindow is the span the two 10-minute limits of step 4b allow, by
// the counter's clock.
const ConfirmWindow = recovery.ConfirmWindowSecs * time.Second

// FirstLook is step 3's verdict on a Status, with retry_at for quiet and
// wait. It decides nothing by itself.
func FirstLook(v *View, quiet time.Duration) (verdict string, retryAt time.Time) {
	switch {
	case v.Closed:
		return VerdictClosed, time.Time{}
	case v.Exhausted():
		return VerdictExhaus, time.Time{}
	case v.PresentAt.IsZero():
		return VerdictQuiet, time.Time{}
	case v.Now.Sub(v.PresentAt) < quiet:
		return VerdictQuiet, v.PresentAt.Add(quiet)
	case !v.WaitUntil.IsZero():
		return VerdictWait, v.WaitUntil
	}
	return VerdictTest, time.Time{}
}

// AfterSpend is step 4b: the guess of attempt n, spent at counter time at
// after a status read at counter time statusNow, is tested only if the
// confirming read c (made after the spend was confirmed) shows no close,
// was made no more than 10 minutes after at, shows a present record none
// of which is later than at minus the quiet period, at is no more than 10
// minutes after statusNow, every earlier attempt without a success is at
// least its wait older than at, and n is the highest attempt with none
// missing below it.
func AfterSpend(c *View, n int, at, statusNow time.Time, quiet, unit time.Duration) (verdict string, retryAt time.Time) {
	if c.Closed {
		return VerdictClosed, time.Time{}
	}
	if c.Now.Sub(at) > ConfirmWindow || at.Sub(statusNow) > ConfirmWindow {
		return VerdictWait, time.Time{}
	}
	if c.PresentAt.IsZero() || c.PresentAt.After(at.Add(-quiet)) {
		var r time.Time
		if !c.PresentAt.IsZero() {
			r = c.PresentAt.Add(quiet)
		}
		return VerdictQuiet, r
	}
	if c.Next() != n+1 {
		return VerdictWait, time.Time{} // a higher attempt exists
	}
	for k := 1; k < n; k++ {
		a, ok := c.Attempt(k)
		if !ok {
			return VerdictWait, time.Time{} // one missing below
		}
		if !a.Success && waitEnd(a, unit).After(at) {
			return VerdictWait, waitEnd(a, unit)
		}
	}
	if _, ok := c.Attempt(n); !ok {
		return VerdictWait, time.Time{}
	}
	return VerdictTest, time.Time{}
}

// NotBefore is §11.14.5's code validity at a recovery request: the latest
// of now + 24 h, now + quiet − the present record's age, and now + the
// running wait's time left, ages measured by the counter's clock (v), now
// by the enclave's. Without a view (the counter unreachable) it is now +
// quiet and earliest is set.
func NotBefore(now time.Time, v *View, quiet, delay time.Duration) (notBefore time.Time, earliest bool) {
	nb := now.Add(delay)
	if v == nil {
		q := now.Add(quiet)
		if q.After(nb) {
			nb = q
		}
		return nb, true
	}
	if !v.PresentAt.IsZero() {
		if q := now.Add(quiet - v.Now.Sub(v.PresentAt)); q.After(nb) {
			nb = q
		}
	} else if q := now.Add(quiet); q.After(nb) {
		nb = q // no present record: refused anyway; the quiet period is the honest estimate
	}
	if !v.WaitUntil.IsZero() {
		if w := now.Add(v.WaitUntil.Sub(v.Now)); w.After(nb) {
			nb = w
		}
	}
	return nb, false
}
