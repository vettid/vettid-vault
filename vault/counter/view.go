package counter

import (
	"context"
	"sort"
	"time"

	"github.com/vettid/vettid-vault/vms/recovery"
)

// Attempt is one used attempt of a generation, as the counter records it.
type Attempt struct {
	N       int
	At      time.Time // the token's LastModified (the newest version's)
	Success bool
}

// View is what one complete listing says about a generation and the
// vault's presence (Status and Confirm answer it).
type View struct {
	Generation uint64
	Used       int // spent and lost attempts: token names in use
	Closed     bool
	Attempts   []Attempt // by N
	PresentAt  time.Time // the newest present record; zero: none
	Now        time.Time // the listing's Date, the counter's time
	// WaitUntil is when the running wait ends (zero: none runs at Now):
	// the later of the binding rule on the attempts' own times and the
	// locks of their wait records.
	WaitUntil time.Time
	// tokens maps attempt numbers in use to their entries' count.
	tokens map[int]int
}

// Exhausted reports whether all ten attempts are used.
func (v *View) Exhausted() bool { return v.Used >= recovery.MaxAttempts }

// Next is the attempt a Spend must name: the one after the highest in use.
func (v *View) Next() int {
	hi := 0
	for k := range v.tokens {
		hi = max(hi, k)
	}
	return hi + 1
}

// Attempt returns attempt n.
func (v *View) Attempt(n int) (Attempt, bool) {
	for _, a := range v.Attempts {
		if a.N == n {
			return a, true
		}
	}
	return Attempt{}, false
}

// waitEnd is the binding rule for one unsuccessful attempt: its own
// counter time plus W(k).
func waitEnd(a Attempt, unit time.Duration) time.Time {
	return a.At.Add(time.Duration(recovery.WaitUnits(a.N)) * unit)
}

// parse reads a listing of the vault's prefix for generation g. Names that
// do not match a computed name are ignored (§8.1).
func parse(l Listing, n *recovery.Names, g uint64) *View {
	v := &View{Generation: g, Now: l.Date, tokens: map[int]int{}}
	byName := map[string][]Entry{}
	for _, e := range l.Entries {
		byName[e.Key] = append(byName[e.Key], e)
	}
	newest := func(es []Entry) time.Time {
		var t time.Time
		for _, e := range es {
			if e.LastModified.After(t) {
				t = e.LastModified
			}
		}
		return t
	}
	if es := byName[n.Present()]; len(es) > 0 {
		v.PresentAt = newest(es)
	}
	v.Closed = len(byName[n.Close(g)]) > 0
	for k := 1; k <= recovery.MaxAttempts; k++ {
		es := byName[n.Token(g, k)]
		if len(es) == 0 {
			continue
		}
		v.tokens[k] = len(es)
		v.Used++
		v.Attempts = append(v.Attempts, Attempt{N: k, At: newest(es), Success: len(byName[n.Success(g, k)]) > 0})
	}
	sort.Slice(v.Attempts, func(i, j int) bool { return v.Attempts[i].N < v.Attempts[j].N })
	return v
}

// computeWait sets WaitUntil at the view's time: the binding rule, and the
// locks of the wait records of unsuccessful attempts (read back from S3;
// an error is returned so the caller answers unavailable).
func (c *Counter) computeWait(ctx context.Context, v *View, l Listing) error {
	var until time.Time
	for _, a := range v.Attempts {
		if a.Success {
			continue // a success ends its own wait
		}
		if e := waitEnd(a, c.unit); e.After(until) {
			until = e
		}
		name := c.names.Wait(v.Generation, a.N)
		for _, e := range l.Entries {
			if e.Key != name || e.DeleteMarker {
				continue
			}
			r, err := c.b.GetRetention(ctx, name, e.VersionID)
			if err != nil {
				return err
			}
			if r.Mode == ModeCompliance && r.Until.After(until) {
				until = r.Until
			}
		}
	}
	if until.After(v.Now) {
		v.WaitUntil = until
	}
	return nil
}
