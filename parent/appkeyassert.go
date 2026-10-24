package parent

import (
	"context"
	"sync/atomic"
	"time"
)

// The enclave's assertions after a connect (EventAppKeyAssert) can be
// thousands: they are written by a worker of
// their own, one vault at a time with a pause between, never on the event
// queue (which the connection's replies and the confirmations wait on).
// They are conditional on seq and header_seq, so they can be late or stale
// without harm: an assertion never replaces a newer key; it can only fill
// in what the row lacks. A write that fails goes to the vault's retry.

// assertPace is the pause between two vaults' assertions (a variable for
// tests).
var assertPace atomic.Int64

func init() { assertPace.Store(int64(5 * time.Millisecond)) }

// queueAssert holds ev for the worker; a later assertion of the same kind
// for the vault replaces an earlier one.
func (p *Parent) queueAssert(ev Lifecycle) {
	p.mu.Lock()
	if p.asserts == nil {
		p.asserts = map[string][]Lifecycle{}
	}
	q := p.asserts[ev.VaultID]
	replaced := false
	for i := range q {
		if q[i].Event == ev.Event {
			q[i], replaced = ev, true
		}
	}
	if !replaced {
		q = append(q, ev)
	}
	p.asserts[ev.VaultID] = q
	start := !p.assertWorker
	p.assertWorker = true
	ctx := p.runCtx
	p.mu.Unlock()
	if !start {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	go p.assertLoop(ctx)
}

func (p *Parent) assertLoop(ctx context.Context) {
	for {
		p.mu.Lock()
		var id string
		var q []Lifecycle
		for id, q = range p.asserts {
			break
		}
		if q == nil {
			p.assertWorker = false
			p.mu.Unlock()
			return
		}
		delete(p.asserts, id)
		p.mu.Unlock()
		for _, ev := range q {
			wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := p.cfg.Tables.AppKeys(wctx, ev, p.now())
			cancel()
			if err != nil && !Permanent(err) {
				p.retryAppKeys(ev, err)
			}
		}
		select {
		case <-ctx.Done():
			p.mu.Lock()
			p.assertWorker = false
			p.mu.Unlock()
			return
		case <-time.After(time.Duration(assertPace.Load())):
		}
	}
}
