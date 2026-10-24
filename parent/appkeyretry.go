package parent

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
)

// The vault row's app_key and app_key_next are how the account side knows
// which phone key the vault adopted (VAULT-MESSAGING §11.5). They are
// written durably:
//
//   - a failed write is tried again, with backoff, until it is written
//     (retryAppKeys), not logged and dropped;
//   - the enclave asks for the row to name a key before it adopts it, and
//     is answered only after the table write (confirmAppKey);
//   - after a restart the enclave asserts the keys it last reported
//     (EventAppKeyAssert, EventAppKeyNextAssert).

// ErrPermanent marks an error as one that trying again cannot cure (fakes
// in tests use it).
var ErrPermanent = errors.New("permanent write failure")

// appKeyRetryFirst and appKeyRetryCap are the backoff of the retry; a
// variable for tests.
var (
	appKeyRetryFirst = atomic.Int64{}
	appKeyRetryCap   = atomic.Int64{}
)

func init() {
	appKeyRetryFirst.Store(int64(time.Second))
	appKeyRetryCap.Store(int64(30 * time.Second))
}

// maxKeyQ bounds the failed writes held for one vault. Every write is
// conditional on seq, so a later one supersedes the earlier; if the bound
// is reached the oldest goes.
const maxKeyQ = 256

// retryAppKeys queues the app key part of ev for writing again and starts
// the vault's retry if none runs. The first failure is logged here, as the
// write failed.
func (p *Parent) retryAppKeys(ev Lifecycle, cause error) {
	p.log.Warn("app key write failed; trying again", "event", ev.Event, "vault_id", ev.VaultID, "error", cause.Error())
	p.mu.Lock()
	if p.keyQ == nil {
		p.keyQ = map[string][]Lifecycle{}
	}
	q := p.keyQ[ev.VaultID]
	start := len(q) == 0
	if len(q) >= maxKeyQ {
		q = q[1:]
	}
	p.keyQ[ev.VaultID] = append(q, ev)
	ctx := p.runCtx
	p.mu.Unlock()
	if !start {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	go p.drainAppKeys(ctx, ev.VaultID)
}

// drainAppKeys writes the vault's queued app key parts, oldest first,
// until the queue is empty or the parent stops.
func (p *Parent) drainAppKeys(ctx context.Context, vaultID string) {
	first := time.Duration(appKeyRetryFirst.Load())
	wait := first
	for {
		p.mu.Lock()
		q := p.keyQ[vaultID]
		if len(q) == 0 {
			delete(p.keyQ, vaultID)
			p.mu.Unlock()
			return
		}
		ev := q[0]
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := p.cfg.Tables.AppKeys(wctx, ev, p.now())
		cancel()
		if err != nil && Permanent(err) {
			// Trying again cannot cure it (a refused request, a role that
			// may not): logged, and the write is given up.
			p.log.Error("app key write refused; not tried again", "event", ev.Event, "vault_id", vaultID, "error", err.Error())
			err = nil
		}
		if err != nil {
			wait = min(2*wait, time.Duration(appKeyRetryCap.Load()))
			p.log.Warn("app key write failed; trying again", "event", ev.Event, "vault_id", vaultID, "error", err.Error())
			continue
		}
		wait = first
		p.mu.Lock()
		if q := p.keyQ[vaultID]; len(q) > 0 {
			p.keyQ[vaultID] = q[1:]
		}
		p.mu.Unlock()
		p.log.Info("app key written after a retry", "event", ev.Event, "vault_id", vaultID)
	}
}

// confirmAppKey answers the enclave's hostproto.KindAppKeyNext.
func (p *Parent) confirmAppKey(ctx context.Context, f [][]byte) [][]byte {
	if len(f) != 5 || !vaultIDOK(string(f[0])) || len(f[2]) == 0 || len(f[2]) > 256 {
		return reply(hostproto.StatusInvalid)
	}
	mode := string(f[1])
	if mode != "next" && mode != "enroll" {
		return reply(hostproto.StatusInvalid)
	}
	var num [2]uint64
	for i, d := range f[3:] {
		n, err := strconv.ParseUint(string(d), 10, 53)
		if err != nil || strconv.FormatUint(n, 10) != string(d) || i == 0 && n == 0 {
			return reply(hostproto.StatusInvalid)
		}
		num[i] = n
	}
	id := string(f[0])
	// A request that outlives its enclave's wait must not write late: the
	// writes below are ordered by header_seq, and this bounds them too.
	ctx, cancel := context.WithTimeout(ctx, confirmDeadline)
	defer cancel()
	// The vault's earlier lifecycle events are written first, as for the
	// deletion mark, and so are its app key writes that failed before.
	p.flushEvents(ctx)
	if !p.waitKeyQ(ctx, id) {
		p.log.Warn("app key not confirmed", "vault_id", id, "mode", mode, "error", "earlier app key writes pending")
		return reply(hostproto.StatusError)
	}
	err := p.cfg.Tables.ConfirmAppKey(ctx, id, mode, clone(f[2]), num[0], num[1], p.now())
	switch {
	case err == nil:
		p.log.Info("app key confirmed", "vault_id", id, "mode", mode)
		return reply(hostproto.StatusOK)
	case errors.Is(err, ErrConflict):
		p.log.Warn("app key refused", "vault_id", id, "mode", mode)
		return reply(hostproto.StatusConflict)
	}
	p.log.Warn("app key not confirmed", "vault_id", id, "mode", mode, "error", err.Error())
	return reply(hostproto.StatusError)
}

// confirmDeadline bounds one AppKeyNext request at the parent.
const confirmDeadline = 8 * time.Second

// waitKeyQ waits until the vault's failed app key writes are written (or
// given up); false if ctx ends first.
func (p *Parent) waitKeyQ(ctx context.Context, vaultID string) bool {
	for {
		p.mu.Lock()
		n := len(p.keyQ[vaultID])
		p.mu.Unlock()
		if n == 0 {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
}
