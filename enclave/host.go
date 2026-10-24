package enclave

import (
	"context"
	"crypto/subtle"
	"errors"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/vault"
)

// LocalHost runs every vault in this process, as goroutines: the V3a model,
// kept for tests and development tools. The enclave itself runs one
// process per vault (VAULT-MESSAGING §12.4, enclave/vaultproc).
type LocalHost struct {
	core    *Core
	stopped func(string, error)

	mu     sync.Mutex
	vaults map[string]*running
}

type running struct {
	m      *vault.Manager
	cancel context.CancelFunc
	done   chan struct{}
	// openedAt is the enqueued_at of the message that opened the vault
	// (0.29.0, release L, §11.5); zero when not known.
	openedAt time.Time
}

// NewLocalHost returns an in-process host over core.
func NewLocalHost(core *Core, stopped func(vaultID string, err error)) *LocalHost {
	return &LocalHost{core: core, stopped: stopped, vaults: map[string]*running{}}
}

// Open implements Host.
func (h *LocalHost) Open(ctx context.Context, j *Job) ([]byte, Marker, error) {
	if j.Op == OpDeleteResume {
		// A resume never runs beside its vault and locks nothing (P20).
		// Opens here are serialized by the instance.
		h.mu.Lock()
		_, runs := h.vaults[j.VaultID]
		h.mu.Unlock()
		if runs {
			return nil, Marker{}, nil
		}
		res, _, marker := h.core.Open(ctx, j)
		return res, marker, nil
	}
	_, _ = h.Lock(ctx, j.VaultID)
	res, m, marker := h.core.Open(ctx, j)
	if m != nil {
		h.start(j.VaultID, m, j.EnqueuedAt)
	}
	return res, marker, nil
}

func (h *LocalHost) start(id string, m *vault.Manager, openedAt time.Time) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{m: m, cancel: cancel, done: make(chan struct{}), openedAt: openedAt}
	h.mu.Lock()
	h.vaults[id] = r
	h.mu.Unlock()
	go func() {
		defer close(r.done)
		err := RunRecovered(ctx, m)
		if h.stopped != nil && ctx.Err() == nil {
			h.stopped(id, err)
		}
		if m.Locked() {
			// Locked from inside (owner request, split brain): the run loop
			// ends; drop the vault.
			h.mu.Lock()
			if h.vaults[id] == r {
				delete(h.vaults, id)
			}
			h.mu.Unlock()
		}
	}()
}

// ErrPanic reports a vault run loop that panicked: the vault was zeroized
// without a flush.
var ErrPanic = errors.New("enclave: vault run loop panicked")

// RunRecovered runs a manager's loop; a panic zeroizes the vault (no
// flush) and returns ErrPanic.
func RunRecovered(ctx context.Context, m *vault.Manager) (err error) {
	defer func() {
		if r := recover(); r != nil {
			m.Crash()
			err = ErrPanic
		}
	}()
	return m.Run(ctx)
}

// Manager returns a running vault's manager.
func (h *LocalHost) Manager(id string) *vault.Manager {
	h.mu.Lock()
	defer h.mu.Unlock()
	if r := h.vaults[id]; r != nil {
		return r.m
	}
	return nil
}

// Lock implements Host: finish the batch, flush, vault.locking, zeroize.
// The error is vault.ErrSplitBrain when the final flush found a newer
// state (the vault was zeroized without it).
func (h *LocalHost) Lock(ctx context.Context, id string) (bool, error) {
	return h.LockReason(ctx, id, "")
}

// LockReason implements Host.
func (h *LocalHost) LockReason(ctx context.Context, id, reason string) (bool, error) {
	h.mu.Lock()
	r := h.vaults[id]
	delete(h.vaults, id)
	h.mu.Unlock()
	if r == nil {
		return false, nil
	}
	r.cancel()
	<-r.done
	return true, r.m.LockReason(ctx, reason)
}

// LockRequest implements Host.
func (h *LocalHost) LockRequest(ctx context.Context, id, unlockID string, enqueuedAt time.Time) (string, error) {
	h.mu.Lock()
	r := h.vaults[id]
	if r == nil {
		h.mu.Unlock()
		return CodeNotRunning, nil
	}
	if LockIsStale(r.m.UnlockID(), r.openedAt, unlockID, enqueuedAt) {
		h.mu.Unlock()
		return CodeStale, nil
	}
	delete(h.vaults, id)
	h.mu.Unlock()
	r.cancel()
	<-r.done
	// The process ends whether or not the final flush succeeds (F12):
	// the vault is locked either way.
	return CodeLocked, r.m.LockReason(ctx, "")
}

// LockIsStale decides a lock request against the running vault (§11.5):
// a bound one is stale when it names another unlock (current is the
// vault's; the process host has the vault's process compare it, and asks
// here for the unconditional rule only); an unconditional one when it was
// queued at or before the message that opened the vault. An opening of
// unknown time is not stale: locking only reduces exposure.
func LockIsStale(current string, openedAt time.Time, unlockID string, enqueuedAt time.Time) bool {
	if unlockID != "" {
		return subtle.ConstantTimeCompare([]byte(unlockID), []byte(current)) != 1
	}
	return !openedAt.IsZero() && !enqueuedAt.After(openedAt)
}

// RecoveryRefusal implements Host.
func (h *LocalHost) RecoveryRefusal(_ context.Context, id string) (bool, string) {
	h.mu.Lock()
	r := h.vaults[id]
	h.mu.Unlock()
	if r == nil {
		return false, ""
	}
	return true, r.m.RecoveryRefusal()
}

// Account implements Host.
func (h *LocalHost) Account(ctx context.Context, id string, snapshot []byte) (bool, error) {
	h.mu.Lock()
	r := h.vaults[id]
	h.mu.Unlock()
	if r == nil {
		return false, nil
	}
	return true, r.m.SetAccount(ctx, snapshot)
}

// Vaults implements Host.
func (h *LocalHost) Vaults() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	ids := make([]string, 0, len(h.vaults))
	for id := range h.vaults {
		ids = append(ids, id)
	}
	return ids
}

// Close implements Host.
func (h *LocalHost) Close(ctx context.Context) {
	for _, id := range h.Vaults() {
		_, _ = h.Lock(ctx, id)
	}
}
