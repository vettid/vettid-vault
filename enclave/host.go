package enclave

import (
	"context"
	"errors"
	"sync"

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
}

// NewLocalHost returns an in-process host over core.
func NewLocalHost(core *Core, stopped func(vaultID string, err error)) *LocalHost {
	return &LocalHost{core: core, stopped: stopped, vaults: map[string]*running{}}
}

// Open implements Host.
func (h *LocalHost) Open(ctx context.Context, j *Job) ([]byte, error) {
	_, _ = h.Lock(ctx, j.VaultID)
	res, m := h.core.Open(ctx, j)
	if m != nil {
		h.start(j.VaultID, m)
	}
	return res, nil
}

func (h *LocalHost) start(id string, m *vault.Manager) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{m: m, cancel: cancel, done: make(chan struct{})}
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
	h.mu.Lock()
	r := h.vaults[id]
	delete(h.vaults, id)
	h.mu.Unlock()
	if r == nil {
		return false, nil
	}
	r.cancel()
	<-r.done
	return true, r.m.Lock(ctx)
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
