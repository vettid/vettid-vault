package supervisor

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// Blob transfers and memory (VAULT-MESSAGING 0.32.0 §10.5.1 "Transfers and
// memory"). A transfer of 8 MiB is held several times over in the vault
// process and in the supervisor, and the memory-pressure lock (§12.3)
// would lock the least recently active vault, whoever caused it. So the
// supervisor admits a transfer only while the instance's available memory,
// less MemoryReserve, is at least the per-transfer budget × (the transfers
// in flight + 1); otherwise it waits, by priority (an owner's fetch first,
// reuploads after missing last), then first come first served, across all
// the instance's vaults. Until the budget is measured on the release, it
// is TransferBudget and an instance runs at most MaxTransfers at once.

// Admission defaults (§10.5.1: 64 MiB until measured; at most 4).
const (
	TransferBudget   = 64 << 20
	MaxTransfers     = 4
	transfersOfVault = 2 // attachment_transfers
	// maxTransferWait bounds one admission request (the vault's channel
	// request times out at 90 s).
	maxTransferWait = 80 * time.Second
	// transferRecheck is how often waiting transfers look at the memory
	// again while none ends.
	transferRecheck = 250 * time.Millisecond
)

var errNotAdmitted = errors.New("supervisor: transfer not admitted")

// admission is the instance's admission of blob transfers.
type admission struct {
	mu       sync.Mutex
	avail    func() uint64 // MemAvailable (0: unknown, then counts only)
	reserve  uint64
	budget   uint64
	max      int
	inflight map[*admitTicket]bool
	byOwner  map[any]int
	waiters  []*admitWaiter
	seq      uint64
	timer    *time.Timer
	// peak counts for Stats (instance totals, never a vault's).
	admitted, refused uint64
}

type admitTicket struct {
	owner any
	id    string
}

type admitWaiter struct {
	t     *admitTicket
	prio  int
	seq   uint64
	ready chan struct{}
	done  bool
}

func newAdmission(avail func() uint64, reserve uint64) *admission {
	return &admission{avail: avail, reserve: reserve, budget: TransferBudget, max: MaxTransfers,
		inflight: map[*admitTicket]bool{}, byOwner: map[any]int{}}
}

// fits reports whether one more transfer fits now (lock held).
func (a *admission) fits() bool {
	n := len(a.inflight)
	if n >= a.max {
		return false
	}
	av := a.avail()
	if av == 0 {
		return true // unknown memory (not Linux): the count alone
	}
	return av >= a.reserve && av-a.reserve >= a.budget*uint64(n+1)
}

// pump admits waiting transfers in order while they fit (lock held).
func (a *admission) pump() {
	sort.SliceStable(a.waiters, func(i, j int) bool {
		if a.waiters[i].prio != a.waiters[j].prio {
			return a.waiters[i].prio < a.waiters[j].prio
		}
		return a.waiters[i].seq < a.waiters[j].seq
	})
	kept := a.waiters[:0]
	for _, w := range a.waiters {
		if w.done {
			continue
		}
		if a.byOwner[w.t.owner] < transfersOfVault && a.fits() {
			a.inflight[w.t] = true
			a.byOwner[w.t.owner]++
			a.admitted++
			w.done = true
			close(w.ready)
			continue
		}
		kept = append(kept, w)
	}
	a.waiters = kept
	if len(a.waiters) > 0 && a.timer == nil {
		a.timer = time.AfterFunc(transferRecheck, func() {
			a.mu.Lock()
			a.timer = nil
			a.pump()
			a.mu.Unlock()
		})
	}
}

// admit waits until a transfer of owner (a vault process) may start, or
// ctx ends.
func (a *admission) admit(ctx context.Context, owner any, id string, prio int) (*admitTicket, error) {
	a.mu.Lock()
	t := &admitTicket{owner: owner, id: id}
	a.seq++
	w := &admitWaiter{t: t, prio: prio, seq: a.seq, ready: make(chan struct{})}
	a.waiters = append(a.waiters, w)
	a.pump()
	a.mu.Unlock()
	select {
	case <-w.ready:
		return t, nil
	case <-ctx.Done():
		a.mu.Lock()
		defer a.mu.Unlock()
		if w.done {
			if a.inflight[t] {
				return t, nil // admitted just as the wait ended
			}
			return nil, errNotAdmitted
		}
		w.done = true
		a.refused++
		return nil, errNotAdmitted
	}
}

// release ends a transfer (or forgets a waiting one) of owner by id.
func (a *admission) release(owner any, id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for t := range a.inflight {
		if t.owner == owner && t.id == id {
			delete(a.inflight, t)
			if a.byOwner[owner]--; a.byOwner[owner] <= 0 {
				delete(a.byOwner, owner)
			}
		}
	}
	for _, w := range a.waiters {
		if w.t.owner == owner && w.t.id == id && !w.done {
			w.done = true
		}
	}
	a.pump()
}

// releaseAll ends every transfer of an owner whose process ended.
func (a *admission) releaseAll(owner any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for t := range a.inflight {
		if t.owner == owner {
			delete(a.inflight, t)
		}
	}
	delete(a.byOwner, owner)
	for _, w := range a.waiters {
		if w.t.owner == owner && !w.done {
			w.done = true
		}
	}
	a.pump()
}

// counts returns the transfers in flight and waiting (Stats: instance
// totals only).
func (a *admission) counts() (inflight, waiting int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, w := range a.waiters {
		if !w.done {
			waiting++
		}
	}
	return len(a.inflight), waiting
}
