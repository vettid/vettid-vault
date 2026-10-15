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
//
// A vault process is not trusted with any of it:
//   - it holds at most 2 admitted transfers and 2 waiting requests;
//   - an admitted transfer it never ends is reclaimed after transferLease
//     (an 8 MiB transfer takes seconds; the relay requests are bounded at
//     75 s), and its end arriving before the request it ends (the channel
//     handles notifications at once and requests in goroutines) is kept as
//     a tombstone that refuses that request;
//   - the priority it declares cannot be verified (the owner's requests
//     are end-to-end encrypted to the vault): the supervisor honours an
//     owner fetch's priority for one transfer of a process at a time, and
//     reads every other request of that process as an ordinary transfer,
//     so a process that declares every transfer an owner fetch gains one
//     place in the queue, never more than its 2;
//   - the relay proxy carries blob bodies (GET /v1/blob/..., and PUT
//     /v1/blob/... over 1 MiB) only within a process's admitted
//     transfers, one body each (vproc.blobBody), on plain clean paths,
//     without following redirects, so admission cannot be bypassed.
//
// Unknown memory (MemAvailable reads 0) admits nothing: fail closed.

// Admission defaults (§10.5.1: 64 MiB until measured; at most 4).
const (
	TransferBudget   = 64 << 20
	MaxTransfers     = 4
	transfersOfVault = 2 // attachment_transfers
	waitersOfVault   = 2
	// maxTransferWait bounds one admission request (the vault's channel
	// request times out at 90 s).
	maxTransferWait = 80 * time.Second
	// transferRecheck is how often waiting transfers look at the memory
	// again while none ends.
	transferRecheck = 250 * time.Millisecond
	// transferLease is how long an admitted transfer is held without its
	// end before it is reclaimed.
	transferLease = 5 * time.Minute
	// tombstoneTTL is how long an end that came before its request is kept.
	tombstoneTTL = 2 * time.Minute
	// tombstonesOfVault bounds a process's tombstones.
	tombstonesOfVault = 16
	// prioOwnerFetch is the owner fetch's priority (vault.PrioOwnerFetch).
	prioOwnerFetch = 0
	prioTransfer   = 1
)

var errNotAdmitted = errors.New("supervisor: transfer not admitted")

// admission is the instance's admission of blob transfers.
type admission struct {
	mu         sync.Mutex
	avail      func() uint64 // MemAvailable (0: unknown: nothing is admitted)
	reserve    uint64
	budget     uint64
	max        int
	lease      time.Duration
	now        func() time.Time
	inflight   map[*admitTicket]bool
	byOwner    map[any]int
	waiters    []*admitWaiter
	tombstones map[tombKey]time.Time
	seq        uint64
	timer      *time.Timer
	// counts for tests (instance totals, never a vault's).
	admitted, refused, reclaimed uint64
}

type tombKey struct {
	owner any
	id    string
}

type admitTicket struct {
	owner any
	id    string
	prio  int
	at    time.Time
}

type admitWaiter struct {
	t     *admitTicket
	prio  int
	seq   uint64
	ready chan struct{}
	done  bool
}

func newAdmission(avail func() uint64, reserve uint64) *admission {
	return &admission{avail: avail, reserve: reserve, budget: TransferBudget, max: MaxTransfers, lease: transferLease, now: time.Now,
		inflight: map[*admitTicket]bool{}, byOwner: map[any]int{}, tombstones: map[tombKey]time.Time{}}
}

// fits reports whether one more transfer fits now (lock held).
func (a *admission) fits() bool {
	n := len(a.inflight)
	if n >= a.max {
		return false
	}
	av := a.avail()
	return av > 0 && av >= a.reserve && av-a.reserve >= a.budget*uint64(n+1)
}

// reclaim ends admitted transfers held past the lease, and forgets old
// tombstones (lock held).
func (a *admission) reclaim() {
	now := a.now()
	for t := range a.inflight {
		if now.Sub(t.at) >= a.lease {
			delete(a.inflight, t)
			if a.byOwner[t.owner]--; a.byOwner[t.owner] <= 0 {
				delete(a.byOwner, t.owner)
			}
			a.reclaimed++
		}
	}
	for k, at := range a.tombstones {
		if now.Sub(at) >= tombstoneTTL {
			delete(a.tombstones, k)
		}
	}
}

// ownerFetchHeld reports whether owner already has a transfer admitted or
// waiting at the owner fetch's priority (lock held).
func (a *admission) ownerFetchHeld(owner any) bool {
	for t := range a.inflight {
		if t.owner == owner && t.prio == prioOwnerFetch {
			return true
		}
	}
	for _, w := range a.waiters {
		if !w.done && w.t.owner == owner && w.prio == prioOwnerFetch {
			return true
		}
	}
	return false
}

// pump admits waiting transfers in order while they fit (lock held).
func (a *admission) pump() {
	a.reclaim()
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
			w.t.at = a.now()
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
	a.reclaim()
	k := tombKey{owner, id}
	if _, ok := a.tombstones[k]; ok {
		// Its end came first: the process gave this request up.
		delete(a.tombstones, k)
		a.refused++
		a.mu.Unlock()
		return nil, errNotAdmitted
	}
	n := 0
	for _, w := range a.waiters {
		if !w.done && w.t.owner == owner {
			n++
		}
	}
	if n >= waitersOfVault {
		a.refused++
		a.mu.Unlock()
		return nil, errNotAdmitted
	}
	if prio < prioOwnerFetch || prio == prioOwnerFetch && a.ownerFetchHeld(owner) {
		prio = prioTransfer // an unverifiable priority, honoured once at a time
	}
	t := &admitTicket{owner: owner, id: id, prio: prio}
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

// release ends a transfer (or forgets a waiting one) of owner by id. An id
// it does not know is kept as a tombstone: its request may still come.
func (a *admission) release(owner any, id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	known := false
	for t := range a.inflight {
		if t.owner == owner && t.id == id {
			known = true
			delete(a.inflight, t)
			if a.byOwner[owner]--; a.byOwner[owner] <= 0 {
				delete(a.byOwner, owner)
			}
		}
	}
	for _, w := range a.waiters {
		if w.t.owner == owner && w.t.id == id && !w.done {
			known = true
			w.done = true
		}
	}
	if !known {
		n := 0
		for k := range a.tombstones {
			if k.owner == owner {
				n++
			}
		}
		if n < tombstonesOfVault {
			a.tombstones[tombKey{owner, id}] = a.now()
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
	for k := range a.tombstones {
		if k.owner == owner {
			delete(a.tombstones, k)
		}
	}
	a.pump()
}

// held is how many admitted transfers owner holds (the relay proxy
// carries one blob body per admitted transfer).
func (a *admission) held(owner any) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reclaim()
	return a.byOwner[owner]
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
