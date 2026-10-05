package supervisor

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/selftest"
)

const fakeMiB = 1 << 20

// fakeEnclave models the enclave's memory: a process costs peak while it
// unlocks and right after, and steady once settleAfter has passed.
type fakeEnclave struct {
	mu          sync.Mutex
	clock       time.Time
	total, base uint64
	peak        uint64
	steady      uint64
	settleAfter time.Duration
	procs       map[*fakeProc]bool
	spawned     int
	failSpawnAt int // 1-based; 0: never
	minAvail    uint64
	stops       int
}

type fakeProc struct {
	e        *fakeEnclave
	unlocked time.Time
	alive    bool
}

func newFakeEnclave(totalMiB, usedMiB uint64) *fakeEnclave {
	e := &fakeEnclave{clock: time.Unix(1_800_000_000, 0), total: totalMiB * fakeMiB, base: (totalMiB - usedMiB) * fakeMiB,
		peak: 80 * fakeMiB, steady: 20 * fakeMiB, settleAfter: 120 * time.Second, procs: map[*fakeProc]bool{}}
	e.minAvail = e.base
	return e
}

func (e *fakeEnclave) availLocked() uint64 {
	used := uint64(0)
	for p := range e.procs {
		if e.clock.Sub(p.unlocked) >= e.settleAfter {
			used += e.steady
		} else {
			used += e.peak
		}
	}
	if used > e.base {
		return 0
	}
	return e.base - used
}

func (e *fakeEnclave) env() capEnv {
	return capEnv{
		spawn: func() (capProc, error) {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.spawned++
			if e.failSpawnAt != 0 && e.spawned >= e.failSpawnAt {
				return nil, errors.New("no slot")
			}
			p := &fakeProc{e: e, unlocked: e.clock, alive: true}
			e.procs[p] = true
			if a := e.availLocked(); a < e.minAvail {
				e.minAvail = a
			}
			return p, nil
		},
		available: func() uint64 { e.mu.Lock(); defer e.mu.Unlock(); return e.availLocked() },
		total:     func() uint64 { return e.total },
		supRSS:    func() uint64 { return 13 * fakeMiB },
		supCPU:    func() int64 { e.mu.Lock(); defer e.mu.Unlock(); return e.clock.Unix() * 100 },
		now:       func() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.clock },
		sleep: func(ctx context.Context, d time.Duration) error {
			e.mu.Lock()
			e.clock = e.clock.Add(d)
			e.mu.Unlock()
			return ctx.Err()
		},
		log: func(string, ...any) {},
	}
}

func (p *fakeProc) call(_ context.Context, op string, _ int) (*selftest.CapacityStats, error) {
	p.e.mu.Lock()
	defer p.e.mu.Unlock()
	if !p.alive {
		return nil, errors.New("gone")
	}
	st := &selftest.CapacityStats{PeakRSS: 76 * fakeMiB, CPUMicros: p.e.clock.Unix() * 10}
	if op == "unlock" {
		p.e.clock = p.e.clock.Add(300 * time.Millisecond)
		st.KDFMicros, st.RSS = 280_000, 70*fakeMiB
	} else {
		st.RSS, st.PSS, st.Private = 20*fakeMiB, 15*fakeMiB, 12*fakeMiB
	}
	return st, nil
}

func (p *fakeProc) stop() bool {
	p.e.mu.Lock()
	defer p.e.mu.Unlock()
	p.alive = false
	delete(p.e.procs, p)
	p.e.stops++
	return true
}

// The fill stops at the floor, after waiting for memory to come back,
// never starts a process that could cross the floor, and ends every
// process.
func TestCapacityFillsToFloor(t *testing.T) {
	e := newFakeEnclave(5120, 100) // 5 GiB enclave
	r := runCapacity(context.Background(), e.env(), selftest.CapacityRequest{MaxVaults: 1000, UnlockConcurrency: []int{1, 2, 4}, UnlockSamples: 4})
	for _, l := range r.Lines() {
		t.Log(l)
	}
	if r.StopReason != "memory_floor" || r.Held < 100 || r.SettleWaits < 2 {
		t.Fatalf("held %d stop %s waits %d", r.Held, r.StopReason, r.SettleWaits)
	}
	if want := uint64(5120 * fakeMiB * 15 / 100); r.FloorBytes != want {
		t.Fatalf("floor %d, want 15%% = %d", r.FloorBytes, want)
	}
	if e.minAvail < r.FloorBytes {
		t.Fatalf("available fell to %d, below the floor %d", e.minAvail, r.FloorBytes)
	}
	if !r.TornDown || len(e.procs) != 0 || e.stops != e.spawned {
		t.Fatalf("teardown: %v, %d left, %d stops of %d", r.TornDown, len(e.procs), e.stops, e.spawned)
	}
	if len(r.Unlock) != 3 {
		t.Fatalf("unlock levels %+v", r.Unlock)
	}
	for _, u := range r.Unlock {
		if u.Skipped != "" || u.Samples < 4 || u.P50Ms < 300 || u.KDFP50Ms != 280 {
			t.Fatalf("unlock %+v", u)
		}
	}
	if r.VaultRSS.Mean != 20*fakeMiB || r.VaultPSS.Mean != 15*fakeMiB || r.VaultPrivate.Mean != 12*fakeMiB || r.VaultRSSAfterUnlock.Mean != 70*fakeMiB ||
		r.VaultPeakRSS != 76*fakeMiB {
		t.Fatalf("per-vault %+v %+v %+v", r.VaultRSS, r.VaultPSS, r.VaultRSSAfterUnlock)
	}
	if r.MarginalPerVault != 20*fakeMiB || r.ProjectedMax < r.Held-1 || r.ProjectedMax > r.Held+5 {
		t.Fatalf("marginal %d projected %d held %d", r.MarginalPerVault, r.ProjectedMax, r.Held)
	}
	if r.IdleCPUMsPerVaultMinute <= 0 || r.SupervisorCPUMsPerMinuteIdle <= 0 {
		t.Fatalf("cpu %v %v", r.IdleCPUMsPerVaultMinute, r.SupervisorCPUMsPerMinuteIdle)
	}
	if r.Steps[0].Vaults != 0 || r.Steps[len(r.Steps)-1].Vaults != r.Held || r.AvailableAfter != e.base {
		t.Fatalf("steps %+v after %d", r.Steps, r.AvailableAfter)
	}
}

func TestCapacityMaxVaults(t *testing.T) {
	e := newFakeEnclave(5120, 100)
	r := runCapacity(context.Background(), e.env(), selftest.CapacityRequest{MaxVaults: 3, UnlockConcurrency: []int{1}, UnlockSamples: 1, StepEvery: 1})
	if r.StopReason != "max_vaults" || r.Held != 3 || r.SettleWaits != 0 || !r.TornDown || len(e.procs) != 0 {
		t.Fatalf("%+v", r)
	}
	if len(r.Steps) != 5 { // 0, 1, 2, 3, steady
		t.Fatalf("steps %+v", r.Steps)
	}
}

// The requested floor can raise the release's 15% but never lower it.
func TestCapacityFloor(t *testing.T) {
	total := uint64(5 << 30)
	if f := capacityFloor(total, 1); f != total*15/100 {
		t.Fatalf("lowered: %d", f)
	}
	if f := capacityFloor(total, 2048); f != 2048<<20 {
		t.Fatalf("raised: %d", f)
	}
	if f := capacityFloor(512<<20, 0); f != selftest.MinFloorMiB<<20 {
		t.Fatalf("minimum: %d", f)
	}
	// No room at all: nothing is started, the unlock levels are skipped.
	e := newFakeEnclave(5120, 4500)
	r := runCapacity(context.Background(), e.env(), selftest.CapacityRequest{MaxVaults: 10, UnlockConcurrency: []int{1}, UnlockSamples: 2, SettleSeconds: 10})
	if e.spawned != 0 || r.Held != 0 || r.StopReason != "memory_floor" || r.Unlock[0].Skipped != "memory floor" || !r.TornDown {
		t.Fatalf("spawned %d, %+v", e.spawned, r)
	}
}

func TestCapacitySpawnFailureTearsDown(t *testing.T) {
	e := newFakeEnclave(5120, 100)
	e.failSpawnAt = 8 // after 1 unlock sample: 6 vaults held, the 7th fails
	r := runCapacity(context.Background(), e.env(), selftest.CapacityRequest{MaxVaults: 50, UnlockConcurrency: []int{1}, UnlockSamples: 1})
	if r.StopReason != "spawn_failed" || r.Held != 6 || !r.TornDown || len(e.procs) != 0 || len(r.Notes) == 0 {
		t.Fatalf("%+v procs %d", r, len(e.procs))
	}
}

func TestCapacityCancelled(t *testing.T) {
	e := newFakeEnclave(5120, 100)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := runCapacity(ctx, e.env(), selftest.CapacityRequest{MaxVaults: 50})
	if r.StopReason != "timeout" || r.Held != 0 || !r.TornDown || len(e.procs) != 0 {
		t.Fatalf("%+v", r)
	}
	for _, u := range r.Unlock {
		if u.Skipped != "timeout" {
			t.Fatalf("unlock %+v", u)
		}
	}
}

// The capacity measurement is part of the self-test: a supervisor whose
// parent did not ask for the self-test refuses it.
func TestCapacityOnlyInSelftest(t *testing.T) {
	ready := make(chan struct{})
	close(ready)
	s := &Supervisor{selftestReady: ready, selftestDone: make(chan struct{}), cfg: Config{SelftestEgress: nil}}
	f := &hostproto.Frame{Kind: hostproto.KindSelftest, Fields: [][]byte{[]byte(`{"run_id":"r","key_arn":"a","account":"111122223333","region":"us-east-1","capacity":{"max_vaults":2}}`)}}
	if r := s.handleSelftest(context.Background(), f); string(r[0]) != hostproto.StatusInvalid {
		t.Fatalf("not in selftest mode: %q", r)
	}
}

// The fill stops in time for the steady-state windows to fit the budget.
func TestCapacityTimeBudget(t *testing.T) {
	e := newFakeEnclave(200<<10, 100) // memory is not the limit
	r := runCapacity(context.Background(), e.env(), selftest.CapacityRequest{MaxVaults: 1000, UnlockConcurrency: []int{1}, UnlockSamples: 1,
		SettleSeconds: 60, IdleSeconds: 60, BudgetMinutes: 6})
	if r.StopReason != "time_budget" || r.Held < 150 || r.Held > 210 || !r.TornDown || r.DurationMs > 6*60*1000 {
		t.Fatalf("held %d stop %s duration %dms", r.Held, r.StopReason, r.DurationMs)
	}
}
