package supervisor

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/enclave/egress"
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
	// The code phase: opens marked now and in all; a code granted while
	// an open is marked when grantDuringOpen (a broken rule, for the test).
	opening, opens  int
	grantDuringOpen bool
	codes           int
	// unlocksMarked: unlocks that ran while an open was marked; grants:
	// what the fake permit gave (the supervisor's record).
	unlocksMarked int
	grants        []time.Time
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
		opening: func() func() {
			e.mu.Lock()
			e.opening++
			e.opens++
			e.mu.Unlock()
			return func() { e.mu.Lock(); e.opening--; e.mu.Unlock() }
		},
	}
}

func (p *fakeProc) call(_ context.Context, op string, _ int) (*selftest.CapacityStats, error) {
	p.e.mu.Lock()
	defer p.e.mu.Unlock()
	if op == "code" && !p.e.grantDuringOpen {
		// As the permit does, a code waits for an opening to end, for a
		// while (here 200 ms of real time), before it is busy.
		for t0 := time.Now(); p.e.opening > 0 && time.Since(t0) < 200*time.Millisecond; {
			p.e.mu.Unlock()
			time.Sleep(time.Millisecond)
			p.e.mu.Lock()
		}
	}
	if !p.alive {
		return nil, errors.New("gone")
	}
	st := &selftest.CapacityStats{PeakRSS: 76 * fakeMiB, CPUMicros: p.e.clock.Unix() * 10}
	switch op {
	case "unlock":
		if p.e.opening > 0 {
			p.e.unlocksMarked++
			if p.e.grantDuringOpen { // a broken rule: a code permit given mid-unlock
				p.e.grants = append(p.e.grants, p.e.clock.Add(100*time.Millisecond))
			}
		}
		p.e.clock = p.e.clock.Add(300 * time.Millisecond)
		st.KDFMicros, st.RSS = 280_000, 70*fakeMiB
	case "code":
		p.e.codes++
		if p.e.opening > 0 && !p.e.grantDuringOpen {
			st.Code, st.WaitMicros = "busy", 5_000_000
			break
		}
		st.Code, st.XMicros, st.TagMicros, st.WaitMicros = "done", 900_000, 950_000, 20_000
		st.GrantedAtsMs = []int64{p.e.clock.UnixMilli(), p.e.clock.UnixMilli()} // x, then the tag, outside any opening
		st.PeakRSS = 300 * fakeMiB
	default:
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

// The self-test's gate, which the capacity run relies on: outside
// self-test mode a self-test request is refused even with the self-test's
// egress configured; and the hello puts a supervisor in self-test mode only
// when it holds no instance and was never given one.
func TestSelftestGate(t *testing.T) {
	ready := make(chan struct{})
	close(ready)
	egressSet := func(string) (*egress.Transport, error) { return nil, errors.New("not used") }
	s := &Supervisor{selftestReady: ready, selftestDone: make(chan struct{}), cfg: Config{SelftestEgress: egressSet}}
	f := &hostproto.Frame{Kind: hostproto.KindSelftest, Fields: [][]byte{[]byte(`{"run_id":"r","key_arn":"a","account":"111122223333","region":"us-east-1","capacity":{"max_vaults":2}}`)}}
	if r := s.handleSelftest(context.Background(), f); string(r[0]) != hostproto.StatusInvalid {
		t.Fatalf("outside self-test mode, with egress: %q", r)
	}
	fresh := &Supervisor{}
	if !fresh.selftestAllowed("selftest") || fresh.selftestAllowed("fresh") {
		t.Fatal("the hello's kind")
	}
	given := &Supervisor{instID: "i-0123456789abcdef0"}
	if given.selftestAllowed("selftest") {
		t.Fatal("self-test on an enclave that was given an instance")
	}
	held := &Supervisor{}
	held.inst.Store(&enclave.Instance{})
	if held.selftestAllowed("selftest") {
		t.Fatal("self-test beside a running instance")
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

// The code phase runs only with Codes: every request is answered done or
// busy, the unlocks started meanwhile are marked as openings, nothing is
// granted during one, and every process is ended.
func TestCapacityCodes(t *testing.T) {
	e := newFakeEnclave(4096, 300)
	r := runCapacity(context.Background(), e.env(), selftest.CapacityRequest{MaxVaults: 5, Codes: 6, CodeConcurrency: 2, CodeUnlocks: 2})
	k := r.Codes
	if k == nil {
		t.Fatal("no code report")
	}
	if k.Requests != 6 || k.Done == 0 || k.Done+k.Busy != 6 || k.Failed != 0 || e.codes != 6 {
		t.Fatalf("codes %+v (asked %d)", k, e.codes)
	}
	// Two before the codes (the comparison) and up to two during them, each
	// marked as an opening for the whole unlock.
	if k.UnlockBeforeMs.N != 2 || k.Unlocks > 2 || e.opens != 2+k.Unlocks+k.UnlocksSkipped || e.opening != 0 || e.unlocksMarked != 2+k.Unlocks {
		t.Fatalf("before %d, during %d (%d skipped), opens marked %d, still open %d, unlocks while marked %d",
			k.UnlockBeforeMs.N, k.Unlocks, k.UnlocksSkipped, e.opens, e.opening, e.unlocksMarked)
	}
	if k.Grants != 2*k.Done || k.HeadroomBytes <= 0 {
		t.Fatalf("grants %d for %d done, headroom %d", k.Grants, k.Done, k.HeadroomBytes)
	}
	if k.Overlap != 0 || k.XMs.N != k.Done || (k.Done > 0) != (k.CodeVaultPeakRSS == 300*fakeMiB) || k.MinAvailable == 0 {
		t.Fatalf("report %+v", k)
	}
	if !r.TornDown || len(e.procs) != 0 {
		t.Fatalf("torn down %v, %d left", r.TornDown, len(e.procs))
	}
	// Without Codes the phase does not run.
	e2 := newFakeEnclave(4096, 300)
	if r2 := runCapacity(context.Background(), e2.env(), selftest.CapacityRequest{MaxVaults: 5}); r2.Codes != nil || e2.codes != 0 || e2.opens != 0 {
		t.Fatalf("codes ran unasked: %+v", r2.Codes)
	}
}

// A permit granted inside an opening is counted, once, and one at its
// edges is not (the rule allows none inside).
func TestCapacityCodesOverlapCounted(t *testing.T) {
	opened := []openSpan{{1000, 2000}, {5000, 6000}}
	if n := overlaps([]int64{1500, 999, 1000, 2000, 5500, 7000}, opened); n != 2 {
		t.Fatalf("%d overlaps, want 2", n)
	}
	if n := overlaps(nil, opened); n != 0 {
		t.Fatal(n)
	}
	// Two openings over one grant: counted once.
	if n := overlaps([]int64{1500}, []openSpan{{1000, 2000}, {1200, 1800}}); n != 1 {
		t.Fatal(n)
	}
}

// The code phase's time comes out of the fill's: with the budget all
// taken by the windows and the phase, the fill stops at once.
func TestCapacityCodesTimeComesOutOfTheFill(t *testing.T) {
	e := newFakeEnclave(4096, 300)
	p := selftest.CapacityRequest{MaxVaults: 50, BudgetMinutes: 10, SettleSeconds: 60, IdleSeconds: 60, Codes: 4, CodeSeconds: 300}
	r := runCapacity(context.Background(), e.env(), p)
	if r.StopReason != "time_budget" || r.Held != 0 {
		t.Fatalf("stop %s with %d held", r.StopReason, r.Held)
	}
}

// The supervisor's record of code permits is what the overlap counts: a
// permit given in the middle of an unlock is counted, and the check fails.
func TestCapacityCodesCountsTheSupervisorsGrants(t *testing.T) {
	e := newFakeEnclave(4096, 300)
	e.grantDuringOpen = true
	env := e.env()
	env.codeGrants = func() []time.Time { e.mu.Lock(); defer e.mu.Unlock(); return append([]time.Time(nil), e.grants...) }
	r := runCapacity(context.Background(), env, selftest.CapacityRequest{MaxVaults: 3, Codes: 2, CodeConcurrency: 1, CodeUnlocks: 2})
	k := r.Codes
	// The two comparison unlocks run before any code, each with a permit
	// given in its middle (a broken rule); the ones during the codes add theirs.
	if k == nil || k.Overlap != 2+k.Unlocks {
		t.Fatalf("overlap %+v", k)
	}
	if ok, _ := codesCheck(k); ok {
		t.Fatal("the check passed with permits given during unlocks")
	}
	if ok, detail := codesCheck(&selftest.CodeReport{Done: 3}); !ok || detail == "" {
		t.Fatal("a clean phase failed its check")
	}
	if ok, _ := codesCheck(&selftest.CodeReport{Busy: 3}); ok {
		t.Fatal("nothing done passed")
	}
}

// No unlock is started without room for one above the floor.
func TestCapacityCodesUnlocksNeedRoom(t *testing.T) {
	e := newFakeEnclave(4096, 300)
	env := e.env()
	var held []heldVault
	for range 2 {
		p, _ := env.spawn()
		held = append(held, heldVault{p: p})
	}
	spawned := e.spawned
	p := selftest.CapacityRequest{Codes: 2, CodeConcurrency: 1, CodeUnlocks: 3, CodeSeconds: 60}
	k := runCodes(context.Background(), env, p, held, 0, func(int) bool { return false }, func(*selftest.CapacityStats) {})
	// Each unlock is marked as an opening before its room is judged.
	// Each unlock is marked as an opening before its room is judged: the
	// comparison's 3, and as many as were tried while the codes ran.
	if k.Unlocks != 0 || e.spawned != spawned || e.opens != 3+k.UnlocksSkipped || k.UnlockBeforeMs.N != 0 || e.opening != 0 {
		t.Fatalf("unlocks %d skipped %d spawned %d opens %d", k.Unlocks, k.UnlocksSkipped, e.spawned-spawned, e.opens)
	}
}

// A synthetic unlock's mark makes the process host report a vault
// opening, as a real open does, until it ends; two marks are counted.
func TestMarkOpening(t *testing.T) {
	h := &procHost{opening: map[string]int{}}
	end := h.markOpening("capacity-open-1")
	end2 := h.markOpening("capacity-open-1")
	if !h.openingAny() {
		t.Fatal("not opening")
	}
	end()
	if !h.openingAny() {
		t.Fatal("one mark of two ended the opening")
	}
	end2()
	if h.openingAny() {
		t.Fatal("still opening")
	}
}

// The self-test's permit keeps the higher of the release's reserve and the
// capacity run's floor.
func TestSelftestPermitFloor(t *testing.T) {
	s := &Supervisor{cfg: Config{MemoryReserve: 300 << 20}, now: time.Now}
	h := s.selftestPermit()
	if h.floor() != 300<<20 {
		t.Fatalf("floor %d before the run", h.floor())
	}
	s.capFloor.Store(900 << 20)
	if h.floor() != 900<<20 {
		t.Fatalf("floor %d with the run's higher floor", h.floor())
	}
	s.capFloor.Store(100 << 20)
	if h.floor() != 300<<20 {
		t.Fatalf("floor %d with the run's lower floor", h.floor())
	}
}

// stuckProc's code requests never answer: only the phase's time bound
// ends them.
type stuckProc struct{}

func (stuckProc) call(ctx context.Context, op string, _ int) (*selftest.CapacityStats, error) {
	if op != "code" {
		return &selftest.CapacityStats{}, nil
	}
	<-ctx.Done()
	return nil, ctx.Err()
}
func (stuckProc) stop() bool { return true }

// The phase ends at CodeSeconds, its requests in flight counted as cut
// short, not failed.
func TestCapacityCodesTimeBound(t *testing.T) {
	e := newFakeEnclave(4096, 300)
	env := e.env()
	held := []heldVault{{p: stuckProc{}}, {p: stuckProc{}}}
	start := time.Now()
	k := runCodes(context.Background(), env, selftest.CapacityRequest{Codes: 4, CodeConcurrency: 2, CodeUnlocks: 1, CodeSeconds: 1},
		held, 0, func(int) bool { return true }, func(*selftest.CapacityStats) {})
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the phase took %v", d)
	}
	if k.CutShort != 2 || k.Failed != 0 || k.Done != 0 {
		t.Fatalf("%+v", k)
	}
}

// The capacity run readies the self-test's permit: the run's floor when it
// is higher, and a record of the code permits given. Without a permit,
// nothing is recorded and the floor is left alone.
func TestCapacityPermit(t *testing.T) {
	s := &Supervisor{cfg: Config{MemoryReserve: 300 << 20, MemAvailable: func() uint64 { return 64 << 30 }}, now: time.Now}
	s.heavy = s.selftestPermit()
	grants := s.capacityPermit(selftest.CapacityRequest{FloorMiB: 2000}, 4096<<20)
	if s.heavy.floor() != 2000<<20 {
		t.Fatalf("floor %d", s.heavy.floor())
	}
	if s.heavy.tryCode("c1") != permitGiven || len(grants()) != 1 {
		t.Fatalf("grants %v", grants())
	}
	bare := &Supervisor{now: time.Now}
	if g := bare.capacityPermit(selftest.CapacityRequest{FloorMiB: 2000}, 4096<<20); len(g()) != 0 || bare.capFloor.Load() != 0 {
		t.Fatal("recorded without a permit")
	}
}

func TestSpansOverlapping(t *testing.T) {
	sp := func(f, to int64) openSpan { return openSpan{f, to} }
	for name, c := range map[string]struct {
		a, b []openSpan
		want int
	}{
		"none":             {nil, []openSpan{sp(0, 10)}, 0},
		"no derivations":   {[]openSpan{sp(0, 10)}, nil, 0},
		"inside":           {[]openSpan{sp(0, 10)}, []openSpan{sp(2, 3)}, 1},
		"around":           {[]openSpan{sp(2, 3)}, []openSpan{sp(0, 10)}, 1},
		"straddles start":  {[]openSpan{sp(5, 10)}, []openSpan{sp(0, 6)}, 1},
		"straddles end":    {[]openSpan{sp(5, 10)}, []openSpan{sp(9, 20)}, 1},
		"touches before":   {[]openSpan{sp(5, 10)}, []openSpan{sp(0, 5)}, 0},
		"touches after":    {[]openSpan{sp(5, 10)}, []openSpan{sp(10, 15)}, 0},
		"counted once":     {[]openSpan{sp(0, 10)}, []openSpan{sp(1, 2), sp(3, 4)}, 1},
		"each of a counts": {[]openSpan{sp(0, 10), sp(20, 30), sp(40, 50)}, []openSpan{sp(5, 25)}, 2},
	} {
		if got := spansOverlapping(c.a, c.b); got != c.want {
			t.Errorf("%s: %d, want %d", name, got, c.want)
		}
	}
}

// funcProc is a held vault whose code request is code.
type funcProc struct {
	code func(context.Context) *selftest.CapacityStats
}

func (p funcProc) call(ctx context.Context, op string, _ int) (*selftest.CapacityStats, error) {
	if op != "code" {
		return &selftest.CapacityStats{}, nil
	}
	return p.code(ctx), nil
}
func (funcProc) stop() bool { return true }

func done() *selftest.CapacityStats {
	return &selftest.CapacityStats{Code: "done", XMicros: 1000, TagMicros: 1000}
}

// The sampler catches a dip that lasts only while a derivation runs: no
// sample at a request's end or around an unlock sees it.
func TestCapacityCodesSamplesMemory(t *testing.T) {
	e := newFakeEnclave(4096, 300)
	env := e.env()
	// The dip lasts until the sampler has read both MemAvailable and
	// MemFree during it, however long that takes: no fixed wait it could
	// miss under load (-race), and no sample half in it, half out.
	var mu sync.Mutex
	dip := false
	seenAvail, seenFree := make(chan struct{}, 1), make(chan struct{}, 1)
	signal := func(c chan struct{}) {
		select {
		case c <- struct{}{}:
		default:
		}
	}
	avail := env.available
	env.available = func() uint64 {
		mu.Lock()
		defer mu.Unlock()
		if dip {
			signal(seenAvail)
			return 1 * fakeMiB
		}
		return avail()
	}
	env.free = func() uint64 { // MemFree, read with it: half of it
		mu.Lock()
		defer mu.Unlock()
		if dip {
			signal(seenFree)
			return fakeMiB / 2
		}
		return avail() / 2
	}
	held := []heldVault{{p: funcProc{func(context.Context) *selftest.CapacityStats {
		mu.Lock()
		dip = true
		mu.Unlock()
		<-seenAvail
		<-seenFree
		mu.Lock()
		dip = false
		mu.Unlock()
		return done()
	}}}}
	// No unlocks: their own samples could land in the dip and hide a sampler that never samples.
	k := runCodes(context.Background(), env, selftest.CapacityRequest{Codes: 1, CodeConcurrency: 1, CodeUnlocks: 0, CodeSeconds: 60},
		held, 0, func(int) bool { return true }, func(*selftest.CapacityStats) {})
	if k.MinAvailable != 1*fakeMiB || k.Done != 1 {
		t.Fatalf("min available %d, %+v", k.MinAvailable, k)
	}
	// The start is reported too, the reading the headroom is based on.
	if k.StartAvailable != avail() || k.HeadroomBytes != int64(k.StartAvailable)-int64(codeNeed()) {
		t.Fatalf("start available %d, headroom %d (available now %d)", k.StartAvailable, k.HeadroomBytes, avail())
	}
	// The sampler's own readings are counted, the highest kept, and
	// MemFree's lowest read with them.
	if k.Samples == 0 || k.MaxAvailable != k.StartAvailable || k.MinFree != fakeMiB/2 {
		t.Fatalf("samples %d, max available %d (start %d), min free %d", k.Samples, k.MaxAvailable, k.StartAvailable, k.MinFree)
	}
}

// Once the codes are done no unlock is started: at most the one already
// past its check.
func TestCapacityCodesUnlocksStopWithTheCodes(t *testing.T) {
	e := newFakeEnclave(8192, 300)
	env := e.env()
	const unlocks = 16
	spawned := func() int { e.mu.Lock(); defer e.mu.Unlock(); return e.spawned }
	// The phase's unlocks take real time, so the codes can end among them.
	spawn := env.spawn
	env.spawn = func() (capProc, error) {
		if spawned() >= unlocks {
			time.Sleep(10 * time.Millisecond)
		}
		return spawn()
	}
	var atDone int
	held := []heldVault{{p: funcProc{func(context.Context) *selftest.CapacityStats {
		// The code ends once two unlocks of the phase have started.
		for t0 := time.Now(); spawned() < unlocks+2 && time.Since(t0) < 2*time.Second; {
			time.Sleep(time.Millisecond)
		}
		atDone = spawned()
		return done()
	}}}}
	k := runCodes(context.Background(), env, selftest.CapacityRequest{Codes: 1, CodeConcurrency: 1, CodeUnlocks: unlocks, CodeSeconds: 60},
		held, 0, func(int) bool { return true }, func(*selftest.CapacityStats) {})
	if atDone < unlocks+2 || spawned() > atDone+1 || k.Unlocks >= unlocks {
		t.Fatalf("spawned %d at the codes' end, %d in all; %d unlocks during", atDone, spawned(), k.Unlocks)
	}
}

// The headroom is what is free at the phase's start less the floor and one
// code derivation's need.
func TestCapacityCodesHeadroom(t *testing.T) {
	e := newFakeEnclave(4096, 300)
	env := e.env()
	held := []heldVault{{p: funcProc{func(context.Context) *selftest.CapacityStats { return done() }}}}
	start := int64(env.available())
	k := runCodes(context.Background(), env, selftest.CapacityRequest{Codes: 1, CodeConcurrency: 1, CodeUnlocks: 1, CodeSeconds: 60},
		held, 100*fakeMiB, func(int) bool { return true }, func(*selftest.CapacityStats) {})
	if want := start - 100*fakeMiB - int64(codeNeed()); k.HeadroomBytes != want {
		t.Fatalf("headroom %d, want %d", k.HeadroomBytes, want)
	}
}

// Without room for one derivation above the floor the report says so.
func TestCapacityCodesNoHeadroomNoted(t *testing.T) {
	e := newFakeEnclave(1024, 100)
	r := runCapacity(context.Background(), e.env(), selftest.CapacityRequest{MaxVaults: 30, Codes: 1, CodeConcurrency: 1, CodeUnlocks: 1})
	if r.Codes == nil || r.Codes.HeadroomBytes >= 0 || !noted(r, "short of one code derivation above the floor") {
		t.Fatalf("held %d, codes %+v, notes %q", r.Held, r.Codes, r.Notes)
	}
}

// With no vault held the phase doesn't run, and the report says why.
func TestCapacityCodesNoVaultHeld(t *testing.T) {
	e := newFakeEnclave(4096, 300)
	e.failSpawnAt = 1
	r := runCapacity(context.Background(), e.env(), selftest.CapacityRequest{MaxVaults: 3, Codes: 2, CodeConcurrency: 1, CodeUnlocks: 1})
	if r.Held != 0 || r.Codes != nil || !noted(r, "code phase skipped: no vault held") {
		t.Fatalf("held %d, codes %+v, notes %q", r.Held, r.Codes, r.Notes)
	}
}

func noted(r *selftest.CapacityReport, s string) bool {
	for _, n := range r.Notes {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

// At most CodeConcurrency requests at a time, never more than the vaults
// held, and never two on one vault.
func TestCapacityCodesOnePerVault(t *testing.T) {
	e := newFakeEnclave(4096, 300)
	var mu sync.Mutex
	inUse, most := 0, 0
	perVault := map[int]int{}
	worst := 0
	proc := func(v int, d time.Duration) capProc {
		return funcProc{func(context.Context) *selftest.CapacityStats {
			mu.Lock()
			inUse++
			perVault[v]++
			most, worst = max(most, inUse), max(worst, perVault[v])
			mu.Unlock()
			time.Sleep(d)
			mu.Lock()
			inUse--
			perVault[v]--
			mu.Unlock()
			return done()
		}}
	}
	// One slow vault and one fast: a request can never be handed to the
	// slow one while it works.
	held := []heldVault{{p: proc(0, 30*time.Millisecond)}, {p: proc(1, time.Millisecond)}}
	k := runCodes(context.Background(), e.env(), selftest.CapacityRequest{Codes: 12, CodeConcurrency: 4, CodeUnlocks: 1, CodeSeconds: 60},
		held, 0, func(int) bool { return true }, func(*selftest.CapacityStats) {})
	if k.Done != 12 || most > 2 || worst > 1 {
		t.Fatalf("done %d, %d at a time, %d on one vault", k.Done, most, worst)
	}
	// More vaults than CodeConcurrency: CodeConcurrency at a time, no more.
	most, worst = 0, 0
	held = []heldVault{{p: proc(0, 20*time.Millisecond)}, {p: proc(1, 20*time.Millisecond)}, {p: proc(2, 20*time.Millisecond)},
		{p: proc(3, 20*time.Millisecond)}}
	k = runCodes(context.Background(), e.env(), selftest.CapacityRequest{Codes: 8, CodeConcurrency: 2, CodeUnlocks: 1, CodeSeconds: 60},
		held, 0, func(int) bool { return true }, func(*selftest.CapacityStats) {})
	if k.Done != 8 || most != 2 || worst > 1 {
		t.Fatalf("done %d, %d at a time (want 2), %d on one vault", k.Done, most, worst)
	}
}

// An unlock during a derivation is counted as overlapping: here every
// derivation spans the whole phase.
func TestCapacityCodesUnlocksOverlapping(t *testing.T) {
	e := newFakeEnclave(4096, 300)
	env := e.env()
	at := env.now().Add(-time.Hour).UnixMilli()
	slow := funcProc{func(context.Context) *selftest.CapacityStats {
		time.Sleep(50 * time.Millisecond) // the phase's unlocks run meanwhile
		return &selftest.CapacityStats{Code: "done", XMicros: int64(10 * time.Hour / time.Microsecond), TagMicros: 1000, GrantedAtsMs: []int64{at, at}}
	}}
	k := runCodes(context.Background(), env, selftest.CapacityRequest{Codes: 1, CodeConcurrency: 1, CodeUnlocks: 2, CodeSeconds: 60},
		[]heldVault{{p: slow}}, 0, func(int) bool { return true }, func(*selftest.CapacityStats) {})
	if k.Unlocks == 0 || k.UnlocksOverlapping != k.Unlocks {
		t.Fatalf("%d unlocks during, %d overlapping", k.Unlocks, k.UnlocksOverlapping)
	}
}
