package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/selftest"
	"github.com/vettid/vettid-vault/internal/vaultipc"
)

// The capacity measurement (docs/SMOKE.md "Capacity measurement",
// VAULT-RELEASES §8.8): part of the self-test, so it runs only in an
// enclave whose parent asked for the self-test, before any instance
// exists. Its vault processes are spawned exactly like real ones (own uid,
// rlimits, seccomp, no environment) in self-test mode, where they answer
// only the self-test's requests and hold synthetic state.

// capProc is one synthetic vault process.
type capProc interface {
	call(ctx context.Context, op string, arg int) (*selftest.CapacityStats, error)
	// stop ends the process and reports whether it exited.
	stop() bool
}

// capEnv is what the measurement uses of the enclave (tests replace it).
type capEnv struct {
	spawn     func() (capProc, error)
	available func() uint64 // MemAvailable
	total     func() uint64 // MemTotal
	supRSS    func() uint64
	supCPU    func() int64 // microseconds
	now       func() time.Time
	sleep     func(ctx context.Context, d time.Duration) error
	log       func(msg string, kv ...any)
}

// initialPeak is the per-unlock memory assumed until one is measured
// (the smoke test measured about 76 MB).
const initialPeak = 96 << 20

// capacityFloor is the memory floor: the requested one, never below the
// release's lock threshold (15% of the enclave's memory, §12.3) or
// selftest.MinFloorMiB.
func capacityFloor(total uint64, floorMiB int) uint64 {
	return max(uint64(floorMiB)<<20, total*15/100, selftest.MinFloorMiB<<20)
}

type heldVault struct {
	p     capProc
	after *selftest.CapacityStats // right after the unlock
}

// runCapacity measures unlock latency, then fills the enclave with
// synthetic vaults up to p.MaxVaults or the memory floor, measures them at
// steady state and tears every one down. It never starts a process that
// could take the available memory below the floor (one unlock's peak is
// kept above it).
func runCapacity(ctx context.Context, env capEnv, p selftest.CapacityRequest) *selftest.CapacityReport {
	p.Defaults()
	start := env.now()
	r := &selftest.CapacityReport{Params: p, MemTotal: env.total()}
	r.FloorBytes = capacityFloor(r.MemTotal, p.FloorMiB)
	r.BaselineAvailable, r.BaselineSupervisorRSS = env.available(), env.supRSS()
	settle := time.Duration(p.SettleSeconds) * time.Second
	peak := uint64(initialPeak)
	var peakMu sync.Mutex
	notePeak := func(st *selftest.CapacityStats) {
		peakMu.Lock()
		defer peakMu.Unlock()
		if est := st.PeakRSS + st.PeakRSS/10; st.PeakRSS > 0 && (peak == initialPeak || est > peak) {
			peak = est
		}
	}
	room := func(n int) bool {
		peakMu.Lock()
		defer peakMu.Unlock()
		a := env.available()
		return a >= r.FloorBytes && a-r.FloorBytes >= uint64(n)*peak
	}
	note := func(f string, a ...any) { r.Notes = append(r.Notes, fmt.Sprintf(f, a...)) }

	// 1. Unlock latency on an otherwise empty enclave: start, hardening
	// and one Argon2id per process, c at a time; each process ends after.
	for _, c := range p.UnlockConcurrency {
		lvl := selftest.UnlockLevel{Concurrency: c}
		var tot, kdf []float64
		for len(tot) < p.UnlockSamples && lvl.Skipped == "" {
			if ctx.Err() != nil {
				lvl.Skipped = "timeout"
				break
			}
			if !room(c) {
				lvl.Skipped = "memory floor"
				break
			}
			type res struct {
				ms, kdfMs float64
				err       error
			}
			out := make([]res, c)
			var wg sync.WaitGroup
			for i := range c {
				wg.Add(1)
				go func() {
					defer wg.Done()
					t0 := env.now()
					pr, err := env.spawn()
					if err != nil {
						out[i].err = err
						return
					}
					st, err := pr.call(ctx, "unlock", 0)
					out[i].ms = float64(env.now().Sub(t0).Microseconds()) / 1000
					pr.stop()
					if err != nil {
						out[i].err = err
						return
					}
					out[i].kdfMs = float64(st.KDFMicros) / 1000
					notePeak(st)
				}()
			}
			wg.Wait()
			for _, o := range out {
				if o.err != nil {
					lvl.Skipped = "error: " + errText(o.err)
					break
				}
				tot, kdf = append(tot, o.ms), append(kdf, o.kdfMs)
			}
		}
		lvl.Samples = len(tot)
		lvl.P50Ms, lvl.P95Ms, lvl.MaxMs = selftest.Percentile(tot, 50), selftest.Percentile(tot, 95), selftest.Percentile(tot, 100)
		lvl.KDFP50Ms, lvl.KDFP95Ms = selftest.Percentile(kdf, 50), selftest.Percentile(kdf, 95)
		r.Unlock = append(r.Unlock, lvl)
		env.log("selftest capacity: unlock", "concurrency", c, "samples", lvl.Samples, "p50_ms", int(lvl.P50Ms), "p95_ms", int(lvl.P95Ms))
	}

	// 2. Fill: unlocked synthetic vaults until MaxVaults, or until the
	// floor holds no room for one more unlock even after waiting settle
	// for the runtime to return the KDFs' memory.
	var held []heldVault
	step := func() {
		r.Steps = append(r.Steps, selftest.CapacityStep{Vaults: len(held), Available: env.available(), SupervisorRSS: env.supRSS()})
	}
	step()
	r.StopReason = "max_vaults"
	// The fill ends early enough for the steady-state windows and the
	// teardown to fit in the budget.
	fillEnd := start.Add(time.Duration(p.BudgetMinutes)*time.Minute - 2*settle - time.Duration(p.IdleSeconds)*time.Second - 2*time.Minute)
	for len(held) < p.MaxVaults {
		if ctx.Err() != nil {
			r.StopReason = "timeout"
			break
		}
		if !env.now().Before(fillEnd) {
			r.StopReason = "time_budget"
			break
		}
		if !room(1) {
			r.SettleWaits++
			deadline := minTime(env.now().Add(settle), fillEnd)
			for !room(1) && env.now().Before(deadline) && ctx.Err() == nil {
				_ = env.sleep(ctx, min(5*time.Second, settle))
			}
			step()
			if !room(1) {
				r.StopReason = "memory_floor"
				if ctx.Err() != nil {
					r.StopReason = "timeout"
				}
				break
			}
		}
		pr, err := env.spawn()
		if err != nil {
			r.StopReason = "spawn_failed"
			note("spawn %d: %s", len(held)+1, errText(err))
			break
		}
		st, err := pr.call(ctx, "unlock", p.StateKiB<<10)
		if err != nil {
			pr.stop()
			r.StopReason = "error"
			if ctx.Err() != nil {
				r.StopReason = "timeout"
			}
			note("unlock %d: %s", len(held)+1, errText(err))
			break
		}
		notePeak(st)
		held = append(held, heldVault{p: pr, after: st})
		if len(held)%p.StepEvery == 0 {
			step()
			env.log("selftest capacity: fill", "vaults", len(held), "available", env.available())
		}
	}
	if n := len(r.Steps); n == 0 || r.Steps[n-1].Vaults != len(held) {
		step()
	}
	r.Held = len(held)
	env.log("selftest capacity: filled", "vaults", r.Held, "stop", r.StopReason)

	// 3. Steady state: wait settle, then measure memory and idle CPU over
	// the idle window.
	if len(held) > 0 && ctx.Err() == nil {
		_ = env.sleep(ctx, settle)
		before, cpu0 := collect(ctx, held)
		sup0, t0 := env.supCPU(), env.now()
		_ = env.sleep(ctx, time.Duration(p.IdleSeconds)*time.Second)
		after, cpu1 := collect(ctx, held)
		window := env.now().Sub(t0)
		var rss, pss, priv, rssUnlock []uint64
		var cpu int64
		n := 0
		for i, st := range after {
			if st == nil || before[i] == nil {
				continue
			}
			n++
			rss, pss, priv = append(rss, st.RSS), append(pss, st.PSS), append(priv, st.Private)
			r.VaultPeakRSS = max(r.VaultPeakRSS, st.PeakRSS)
			cpu += cpu1[i] - cpu0[i]
		}
		for _, h := range held {
			rssUnlock = append(rssUnlock, h.after.RSS)
		}
		if n < len(held) {
			note("%d of %d vaults did not answer the steady-state measurement", len(held)-n, len(held))
		}
		r.VaultRSS, r.VaultPSS, r.VaultPrivate = selftest.Summarize(rss), selftest.Summarize(pss), selftest.Summarize(priv)
		r.VaultRSSAfterUnlock = selftest.Summarize(rssUnlock)
		r.SteadyAvailable, r.SupervisorRSS = env.available(), env.supRSS()
		if mins := window.Minutes(); n > 0 && mins > 0 {
			r.IdleCPUMsPerVaultMinute = float64(cpu) / 1000 / float64(n) / mins
			r.SupervisorCPUMsPerMinuteIdle = float64(env.supCPU()-sup0) / 1000 / mins
		}
		if r.BaselineAvailable > r.SteadyAvailable {
			r.MarginalPerVault = (r.BaselineAvailable - r.SteadyAvailable) / uint64(len(held))
		}
		if usable := r.FloorBytes + peak; r.MarginalPerVault > 0 && r.BaselineAvailable > usable {
			r.ProjectedMax = int((r.BaselineAvailable - usable) / r.MarginalPerVault)
		}
		step()
	}

	// 4. Teardown: every synthetic vault process ends.
	r.TornDown = true
	for _, h := range held {
		if !h.p.stop() {
			r.TornDown = false
		}
	}
	if !r.TornDown {
		note("a synthetic vault process did not exit")
	}
	_ = env.sleep(context.WithoutCancel(ctx), 2*time.Second)
	r.AvailableAfter = env.available()
	r.DurationMs = env.now().Sub(start).Milliseconds()
	return r
}

// collect asks every held vault for its stats (nil where it did not
// answer) and returns them with their CPU times.
func collect(ctx context.Context, held []heldVault) ([]*selftest.CapacityStats, []int64) {
	sts, cpu := make([]*selftest.CapacityStats, len(held)), make([]int64, len(held))
	for i, h := range held {
		if st, err := h.p.call(ctx, "stats", 0); err == nil {
			sts[i], cpu[i] = st, st.CPUMicros
		}
	}
	return sts, cpu
}

// selftestCapacity runs the capacity measurement with real vault
// processes and adds it to the report.
func (s *Supervisor) selftestCapacity(ctx context.Context, r *selftest.Report, p selftest.CapacityRequest) {
	h := newProcHost(s, s.cfg.Proc)
	var n atomic.Int64
	env := capEnv{
		spawn: func() (capProc, error) {
			p, err := h.spawn("capacity-"+strconv.FormatInt(n.Add(1), 10), "selftest", false, "-selftest")
			if err != nil {
				return nil, err
			}
			return &capVProc{h: h, p: p}, nil
		},
		available: func() uint64 { return meminfo("MemAvailable") },
		total:     func() uint64 { return meminfo("MemTotal") },
		supRSS:    func() uint64 { return selfStatus("VmRSS") },
		supCPU:    selfCPUMicros,
		now:       time.Now,
		sleep: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		log: func(msg string, kv ...any) { s.log.Info(msg, kv...) },
	}
	c := runCapacity(ctx, env, p)
	r.Capacity = c
	measured := c.Held > 0 && (c.StopReason == "max_vaults" || c.StopReason == "memory_floor" || c.StopReason == "time_budget")
	r.Add("capacity.measured", measured, true, fmt.Sprintf("held=%d stop=%s projected_max=%d marginal_per_vault=%d",
		c.Held, c.StopReason, c.ProjectedMax, c.MarginalPerVault))
	r.Add("capacity.torn_down", c.TornDown, true, fmt.Sprintf("available_after=%d", c.AvailableAfter))
	all := len(c.Unlock) > 0
	for _, u := range c.Unlock {
		all = all && u.Skipped == ""
	}
	r.Add("capacity.unlock_latency", all, false, fmt.Sprintf("%d levels", len(c.Unlock)))
}

// capVProc is a synthetic vault in a real vault process.
type capVProc struct {
	h *procHost
	p *vproc
}

var errCapacity = errors.New("supervisor: synthetic vault did not answer")

func (c *capVProc) call(ctx context.Context, op string, arg int) (*selftest.CapacityStats, error) {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	rep, err := c.p.conn.Call(cctx, vaultipc.KindSelftestCapacity, []byte(op), []byte(strconv.Itoa(arg)))
	if err != nil {
		return nil, err
	}
	if len(rep) != 2 || string(rep[0]) != hostproto.StatusOK {
		return nil, errCapacity
	}
	var st selftest.CapacityStats
	if json.Unmarshal(rep[1], &st) != nil {
		return nil, errCapacity
	}
	return &st, nil
}

func (c *capVProc) stop() bool {
	c.h.stop(c.p)
	select {
	case <-c.p.exited:
		return true
	default:
		return false
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
