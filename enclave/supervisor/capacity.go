package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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
	// opening marks a vault opening for the code permit's unlock-first
	// rule, as a real open is marked, until the returned func is called;
	// nil: nothing to mark (tests).
	opening func() (end func())
	// codeGrants is when the supervisor gave each code permit so far, on
	// the clock of now; nil: the vault processes' own stamps (tests).
	codeGrants func() []time.Time
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
	fillEnd := start.Add(time.Duration(p.BudgetMinutes)*time.Minute - 2*settle - time.Duration(p.IdleSeconds)*time.Second - 2*time.Minute -
		time.Duration(p.CodeSeconds)*time.Second)
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

	// 4. Code pairings' derivations under the code permit, with unlocks
	// started meanwhile (only with p.Codes, and vaults held).
	if p.Codes > 0 && len(held) == 0 {
		note("code phase skipped: no vault held")
	}
	if p.Codes > 0 && len(held) > 0 && ctx.Err() == nil {
		r.Codes = runCodes(ctx, env, p, held, r.FloorBytes, room, notePeak)
		if r.Codes.HeadroomBytes < 0 {
			note("code phase: %.1f MiB short of one code derivation above the floor at its start; requests are answered no room (stop the fill below the floor: a lower -capacity)",
				float64(-r.Codes.HeadroomBytes)/(1<<20))
		}
		env.log("selftest capacity: codes", "done", r.Codes.Done, "busy", r.Codes.Busy, "no_room", r.Codes.NoRoom, "unlocks", r.Codes.Unlocks)
	}

	// 5. Teardown: every synthetic vault process ends.
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

// runCodes runs p.Codes code pairings' derivations on the held vaults,
// p.CodeConcurrency at a time (at most one per held vault), while fresh
// synthetic vaults unlock one after another, each marked as an opening
// (before its room is judged), so that the code permit gives way to them
// as it does to real unlocks; unlocks stop being started once the codes
// are done. Before the first code, as many unlocks are timed at the same
// held count (the comparison). Each derivation is admitted by the
// supervisor's permit (its own memory check, floor plus 1.2 × 256 MiB); an
// unlock is started only with room for one above the floor. Free memory is
// sampled every sampleEvery for the phase. It ends at p.CodeSeconds
// whatever is left.
func runCodes(ctx context.Context, env capEnv, p selftest.CapacityRequest, held []heldVault, floor uint64,
	room func(int) bool, notePeak func(*selftest.CapacityStats)) *selftest.CodeReport {
	k := &selftest.CodeReport{MinAvailable: env.available()}
	k.HeadroomBytes = int64(k.MinAvailable) - int64(floor) - int64(codeNeed())
	t0 := env.now()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.CodeSeconds)*time.Second)
	defer cancel()
	var mu sync.Mutex
	var xs, tags, waits, before, unlocks []float64
	var opened, beforeSpans, derived []openSpan
	var granted []int64
	sample := func() {
		a := env.available()
		mu.Lock()
		k.MinAvailable = min(k.MinAvailable, a)
		mu.Unlock()
	}
	// unlock runs one synthetic unlock, marked as an opening from before its
	// room is judged; its span, or false when it was not run.
	unlock := func() (openSpan, float64, bool) {
		end := func() {}
		if env.opening != nil {
			end = env.opening()
		}
		defer end()
		if !room(1) {
			return openSpan{}, 0, false
		}
		from := env.now()
		pr, err := env.spawn()
		if err != nil {
			return openSpan{}, 0, false
		}
		st, err := pr.call(ctx, "unlock", 0)
		to := env.now()
		pr.stop()
		if err != nil {
			return openSpan{}, 0, false
		}
		notePeak(st)
		return openSpan{from.UnixMilli(), to.UnixMilli()}, float64(to.Sub(from).Microseconds()) / 1000, true
	}

	// The comparison: the same unlocks at the same held count, codes not yet
	// started.
	for range p.CodeUnlocks {
		if ctx.Err() != nil {
			break
		}
		if span, ms, ok := unlock(); ok {
			before = append(before, ms)
			beforeSpans = append(beforeSpans, span)
		}
		sample()
	}

	codesDone := make(chan struct{})
	var wg sync.WaitGroup
	// Free memory, sampled for the phase.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			sample()
			select {
			case <-codesDone:
				return
			case <-ctx.Done():
				return
			default:
			}
			_ = env.sleep(ctx, sampleEvery)
		}
	}()
	// The unlocks, one after another, while codes are still running.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range p.CodeUnlocks {
			select {
			case <-codesDone:
				return
			default:
			}
			if ctx.Err() != nil {
				return
			}
			span, ms, ok := unlock()
			sample()
			mu.Lock()
			if ok {
				unlocks = append(unlocks, ms)
				opened = append(opened, span)
			} else {
				k.UnlocksSkipped++
			}
			mu.Unlock()
			_ = env.sleep(ctx, 2*time.Second)
		}
	}()

	// The codes, at most one per held vault at a time.
	next := make(chan int)
	go func() {
		defer close(next)
		for i := range p.Codes {
			select {
			case next <- i:
			case <-ctx.Done():
				return
			}
		}
	}()
	var codes sync.WaitGroup
	for range min(p.CodeConcurrency, len(held)) {
		codes.Add(1)
		go func() {
			defer codes.Done()
			for i := range next {
				if ctx.Err() != nil {
					return // the phase is over: no request is counted that was not made
				}
				st, err := held[i%len(held)].p.call(ctx, "code", 0)
				sample()
				mu.Lock()
				k.Requests++
				switch {
				case err != nil && ctx.Err() != nil:
					k.CutShort++
				case err != nil || st == nil:
					k.Failed++
				case st.Code == "done":
					k.Done++
					xs, tags = append(xs, float64(st.XMicros)/1000), append(tags, float64(st.TagMicros)/1000)
					k.CodeVaultPeakRSS = max(k.CodeVaultPeakRSS, st.PeakRSS)
					if len(st.GrantedAtsMs) == 2 {
						derived = append(derived, openSpan{st.GrantedAtsMs[0], st.GrantedAtsMs[0] + st.XMicros/1000},
							openSpan{st.GrantedAtsMs[1], st.GrantedAtsMs[1] + st.TagMicros/1000})
					}
				case st.Code == "busy":
					k.Busy++
				case st.Code == "no_room":
					k.NoRoom++
				default:
					k.Failed++
				}
				if st != nil {
					waits = append(waits, float64(st.WaitMicros)/1000)
					if env.codeGrants == nil {
						granted = append(granted, st.GrantedAtsMs...)
					}
				}
				mu.Unlock()
			}
		}()
	}
	codes.Wait()
	close(codesDone)
	wg.Wait()
	if env.codeGrants != nil {
		// The supervisor's own record: the same clock as the openings'.
		for _, at := range env.codeGrants() {
			if !at.Before(t0) {
				granted = append(granted, at.UnixMilli())
			}
		}
	}
	k.Grants = len(granted)
	// No code permit may be given during any unlock, the comparison's too.
	k.Overlap = overlaps(granted, append(slices.Clone(beforeSpans), opened...))
	k.UnlocksOverlapping = spansOverlapping(opened, derived)
	k.XMs, k.TagMs, k.PermitWaitMs = selftest.MillisOf(xs), selftest.MillisOf(tags), selftest.MillisOf(waits)
	k.UnlockBeforeMs, k.UnlockMs = selftest.MillisOf(before), selftest.MillisOf(unlocks)
	k.Unlocks = len(unlocks)
	k.DurationMs = env.now().Sub(t0).Milliseconds()
	return k
}

// sampleEvery is how often the code phase samples free memory.
const sampleEvery = 200 * time.Millisecond

// spansOverlapping counts the spans of a that overlap any span of b.
func spansOverlapping(a, b []openSpan) int {
	n := 0
	for _, x := range a {
		for _, y := range b {
			if x.from < y.to && y.from < x.to {
				n++
				break
			}
		}
	}
	return n
}

// selftestPermit is the heavy-derivation permit of a self-test enclave,
// made as start() makes it, with the floor the higher of the release's
// reserve and the capacity run's (capFloor, 0 until the run sets it).
func (s *Supervisor) selftestPermit() *heavyPermit {
	avail := s.cfg.MemAvailable
	if avail == nil {
		avail = memAvailable
	}
	return &heavyPermit{avail: avail, floor: func() uint64 { return max(s.cfg.MemoryReserve, s.capFloor.Load()) }, now: s.now}
}

// codesCheck is the code phase's informational check: some requests done,
// and no code permit given while an unlock was opening.
func codesCheck(k *selftest.CodeReport) (bool, string) {
	return k.Done > 0 && k.Overlap == 0,
		fmt.Sprintf("done=%d busy=%d no_room=%d failed=%d granted_during_unlock=%d", k.Done, k.Busy, k.NoRoom, k.Failed, k.Overlap)
}

// openSpan is one marked opening, in Unix milliseconds.
type openSpan struct{ from, to int64 }

// overlaps counts the permits granted strictly inside an opening (the
// unlock-first rule allows none).
func overlaps(granted []int64, opened []openSpan) int {
	n := 0
	for _, g := range granted {
		for _, o := range opened {
			if g > o.from && g < o.to {
				n++
				break
			}
		}
	}
	return n
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
	// The permit runSelftest made (a self-test enclave never runs start())
	// takes the run's floor when it is higher than the release's reserve,
	// and records the code permits it gives.
	var grantsMu sync.Mutex
	var grants []time.Time
	if s.heavy != nil {
		pp := p
		pp.Defaults()
		s.capFloor.Store(capacityFloor(meminfo("MemTotal"), pp.FloorMiB))
		s.heavy.setCodeGranted(func(at time.Time) {
			grantsMu.Lock()
			grants = append(grants, at)
			grantsMu.Unlock()
		})
	}
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
		// A synthetic unlock counts as a vault opening for the code permit,
		// as a real one does (procHost.openingAny).
		opening: func() func() { return h.markOpening("capacity-open-" + strconv.FormatInt(n.Add(1), 10)) },
		codeGrants: func() []time.Time {
			grantsMu.Lock()
			defer grantsMu.Unlock()
			return slices.Clone(grants)
		},
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
	if k := c.Codes; k != nil {
		ok, detail := codesCheck(k)
		r.Add("capacity.codes", ok, false, detail)
	}
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
		return nil, c.why(err)
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

// capExitWait is how long a failed call waits for its process to end, to
// report how it ended.
var capExitWait = 2 * time.Second

// why adds to a call's error how the process ended, when the channel
// closed because it did: its exit code or signal and the channel's own
// error (the report's Skipped and notes; no member data in either).
func (c *capVProc) why(err error) error {
	if !errors.Is(err, hostproto.ErrClosed) {
		return err
	}
	select {
	case <-c.p.exited:
	case <-time.After(capExitWait):
		return fmt.Errorf("%w (vault process still running; channel: %s)", err, errText(c.p.conn.Err()))
	}
	return fmt.Errorf("%w (vault process %s; channel: %s)", err, exitDetail(c.p.exitCode), errText(c.p.conn.Err()))
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
