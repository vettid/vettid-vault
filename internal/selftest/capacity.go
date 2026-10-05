package selftest

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// CapacityRequest asks the self-test to measure how many vaults the
// enclave holds (docs/SMOKE.md "Capacity measurement", VAULT-RELEASES
// §8.8). The vault processes are synthetic: started exactly like real
// ones, with test keys and random state, no member data. Zero values take
// the defaults below.
type CapacityRequest struct {
	// MaxVaults is the most synthetic vaults held at once (1..MaxCapacityVaults);
	// the run usually stops earlier, at the memory floor.
	MaxVaults int `json:"max_vaults"`
	// StateKiB is each vault's decrypted state (default 1024, at most 65536).
	StateKiB int `json:"state_kib,omitempty"`
	// FloorMiB raises the memory floor: no process is started that could
	// bring the enclave's available memory below it. It can only raise the
	// floor, never lower it below the release's lock threshold (15% of the
	// enclave's memory) or MinFloorMiB.
	FloorMiB int `json:"floor_mib,omitempty"`
	// UnlockConcurrency are the levels of concurrent unlocks timed
	// (default 1, 2, 4; each 1..8, at most 4 levels).
	UnlockConcurrency []int `json:"unlock_concurrency,omitempty"`
	// UnlockSamples is the number of unlocks timed per level (default 8, 1..64).
	UnlockSamples int `json:"unlock_samples,omitempty"`
	// SettleSeconds is how long the run waits, at the floor, for memory to
	// come back (the Go runtime returns the KDF's memory only after a
	// collection, forced every 2 minutes in an idle process), and before
	// the steady-state measurement (default 180, at most 900).
	SettleSeconds int `json:"settle_seconds,omitempty"`
	// IdleSeconds is the window over which idle CPU time is measured
	// (default 60, at most 900).
	IdleSeconds int `json:"idle_seconds,omitempty"`
	// StepEvery records the memory every so many vaults (default 5).
	StepEvery int `json:"step_every,omitempty"`
	// BudgetMinutes bounds the whole measurement (default 90, at most
	// 240): the fill stops ("time_budget") early enough for the settle and
	// idle windows and the teardown to fit.
	BudgetMinutes int `json:"budget_minutes,omitempty"`
}

// Capacity limits.
const (
	MaxCapacityVaults = 1000
	MinFloorMiB       = 256
)

// Defaults fills in the zero values.
func (c *CapacityRequest) Defaults() {
	if c.StateKiB == 0 {
		c.StateKiB = 1024
	}
	if len(c.UnlockConcurrency) == 0 {
		c.UnlockConcurrency = []int{1, 2, 4}
	}
	if c.UnlockSamples == 0 {
		c.UnlockSamples = 8
	}
	if c.SettleSeconds == 0 {
		c.SettleSeconds = 180
	}
	if c.IdleSeconds == 0 {
		c.IdleSeconds = 60
	}
	if c.StepEvery == 0 {
		c.StepEvery = 5
	}
	if c.BudgetMinutes == 0 {
		c.BudgetMinutes = 90
	}
}

func (c *CapacityRequest) valid() bool {
	if c.MaxVaults < 1 || c.MaxVaults > MaxCapacityVaults || c.StateKiB < 0 || c.StateKiB > 64<<10 || c.FloorMiB < 0 || c.FloorMiB > 1<<20 ||
		len(c.UnlockConcurrency) > 4 || c.UnlockSamples < 0 || c.UnlockSamples > 64 || c.SettleSeconds < 0 || c.SettleSeconds > 900 ||
		c.IdleSeconds < 0 || c.IdleSeconds > 900 || c.StepEvery < 0 || c.StepEvery > MaxCapacityVaults ||
		c.BudgetMinutes < 0 || c.BudgetMinutes > 240 {
		return false
	}
	for _, n := range c.UnlockConcurrency {
		if n < 1 || n > 8 {
			return false
		}
	}
	return true
}

// CapacityReport is the capacity section of the report: sizes in bytes,
// durations in milliseconds. It holds no secret.
type CapacityReport struct {
	Params CapacityRequest `json:"params"`
	// MemTotal and FloorBytes: the enclave's memory and the floor used.
	MemTotal   uint64 `json:"mem_total_bytes"`
	FloorBytes uint64 `json:"floor_bytes"`
	// Baseline before any synthetic vault.
	BaselineAvailable     uint64 `json:"baseline_available_bytes"`
	BaselineSupervisorRSS uint64 `json:"baseline_supervisor_rss_bytes"`

	Unlock []UnlockLevel `json:"unlock"`

	// Steps is the available memory and supervisor RSS as vaults were
	// added (every StepEvery vaults, the last one, and after waits).
	Steps []CapacityStep `json:"steps"`
	// Held is the most synthetic vaults held at once; StopReason why the
	// fill stopped: max_vaults, memory_floor, time_budget (all three
	// complete measurements), spawn_failed, timeout or error.
	Held       int    `json:"held"`
	StopReason string `json:"stop_reason"`
	// SettleWaits is how often the fill waited at the floor for memory to
	// come back.
	SettleWaits int `json:"settle_waits"`

	// Steady state, after the settle and idle windows: per vault process
	// (RSS counts the shared binary pages in every process; PSS shares
	// them out; private is what the process alone holds).
	VaultRSS     Stat   `json:"vault_rss_bytes"`
	VaultPSS     Stat   `json:"vault_pss_bytes"`
	VaultPrivate Stat   `json:"vault_private_bytes"`
	VaultPeakRSS uint64 `json:"vault_peak_rss_bytes"`
	// RSS right after the unlock (KDF memory not yet returned).
	VaultRSSAfterUnlock Stat `json:"vault_rss_after_unlock_bytes"`
	// SteadyAvailable is the enclave's available memory with Held vaults
	// at steady state; MarginalPerVault = (BaselineAvailable −
	// SteadyAvailable) / Held.
	SteadyAvailable  uint64 `json:"steady_available_bytes"`
	MarginalPerVault uint64 `json:"marginal_bytes_per_vault"`
	SupervisorRSS    uint64 `json:"supervisor_rss_bytes"`
	// ProjectedMax is (BaselineAvailable − floor − one unlock's peak) /
	// MarginalPerVault: the vaults the enclave holds at steady state
	// while keeping room for one unlock above the floor.
	ProjectedMax int `json:"projected_max_vaults"`

	// Idle CPU over IdleSeconds (0 if not measured).
	IdleCPUMsPerVaultMinute      float64 `json:"idle_cpu_ms_per_vault_minute"`
	SupervisorCPUMsPerMinuteIdle float64 `json:"supervisor_cpu_ms_per_minute_idle"`

	// TornDown: every synthetic vault process exited; AvailableAfter is
	// the available memory after the teardown.
	TornDown       bool     `json:"torn_down"`
	AvailableAfter uint64   `json:"available_after_bytes"`
	DurationMs     int64    `json:"duration_ms"`
	Notes          []string `json:"notes,omitempty"`
}

// UnlockLevel is the unlock latency at one concurrency: process start,
// hardening and one Argon2id at the release's parameters (no KMS or S3
// round trip), as the supervisor sees it, and the KDF alone.
type UnlockLevel struct {
	Concurrency int     `json:"concurrency"`
	Samples     int     `json:"samples"`
	P50Ms       float64 `json:"p50_ms"`
	P95Ms       float64 `json:"p95_ms"`
	MaxMs       float64 `json:"max_ms"`
	KDFP50Ms    float64 `json:"kdf_p50_ms"`
	KDFP95Ms    float64 `json:"kdf_p95_ms"`
	Skipped     string  `json:"skipped,omitempty"`
}

// CapacityStep is one point of the fill.
type CapacityStep struct {
	Vaults        int    `json:"vaults"`
	Available     uint64 `json:"available_bytes"`
	SupervisorRSS uint64 `json:"supervisor_rss_bytes"`
}

// Stat summarizes per-process values.
type Stat struct {
	N    int    `json:"n"`
	Min  uint64 `json:"min"`
	Mean uint64 `json:"mean"`
	Max  uint64 `json:"max"`
}

// Summarize computes a Stat.
func Summarize(v []uint64) Stat {
	if len(v) == 0 {
		return Stat{}
	}
	s := Stat{N: len(v), Min: v[0], Max: v[0]}
	var sum float64
	for _, x := range v {
		s.Min, s.Max = min(s.Min, x), max(s.Max, x)
		sum += float64(x)
	}
	s.Mean = uint64(sum / float64(len(v)))
	return s
}

// Percentile is the nearest-rank percentile p (0..100) of v.
func Percentile(v []float64, p float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	r := int(math.Ceil(p / 100 * float64(len(s))))
	return s[min(max(r, 1), len(s))-1]
}

// CapacityStats is what a synthetic vault process reports about itself
// (sizes in bytes, times in microseconds).
type CapacityStats struct {
	KDFMicros int64  `json:"kdf_us,omitempty"`
	RSS       uint64 `json:"rss"`
	PeakRSS   uint64 `json:"peak_rss"`
	PSS       uint64 `json:"pss"`
	Private   uint64 `json:"private"`
	CPUMicros int64  `json:"cpu_us"`
}

const mib = 1 << 20

// Lines is the capacity section as human-readable lines.
func (c *CapacityReport) Lines() []string {
	if c == nil {
		return nil
	}
	m := func(b uint64) string { return fmt.Sprintf("%.1fMiB", float64(b)/mib) }
	out := []string{
		fmt.Sprintf("CAPACITY enclave memory %s, floor %s, baseline available %s, supervisor %s",
			m(c.MemTotal), m(c.FloorBytes), m(c.BaselineAvailable), m(c.BaselineSupervisorRSS)),
	}
	for _, u := range c.Unlock {
		if u.Skipped != "" {
			out = append(out, fmt.Sprintf("CAPACITY unlock x%d skipped: %s", u.Concurrency, u.Skipped))
			continue
		}
		out = append(out, fmt.Sprintf("CAPACITY unlock x%d n=%d p50=%.0fms p95=%.0fms max=%.0fms (kdf p50=%.0fms p95=%.0fms)",
			u.Concurrency, u.Samples, u.P50Ms, u.P95Ms, u.MaxMs, u.KDFP50Ms, u.KDFP95Ms))
	}
	var steps []string
	every := max(1, (len(c.Steps)+23)/24) // at most about 24 points
	for i, s := range c.Steps {
		if i%every == 0 || i == len(c.Steps)-1 {
			steps = append(steps, fmt.Sprintf("%d:%s", s.Vaults, m(s.Available)))
		}
	}
	out = append(out,
		fmt.Sprintf("CAPACITY held %d vaults (stop: %s, %d settle waits); available by vaults %s", c.Held, c.StopReason, c.SettleWaits, strings.Join(steps, " ")),
		fmt.Sprintf("CAPACITY per vault at steady state: rss mean %s max %s, pss mean %s, private mean %s; after unlock rss mean %s; peak %s",
			m(c.VaultRSS.Mean), m(c.VaultRSS.Max), m(c.VaultPSS.Mean), m(c.VaultPrivate.Mean), m(c.VaultRSSAfterUnlock.Mean), m(c.VaultPeakRSS)),
		fmt.Sprintf("CAPACITY marginal %s per vault, steady available %s, supervisor %s; projected max %d vaults",
			m(c.MarginalPerVault), m(c.SteadyAvailable), m(c.SupervisorRSS), c.ProjectedMax),
		fmt.Sprintf("CAPACITY idle cpu %.1fms per vault per minute, supervisor %.1fms per minute", c.IdleCPUMsPerVaultMinute, c.SupervisorCPUMsPerMinuteIdle),
		fmt.Sprintf("CAPACITY torn down %v, available after %s, %ds", c.TornDown, m(c.AvailableAfter), c.DurationMs/1000),
	)
	for _, n := range c.Notes {
		out = append(out, "CAPACITY note: "+n)
	}
	return out
}
