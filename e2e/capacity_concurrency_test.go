//go:build devenclave && e2e && linux

package e2e

import (
	"os"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/vettid/vettid-vault/internal/selftest"
)

// Concurrent unlocks in the capacity measurement on one CPU, as in a
// 1-vCPU enclave: every vault process must answer its first request, also
// when that request is already waiting while the process is still setting
// up its channel. Before the fix, the hardware smoke run of 2026-10-14 lost
// processes here with "hostproto: connection closed" (the vault process's
// handler ran before its connection was set: nil dereference, exit 2).
// With several CPUs the window rarely opens, so the test pins itself, and
// with it the vault processes it starts, to one CPU while it runs.
func TestSelftestCapacityConcurrentUnlocks(t *testing.T) {
	pinToOneCPU(t)
	_, rep := runSelftestE2E(t, &selftest.CapacityRequest{MaxVaults: 2, StateKiB: 256, UnlockConcurrency: []int{1, 2, 4, 8}, UnlockSamples: 16,
		SettleSeconds: 1, IdleSeconds: 2, StepEvery: 1})
	c := rep.Capacity
	if c == nil {
		t.Fatal("no capacity section")
	}
	for _, l := range c.Lines() {
		t.Log(l)
	}
	for _, u := range c.Unlock {
		if u.Skipped != "" || u.Samples != 16 {
			t.Errorf("unlock x%d: %d samples, skipped %q", u.Concurrency, u.Samples, u.Skipped)
		}
	}
}

// pinToOneCPU restricts every thread of the test process to one CPU it
// may run on (threads and processes started later inherit it) and
// restores each thread's mask at the end of the test.
func pinToOneCPU(t *testing.T) {
	t.Helper()
	var orig unix.CPUSet
	if err := unix.SchedGetaffinity(0, &orig); err != nil {
		t.Skipf("no CPU affinity: %v", err)
	}
	var one unix.CPUSet
	for i := 0; i < 1024; i++ {
		if orig.IsSet(i) {
			one.Set(i)
			break
		}
	}
	setAll := func(s *unix.CPUSet) {
		ents, err := os.ReadDir("/proc/self/task")
		if err != nil {
			t.Fatalf("threads: %v", err)
		}
		for _, e := range ents {
			if tid, err := strconv.Atoi(e.Name()); err == nil {
				_ = unix.SchedSetaffinity(tid, s) // a thread that ended meanwhile is gone
			}
		}
	}
	setAll(&one)
	t.Cleanup(func() { setAll(&orig) })
}
