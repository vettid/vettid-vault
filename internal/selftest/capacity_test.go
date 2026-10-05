package selftest

import (
	"strings"
	"testing"
)

func req(capacity string) []byte {
	return []byte(`{"run_id":"run-1","key_arn":"arn","account":"111122223333","region":"us-east-1"` + capacity + `}`)
}

func TestCapacityRequest(t *testing.T) {
	r, err := ParseRequest(req(""))
	if err != nil || r.Capacity != nil {
		t.Fatalf("no capacity: %v %+v", err, r)
	}
	r, err = ParseRequest(req(`,"capacity":{"max_vaults":3}`))
	if err != nil || r.Capacity == nil {
		t.Fatalf("capacity: %v", err)
	}
	c := r.Capacity
	if c.StateKiB != 1024 || len(c.UnlockConcurrency) != 3 || c.UnlockSamples != 8 || c.SettleSeconds != 180 || c.IdleSeconds != 60 || c.StepEvery != 5 {
		t.Fatalf("defaults %+v", c)
	}
	for _, bad := range []string{
		`{"max_vaults":0}`, `{"max_vaults":1001}`, `{"max_vaults":-1}`,
		`{"max_vaults":2,"state_kib":65537}`, `{"max_vaults":2,"floor_mib":-1}`,
		`{"max_vaults":2,"unlock_concurrency":[0]}`, `{"max_vaults":2,"unlock_concurrency":[9]}`,
		`{"max_vaults":2,"unlock_concurrency":[1,1,1,1,1]}`, `{"max_vaults":2,"unlock_samples":65}`,
		`{"max_vaults":2,"settle_seconds":901}`, `{"max_vaults":2,"idle_seconds":-5}`, `"x"`,
	} {
		if _, err := ParseRequest(req(`,"capacity":` + bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestPercentileSummarize(t *testing.T) {
	v := []float64{5, 1, 4, 2, 3, 6, 7, 8, 9, 10}
	if Percentile(v, 50) != 5 || Percentile(v, 95) != 10 || Percentile(v, 100) != 10 || Percentile(v, 0) != 1 || Percentile(nil, 50) != 0 {
		t.Fatalf("percentiles %v %v", Percentile(v, 50), Percentile(v, 95))
	}
	if v[0] != 5 {
		t.Fatal("input sorted in place")
	}
	s := Summarize([]uint64{3, 1, 2})
	if s.N != 3 || s.Min != 1 || s.Max != 3 || s.Mean != 2 {
		t.Fatalf("%+v", s)
	}
	if (Summarize(nil) != Stat{}) {
		t.Fatal("empty")
	}
}

func TestCapacityLines(t *testing.T) {
	var none *CapacityReport
	if none.Lines() != nil {
		t.Fatal("nil report")
	}
	c := &CapacityReport{Held: 7, StopReason: "memory_floor", ProjectedMax: 61, Unlock: []UnlockLevel{{Concurrency: 1, Samples: 8, P50Ms: 310},
		{Concurrency: 4, Skipped: "memory floor"}}, Steps: []CapacityStep{{Vaults: 0, Available: 4 << 30}}, Notes: []string{"n"}}
	out := strings.Join(c.Lines(), "\n")
	for _, want := range []string{"held 7 vaults (stop: memory_floor", "projected max 61", "unlock x1 n=8 p50=310ms", "unlock x4 skipped", "0:4096.0MiB", "note: n"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	for _, l := range c.Lines() {
		if !strings.HasPrefix(l, "CAPACITY ") {
			t.Errorf("line %q", l)
		}
	}
}
