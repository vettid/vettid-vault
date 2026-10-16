package supervisor

import (
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/recovery"
)

// The heavy-derivation permit (VAULT-MESSAGING 0.33.0 §11.14.3): one at a
// time, only with room above the memory-pressure floor, never reserved.
func TestHeavyPermitAdmission(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	floor := uint64(768 << 20)
	avail := floor + heavyNeed()
	h := &heavyPermit{avail: func() uint64 { return avail }, floor: func() uint64 { return floor }, now: func() time.Time { return now }}
	if !h.free() || !h.acquire("v1") {
		t.Fatal("refused with room")
	}
	if h.free() || h.acquire("v2") {
		t.Fatal("two permits at once")
	}
	h.release("v2") // not the holder: nothing
	if h.acquire("v2") {
		t.Fatal("released by another vault")
	}
	h.release("v1")
	avail = floor + heavyNeed() - 1
	if h.free() || h.acquire("v2") {
		t.Fatal("given below the floor plus the need")
	}
	avail = 0 // unknown memory: no permit
	if h.acquire("v2") {
		t.Fatal("given with unknown memory")
	}
	avail = floor + heavyNeed()
	if !h.acquire("v2") {
		t.Fatal("refused after release")
	}
	now = now.Add(heavyLease + time.Second) // the holder died
	if !h.acquire("v3") {
		t.Fatal("a lost permit never ended")
	}
	if !recovery.TestCost && heavyNeed() < 1200<<20 {
		t.Fatalf("release need %d below 1.2 GiB", heavyNeed())
	}
}

func TestCounterPrefixPinned(t *testing.T) {
	p := &vproc{}
	a := "recovery/v1/486f02bad2b24e6b020d1211ab3bb070/"
	b := "recovery/v1/0000000000000000000000000000000a/"
	for _, bad := range []string{"", "recovery/v1/", "state/x", "recovery/v1/486f02bad2b24e6b020d1211ab3bb07/x", "recovery/v1/486F02BAD2B24E6B020D1211AB3BB070/x"} {
		if p.mayCounter(bad) {
			t.Fatalf("admitted %q", bad)
		}
	}
	if !p.mayCounter(a+"present-x") || !p.mayCounter(a) {
		t.Fatal("own prefix refused")
	}
	if p.mayCounter(b + "present-x") {
		t.Fatal("a second vault's prefix admitted")
	}
}
