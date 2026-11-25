package supervisor

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/vaultipc"
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

// A code pairing's permit (0.94.0 §6.7.2): the same single permit, with
// room for 256 MiB (1.2 times) above the floor, never while a vault
// process is opening: unlocks go first.
func TestCodePermitAdmission(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	floor := uint64(768 << 20)
	avail := floor + codeNeed()
	opening := false
	h := &heavyPermit{avail: func() uint64 { return avail }, floor: func() uint64 { return floor }, now: func() time.Time { return now },
		opening: func() bool { return opening }}
	if !h.acquireCode("v1") {
		t.Fatal("refused with room")
	}
	if h.acquireCode("v2") || h.acquire("v2") {
		t.Fatal("a second permit while one is held (one heavy derivation at a time)")
	}
	h.release("v1")
	opening = true
	if h.acquireCode("v1") {
		t.Fatal("given while a vault is opening")
	}
	opening = false
	avail = floor + codeNeed() - 1
	if h.acquireCode("v1") {
		t.Fatal("given below the floor plus the need")
	}
	avail = 0
	if h.acquireCode("v1") {
		t.Fatal("given with unknown memory")
	}
	// The recovery wrap's permit is held: no code permit. (Room for either
	// need: under vettid_testcost the recovery wrap's is the smaller.)
	avail = floor + max(heavyNeed(), codeNeed())
	if !h.acquire("v3") || h.acquireCode("v1") {
		t.Fatal("a code permit beside the recovery wrap's")
	}
	h.release("v3")
	if !h.acquireCode("v1") {
		t.Fatal("refused after release")
	}
	if codeNeed() != 256<<20*6/5 {
		t.Fatalf("code need %d", codeNeed())
	}
	// Without an opening probe (nil): only memory and the holder decide.
	h2 := &heavyPermit{avail: func() uint64 { return floor + codeNeed() }, floor: func() uint64 { return floor }, now: func() time.Time { return now }}
	if !h2.acquireCode("v1") {
		t.Fatal("refused without a probe")
	}
}

// The supervisor answers a vault's acquire_code over its channel.
func TestHeavyCallCodePermit(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	floor := uint64(768 << 20)
	opening := false
	s := &Supervisor{heavy: &heavyPermit{avail: func() uint64 { return floor + codeNeed() }, floor: func() uint64 { return floor },
		now: func() time.Time { return now }, opening: func() bool { return opening }}}
	p := &vproc{vaultID: "v1", h: &procHost{s: s}}
	ans := func(op string) string {
		r := p.heavyCall([][]byte{[]byte(op)})
		if len(r) != 2 || string(r[0]) != hostproto.StatusOK {
			t.Fatalf("%s: %q", op, r)
		}
		return string(r[1])
	}
	opening = true
	if ans(vaultipc.HeavyAcquireCode) != "0" {
		t.Fatal("given while opening")
	}
	opening = false
	if ans(vaultipc.HeavyAcquireCode) != "1" || ans(vaultipc.HeavyAcquireCode) != "0" {
		t.Fatal("not one at a time")
	}
	if ans(vaultipc.HeavyRelease) != "1" || ans(vaultipc.HeavyAcquireCode) != "1" {
		t.Fatal("not given again after release")
	}
}

// openingAny follows the opens in flight.
func TestOpeningAny(t *testing.T) {
	h := &procHost{opening: map[string]int{}}
	if h.openingAny() {
		t.Fatal("none opening")
	}
	h.opening["v1"] = 1
	if !h.openingAny() {
		t.Fatal("one opening")
	}
}

// The opening probe is wired by newProcHost and follows the real opens:
// reserve() makes it true, its end false; meanwhile no code permit is given,
// and the recovery wrap's still is (it does not yield to opens).
func TestCodePermitYieldsToARealOpen(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	floor := uint64(768 << 20)
	s := &Supervisor{heavy: &heavyPermit{avail: func() uint64 { return floor + max(heavyNeed(), codeNeed()) },
		floor: func() uint64 { return floor }, now: func() time.Time { return now }}}
	h := newProcHost(s, ProcConfig{})
	if s.heavy.opening == nil {
		t.Fatal("newProcHost did not wire the opening probe")
	}
	done, ok, err := h.reserve(context.Background(), &enclave.Job{Op: enclave.OpUnlock, VaultID: "aaaa"})
	if !ok || err != nil {
		t.Fatal("reserve")
	}
	if s.heavy.acquireCode("v1") {
		t.Fatal("a code permit while an unlock opens")
	}
	if !s.heavy.acquire("v2") {
		t.Fatal("the recovery wrap's permit refused while a vault opens")
	}
	s.heavy.release("v2")
	done()
	if !s.heavy.acquireCode("v1") {
		t.Fatal("refused once the open ended")
	}
}

// A code permit whose holder never returns it ends at its lease; a holder
// whose process ended returns it at once.
func TestCodePermitLeaseAndExit(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	floor := uint64(768 << 20)
	h := &heavyPermit{avail: func() uint64 { return floor + codeNeed() }, floor: func() uint64 { return floor }, now: func() time.Time { return now }}
	if !h.acquireCode("v1") || h.acquireCode("v2") {
		t.Fatal("setup")
	}
	now = now.Add(heavyLease + time.Second)
	if !h.acquireCode("v2") {
		t.Fatal("a lost code permit never ended")
	}
	s := &Supervisor{heavy: h}
	ph := newProcHost(s, ProcConfig{})
	ph.exited(&vproc{vaultID: "v2", h: ph, stopping: true})
	if !h.acquireCode("v3") {
		t.Fatal("an ended process kept its permit")
	}
}
