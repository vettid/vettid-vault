package parent_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/parent"
)

// hungTables is an instances table that does not answer: PutInstance
// returns only when its context ends.
type hungTables struct {
	parent.Tables
	puts atomic.Int64
}

func (h *hungTables) PutInstance(ctx context.Context, _ parent.InstanceRow) error {
	h.puts.Add(1)
	<-ctx.Done()
	return ctx.Err()
}

// The enclave locks every vault after 120 s without a Ping (§12.3), and
// the parent pings before it writes the registry row, on one ticker. A
// table that does not answer must not stop the pings: the write is given
// up after its time (10 s in a release; shortened here), the next tick
// pings again, and the parent says that its heartbeat is late.
func TestPingsGoOnWhenTheRegistryHangs(t *testing.T) {
	t.Cleanup(parent.SetRegistryWriteTimeoutForTest(150 * time.Millisecond)) // restored after the parent has stopped
	tables := &hungTables{}
	h := newHarness(t, func(c *parent.Config) {
		tables.Tables = c.Tables
		c.Tables = tables
		c.Heartbeat = 50 * time.Millisecond
	})
	c, err := net.Dial("tcp", h.ctl)
	if err != nil {
		t.Fatal(err)
	}
	var pings atomic.Int64
	conn := hostproto.NewConn(c, func(_ context.Context, f *hostproto.Frame) [][]byte {
		if f.Kind == hostproto.KindPing {
			pings.Add(1)
			return hostproto.Strings(hostproto.StatusOK, "1")
		}
		return nil
	}, nil)
	t.Cleanup(conn.Close)
	if r, err := conn.Call(context.Background(), hostproto.KindHello, []byte(pcr), []byte("boot-1")); err != nil || string(r[0]) != hostproto.StatusOK {
		t.Fatalf("hello: %v %q", err, r)
	}
	if err := conn.Notify(hostproto.KindDescriptor, []byte(pcr), []byte(`{"v":1}`), []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	// Each ping is followed by a write that hangs for 150 ms: a ping about
	// every 200 ms. With a write that never returned there would be two
	// (the descriptor's and the first tick's) and no more.
	waitFor(t, "five pings past a registry that hangs", func() bool { return pings.Load() >= 5 })
	if tables.puts.Load() < 4 {
		t.Fatalf("%d pings, %d registry writes: the ping must stay tied to the write", pings.Load(), tables.puts.Load())
	}
	if _, ok := h.tables.Instance("i-test"); ok {
		t.Fatal("a registry row was written")
	}
	waitFor(t, "the late heartbeat's warning", func() bool {
		h.logMu.Lock()
		defer h.logMu.Unlock()
		return strings.Contains(h.logs.String(), "heartbeat took longer than its interval") && strings.Contains(h.logs.String(), "heartbeat failed")
	})
}

// hungLeases is a lease table that does not answer: RenewLease returns
// only when its context ends.
type hungLeases struct {
	hungTables
	renews atomic.Int64
}

func (h *hungLeases) RenewLease(ctx context.Context, _, _ string, _ int64) error {
	h.renews.Add(1)
	<-ctx.Done()
	return ctx.Err()
}

// The tables do not answer while vaults run. The pings go on (above), so
// the enclave's own rule does not lock them: the parent must. A renewal
// is given up in time, the lease is lost before it ends, and the enclave
// is told for every vault, with one call to the table in a pass however
// many vaults run. (Before: the first renewal waited for ever, nobody was
// told, and the leases ran out under running vaults.) Lease 3 s, lost
// 1 s before its end; a renewal waits 400 ms at most.
func TestLeaseLostWhenTheTableHangs(t *testing.T) {
	const vaults = 40
	t.Cleanup(parent.SetRegistryWriteTimeoutForTest(100 * time.Millisecond)) // restored after the parent has stopped
	t.Cleanup(parent.SetLeaseTimesForTest(400*time.Millisecond, 50*time.Millisecond, time.Second))
	tables := &hungLeases{}
	h := newHarness(t, func(c *parent.Config) {
		tables.Tables = c.Tables
		c.Tables = tables
		c.Heartbeat = 50 * time.Millisecond
		c.LeaseRenew = 200 * time.Millisecond
		c.LeaseLength = 3 * time.Second
	})
	c, err := net.Dial("tcp", h.ctl)
	if err != nil {
		t.Fatal(err)
	}
	var pings, lost atomic.Int64
	var first, last atomic.Int64 // since the vaults' unlock, ns
	var t0 time.Time
	conn := hostproto.NewConn(c, func(_ context.Context, f *hostproto.Frame) [][]byte {
		switch f.Kind {
		case hostproto.KindPing:
			pings.Add(1)
			return hostproto.Strings(hostproto.StatusOK, "1")
		case hostproto.KindLeaseLost:
			d := int64(time.Since(t0))
			if lost.Add(1) == 1 {
				first.Store(d)
			}
			last.Store(d)
			return hostproto.Strings(hostproto.StatusOK)
		}
		return nil
	}, nil)
	t.Cleanup(conn.Close)
	if r, err := conn.Call(context.Background(), hostproto.KindHello, []byte(pcr), []byte("boot-1")); err != nil || string(r[0]) != hostproto.StatusOK {
		t.Fatalf("hello: %v %q", err, r)
	}
	t0 = time.Now()
	_ = conn.Notify(hostproto.KindDescriptor, []byte(pcr), []byte(`{"v":1}`), []byte{1, 2, 3})
	for i := 0; i < vaults; i++ {
		_ = conn.Notify(hostproto.KindLifecycle, hostproto.Strings("unlocked", fmt.Sprintf("vault-%02d", i), pcr, pcr, "1")...)
	}
	waitFor(t, "lease lost for every vault", func() bool { return lost.Load() == vaults })
	f, l := time.Duration(first.Load()), time.Duration(last.Load())
	t.Logf("%d vaults: lease lost told from %v to %v after the unlock (leases end at 3 s); %d renewal calls, %d pings",
		vaults, f.Round(10*time.Millisecond), l.Round(10*time.Millisecond), tables.renews.Load(), pings.Load())
	if f < 1900*time.Millisecond {
		t.Fatalf("the first lease was lost after %v: before its margin", f)
	}
	if l >= 3*time.Second {
		t.Fatalf("the last vault was told after %v: its lease had ended", l)
	}
	// One call a pass: far fewer than a call a vault.
	if n := tables.renews.Load(); n >= vaults {
		t.Fatalf("%d renewal calls for %d vaults", n, vaults)
	}
	if pings.Load() < 5 {
		t.Fatalf("%d pings", pings.Load())
	}
}
