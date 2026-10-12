package parent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/parenttest"
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

// The enclave reports the vaults that ended while the parent was
// unreachable when it reads the parent's next Ping (Stopped). An unlock
// of one of them may be under way by then: the parent has taken the lease
// for it and still has the vault in its running set from the run before.
// The report must not release the lease of the run that is starting, or
// the next renewal finds no lease and the vault just unlocked is locked
// again.
func TestStoppedDuringUnlockKeepsLease(t *testing.T) {
	h := newHarness(t, nil)
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked"})
	env := bytes.Repeat([]byte{7}, 5252)
	var e *fakeEnclave
	e = h.connect("boot-1", func(msg []byte) []byte {
		var m struct {
			RequestID string `json:"request_id"`
		}
		_ = json.Unmarshal(msg, &m)
		if m.RequestID == "01JBBBBBBBBBBBBBBBBBBBBBBB" {
			// The report of the earlier run, then this run's own event.
			_ = e.conn.Notify(hostproto.KindStopped, hostproto.Strings(vaultID, hostproto.StopLocked)...)
		}
		e.lifecycle("unlocked")
		return response(m.RequestID, "done", env)
	})
	e.descriptor()
	waitFor(t, "ready", func() bool { return h.p.Health().Release == pcr })
	send := func(rid string) {
		t.Helper()
		h.tables.PutSlot(rid, "i-test")
		h.queues.Send(h.queue, queueMsg("unlock", rid))
		waitFor(t, "slot "+rid, func() bool { s, _ := h.tables.Slot(rid); return s.Status != "queued" })
	}
	send("01JAAAAAAAAAAAAAAAAAAAAAAA") // the earlier run: the parent counts the vault as running
	send("01JBBBBBBBBBBBBBBBBBBBBBBB") // the unlock under way when the report comes
	// The lease is still this instance's and goes on being renewed.
	for i := 0; i < 3; i++ {
		r0, _ := h.tables.Vault(vaultID)
		if r0.LeaseInstance != "i-test" {
			t.Fatalf("the lease was released: %+v", r0)
		}
		waitFor(t, "renewal", func() bool {
			r, _ := h.tables.Vault(vaultID)
			return r.LeaseExpires > r0.LeaseExpires || r.LeaseInstance != "i-test"
		})
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.lost) != 0 {
		t.Fatalf("lease lost told to the enclave: %v", e.lost)
	}
}

// flakyLeases fails the first renewals at once and records when each
// was asked for.
type flakyLeases struct {
	parent.Tables
	mu    sync.Mutex
	fail  int
	calls []time.Time
}

func (f *flakyLeases) RenewLease(ctx context.Context, id, me string, exp int64) error {
	f.mu.Lock()
	f.calls = append(f.calls, time.Now())
	fail := len(f.calls) <= f.fail
	f.mu.Unlock()
	if fail {
		return errors.New("table down")
	}
	return f.Tables.RenewLease(ctx, id, me, exp)
}

// After a renewal that failed the next is tried soon (5 s in a release,
// 50 ms here), not a whole renewal interval later (60 s; 1 s here): the
// lease-lost rule is looked at only when a renewal has failed, so without
// the retry it would be looked at too late. Once a renewal succeeds the
// interval is the usual one again, and nothing was lost.
func TestRenewalRetriesSoon(t *testing.T) {
	t.Cleanup(parent.SetLeaseTimesForTest(time.Second, 50*time.Millisecond, time.Second))
	tables := &flakyLeases{fail: 2}
	h := newHarness(t, func(c *parent.Config) {
		tables.Tables = c.Tables
		c.Tables = tables
		c.LeaseRenew = time.Second
		c.LeaseLength = time.Minute
	})
	h.tables.PutVault(parenttest.VaultRow{VaultID: vaultID, UserGUID: "u1", State: "locked"})
	h.tables.SetLease(vaultID, "i-test", time.Now().Add(time.Minute).Unix())
	e := h.connect("boot-1", nil)
	e.descriptor()
	e.lifecycle("unlocked")
	calls := func() []time.Time {
		tables.mu.Lock()
		defer tables.mu.Unlock()
		return append([]time.Time(nil), tables.calls...)
	}
	waitFor(t, "four renewals", func() bool { return len(calls()) >= 4 })
	c := calls()
	if d := c[1].Sub(c[0]); d > 500*time.Millisecond {
		t.Fatalf("the renewal after a failed one came after %v", d)
	}
	if d := c[2].Sub(c[1]); d > 500*time.Millisecond {
		t.Fatalf("the renewal after a second failed one came after %v", d)
	}
	if d := c[3].Sub(c[2]); d < 700*time.Millisecond {
		t.Fatalf("the renewal after one that succeeded came after %v: not the interval", d)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.lost) != 0 {
		t.Fatalf("lease lost: %v", e.lost)
	}
}
