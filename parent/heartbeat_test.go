package parent_test

import (
	"context"
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
	defer parent.SetRegistryWriteTimeoutForTest(150 * time.Millisecond)()
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
