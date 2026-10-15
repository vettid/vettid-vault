package vaultproc

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/selftest"
	"github.com/vettid/vettid-vault/internal/vaultipc"
)

// queuedConn is a channel whose peer wrote a request before the vault
// process started reading: the reader finds the frame at once, as when the
// supervisor's first request is already in the socket while the vault
// process is still setting up (a busy single-vCPU enclave).
type queuedConn struct {
	net.Conn
	r io.Reader
}

func (c *queuedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// The handler must never see the connection before it is set: a request
// queued before serveSelftest starts is answered (under -race, the old
// code is reported as a data race; on hardware it was a nil dereference,
// exit 2, "hostproto: connection closed" in the capacity measurement).
func TestSelftestRequestQueuedBeforeStart(t *testing.T) {
	for i := 0; i < 50; i++ {
		a, b := net.Pipe()
		req, err := (&hostproto.Frame{Kind: vaultipc.KindSelftestCapacity, ID: 1, Fields: hostproto.Strings("stats", "0")}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		vc := &queuedConn{Conn: b, r: io.MultiReader(bytes.NewReader(req), b)}
		done := make(chan int, 1)
		go func() { done <- serveSelftest(vc, nil, preFilter{}) }()
		a.SetDeadline(time.Now().Add(5 * time.Second))
		f, err := hostproto.ReadFrame(a)
		if err != nil || f.Kind != hostproto.KindReply || f.ID != 1 || len(f.Fields) != 2 || string(f.Fields[0]) != hostproto.StatusOK {
			t.Fatalf("round %d: reply %+v %v", i, f, err)
		}
		var st selftest.CapacityStats
		if json.Unmarshal(f.Fields[1], &st) != nil {
			t.Fatalf("round %d: stats %q", i, f.Fields[1])
		}
		a.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("vault process did not end with its channel")
		}
	}
}
