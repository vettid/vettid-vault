//go:build linux

package vsock

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

// The loopback test needs the vsock_loopback module (VMADDR_CID_LOCAL); it
// is skipped where AF_VSOCK is unavailable.
func TestLoopback(t *testing.T) {
	l, err := Listen(0x5a5a)
	if err != nil {
		t.Skipf("vsock unavailable: %v", err)
	}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()
	c, err := Dial(ctx, 1 /* VMADDR_CID_LOCAL */, 0x5a5a)
	if err != nil {
		t.Skipf("vsock loopback unavailable: %v", err)
	}
	defer c.Close()
	msg := bytes.Repeat([]byte("vettid"), 20000)
	go func() { _, _ = c.Write(msg) }()
	got := make([]byte, len(msg))
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echo: %v", err)
	}
}
