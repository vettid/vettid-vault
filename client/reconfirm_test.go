package client

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
)

// §6.3.1 "Responder" (vettid.org #554 at 9839e49), toward the vault: while
// the device's current epoch (a rekey it activated as responder) is not
// its confirmed epoch, it sends hs.confirm again 12 days after the last
// one; it stops once the vault sends under the epoch.
func TestDeviceReconfirmEvery12Days(t *testing.T) {
	ctx := context.Background()
	_, v, d := pair(t)
	clk := time.Now()
	d.mu.Lock()
	d.cfg.Now = func() time.Time { return clk }
	d.mu.Unlock()
	confirms := func() int {
		v.process()
		n := 0
		for _, ty := range v.receivedTypes {
			if ty == handshake.TypeConfirm {
				n++
			}
		}
		return n
	}
	v.startRekey()
	if err := d.Poll(ctx); err != nil { // hs.resp
		t.Fatal(err)
	}
	v.process()                         // hs.fin
	if err := d.Poll(ctx); err != nil { // activates, hs.confirm
		t.Fatal(err)
	}
	if n := confirms(); n != 1 {
		t.Fatalf("setup: %d hs.confirm", n)
	}
	clk = clk.Add(confirmResend - time.Hour)
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if n := confirms(); n != 1 {
		t.Fatalf("%d hs.confirm before 12 days", n)
	}
	clk = clk.Add(2 * time.Hour)
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if n := confirms(); n != 2 {
		t.Fatalf("%d hs.confirm 12 days after the last", n)
	}
	// The vault sends under the epoch: confirmed; no more.
	v.send("test.ping", []byte(`{}`))
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	clk = clk.Add(2 * confirmResend)
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if n := confirms(); n != 2 {
		t.Fatalf("%d hs.confirm after the epoch was confirmed", n)
	}
}
