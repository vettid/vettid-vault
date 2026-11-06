package client

import (
	"context"
	"net/http"
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

// confirmsQueued counts the hs.confirm entries in the device's outbox.
func confirmsQueued(d *Device) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, o := range d.st.Outbox {
		if o.Kind == "hs.confirm" {
			n++
		}
	}
	return n
}

// reconfirmPaired: a device on a rekeyed epoch the vault never confirmed,
// its first hs.confirm delivered, on a test clock; with Persist when
// persist is set.
func reconfirmPaired(t *testing.T, persist bool) (*fakeRelay, *fakeVault, *Device, *time.Time) {
	t.Helper()
	ctx := context.Background()
	r, v, d := pair(t)
	clk := time.Now()
	d.mu.Lock()
	d.cfg.Now = func() time.Time { return clk }
	if persist {
		d.cfg.Persist = keep(new([]byte), r)
	}
	d.mu.Unlock()
	v.startRekey()
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	v.process()
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	v.process()
	return r, v, d, &clk
}

func vaultConfirms(v *fakeVault) int {
	v.process()
	n := 0
	for _, ty := range v.receivedTypes {
		if ty == handshake.TypeConfirm {
			n++
		}
	}
	return n
}

// Under Persist the hs.confirm sent again is queued in the outbox: a
// failed deposit leaves it queued and it is retried; while it waits no
// second copy is queued, even 12 days on.
func TestDeviceReconfirmQueuedPersist(t *testing.T) {
	ctx := context.Background()
	r, v, d, clk := reconfirmPaired(t, true)
	if n := vaultConfirms(v); n != 1 {
		t.Fatalf("setup: %d hs.confirm", n)
	}
	*clk = clk.Add(confirmResend + time.Hour)
	at := *clk
	r.mu.Lock()
	r.failDeposit, r.depositStatus = 1000, http.StatusServiceUnavailable
	r.mu.Unlock()
	_ = d.Poll(ctx)
	if confirmsQueued(d) != 1 || !d.st.Vault.ConfirmAt.Equal(at) {
		t.Fatalf("not queued once at the tick: %d queued, ConfirmAt %v", confirmsQueued(d), d.st.Vault.ConfirmAt)
	}
	*clk = clk.Add(confirmResend + time.Hour) // still failing, 12 days on
	_ = d.Poll(ctx)
	if n := confirmsQueued(d); n != 1 {
		t.Fatalf("%d hs.confirm queued: a second copy beside the waiting one", n)
	}
	if !d.st.Vault.ConfirmAt.Equal(at) {
		t.Fatal("ConfirmAt moved while the queued one waits")
	}
	r.mu.Lock()
	r.failDeposit = 0
	r.mu.Unlock()
	*clk = clk.Add(time.Hour)
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if n := vaultConfirms(v); n != 2 || confirmsQueued(d) != 0 {
		t.Fatalf("the queued hs.confirm was not retried: %d received, %d queued", n, confirmsQueued(d))
	}
}

// Without Persist a failed deposit does not count: ConfirmAt stays, and
// the next poll sends it.
func TestDeviceReconfirmFailedNotCounted(t *testing.T) {
	ctx := context.Background()
	r, v, d, clk := reconfirmPaired(t, false)
	before := d.st.Vault.ConfirmAt
	*clk = clk.Add(confirmResend + time.Hour)
	r.mu.Lock()
	r.failDeposit, r.depositStatus = 1, http.StatusBadRequest // not retried by the relay client
	r.mu.Unlock()
	_ = d.Poll(ctx)
	if !d.st.Vault.ConfirmAt.Equal(before) || vaultConfirms(v) != 1 {
		t.Fatal("a failed deposit advanced ConfirmAt, or was delivered")
	}
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if n := vaultConfirms(v); n != 2 || d.st.Vault.ConfirmAt.Equal(before) {
		t.Fatalf("not sent at the next poll: %d", n)
	}
}
