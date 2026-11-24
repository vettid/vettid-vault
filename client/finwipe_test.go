package client

import (
	"context"
	"testing"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// A rekey's hs.fin that finishes the handshake is wiped once its epoch is
// established: only the epoch is kept.
func TestFinishedRekeyWipesItsFin(t *testing.T) {
	ctx := context.Background()
	_, v, d := pair(t)
	v.startRekey()
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	var drops []*envelope.Inner
	testDropHook = func(in *envelope.Inner) { drops = append(drops, in) }
	defer func() { testDropHook = nil }()
	v.process() // the vault answers with hs.fin
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	fins := 0
	for _, in := range drops {
		if in.Type == handshake.TypeFin {
			fins++
			if len(in.Body) == 0 || !allZeroBytes(in.Body) {
				t.Fatal("the hs.fin's body was not wiped")
			}
		}
	}
	if fins != 1 {
		t.Fatalf("%d hs.fin inners wiped, want 1", fins)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.awaiting) != 0 {
		t.Fatal("the rekey did not finish")
	}
}
