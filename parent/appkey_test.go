package parent_test

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/parenttest"
	"github.com/vettid/vettid-vault/parent"
)

// §11.5 (0.15.0): the parent writes app_key = {key, kid, seq} whatever
// the lease, when seq is higher than the row's; enrolled always replaces
// it.
func TestAppKeyWrite(t *testing.T) {
	tb := parenttest.NewTables()
	tb.PutVault(parenttest.VaultRow{VaultID: "v1", UserGUID: "u1", State: "enrolling", LeaseInstance: "other", LeaseExpires: time.Now().Add(time.Hour).Unix()})
	ctx, now := context.Background(), time.Now()
	write := func(event string, key string, seq uint64) {
		if err := tb.Lifecycle(ctx, parent.Lifecycle{Event: event, VaultID: "v1", AppKey: []byte(key), AppKeySeq: seq}, "me", now); err != nil {
			t.Fatal(err)
		}
	}
	write("unlocked", "k2", 2)
	if r, _ := tb.Vault("v1"); string(r.AppKey) != "k2" || r.AppKeySeq != 2 || r.AppKeyID != parent.AppKeyID([]byte("k2")) {
		t.Fatalf("not written whatever the lease: %+v", r)
	}
	write(parent.EventAppKey, "k1", 1) // a stale instance's older report
	write("locked", "k2", 2)
	if r, _ := tb.Vault("v1"); string(r.AppKey) != "k2" || r.AppKeySeq != 2 {
		t.Fatalf("older key written: %+v", r)
	}
	write(parent.EventAppKey, "k3", 3)
	write("enrolled", "k1", 1) // a replaced provisional vault starts again at 1
	if r, _ := tb.Vault("v1"); string(r.AppKey) != "k1" || r.AppKeySeq != 1 {
		t.Fatalf("enrolled did not replace: %+v", r)
	}
}
