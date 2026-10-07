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

// §11.5 (0.16.0): the backup bit is written under the lease rule.
func TestCredentialBackupWrite(t *testing.T) {
	tb := parenttest.NewTables()
	tb.PutVault(parenttest.VaultRow{VaultID: "v1", UserGUID: "u1", State: "locked"})
	ctx, now := context.Background(), time.Now()
	f, tr := false, true
	if err := tb.Lifecycle(ctx, parent.Lifecycle{Event: "unlocked", VaultID: "v1", CredentialBackup: &tr}, "me", now); err != nil {
		t.Fatal(err)
	}
	if err := tb.Lifecycle(ctx, parent.Lifecycle{Event: parent.EventCredentialBackup, VaultID: "v1", CredentialBackup: &f}, "me", now); err != nil {
		t.Fatal(err)
	}
	if r, _ := tb.Vault("v1"); r.CredentialBackup == nil || *r.CredentialBackup {
		t.Fatalf("bit %+v", r.CredentialBackup)
	}
	tb.PutVault(parenttest.VaultRow{VaultID: "v2", UserGUID: "u1", State: "unlocked", LeaseInstance: "other", LeaseExpires: now.Add(time.Hour).Unix()})
	_ = tb.Lifecycle(ctx, parent.Lifecycle{Event: parent.EventCredentialBackup, VaultID: "v2", CredentialBackup: &f}, "me", now)
	if r, _ := tb.Vault("v2"); r.CredentialBackup != nil {
		t.Fatal("written without the lease")
	}
}

// §11.5 (0.18.0): name_change = {seq, first_name, last_name, at} and
// name_change_pending = true, whatever the lease, when seq is higher than
// the row's.
func TestNameChangeWrite(t *testing.T) {
	tb := parenttest.NewTables()
	tb.PutVault(parenttest.VaultRow{VaultID: "v1", UserGUID: "u1", State: "unlocked", LeaseInstance: "other", LeaseExpires: time.Now().Add(time.Hour).Unix()})
	ctx, now := context.Background(), time.Now()
	write := func(seq uint64, last string) {
		ev := parent.Lifecycle{Event: parent.EventAccountName, VaultID: "v1", Name: &parent.NameChange{Seq: seq, FirstName: "Ada", LastName: last}}
		if err := tb.Lifecycle(ctx, ev, "me", now); err != nil {
			t.Fatal(err)
		}
	}
	write(2, "King")
	r, _ := tb.Vault("v1")
	if r.NameChange == nil || *r.NameChange != (parent.NameChange{Seq: 2, FirstName: "Ada", LastName: "King"}) || !r.NameChangePending || r.NameChangeAt != now.Unix() {
		t.Fatalf("row %+v", r)
	}
	write(1, "Old")
	if r, _ := tb.Vault("v1"); r.NameChange.LastName != "King" {
		t.Fatal("an older request replaced a newer one")
	}
	write(3, "Byron")
	if r, _ := tb.Vault("v1"); r.NameChange.Seq != 3 || r.NameChange.LastName != "Byron" || r.State != "unlocked" || r.LeaseInstance != "other" {
		t.Fatalf("row %+v", r)
	}
}
