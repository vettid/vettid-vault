package enclave_test

import (
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vault"
)

// §11.5 (0.18.0): an enroll without a well-formed account snapshot (one
// without the names, or none) is answered bad_request; with one, the new
// vault holds its names from its first flush.
func TestEnrollNeedsAccount(t *testing.T) {
	f := newFx(t)
	a := f.newApp("user-names", android(0x61))
	f.w.NoEnrollAccount = true
	if r := f.enroll(a, pin); r.OK || r.Code != "bad_request" {
		t.Fatalf("enroll without a snapshot: %+v", r)
	}
	f.w.NoEnrollAccount = false
	f.w.Account = func(string) []byte {
		return []byte(`{"v":1,"as_of":"` + f.clk.Now().UTC().Format(time.RFC3339) + `","state":"member"}`)
	}
	if r := f.enroll(a, pin); r.OK || r.Code != "bad_request" {
		t.Fatalf("enroll with a snapshot without names: %+v", r)
	}
	f.w.Account = func(string) []byte { return enclavetest.Snapshot(f.clk.Now(), "Ada", "Lovelace") }
	if r := f.enroll(a, pin); !r.OK {
		t.Fatalf("enroll: %+v", r)
	}
	m := f.w.Instance(3).Manager(a.vid)
	if m == nil || m.AccountVersion() != 1 {
		t.Fatal("the enrollment's snapshot not stored")
	}
}

// §11.5 (0.18.0): the lifecycle frame's name fields.
func TestLifecycleNameFields(t *testing.T) {
	ev := vault.LifecycleEvent{Event: vault.EventAccountName, VaultID: "v1", Release: "r", VaultVersion: "r", StateVersion: 1,
		Name: &vault.NameChange{Seq: 7, FirstName: "Ada", LastName: "O’Brien"}}
	f := enclave.LifecycleFields(ev)
	if len(f) != enclave.LifecycleFieldCount || string(f[8]) != "7" || string(f[9]) != "Ada" || string(f[10]) != "O’Brien" {
		t.Fatalf("fields %q", f)
	}
	if n, ok := enclave.ParseNameFields(f[8], f[9], f[10]); !ok || *n != *ev.Name {
		t.Fatalf("parsed %+v %v", n, ok)
	}
	plain := enclave.LifecycleFields(vault.LifecycleEvent{Event: "unlocked", VaultID: "v1"})
	if len(plain) != enclave.LifecycleFieldCount || string(plain[8]) != "0" || len(plain[9]) != 0 || len(plain[10]) != 0 {
		t.Fatalf("plain %q", plain)
	}
	if n, ok := enclave.ParseNameFields(plain[8], plain[9], plain[10]); !ok || n != nil {
		t.Fatal("plain fields")
	}
	for _, bad := range [][3]string{{"0", "Ada", ""}, {"01", "Ada", "L"}, {"1", "", "L"}, {"1", "A\x07", "L"}, {"x", "A", "L"}, {"1", "A", ""}} {
		if _, ok := enclave.ParseNameFields([]byte(bad[0]), []byte(bad[1]), []byte(bad[2])); ok {
			t.Fatalf("accepted %q", bad)
		}
	}
}
