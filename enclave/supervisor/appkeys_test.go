package supervisor

import (
	"context"
	"fmt"
	"github.com/vettid/vettid-vault/internal/vaultipc"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/vault"
)

var keyRel = strings.Repeat("a", 96)

func ev(event, vid, key string, seq uint64) vault.LifecycleEvent {
	return vault.LifecycleEvent{Event: event, VaultID: vid, Release: keyRel, VaultVersion: keyRel, StateVersion: vault.StateVersion, AppKey: []byte(key), AppKeySeq: seq}
}

// The book keeps the current app key relayed for each vault, and nothing
// of a replacement in progress (R1: its key is on the row before the vault
// stores anything that names it, and a stale assertion of it could only
// bring back a key the vault dropped).
func TestKeyBook(t *testing.T) {
	var b keyBook
	now := time.Now()
	b.note(ev("enrolled", "v1", "k1", 1), now)
	b.note(ev("locked", "v1", "k1", 1), now)
	b.note(ev("unlocked", "v2", "a1", 3), now)
	n := ev(vault.EventAppKeyNext, "v1", "k2", 2)
	n.HeaderSeq = 9
	b.note(n, now)
	got := map[string]vault.LifecycleEvent{}
	for _, e := range b.events(now) {
		if e.Event != vault.EventAppKeyAssert {
			t.Fatalf("event %s", e.Event)
		}
		got[e.VaultID] = e
	}
	if len(got) != 2 || string(got["v1"].AppKey) != "k1" || got["v1"].AppKeySeq != 1 || string(got["v2"].AppKey) != "a1" {
		t.Fatalf("book %+v", got)
	}
	// A transfer's app_key moves it on.
	b.note(ev(vault.EventAppKey, "v1", "k2", 2), now)
	for _, e := range b.events(now) {
		if e.VaultID == "v1" && (string(e.AppKey) != "k2" || e.AppKeySeq != 2) {
			t.Fatalf("not moved on: %+v", e)
		}
	}
	// A deleted vault is forgotten.
	b.note(ev("deleted", "v2", "", 0), now)
	for _, e := range b.events(now) {
		if e.VaultID == "v2" {
			t.Fatal("deleted vault kept")
		}
	}
}

// The book holds 4096 vaults; past that the one reported least recently
// goes.
func TestKeyBookCap(t *testing.T) {
	var b keyBook
	t0 := time.Now()
	for i := 0; i < keyBookMax+10; i++ {
		b.note(ev("unlocked", fmt.Sprintf("v%05d", i), "k", 1), t0.Add(time.Duration(i)*time.Millisecond))
	}
	got := b.events(t0.Add(time.Hour))
	have := map[string]bool{}
	for _, e := range got {
		have[e.VaultID] = true
	}
	if len(got) != keyBookMax || have["v00000"] || have["v00009"] || !have["v00010"] || !have[fmt.Sprintf("v%05d", keyBookMax+9)] {
		t.Fatalf("%d entries, oldest kept: %v", len(got), have["v00010"])
	}
}

// After a connect the supervisor tells the parent the app keys it last
// relayed: a parent that restarted lost what it had queued.
func TestReassertAppKeysOnConnect(t *testing.T) {
	var mu sync.Mutex
	var got []*hostproto.Frame
	a, b := net.Pipe()
	p := hostproto.NewConn(b, nil, func(f *hostproto.Frame) {
		mu.Lock()
		got = append(got, &hostproto.Frame{Kind: f.Kind, Fields: append([][]byte(nil), f.Fields...)})
		mu.Unlock()
	})
	c := hostproto.NewConn(a, nil, nil)
	t.Cleanup(func() { c.Close(); p.Close() })
	s := &Supervisor{link: &link{}, now: time.Now, activity: map[string]time.Time{}}
	// Reported while no parent listened (the old connection was gone).
	s.lifecycle(ev("unlocked", "v1", "k1", 1))
	n := ev(vault.EventAppKeyNext, "v1", "k2", 2)
	n.HeaderSeq = 4
	s.lifecycle(n)
	s.link.set(c)
	s.reassertAppKeys()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	seen := map[string]string{}
	for _, f := range got {
		if f.Kind != hostproto.KindLifecycle || len(f.Fields) != enclave.LifecycleFieldCount {
			t.Fatalf("frame %+v", f)
		}
		seen[string(f.Fields[0])] = string(f.Fields[5])
	}
	if len(got) != 1 || seen[vault.EventAppKeyAssert] != "k1" {
		t.Fatalf("frames %v", seen)
	}
}

// A vault process's acknowledged app key reaches the parent only for its
// own vault and in a well-formed request; the parent's ok and conflict
// come back, anything else is an error to the process.
func TestChannelAppKeyNext(t *testing.T) {
	var asked [][]string
	reply := hostproto.StatusOK
	l := fakeParent(t, func(f *hostproto.Frame) [][]byte {
		if f.Kind != hostproto.KindAppKeyNext {
			return hostproto.Strings(hostproto.StatusInvalid)
		}
		var a []string
		for _, x := range f.Fields {
			a = append(a, string(x))
		}
		asked = append(asked, a)
		return hostproto.Strings(reply)
	})
	s := &Supervisor{link: l, activity: map[string]time.Time{}}
	p := &vproc{h: &procHost{s: s}, vaultID: "aaaa", userGUID: "u1"}
	call := func(f ...string) string {
		return string(p.handle(context.Background(), &hostproto.Frame{Kind: vaultipc.KindAppKeyNext, ID: 1, Fields: hostproto.Strings(f...)})[0])
	}
	if got := call("aaaa", "next", "key", "2", "7"); got != hostproto.StatusOK {
		t.Fatalf("own vault: %s", got)
	}
	if got := call("aaaa", "enroll", "key", "1", "1"); got != hostproto.StatusOK {
		t.Fatalf("enroll: %s", got)
	}
	for _, f := range [][]string{{"bbbb", "next", "key", "2", "7"}, {}, {"aaaa", "next", "key", "2"}, {"aaaa", "other", "key", "2", "7"},
		{"aaaa", "next", "", "2", "7"}, {"aaaa", "next", "key", "02", "7"}, {"aaaa", "next", "key", "2", "x"}} {
		if got := call(f...); got != vaultipc.StatusDenied {
			t.Fatalf("%v: %s", f, got)
		}
	}
	reply = hostproto.StatusConflict
	if got := call("aaaa", "next", "key", "2", "7"); got != hostproto.StatusConflict {
		t.Fatalf("conflict: %s", got)
	}
	for _, r := range []string{hostproto.StatusError, hostproto.StatusInvalid, "other"} {
		reply = r
		if got := call("aaaa", "next", "key", "2", "7"); got != hostproto.StatusError {
			t.Fatalf("parent %s: %s", r, got)
		}
	}
	if len(asked) != 6 || asked[0][4] != "7" {
		t.Fatalf("the parent was asked %v", asked)
	}
}

// A vault that locked here and has been locked for a day is no longer
// asserted (it may run elsewhere now), and a moved vault is forgotten.
func TestKeyBookPrunesLocked(t *testing.T) {
	var b keyBook
	t0 := time.Now()
	b.note(ev("locked", "v1", "k1", 1), t0)
	b.note(ev("unlocked", "v2", "k2", 1), t0)
	b.note(ev("unlocked", "v3", "k3", 1), t0)
	b.note(ev("moved", "v3", "", 0), t0)
	if got := b.events(t0.Add(time.Hour)); len(got) != 2 {
		t.Fatalf("within a day: %d", len(got))
	}
	got := b.events(t0.Add(25 * time.Hour))
	if len(got) != 1 || got[0].VaultID != "v2" {
		t.Fatalf("after a day: %+v", got)
	}
}
