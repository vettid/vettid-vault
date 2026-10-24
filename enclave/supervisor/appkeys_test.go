package supervisor

import (
	"context"
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

// The book keeps the last app key state relayed for each vault, and what
// a later report supersedes goes.
func TestKeyBook(t *testing.T) {
	var b keyBook
	now := time.Now()
	yes, no := true, false
	b.note(ev("enrolled", "v1", "k1", 1), now)
	b.note(ev("locked", "v1", "k1", 1), now)
	b.note(ev("unlocked", "v2", "a1", 3), now)
	n := ev(vault.EventAppKeyNext, "v1", "k2", 2)
	n.HeaderSeq = 9
	b.note(n, now)
	got := map[string]vault.LifecycleEvent{}
	for _, e := range b.events() {
		got[e.Event+"/"+e.VaultID] = e
	}
	if len(got) != 3 || string(got[vault.EventAppKeyAssert+"/v1"].AppKey) != "k1" || string(got[vault.EventAppKeyAssert+"/v2"].AppKey) != "a1" ||
		got[vault.EventAppKeyNextAssert+"/v1"].HeaderSeq != 9 || string(got[vault.EventAppKeyNextAssert+"/v1"].AppKey) != "k2" {
		t.Fatalf("book %+v", got)
	}
	// A next the header still has stays through an unlocked that says so.
	u := ev("unlocked", "v1", "k1", 1)
	u.Next = &yes
	b.note(u, now)
	if len(b.events()) != 3 {
		t.Fatal("the next key went with next: true")
	}
	// The app key reaching its seq, next_cleared, next: false and a new
	// enrollment each end it.
	for name, e := range map[string]vault.LifecycleEvent{
		"app_key":      ev(vault.EventAppKey, "v1", "k2", 2),
		"next_cleared": func() vault.LifecycleEvent { c := ev(vault.EventAppKey, "v1", "k1", 1); c.NextCleared = true; return c }(),
		"next false":   func() vault.LifecycleEvent { c := ev("locked", "v1", "k1", 1); c.Next = &no; return c }(),
		"enrolled":     ev("enrolled", "v1", "k0", 1),
	} {
		var c keyBook
		c.note(ev("unlocked", "v1", "k1", 1), now)
		c.note(n, now)
		c.note(e, now)
		for _, x := range c.events() {
			if x.Event == vault.EventAppKeyNextAssert {
				t.Fatalf("%s: the next key stayed", name)
			}
		}
	}
	// A deleted vault is forgotten.
	b.note(ev("deleted", "v2", "", 0), now)
	for _, e := range b.events() {
		if e.VaultID == "v2" {
			t.Fatal("deleted vault kept")
		}
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
		if n >= 2 || time.Now().After(deadline) {
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
	if len(got) != 2 || seen[vault.EventAppKeyAssert] != "k1" || seen[vault.EventAppKeyNextAssert] != "k2" {
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
