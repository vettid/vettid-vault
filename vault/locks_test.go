package vault

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/altchan"
)

// VAULT-MESSAGING 0.29.0 §10.2 "Locks" (release L): every opening of the
// vault has its own unlock_id, 32 lowercase hex, in memory only.
func TestUnlockIDPerOpening(t *testing.T) {
	f := newFixture(t)
	first := f.m.UnlockID()
	if !altchan.ValidUnlockID(first) {
		t.Fatalf("unlock_id %q", first)
	}
	st, _ := json.Marshal(f.m.st)
	hdr, _ := json.Marshal(f.m.hdr)
	if strings.Contains(string(st), first) || strings.Contains(string(hdr), first) {
		t.Fatal("unlock_id in the state or the header")
	}
	seen := map[string]bool{first: true}
	if err := f.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		m, _, err := f.unlock(testPIN, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		id := m.UnlockID()
		if !altchan.ValidUnlockID(id) || seen[id] {
			t.Fatalf("unlock %d: unlock_id %q repeats or is malformed", i, id)
		}
		seen[id] = true
		st, _ := json.Marshal(m.st)
		hdr, _ := json.Marshal(m.hdr)
		for old := range seen {
			if strings.Contains(string(st), old) || strings.Contains(string(hdr), old) {
				t.Fatal("an unlock_id reached the state or the header")
			}
		}
		if err := m.Lock(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

// vault.status gives unlock_id to the app and desktops, not to agents or
// a recovering app.
func TestStatusUnlockID(t *testing.T) {
	f := newOCFixture(t)
	want := f.m.UnlockID()
	for _, c := range []struct {
		td   *tdev
		want bool
	}{{f.app, true}, {f.desk, true}, {f.agent, false}} {
		o, err := strictjson.ParseObject(f.req(t, c.td, "vault.status", `{}`).Body)
		if err != nil {
			t.Fatal(err)
		}
		got, ok, _ := o.OptString("unlock_id")
		if ok != c.want || ok && got != want {
			t.Fatalf("%s: unlock_id %q present %v", c.td.peer.ID, got, ok)
		}
	}
	f.devPeer.Recovering = true
	r := f.req(t, f.app, "vault.status", `{}`)
	if strings.Contains(string(r.Body), "unlock_id") {
		t.Fatal("a recovering app got unlock_id")
	}
}

// vault.lock {unlock_id}: the current value locks and vault.locking names
// it; another value answers stale_lock and locks nothing; a malformed one
// is bad_request; no value locks as before release L (VAULT-LOCK L2).
func TestBoundRelayLock(t *testing.T) {
	cases := []struct {
		name, body, code string
		locks            bool
	}{
		{"current", `{"unlock_id":"%s"}`, "", true},
		{"other", `{"unlock_id":"0123456789abcdef0123456789abcdef"}`, "stale_lock", false},
		{"upper case", `{"unlock_id":"0123456789ABCDEF0123456789ABCDEF"}`, "bad_request", false},
		{"short", `{"unlock_id":"0123"}`, "bad_request", false},
		{"not a string", `{"unlock_id":7}`, "bad_request", false},
		{"none", `{}`, "", true},
	}
	for _, c := range cases {
		f := newOCFixture(t)
		id := f.m.UnlockID()
		body := strings.Replace(c.body, "%s", id, 1)
		rid := f.sendAs(f.app, "vault.lock", body)
		in := f.inbox(f.app, f.desk)
		r := find(in["dev1"], reply(rid))
		if r == nil || errCode(r) != c.code {
			t.Fatalf("%s: answer %+v", c.name, r)
		}
		if f.m.Locked() != c.locks {
			t.Fatalf("%s: locked %v", c.name, f.m.Locked())
		}
		l := find(in["desk1"], ofType("vault.locking"))
		if !c.locks {
			if l != nil {
				t.Fatalf("%s: vault.locking sent", c.name)
			}
			continue
		}
		o, err := strictjson.ParseObject(l.Body)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := o.String("unlock_id"); got != id {
			t.Fatalf("%s: vault.locking names %q, want %q", c.name, got, id)
		}
	}
}

// The vault's own locks (here ten failed checks) name the unlock too,
// beside the reason (§10.2 "Locks": "for a lock from any cause").
func TestLockingNamesUnlockForEveryCause(t *testing.T) {
	f := newOCFixture(t)
	id := f.m.UnlockID()
	for i := 1; i <= 10; i++ {
		f.sendAs(f.app, TypeOwnerCheck, `{"ok":false}`)
	}
	if !f.m.Locked() {
		t.Fatal("not locked")
	}
	l := find(f.inbox(f.app)["dev1"], ofType("vault.locking"))
	if l == nil || !strings.Contains(string(l.Body), `"reason":"owner_check"`) || !strings.Contains(string(l.Body), `"unlock_id":"`+id+`"`) {
		t.Fatalf("vault.locking %+v", l)
	}
}
