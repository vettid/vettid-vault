package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
	"reflect"
	"runtime"
	"testing"
	"time"
	"unsafe"
	"weak"

	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// keySpan is the address range of a key's bytes: a span, unlike the
// slice, does not keep the key reachable.
type keySpan struct{ lo, hi uintptr }

func spanOf(k ed25519.PrivateKey) keySpan {
	lo := uintptr(unsafe.Pointer(unsafe.SliceData(k)))
	return keySpan{lo, lo + uintptr(cap(k))}
}

// keyRefs walks the values reachable from v through fields (unexported
// too), pointers, interfaces, slices, arrays and maps, and reports the
// paths of the byte slices inside one of spans. It does not see closures,
// channels or goroutine stacks, nor a new copy of a key's bytes in another
// allocation (the GC check below covers the first, nothing here the
// second), nor HTTP clients (the transport's pools; a relay's client holds
// no key): a diagnostic, naming the holders.
func keyRefs(v any, spans []keySpan) []string {
	inKey := func(p uintptr) bool {
		for _, s := range spans {
			if p >= s.lo && p < s.hi {
				return true
			}
		}
		return false
	}
	httpClient := reflect.TypeOf((*http.Client)(nil))
	type seenKey struct {
		p uintptr
		t reflect.Type
	}
	seen := map[seenKey]bool{}
	var found []string
	var walk func(v reflect.Value, path string)
	once := func(v reflect.Value) bool {
		k := seenKey{v.Pointer(), v.Type()}
		if seen[k] {
			return false
		}
		seen[k] = true
		return true
	}
	walk = func(v reflect.Value, path string) {
		switch v.Kind() {
		case reflect.Pointer:
			if !v.IsNil() && v.Type() != httpClient && once(v) {
				walk(v.Elem(), path)
			}
		case reflect.Interface:
			if !v.IsNil() {
				walk(v.Elem(), path)
			}
		case reflect.Struct:
			for i := range v.NumField() {
				walk(v.Field(i), path+"."+v.Type().Field(i).Name)
			}
		case reflect.Slice:
			switch {
			case v.IsNil():
			case v.Type().Elem().Kind() == reflect.Uint8:
				if v.Cap() > 0 && inKey(v.Pointer()) {
					found = append(found, path)
				}
			case once(v):
				for i := range v.Len() {
					walk(v.Index(i), path+"[]")
				}
			}
		case reflect.Array:
			for i := range v.Len() {
				walk(v.Index(i), path+"[]")
			}
		case reflect.Map:
			if !v.IsNil() && once(v) {
				it := v.MapRange()
				for it.Next() {
					walk(it.Key(), path+"{k}")
					walk(it.Value(), path+"{}")
				}
			}
		}
	}
	walk(reflect.ValueOf(v), reflect.TypeOf(v).String())
	return found
}

// collected reports whether every key behind ws was freed, after a few
// GCs (crypto/ed25519's cache holds its keys weakly: a reachable key keeps
// its cached expansion, a collected one lets it go).
func collected(ws []weak.Pointer[byte]) bool {
	for range 10 {
		runtime.GC()
		all := true
		for _, w := range ws {
			all = all && w.Value() == nil
		}
		if all {
			return true
		}
	}
	return false
}

// keyHolders is what TestZeroizeDropsEveryKeyReference keeps of the keys:
// weak pointers and spans only, so that the test itself holds none.
type keyHolders struct {
	cr, derived *ClientRelay
	olds        []*ClientRelay
	clients     []*relayclient.Client
	weaks       []weak.Pointer[byte]
	spans       []keySpan
}

// keyFixture gives the vault what zeroize finds when it holds every kind
// of key copy: a pending relay key and two old ones, ClientRelays of the
// relay key and of each of those (WithKey) with cached clients, an
// outgoing handshake (a reconnect: its Initiator keeps ik) and an awaiting
// one (an hs.init answered: its Responder signed with ik and keeps none). It signs with every key, so crypto/ed25519
// caches its expansion. The fixture's own stub relay (the vault's m.relay,
// test only) is given a copy of the relay key, so that it does not hold
// the vault's.
func keyFixture(t *testing.T, d *devFixture) keyHolders {
	t.Helper()
	inv := d.invite(t, KindConnection, 10*time.Minute)
	newNewcomer(t, 0x50).hsInit(t, d.m, handshake.PurposeConnection, inv.ID, "k1") // awaiting its hs.fin
	d.asConnection(t, "c1", 0x70)
	f := d.fixture
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	p := f.m.st.Connections["c1"]
	p.Reconnect = HeldToken{Token: "v4.public.VEVTVA", Exp: f.m.now().Add(24 * time.Hour)}
	p.LastEpochID = bytes.Repeat([]byte{0xe1}, 16)
	reconnectOf(t, f.m, p) // outgoing
	if len(f.m.awaiting) == 0 || len(f.m.outgoing) == 0 {
		t.Fatalf("handshakes: %d awaiting, %d outgoing", len(f.m.awaiting), len(f.m.outgoing))
	}
	f.relay.mu.Lock()
	f.relay.key = append(ed25519.PrivateKey(nil), f.relay.key...)
	f.relay.mu.Unlock()
	f.m.keys.pendingRelay = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{23}, 32))
	f.m.keys.oldRelay = []ed25519.PrivateKey{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{24}, 32)),
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{25}, 32))}
	cr := NewClientRelay("https://relay.example", f.m.keys.relay, nil, nil)
	derived := cr.WithKey(f.m.keys.pendingRelay).(*ClientRelay)
	olds := []*ClientRelay{cr.WithKey(f.m.keys.oldRelay[0]).(*ClientRelay), cr.WithKey(f.m.keys.oldRelay[1]).(*ClientRelay)}
	h := keyHolders{cr: cr, derived: derived, olds: olds, clients: []*relayclient.Client{cr.client("https://relay.example"),
		cr.depositClient("https://other.example"), derived.client("https://relay.example"), olds[1].client("https://relay.example")}}
	for _, r := range append([]*ClientRelay{cr, derived}, olds...) {
		f.m.track(r)
	}
	f.m.rk.pending = derived
	f.m.rk.old = []Relay{olds[0], olds[1]}
	keys := map[string]ed25519.PrivateKey{"relay": f.m.keys.relay, "ik": f.m.keys.ik, "pending": f.m.keys.pendingRelay,
		"old0": f.m.keys.oldRelay[0], "old1": f.m.keys.oldRelay[1], "cr": cr.key, "derived": derived.key,
		"old0 copy": olds[0].key, "old1 copy": olds[1].key}
	for name, k := range keys {
		if len(k) != ed25519.PrivateKeySize {
			t.Fatalf("no %s key to check", name)
		}
		_ = ed25519.Sign(k, []byte("cache it"))
		h.weaks = append(h.weaks, weak.Make(&k[0]))
		h.spans = append(h.spans, spanOf(k))
	}
	// Each holder is seen by the walk before zeroize, the Manager root first.
	holders := map[string]any{"manager": f.m, "keys": f.m.keys, "outgoing": f.m.outgoing,
		"cr": cr, "derived": derived, "old0 relay": olds[0], "old1 relay": olds[1]}
	for name, held := range holders {
		if len(keyRefs(held, h.spans)) == 0 {
			t.Fatalf("the walk does not see %s's key", name)
		}
	}
	for _, name := range []string{"ik", "pending", "old0", "old1"} {
		if len(keyRefs(f.m, []keySpan{spanOf(keys[name])})) == 0 {
			t.Fatalf("the walk from the Manager does not see %s", name)
		}
	}
	if len(keyRefs(f.m.outgoing, []keySpan{spanOf(f.m.keys.ik)})) == 0 {
		t.Fatal("the outgoing handshake does not hold ik")
	}
	for i, c := range h.clients {
		if c.Key == nil || len(keyRefs(c, h.spans)) == 0 {
			t.Fatalf("the walk does not see client %d's key", i)
		}
	}
	return h
}

// After zeroize none of the vault's Ed25519 private keys (relay, ik, the
// relays' own copies) is reachable: not from the Manager, nor from a
// ClientRelay it made or that relay's cached clients, though they are
// still held (as a worker or a collector holds them). So the next GCs free
// them, and crypto/ed25519's cached expansion with them.
func TestZeroizeDropsEveryKeyReference(t *testing.T) {
	d := newDevFixture(t)
	f := d.fixture
	h := keyFixture(t, d)
	f.m.Crash()
	f.m.mu.Lock()
	for name, held := range map[string]any{"manager": f.m, "cr": h.cr, "derived": h.derived, "olds": h.olds, "clients": h.clients} {
		if got := keyRefs(held, h.spans); len(got) > 0 {
			t.Errorf("key bytes still reachable from the %s: %v", name, got)
		}
	}
	f.m.mu.Unlock()
	if !collected(h.weaks) {
		t.Fatal("a key was not collected after zeroize")
	}
	runtime.KeepAlive(d)
	runtime.KeepAlive(h.olds)
	runtime.KeepAlive(h.cr)
	runtime.KeepAlive(h.derived)
	runtime.KeepAlive(h.clients)
}

// A close that timed out on a call still in flight keeps the references
// (the call may be signing with them), and drops them as that call ends.
func TestRelayDropsKeyAsTheLastCallEnds(t *testing.T) {
	cr := NewClientRelay("https://relay.example", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{22}, 32)), nil, nil)
	cl := cr.client("https://relay.example")
	w, spans := weak.Make(&cr.key[0]), []keySpan{spanOf(cr.key)}
	entered, release, ended := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(ended)
		_, _ = guarded(cr, context.Background(), func(context.Context) (int, error) { close(entered); <-release; return 0, nil })
	}()
	waitClosed(t, entered)
	saved := relayCloseWait
	defer func() { relayCloseWait = saved }()
	relayCloseWait = 10 * time.Millisecond // the call ignores its cancel
	cr.Close()
	if got := keyRefs(cr, spans); len(got) == 0 {
		t.Fatal("the references were dropped under a call in flight")
	}
	close(release)
	waitClosed(t, ended)
	if got := keyRefs([]any{cr, cl}, spans); len(got) > 0 {
		t.Fatalf("key bytes still reachable after the last call: %v", got)
	}
	if !collected([]weak.Pointer[byte]{w}) {
		t.Fatal("the key was not collected after the last call")
	}
	runtime.KeepAlive(cr)
	runtime.KeepAlive(cl)
}
