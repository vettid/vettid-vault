package supervisor

import (
	"sync"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/vault"
)

// Re-assertion of the app keys (VAULT-MESSAGING §11.5). The parent writes
// a vault's app_key and app_key_next on the vault row from the lifecycle
// events, and a parent that restarts loses what it had queued. The
// supervisor keeps the last app key state it relayed for each vault and,
// every time it connects to a parent, tells the parent again:
// app_key_assert (the current key) and app_key_next_assert (a key of a
// replacement in progress). The parent writes them as it writes app_key
// and app_key_next (conditional on seq, idempotent). A vault whose process
// ended, locked or never unlocked here is covered the same way: the state
// is kept after a lock and dropped only by `deleted`.

// keyBookMax bounds the vaults the book keeps; the least recently reported
// goes first.
const keyBookMax = 4096

type keyEntry struct {
	key  []byte
	seq  uint64
	next *vault.LifecycleEvent // the app_key_next event, while pending
	rel  string                // the release that reported
	at   time.Time
}

type keyBook struct {
	mu sync.Mutex
	m  map[string]*keyEntry
}

// note records what a lifecycle event says of the vault's app keys.
func (b *keyBook) note(ev vault.LifecycleEvent, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ev.Event == "deleted" {
		delete(b.m, ev.VaultID)
		return
	}
	if ev.Event != "enrolled" && ev.Event != "unlocked" && ev.Event != "locked" && ev.Event != vault.EventAppKey && ev.Event != vault.EventAppKeyNext {
		return
	}
	if b.m == nil {
		b.m = map[string]*keyEntry{}
	}
	e := b.m[ev.VaultID]
	if e == nil {
		if len(b.m) >= keyBookMax {
			var oldest string
			for id, x := range b.m {
				if oldest == "" || x.at.Before(b.m[oldest].at) {
					oldest = id
				}
			}
			delete(b.m, oldest)
		}
		e = &keyEntry{}
		b.m[ev.VaultID] = e
	}
	e.at, e.rel = now, ev.VaultVersion
	switch {
	case ev.Event == vault.EventAppKeyNext:
		c := ev
		c.AppKey = append([]byte(nil), ev.AppKey...)
		e.next = &c
		return
	case len(ev.AppKey) > 0:
		e.key, e.seq = append([]byte(nil), ev.AppKey...), ev.AppKeySeq
	}
	switch {
	case ev.Event == "enrolled", ev.Event == vault.EventAppKey && ev.NextCleared,
		(ev.Event == "unlocked" || ev.Event == "locked") && ev.Next != nil && !*ev.Next,
		e.next != nil && e.next.AppKeySeq <= e.seq:
		e.next = nil
	}
}

// events are the assertions to send after a connect.
func (b *keyBook) events() []vault.LifecycleEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []vault.LifecycleEvent
	for id, e := range b.m {
		if len(e.key) > 0 {
			out = append(out, vault.LifecycleEvent{Event: vault.EventAppKeyAssert, VaultID: id, Release: e.rel, VaultVersion: e.rel,
				StateVersion: vault.StateVersion, AppKey: append([]byte(nil), e.key...), AppKeySeq: e.seq})
		}
		if n := e.next; n != nil {
			c := *n
			c.Event = vault.EventAppKeyNextAssert
			out = append(out, c)
		}
	}
	return out
}

// reassertAppKeys sends the book to the parent (on a connect).
func (s *Supervisor) reassertAppKeys() {
	for _, ev := range s.keys.events() {
		s.link.notify(hostproto.KindLifecycle, enclave.LifecycleFields(ev)...)
	}
}
