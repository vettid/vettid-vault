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

// keyLockedFor is how long a locked vault's keys are asserted.
const keyLockedFor = 24 * time.Hour

// keyAssertPace is the pause between two assertions sent: a few thousand
// vaults must not fill the connection's queue (enclave log records are
// dropped when it is full) or the parent's.
const keyAssertPace = 2 * time.Millisecond

type keyEntry struct {
	key []byte
	seq uint64
	rel string // the release that reported
	at  time.Time
	// locked: the vault's last report was `locked`; such an entry is
	// asserted for keyLockedFor only (a vault that locked here may run on
	// another instance since, whose book and writes are the newer).
	locked bool
}

type keyBook struct {
	mu sync.Mutex
	m  map[string]*keyEntry
}

// note records what a lifecycle event says of the vault's app keys.
func (b *keyBook) note(ev vault.LifecycleEvent, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ev.Event == "deleted" || ev.Event == "moved" {
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
	e.at, e.rel, e.locked = now, ev.VaultVersion, ev.Event == "locked"
	// Only the current key is kept: a key of a replacement in progress is
	// on the row before the vault stores anything that names it (the
	// acknowledged request), so no assertion of it repairs anything, and a
	// stale one could only bring back a key the vault dropped.
	if ev.Event != vault.EventAppKeyNext && len(ev.AppKey) > 0 {
		e.key, e.seq = append([]byte(nil), ev.AppKey...), ev.AppKeySeq
	}
}

// events are the assertions to send after a connect.
func (b *keyBook) events(now time.Time) []vault.LifecycleEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []vault.LifecycleEvent
	for id, e := range b.m {
		if e.locked && now.Sub(e.at) > keyLockedFor {
			delete(b.m, id) // long locked: whoever runs it now reports it
			continue
		}
		if len(e.key) > 0 {
			out = append(out, vault.LifecycleEvent{Event: vault.EventAppKeyAssert, VaultID: id, Release: e.rel, VaultVersion: e.rel,
				StateVersion: vault.StateVersion, AppKey: append([]byte(nil), e.key...), AppKeySeq: e.seq})
		}
	}
	return out
}

// reassertAppKeys sends the book to the parent (on a connect).
func (s *Supervisor) reassertAppKeys() {
	for _, ev := range s.keys.events(s.now()) {
		s.link.notify(hostproto.KindLifecycle, enclave.LifecycleFields(ev)...)
		time.Sleep(keyAssertPace)
	}
}
