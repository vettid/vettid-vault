package items

import (
	"time"

	"github.com/vettid/vettid-vault/features/credential"
	"github.com/vettid/vettid-vault/features/itemspec"
)

// WaysCopies returns the settings on the agent's inclusions of the item
// under its rules in force, in rule order (§10.11; the copies, kept equal).
func (f *Feature) WaysCopies(agent, item string, now time.Time) []*itemspec.ItemWays {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*itemspec.ItemWays
	for _, inc := range f.agentCopies(agent, item, f.agentRuleIDs(now), nil) {
		out = append(out, inc.Ways)
	}
	return out
}

// DropWaysCopies removes the copy from every inclusion but the first, as a
// path that missed it would leave them.
func (f *Feature) DropWaysCopies(agent, item string, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, inc := range f.agentCopies(agent, item, f.agentRuleIDs(now), nil)[1:] {
		inc.Ways = nil
	}
}

// AnyWays reports whether any inclusion of the item, in force or not,
// holds settings.
func (f *Feature) AnyWays(item string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.st.Incl {
		if inc := m[item]; inc != nil && inc.Ways != nil {
			return true
		}
	}
	return false
}

// OpenSealed decrypts a critical item's ciphertext with a credential
// entry (tests of the envelope encryption).
func OpenSealed(vaultID string, it *itemspec.Item, e *credential.Item) ([]byte, error) {
	return open(vaultID, it, e)
}

// SetContract makes f stand for an image whose `contract` is v (§10.8).
func (f *Feature) SetContract(v string) { f.contract = v }

// SetKeptHook sees the stored values a critical replacement opens for its
// kept values (0.21.0), before they are wiped; nil removes it.
func SetKeptHook(h func(fields map[string][]byte)) {
	if h == nil {
		testHookKept = nil
		return
	}
	testHookKept = func(v *Values) {
		m := map[string][]byte{}
		for id, x := range v.Fields {
			m[id] = x
		}
		h(m)
	}
}
