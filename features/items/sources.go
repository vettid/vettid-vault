package items

import (
	"time"

	"github.com/vettid/vettid-vault/features/itemspec"
)

// Entry points for the features that share items (grants §10.12, leash
// §10.11, critical-item use §10.13, shared actions §10.14). They are
// called from those features' handlers, with their locks held, and call
// nothing outside this feature.

// Readable returns the metadata of a data or secret item restricted to
// fields (nil: all); ok is false if the item does not exist, is
// critical, or lacks a field.
func (f *Feature) Readable(itemID string, fields []string) (itemspec.Meta, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	it := f.st.Items[itemID]
	if it == nil || it.Sensitivity == itemspec.Critical || !it.HasFields(fields) {
		return itemspec.Meta{}, false
	}
	return itemspec.MetaOf(it, fields), true
}

// Content returns a readable item's shareable content (§10.12),
// restricted to fields (nil: all, with the notes).
func (f *Feature) Content(itemID string, fields []string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	it := f.st.Items[itemID]
	if it == nil || it.Sensitivity == itemspec.Critical || !it.HasFields(fields) {
		return nil, false
	}
	return it.Content(fields), true
}

// CategoryItems reports whether an item of category exists that could
// answer a request by category (§10.12).
func (f *Feature) HasCategory(category string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, it := range f.st.Items {
		if it.Category == category && it.Sensitivity != itemspec.Critical {
			return true
		}
	}
	return false
}

// usableIncl returns whether a connection rule in force includes the
// critical item for conn.
func (f *Feature) usableIncl(conn, itemID string, now time.Time) bool {
	for rid, m := range f.st.Incl {
		r := f.st.Rules[rid]
		if r == nil || r.Conn != conn || !r.Terms.InForce(now) {
			continue
		}
		if inc := m[itemID]; inc != nil && inc.State == StateIncluded {
			return true
		}
	}
	return false
}

// Usable lists the critical items share rules make usable to conn
// (§10.12, §10.13), sorted by id.
func (f *Feature) Usable(conn string, now time.Time) []itemspec.Meta {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []itemspec.Meta
	for _, it := range f.sortedItems() {
		if it.Sensitivity == itemspec.Critical && f.usableIncl(conn, it.ID, now) {
			out = append(out, itemspec.MetaOf(it, nil))
		}
	}
	return out
}

// UsableField returns a usable critical item's name and a field's label
// for a use request of conn (§10.13); ok is false otherwise (an item not
// included is not told apart from a missing one).
func (f *Feature) UsableField(conn, itemID, fieldID string, now time.Time) (name, label string, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	it := f.st.Items[itemID]
	if it == nil || it.Sensitivity != itemspec.Critical || !f.usableIncl(conn, itemID, now) {
		return "", "", false
	}
	fl, found := it.Field(fieldID)
	if !found || fl.Kind == itemspec.KindAddress {
		return "", "", false
	}
	return it.Name, fl.Label, true
}

// --- agents (§10.11) ---

// agentIncl returns the inclusion of an item for the first of rules (the
// agent's items.read rules in force) that includes it with a use left.
func (f *Feature) agentIncl(agent string, rules []itemspec.AgentRule, itemID string) (*Inclusion, string) {
	it := f.st.Items[itemID]
	if it == nil || it.Sensitivity == itemspec.Critical {
		return nil, ""
	}
	for i := range rules {
		r := &rules[i]
		if r.AgentID != agent {
			continue
		}
		inc := f.incl(r.ID, itemID)
		if inc == nil || inc.State != StateIncluded || r.Terms.Uses > 0 && inc.Used >= r.Terms.Uses {
			continue
		}
		return inc, r.ID
	}
	return nil, ""
}

// AgentIncluded returns the id of an agent rule that includes the item
// with a use left ("" for none): the LEASH decision's coverage.
func (f *Feature) AgentIncluded(agent string, rules []itemspec.AgentRule, itemID string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, rid := f.agentIncl(agent, rules, itemID)
	return rid
}

// AgentCatalog lists the items the agent's rules include (with a use
// left), metadata only.
func (f *Feature) AgentCatalog(agent string, rules []itemspec.AgentRule) []itemspec.Meta {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []itemspec.Meta
	for _, it := range f.sortedItems() {
		if inc, _ := f.agentIncl(agent, rules, it.ID); inc != nil {
			out = append(out, itemspec.MetaOf(it, nil))
		}
	}
	return out
}

// AgentRead returns an included item's content for the agent (fields:
// nil for all) and counts one use; ok is false if no rule includes it or
// a field is missing.
func (f *Feature) AgentRead(agent string, rules []itemspec.AgentRule, itemID string, fields []string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	inc, _ := f.agentIncl(agent, rules, itemID)
	it := f.st.Items[itemID]
	if inc == nil || !it.HasFields(fields) {
		return nil, false
	}
	inc.Used++
	return it.Content(fields), true
}

// AgentFieldValue returns a string field's value of an included item for
// an agent's use without exposure and counts one use.
func (f *Feature) AgentFieldValue(agent string, rules []itemspec.AgentRule, itemID, fieldID string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	inc, _ := f.agentIncl(agent, rules, itemID)
	if inc == nil {
		return "", false
	}
	fl, ok := f.st.Items[itemID].Field(fieldID)
	if !ok {
		return "", false
	}
	v, ok := itemspec.ValueString(fl.Value)
	if !ok {
		return "", false
	}
	inc.Used++
	return v, true
}
