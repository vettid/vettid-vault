package items

import (
	"time"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/vault"
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
// and kind for a use request of conn (§10.13); ok is false otherwise (an
// item not included is not told apart from a missing one). suitable
// (0.21.0) is whether the field can hold an Ed25519 seed: a password,
// text or multiline field of an item that is not a wallet's. The wallet's
// ItemInUse takes only its own guard lock.
func (f *Feature) UsableField(conn, itemID, fieldID string, now time.Time) (name, label, kind string, suitable, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	it := f.st.Items[itemID]
	if it == nil || it.Sensitivity != itemspec.Critical || !f.usableIncl(conn, itemID, now) {
		return "", "", "", false, false
	}
	fl, found := it.Field(fieldID)
	if !found {
		return "", "", "", false, false
	}
	switch fl.Kind {
	case itemspec.KindPassword, itemspec.KindText, itemspec.KindMultiline:
		suitable = !f.guarded(itemID)
	}
	return it.Name, fl.Label, fl.Kind, suitable, true
}

// --- rate limits for connections (0.23.0, §10.12) ---

// includingRules returns the connection rules of conn in force that
// include the item, sorted by id.
func (f *Feature) includingRules(conn, itemID string, now time.Time) []*Rule {
	var out []*Rule
	for _, id := range sortedKeys(f.st.Rules) {
		r := f.st.Rules[id]
		if r.Conn != conn || !r.Terms.InForce(now) {
			continue
		}
		if inc := f.incl(id, itemID); inc != nil && inc.State == StateIncluded {
			out = append(out, r)
		}
	}
	return out
}

// fullUntil returns when r's full windows end (the later of them), or the
// zero time if neither window is full at now.
func (r *Rule) fullUntil(now time.Time) time.Time {
	var until time.Time
	w := &r.Windows
	if r.Limits.PerHour > 0 && !w.HourStart.IsZero() && now.Before(w.HourStart.Add(time.Hour)) && w.HourN >= r.Limits.PerHour {
		until = w.HourStart.Add(time.Hour)
	}
	if r.Limits.PerDay > 0 && !w.DayStart.IsZero() && now.Before(w.DayStart.Add(24*time.Hour)) && w.DayN >= r.Limits.PerDay {
		if e := w.DayStart.Add(24 * time.Hour); e.After(until) {
			until = e
		}
	}
	return until
}

// RuleFetchAllowed is the rate check of a connection's fetch of an item
// through a rule grant (§10.12 Rate limits for connections): the fetch is
// refused while a window of any rule of conn that includes the item is
// full, and retry is then the time until every full window that refused
// it ends. The first refusal under a rule in 24 hours is a feed item
// share.rate_limited (ref = rule_id).
func (f *Feature) RuleFetchAllowed(s *vault.Session, conn, itemID string) (retry time.Duration, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now()
	var until time.Time
	for _, r := range f.includingRules(conn, itemID, now) {
		u := r.fullUntil(now)
		if u.IsZero() {
			continue
		}
		if u.After(until) {
			until = u
		}
		if w := &r.Windows; w.FedAt.IsZero() || now.Sub(w.FedAt) >= 24*time.Hour {
			w.FedAt = now.UTC().Truncate(time.Millisecond)
			s.Record(vault.Activity{Kind: "share.rate_limited", ConnectionID: conn, Ref: r.ID, Feed: true})
		}
	}
	if until.IsZero() {
		return 0, true
	}
	return until.Sub(now), false
}

// RuleFetched counts a connection's answered fetch of an item through a
// rule grant in the windows of every rule of conn that includes it.
func (f *Feature) RuleFetched(conn, itemID string, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := now.UTC().Truncate(time.Millisecond)
	for _, r := range f.includingRules(conn, itemID, now) {
		w := &r.Windows
		if w.HourStart.IsZero() || !now.Before(w.HourStart.Add(time.Hour)) {
			w.HourStart, w.HourN = t, 0
		}
		if w.DayStart.IsZero() || !now.Before(w.DayStart.Add(24*time.Hour)) {
			w.DayStart, w.DayN = t, 0
		}
		w.HourN++
		w.DayN++
	}
}

// --- agents (§10.11) ---

// agentIncls returns the agent's rules (of rules: its items.read rules in
// force) that include the item, with their inclusions; none if the item
// is critical or (0.23.0, §10.12 Overlapping rules) any of them that has
// uses has none left.
func (f *Feature) agentIncls(agent string, rules []itemspec.AgentRule, itemID string) ([]*Inclusion, []string) {
	it := f.st.Items[itemID]
	if it == nil || it.Sensitivity == itemspec.Critical {
		return nil, nil
	}
	var incs []*Inclusion
	var ids []string
	for i := range rules {
		r := &rules[i]
		if r.AgentID != agent {
			continue
		}
		inc := f.incl(r.ID, itemID)
		if inc == nil || inc.State != StateIncluded {
			continue
		}
		if r.Terms.Uses > 0 && inc.Used >= r.Terms.Uses {
			return nil, nil // no use left in one: included in none
		}
		incs = append(incs, inc)
		ids = append(ids, r.ID)
	}
	return incs, ids
}

// countRead counts one agent read on every including rule that has uses.
func countRead(rules []itemspec.AgentRule, ids []string, incs []*Inclusion) {
	for i, id := range ids {
		for j := range rules {
			if rules[j].ID == id && rules[j].Terms.Uses > 0 {
				incs[i].Used++
			}
		}
	}
}

// AgentIncluding returns the ids of the agent rules that include the item
// (none if it has no use left in one of them): the LEASH decision's
// coverage (§10.11), all of whose windows a read must fit (0.23.0).
func (f *Feature) AgentIncluding(agent string, rules []itemspec.AgentRule, itemID string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ids := f.agentIncls(agent, rules, itemID)
	return ids
}

// AgentCatalog lists the items the agent's rules include (with a use
// left), metadata only.
func (f *Feature) AgentCatalog(agent string, rules []itemspec.AgentRule) []itemspec.Meta {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []itemspec.Meta
	for _, it := range f.sortedItems() {
		if incs, _ := f.agentIncls(agent, rules, it.ID); len(incs) > 0 {
			out = append(out, itemspec.MetaOf(it, nil))
		}
	}
	return out
}

// AgentRead returns an included item's content for the agent (fields:
// nil for all) and counts one use in every including rule that has uses;
// ok is false if no rule includes it or a field is missing.
func (f *Feature) AgentRead(agent string, rules []itemspec.AgentRule, itemID string, fields []string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	incs, ids := f.agentIncls(agent, rules, itemID)
	it := f.st.Items[itemID]
	if len(incs) == 0 || !it.HasFields(fields) {
		return nil, false
	}
	countRead(rules, ids, incs)
	return it.Content(fields), true
}

// AgentFieldValue returns a string field's value of an included item for
// an agent's use without exposure and counts one use in every including
// rule that has uses.
func (f *Feature) AgentFieldValue(agent string, rules []itemspec.AgentRule, itemID, fieldID string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	incs, ids := f.agentIncls(agent, rules, itemID)
	if len(incs) == 0 {
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
	countRead(rules, ids, incs)
	return v, true
}
