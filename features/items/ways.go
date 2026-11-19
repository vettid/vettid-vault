package items

import (
	"sort"
	"time"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/strictjson"
)

// Ways to use a secret (VAULT-MESSAGING §10.11, 0.42.0): an agent's
// settings for an item exist while at least one of its rules includes the
// item. They are kept as a copy on each of the agent's inclusions of the
// item (Inclusion.Ways), all equal, so they go with the last inclusion and
// a later inclusion starts again at ["use"]. Every path that misses a copy
// fails secure: a new inclusion that takes no copy starts at ["use"], and
// copies that differ count as absent (waysOf), never as the wider one.

// waysOf is the agent's settings among the copies on incs: their common
// value, or nil (["use"]) when there is none or two differ.
func waysOf(incs []*Inclusion) *itemspec.ItemWays {
	if len(incs) == 0 {
		return nil
	}
	w := incs[0].Ways
	for _, inc := range incs[1:] {
		if !inc.Ways.Equal(w) {
			return nil
		}
	}
	return w
}

// agentRuleIDs is the ids of the agent rules in force. It calls the leash
// feature, so only this feature's own handlers use it (never the entry
// points leash calls with its lock held).
func (f *Feature) agentRuleIDs(now time.Time) map[string]bool {
	ids := map[string]bool{}
	if f.agents != nil {
		for _, r := range f.agents.AgentRules(now) {
			ids[r.ID] = true
		}
	}
	return ids
}

// agentCopies is the agent's inclusions of the item under rules in force
// (inForce), whatever their uses, skipping those in skip.
func (f *Feature) agentCopies(agent, itemID string, inForce map[string]bool, skip map[*Inclusion]bool) []*Inclusion {
	var out []*Inclusion
	for _, rid := range sortedKeys(f.st.Incl) {
		inc := f.st.Incl[rid][itemID]
		if inc == nil || inc.Agent != agent || inc.State != StateIncluded || !inForce[rid] || skip[inc] {
			continue
		}
		out = append(out, inc)
	}
	return out
}

// settle is waysOf that also makes "absent" stored: when the copies differ
// it clears all of them, so a wider copy can never come back later when
// the others go (fail secure).
func settle(incs []*Inclusion) *itemspec.ItemWays {
	w := waysOf(incs)
	if w == nil {
		for _, inc := range incs {
			inc.Ways = nil
		}
	}
	return w
}

// copyWays gives each of an agent's new inclusions (rule, item) the
// settings the agent's other inclusions of the item kept through the
// change, or else those the same change withdrew (carried, by agent and
// item: a move between the agent's rules); with none, or copies that
// differ, it starts at ["use"].
func (f *Feature) copyWays(s *vault.Session, added [][2]string, carried map[[2]string]*itemspec.ItemWays) {
	if len(added) == 0 {
		return
	}
	fresh := map[*Inclusion]bool{}
	for _, k := range added {
		if inc := f.incl(k[0], k[1]); inc != nil {
			fresh[inc] = true
		}
	}
	inForce := f.agentRuleIDs(s.Now())
	for _, k := range added {
		inc := f.incl(k[0], k[1])
		if inc == nil || inc.State != StateIncluded || inc.Agent == "" {
			continue
		}
		if kept := f.agentCopies(inc.Agent, k[1], inForce, fresh); len(kept) > 0 {
			inc.Ways = settle(kept).Clone()
		} else {
			inc.Ways = carried[[2]string{inc.Agent, k[1]}].Clone()
		}
	}
}

// noteWaysGone notes an inclusion about to go that holds settings.
func (f *Feature) noteWaysGone(inc *Inclusion, itemID string) {
	if inc != nil && inc.Agent != "" && inc.Ways != nil {
		f.waysGone = append(f.waysGone, [2]string{inc.Agent, itemID})
	}
}

// flushWays announces the settings whose last copy went
// (sync.event{leash.item.changed} without version, audited as
// leash.item.changed with ref = item_id, §10.11).
func (f *Feature) flushWays(s *vault.Session) {
	if len(f.waysGone) == 0 {
		return
	}
	gone := f.waysGone
	f.waysGone = nil
	sort.Slice(gone, func(i, j int) bool {
		return gone[i][0] < gone[j][0] || gone[i][0] == gone[j][0] && gone[i][1] < gone[j][1]
	})
	inForce := f.agentRuleIDs(s.Now())
	for i, k := range gone {
		if i > 0 && gone[i-1] == k {
			continue
		}
		if settle(f.agentCopies(k[0], k[1], inForce, nil)) != nil {
			continue // still set through another rule
		}
		s.SyncEvent("leash.item.changed", strictjson.NewBuilder().String("agent_id", k[0]).String("item_id", k[1]).Bytes())
		s.Record(vault.Activity{Kind: "leash.item.changed", DeviceID: k[0], Ref: k[1], Audit: true})
	}
}

// --- entry points for the leash feature (called with its lock held) ---

// AgentWays returns the agent's settings for an item its rules (in force)
// include: nil for absent settings (["use"]); ok is false if none of them
// includes it (or it has no use left in one, as for every agent request).
func (f *Feature) AgentWays(agent string, rules []itemspec.AgentRule, itemID string) (*itemspec.ItemWays, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	incs, _ := f.agentIncls(agent, rules, itemID)
	if len(incs) == 0 {
		return nil, false
	}
	return settle(incs).Clone(), true
}

// AgentSetWays stores the agent's settings for an item on every inclusion
// of it by the agent's rules in force; false if none includes it.
func (f *Feature) AgentSetWays(agent string, rules []itemspec.AgentRule, itemID string, w *itemspec.ItemWays) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	incs, _ := f.agentIncls(agent, rules, itemID)
	if len(incs) == 0 {
		return false
	}
	for _, inc := range incs {
		inc.Ways = w.Clone()
	}
	return true
}

// AgentWaysList lists the settings of each item the agent's rules include
// (nil Ways: absent), sorted by item id.
func (f *Feature) AgentWaysList(agent string, rules []itemspec.AgentRule) []itemspec.AgentItemWays {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []itemspec.AgentItemWays
	for _, it := range f.sortedItems() {
		if incs, _ := f.agentIncls(agent, rules, it.ID); len(incs) > 0 {
			out = append(out, itemspec.AgentItemWays{ItemID: it.ID, Ways: settle(incs).Clone()})
		}
	}
	return out
}
