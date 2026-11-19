package items

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
)

// inForce is an AgentRules stand-in that lists the given rules as in force.
type inForce []string

func (r inForce) SetAgentRule(*vault.Session, *itemspec.AgentRule) (*itemspec.AgentRule, error) {
	return nil, nil
}
func (r inForce) DeleteAgentRule(*vault.Session, string) bool { return false }
func (r inForce) AgentRules(time.Time) []itemspec.AgentRule {
	var out []itemspec.AgentRule
	for _, id := range r {
		out = append(out, itemspec.AgentRule{ID: id, AgentID: "ag"})
	}
	return out
}

// Defence in depth (§10.11): a new inclusion never copies the settings of
// an inclusion whose rule is no longer in force (today expire drops those
// before any plan runs), nor of an inclusion included by the same change.
func TestCopyWaysOnlyFromRulesInForce(t *testing.T) {
	f := New(nil)
	wide := &itemspec.ItemWays{Version: 1, Ways: []string{itemspec.WayUse, itemspec.WayReveal}}
	f.st.Incl = map[string]map[string]*Inclusion{
		"gone": {"it": {State: StateIncluded, Agent: "ag", Ways: wide}},
		"new":  {"it": {State: StateIncluded, Agent: "ag"}},
		"new2": {"it": {State: StateIncluded, Agent: "ag", Ways: wide}}, // stands for a fresh one already given a value
	}
	f.agents = inForce{"new", "new2"}
	s := vault.NewSession(context.Background(), featuretest.NewHost(), vault.PeerInfo{}, time.Now(), nil)
	f.copyWays(s, [][2]string{{"new", "it"}, {"new2", "it"}})
	if f.st.Incl["new"]["it"].Ways != nil || f.st.Incl["new2"]["it"].Ways != nil {
		t.Fatal("copied from a rule not in force or from the same change")
	}
	// With the old rule in force, its settings are taken.
	f.st.Incl["new"]["it"].Ways = nil
	f.agents = inForce{"gone", "new"}
	f.copyWays(s, [][2]string{{"new", "it"}})
	if !f.st.Incl["new"]["it"].Ways.Equal(wide) || f.st.Incl["new"]["it"].Ways == wide {
		t.Fatal("not copied (deep) from a rule in force")
	}
}
