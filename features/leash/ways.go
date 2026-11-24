package leash

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/strictjson"
)

// Ways to use a secret (VAULT-MESSAGING §10.11, 0.42.0; 0.85.3): the
// member's settings per agent and included item, leash.item.set and
// leash.item.list. The items feature keeps them (with the agent's
// inclusions of the item, so they go when the item is withdrawn from every
// rule of the agent); this feature parses, checks and enforces them.

// Approval flags the vault sets (approval.pending{flags}, §10.11, 0.42.0).
// item.run's (shell, inline_code, unbound_program, program_unrecorded,
// program_changed, member_folder, member_files) come with item.run
// (AGENT-PLAN AV10).
const FlagHistory = "history" // an item.get: the agent's app may keep the value in its history

// wayNotAllowed is the answer to a request of a way the item's settings do
// not hold: way_not_allowed with the ways they do (§10.11).
func wayNotAllowed(w *itemspec.ItemWays) error {
	return &vault.HandlerError{Code: "way_not_allowed", Body: strictjson.NewBuilder().Raw("ways", itemspec.StrList(w.WayList())).Bytes()}
}

// catalogEntry is one item of the catalog (§10.11): its metadata, its
// ways and, when present, its programs ({program, env, path?}: the pinned
// path, never the hash), (0.93.0) folders ([{path, write}], an empty list
// when none, for every item with a run way) and hosts (never header or
// prefix).
func catalogEntry(e itemspec.AgentEntry) []byte {
	b := strictjson.NewBuilder().String("item_id", e.Meta.ItemID).String("name", e.Meta.Name).String("category", e.Meta.Category).
		Raw("labels", itemspec.LabelsJSON(e.Meta.Labels)).Raw("ways", itemspec.StrList(e.Ways.WayList()))
	if p := e.Ways.CatalogPrograms(); p != nil {
		b.Raw("programs", p)
	}
	if f := e.Ways.CatalogFolders(); f != nil {
		b.Raw("folders", f)
	}
	if h := e.Ways.CatalogHosts(); h != nil {
		b.Raw("hosts", h)
	}
	return b.Bytes()
}

// windowChecker is the credential feature's check of the unlock window
// that does not extend it (credential.Feature.WindowOpen).
type windowChecker interface {
	WindowOpen(now time.Time) bool
}

// windowOpen reports whether the credential's unlock window is open. A key
// user that cannot say counts as closed (fail secure).
func (f *Feature) windowOpen(s *vault.Session) bool {
	wc, ok := f.keys.(windowChecker)
	return ok && wc.WindowOpen(s.Now())
}

// itemRules is the agent's share rules (items.read grants) in force.
func (f *Feature) itemRules(agent string, now time.Time) []itemspec.AgentRule {
	return rulesOf(f.matching(agent, ScopeItems, "", "", now))
}

// activeAgent reports whether id names an active device of role agent.
func activeAgent(s *vault.Session, id string) bool {
	d, ok := s.PairedDevice(id)
	return ok && d.Kind == vault.KindAgent
}

// itemSet handles leash.item.set (app): {agent_id, item_id, version?,
// ways, run?, proxy?}. version is required to replace existing settings
// and refused when there are none (conflict). A widening needs the unlock
// window (credential_locked); narrowing does not.
func (f *Feature) itemSet(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	agentID, err := o.String("agent_id")
	if err != nil || agentID == "" {
		return nil, errBad
	}
	itemID, err := o.String("item_id")
	if err != nil || !envelope.ValidULID(itemID) {
		return nil, errBad
	}
	ver, hasVer, err := o.OptUint("version", 1, strictjson.MaxSafeInteger)
	if err != nil {
		return nil, errBad
	}
	if !activeAgent(s, agentID) || f.items == nil {
		return nil, errNotFound
	}
	now := s.Now()
	rules := f.itemRules(agentID, now)
	cur, ok := f.items.AgentMemberWays(agentID, rules, itemID)
	if !ok {
		return nil, errNotFound // no rule of the agent includes the item (a use left or not)
	}
	if hasVer != (cur != nil) || cur != nil && cur.Version != ver {
		return nil, errConflict
	}
	next, err := itemspec.ParseWays(o, cur)
	if err != nil {
		// (0.93.2) error.message names the member and the rule broken
		// (§10.11 "Why a setting is refused").
		var r *itemspec.Refusal
		if errors.As(err, &r) {
			return nil, vault.NewError("bad_request", r.Message())
		}
		return nil, errBad
	}
	if itemspec.Widens(cur, next) && !f.windowOpen(s) {
		return nil, errLocked // widening needs the member, as issuing a grant does
	}
	next.Version = 1
	if cur != nil {
		next.Version = cur.Version + 1
	}
	next.Updated = now.UTC().Truncate(time.Millisecond)
	if !f.items.AgentSetWays(agentID, rules, itemID, next) {
		return nil, errNotFound
	}
	s.SyncEvent("leash.item.changed", strictjson.NewBuilder().String("agent_id", agentID).String("item_id", itemID).
		Uint("version", next.Version).Bytes())
	s.Record(vault.Activity{Kind: "leash.item.changed", DeviceID: agentID, Ref: itemID, Audit: true})
	return next.JSON(agentID, itemID), nil
}

// itemList handles leash.item.list (app, desktop): {agent_id, item_id?}:
// the settings of each item the agent's rules include (absent settings as
// {agent_id, item_id, ways: ["use"]}), only item_id's when it is given.
func (f *Feature) itemList(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	agentID, err := o.String("agent_id")
	if err != nil || agentID == "" {
		return nil, errBad
	}
	itemID, hasItem, err := o.OptString("item_id")
	if err != nil || hasItem && !envelope.ValidULID(itemID) {
		return nil, errBad
	}
	if !activeAgent(s, agentID) {
		return nil, errNotFound
	}
	arr := []byte{'['}
	if f.items != nil {
		n := 0
		for _, e := range f.items.AgentWaysList(agentID, f.itemRules(agentID, s.Now())) {
			if hasItem && e.ItemID != itemID {
				continue
			}
			if n > 0 {
				arr = append(arr, ',')
			}
			arr = append(arr, e.Ways.JSON(agentID, e.ItemID)...)
			n++
		}
	}
	return strictjson.NewBuilder().Raw("items", append(arr, ']')).Bytes(), nil
}
