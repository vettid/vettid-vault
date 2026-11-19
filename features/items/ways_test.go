package items_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/vault"
)

// Ways to use a secret (VAULT-MESSAGING §10.11, 0.42.0): the settings live
// as a copy on each of the agent's inclusions of the item. These tests use
// the real leash feature.

const agentID = "dev-agent"

func agentRule(tags ...string) map[string]any {
	return map[string]any{"subject": map[string]any{"agent_id": agentID}, "tags": tags, "mode": "auto"}
}

// copies are the settings on the agent's inclusions of the item under its
// rules in force.
func (e *env) copies(item string) []*itemspec.ItemWays {
	e.t.Helper()
	return e.set.Items.WaysCopies(agentID, item, e.clk.T)
}

// allEqual is the invariant: every copy of the agent's settings for the
// item is the same.
func (e *env) allEqual(item string) {
	e.t.Helper()
	cs := e.copies(item)
	for _, c := range cs[min(1, len(cs)):] {
		if !c.Equal(cs[0]) {
			e.t.Fatalf("copies differ: %s / %s", cs[0].JSON("", ""), c.JSON("", ""))
		}
	}
}

// listed is the item's entry of leash.item.list ("" if not listed).
func (e *env) listed(item string) string {
	e.t.Helper()
	o := e.ok(e.call("app", "leash.item.list", js(map[string]any{"agent_id": agentID, "item_id": item})))
	return strings.TrimSuffix(strings.TrimPrefix(string(o["items"]), "["), "]")
}

func (e *env) setWays(item string, version uint64, ways ...string) {
	e.t.Helper()
	body := map[string]any{"agent_id": agentID, "item_id": item, "ways": ways}
	if version > 0 {
		body["version"] = version
	}
	e.ok(e.call("app", "leash.item.set", js(body)))
}

// itemChanged counts the leash.item.changed sync events for the item, and
// those of them without a version (settings deleted).
func (e *env) itemChanged(item string) (all, deleted int) {
	for _, s := range e.sentTo("devices", "sync.event") {
		b := string(s.Body)
		if strings.Contains(b, `"kind":"leash.item.changed"`) && strings.Contains(b, `"item_id":"`+item+`"`) {
			all++
			if !strings.Contains(b, `"version"`) {
				deleted++
			}
		}
	}
	return all, deleted
}

func (e *env) auditedChanged(item string) int {
	n := 0
	for _, a := range e.h.Activities {
		if a.Kind == "leash.item.changed" && a.Ref == item && a.DeviceID == agentID && a.Audit {
			n++
		}
	}
	return n
}

// §10.11: copies stay equal through set, a rule added, a rule withdrawn;
// the settings go when the item is withdrawn from every rule of the agent
// (announced without version, audited), and a later inclusion starts at
// ["use"].
func TestWaysCopiesKeptEqual(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	e.unlock()
	doc := e.put("secret", "Doc", []string{"a", "b"}, field{Label: "Token", Kind: "password", Value: "tok"})
	e.rule(agentRule("a"))
	e.setWays(doc, 0, "use", "reveal")
	if cs := e.copies(doc); len(cs) != 1 || !cs[0].Has(itemspec.WayReveal) || cs[0].Version != 1 {
		t.Fatalf("one rule: %v", cs)
	}
	// A second rule including the item takes the copy.
	e.rule(agentRule("b"))
	if cs := e.copies(doc); len(cs) != 2 || !cs[1].Has(itemspec.WayReveal) {
		t.Fatalf("two rules: %d copies", len(cs))
	}
	e.allEqual(doc)
	// A set writes every copy.
	e.setWays(doc, 1, "use")
	e.allEqual(doc)
	if cs := e.copies(doc); cs[0].Version != 2 || cs[0].Has(itemspec.WayReveal) {
		t.Fatal("set did not reach the copies")
	}
	e.setWays(doc, 2, "use", "reveal")
	// Withdrawn from one rule: the settings stay, nothing announced.
	e.h.Reset()
	e.retag(doc, "b")
	if cs := e.copies(doc); len(cs) != 1 || !cs[0].Has(itemspec.WayReveal) || cs[0].Version != 3 {
		t.Fatalf("after one withdrawal: %v", cs)
	}
	if n, _ := e.itemChanged(doc); n != 0 {
		t.Fatal("announced while still set")
	}
	// Withdrawn from every rule: gone, announced once without version.
	e.retag(doc)
	if len(e.copies(doc)) != 0 {
		t.Fatal("settings outlived the last inclusion")
	}
	if n, del := e.itemChanged(doc); n != 1 || del != 1 || e.auditedChanged(doc) != 1 {
		t.Fatalf("deletion: %d events, %d without version, %d audited", n, del, e.auditedChanged(doc))
	}
	// Included again: ["use"], no version.
	e.retag(doc, "a", "b")
	if l := e.listed(doc); l != `{"agent_id":"dev-agent","item_id":"`+doc+`","ways":["use"]}` {
		t.Fatalf("re-included: %s", l)
	}
	for _, c := range e.copies(doc) {
		if c != nil {
			t.Fatal("a re-included item kept settings")
		}
	}
}

// Lead's note (GC #14226): a missed copy fails secure. Copies that differ
// count as absent (["use"]), never the wider one; a new inclusion does not
// copy from them; a set without version makes them equal again.
func TestWaysMissedCopyFailsSecure(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	e.unlock()
	doc := e.put("secret", "Doc", []string{"a", "b", "c"}, field{Label: "Token", Kind: "password", Value: "tok"})
	e.rule(agentRule("a"))
	e.setWays(doc, 0, "use", "reveal")
	e.rule(agentRule("b"))
	// Simulate a path that missed the copy: one inclusion without it.
	e.set.Items.DropWaysCopies(agentID, doc, e.clk.T)
	if l := e.listed(doc); l != `{"agent_id":"dev-agent","item_id":"`+doc+`","ways":["use"]}` {
		t.Fatalf("differing copies: %s", l)
	}
	// Reading them made "absent" stored: the wider copy is cleared, so it
	// cannot come back when the others go (review finding 2).
	for _, c := range e.copies(doc) {
		if c != nil {
			t.Fatal("a differing copy kept")
		}
	}
	// A third rule copies nothing from copies that differ.
	e.rule(agentRule("c"))
	if cs := e.copies(doc); len(cs) != 3 || cs[2] != nil {
		t.Fatalf("copied from differing copies: %v", cs)
	}
	// The member's next set (absent settings: no version) repairs them.
	e.code(e.call("app", "leash.item.set", js(map[string]any{"agent_id": agentID, "item_id": doc, "version": 1, "ways": []string{"use"}})), "conflict")
	e.setWays(doc, 0, "use", "reveal")
	e.allEqual(doc)
	if cs := e.copies(doc); len(cs) != 3 || !cs[0].Has(itemspec.WayReveal) {
		t.Fatal("not repaired")
	}
}

// §10.11 "Settings exist while at least one rule of the agent includes the
// item": a change that moves the item from one of the agent's auto rules
// to another never leaves it without one, so the settings carry over and
// nothing is announced (review finding 1). A move to an ask rule leaves it
// pending, included nowhere: the settings go.
func TestWaysMoveBetweenRules(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	e.unlock()
	doc := e.put("secret", "Doc", []string{"a"}, field{Label: "Token", Kind: "password", Value: "tok"})
	e.rule(agentRule("a"))
	e.rule(agentRule("b"))
	e.setWays(doc, 0, "use", "reveal")
	e.h.Reset()
	e.retag(doc, "b") // out of a, into b, in one change
	if cs := e.copies(doc); len(cs) != 1 || !cs[0].Has(itemspec.WayReveal) || cs[0].Version != 1 {
		t.Fatalf("after the move: %v", cs)
	}
	if n, _ := e.itemChanged(doc); n != 0 || e.auditedChanged(doc) != 0 {
		t.Fatal("a move announced as a deletion")
	}
	// To an ask rule: pending only, so the settings go.
	ask := agentRule("c")
	ask["mode"] = "ask"
	e.rule(ask)
	e.h.Reset()
	e.retag(doc, "c")
	if len(e.copies(doc)) != 0 {
		t.Fatal("settings while only pending")
	}
	if _, del := e.itemChanged(doc); del != 1 {
		t.Fatal("not announced")
	}
}

// An agent rule that expires takes the settings with it; the end is
// announced when this feature next handles a request.
func TestWaysRuleExpiry(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	e.unlock()
	doc := e.put("secret", "Doc", []string{"a"}, field{Label: "Token", Kind: "password", Value: "tok"})
	r := agentRule("a")
	r["expires_at"] = e.clk.T.Add(time.Hour).Format("2006-01-02T15:04:05.000Z")
	e.rule(r)
	e.setWays(doc, 0, "use", "reveal")
	e.clk.Advance(2 * time.Hour)
	e.h.Reset()
	e.ok(e.call("app", "item.list", `{}`))
	if len(e.copies(doc)) != 0 || e.set.Items.AnyWays(doc) {
		t.Fatal("settings outlived the expired rule")
	}
	if _, del := e.itemChanged(doc); del != 1 {
		t.Fatal("expiry not announced")
	}
}

// A rule revoked through leash (its inclusions linger in this feature
// until the next change): a new rule never copies from it, and the
// settings' end is announced when the lingering inclusion goes.
func TestWaysRevokedRule(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	e.unlock()
	doc := e.put("secret", "Doc", []string{"a", "b"}, field{Label: "Token", Kind: "password", Value: "tok"})
	ra := e.rule(agentRule("a"))
	e.setWays(doc, 0, "use", "reveal")
	e.h.Reset()
	e.ok(e.call("app", "leash.grant.revoke", js(map[string]any{"grant_id": ra})))
	e.rule(agentRule("b"))
	if cs := e.copies(doc); len(cs) != 1 || cs[0] != nil {
		t.Fatalf("new rule after a revoked one: %v", cs)
	}
	if _, del := e.itemChanged(doc); del != 1 {
		t.Fatalf("end not announced: %d", del)
	}
}

// A change refused (outside the unlock window, or a bad decide) leaves the
// copies as they were; a decline that withdraws the item from the agent's
// other rule deletes them.
func TestWaysRefusedAndDeclined(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	e.unlock()
	doc := e.put("secret", "Doc", []string{"a", "b"}, field{Label: "Token", Kind: "password", Value: "tok"})
	e.rule(agentRule("a"))
	e.setWays(doc, 0, "use", "reveal")
	before := e.copies(doc)[0].Clone()
	// A rule set outside the window is refused whole.
	e.ok(e.call("app", "credential.lock", `{}`))
	e.code(e.call("app", "share.rule.set", js(agentRule("b"))), "credential_locked")
	if cs := e.copies(doc); len(cs) != 1 || !cs[0].Equal(before) {
		t.Fatal("refused rule changed the copies")
	}
	e.code(e.call("app", "share.decide", js(map[string]any{"rule_id": "01JB2Z6V9K3M4N5P6Q7R8S9T0V", "include": []string{doc}})), "not_found")
	e.allEqual(doc)
	// Widening outside the window: refused, nothing changed.
	e.code(e.call("app", "leash.item.set", js(map[string]any{"agent_id": agentID, "item_id": doc, "version": 1,
		"ways": []string{"use", "reveal", "run"}, "run": map[string]any{"programs": []any{}}})), "credential_locked")
	if cs := e.copies(doc); len(cs) != 1 || !cs[0].Equal(before) {
		t.Fatal("refused widening changed the copies")
	}
	// An ask rule holds the item pending; declining it there withdraws it
	// from the auto rule too (§10.12): the settings go.
	e.unlock()
	ask := agentRule("b")
	ask["mode"] = "ask"
	rb := e.rule(ask)
	e.h.Reset()
	e.ok(e.call("app", "share.decide", js(map[string]any{"rule_id": rb, "decline": []string{doc}})))
	if len(e.copies(doc)) != 0 {
		t.Fatal("settings after the decline")
	}
	if _, del := e.itemChanged(doc); del != 1 {
		t.Fatal("decline not announced")
	}
}

// Deleting the item, or unlinking the agent, takes the settings with it.
func TestWaysItemDeletedAndUnlink(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	e.unlock()
	doc := e.put("secret", "Doc", []string{"a"}, field{Label: "Token", Kind: "password", Value: "tok"})
	doc2 := e.put("secret", "Doc2", []string{"a"}, field{Label: "Token", Kind: "password", Value: "tok2"})
	e.rule(agentRule("a"))
	e.setWays(doc, 0, "use", "reveal")
	e.setWays(doc2, 0, "use", "reveal")
	e.h.Reset()
	e.ok(e.call("app", "item.delete", js(map[string]any{"item_id": doc, "version": e.version(doc)})))
	if len(e.copies(doc)) != 0 {
		t.Fatal("settings of a deleted item")
	}
	if _, del := e.itemChanged(doc); del != 1 {
		t.Fatal("deletion not announced")
	}
	if !e.set.Items.AnyWays(doc2) {
		t.Fatal("doc2 lost its settings early")
	}
	s := vault.NewSession(context.TODO(), e.h, vault.PeerInfo{}, e.clk.T, nil)
	e.set.Leash.DeviceRemoved(s, agentID)
	e.set.Items.DeviceRemoved(s, agentID)
	if e.set.Items.AnyWays(doc2) {
		t.Fatal("settings outlived the agent")
	}
}
