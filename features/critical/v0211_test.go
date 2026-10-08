package critical

import (
	"encoding/json"
	"testing"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

// VAULT-MESSAGING 0.21.1 (§15 item 29.7): errata to 0.21.0 from this
// implementation.

// §10.13 (0.21.1, point 6): an incoming use is checked usable, then
// suitable, then against the 8 pending requests per connection: an
// unsuitable request is answered unsuitable even at the cap, an unusable
// one unavailable whatever its kind.
func TestCheckOrder(t *testing.T) {
	clk := newClock()
	a := newSide(t, clk, 0x0a)
	a.h.AddConnection("conn-b")
	a.items.SetGuard(guard{})
	sid := a.setupKinds(
		map[string]any{"label": "Seed", "kind": "password", "value": ""}, // f1
		map[string]any{"label": "Count", "kind": "number", "value": "1"}, // f2
	)
	for i := 0; i < MaxPendingIn; i++ {
		a.askField(sid, "f1")
	}
	if len(a.f.Pending()) != MaxPendingIn {
		t.Fatalf("pending: %d", len(a.f.Pending()))
	}
	for _, c := range []struct{ item, field, want string }{
		{sid, "f2", StatusUnsuitable},          // suitable before the cap
		{sid, "f1", StatusUnavailable},         // the cap
		{sid, "f9", StatusUnavailable},         // usable before suitable: no such field
		{ulid(clk.T), "f2", StatusUnavailable}, // nor such item
	} {
		a.h.Reset()
		a.askField(c.item, c.field)
		res := a.h.SentOfType("critical-secret.result")
		if len(res) != 1 || field(t, res[0].Body, "status") != c.want {
			t.Fatalf("%s/%s: %+v, want %s", c.item, c.field, res, c.want)
		}
	}
	if len(a.f.Pending()) != MaxPendingIn {
		t.Fatal("a refused request was kept")
	}
}

// §10.13 (0.21.1, point 5): a request recorded before 0.21.0 has no kind.
// It is carried without kind while the vault cannot fill it in (the field
// is no longer usable), and with the field's current kind once it can;
// it expires within 24 h. Its approval still decides suitability.
func TestKindAbsentBefore021(t *testing.T) {
	clk := newClock()
	a := newSide(t, clk, 0x0a)
	a.h.AddConnection("conn-b")
	a.items.SetGuard(guard{})
	sid := a.setupKinds(map[string]any{"label": "Seed", "kind": "password", "value": ""})
	id := a.askField(sid, "f1")

	// The state as a 0.20.0 vault saved it: no kind.
	raw, err := a.f.Save()
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	for _, r := range st["in"].(map[string]any) {
		delete(r.(map[string]any), "kind")
	}
	old, _ := json.Marshal(st)
	if err := a.f.Load(old); err != nil {
		t.Fatal(err)
	}
	if a.f.d.In[id].Kind != "" {
		t.Fatal("kind still recorded")
	}
	hasKind := func(raw json.RawMessage) bool {
		o, err := strictjson.ParseObject(raw)
		if err != nil {
			t.Fatalf("%v: %s", err, raw)
		}
		return o.Has("kind")
	}
	listed := func() json.RawMessage {
		l := a.call(a.f, "app", "critical-secret-use.list", `{}`).Obj(t)
		in, _ := l.Array("incoming")
		if len(in) != 1 {
			t.Fatalf("incoming: %s", l["incoming"])
		}
		return in[0]
	}

	// The field is no longer usable (its rule is gone): kind stays absent
	// in .list and .get, and the saved state has none.
	rules := a.call(a.items, "app", "share.rule.list", `{}`).Obj(t)
	rs, _ := rules.Array("rules")
	ruleIDs := []string{}
	for _, r := range rs {
		o, _ := strictjson.ParseObject(r)
		rid, _ := o.String("rule_id")
		ruleIDs = append(ruleIDs, rid)
	}
	for _, rid := range ruleIDs {
		if r := a.call(a.items, "app", "share.rule.delete", `{"rule_id":"`+rid+`"}`); r.Code != "" {
			t.Fatalf("rule delete: %s", r.Code)
		}
	}
	if hasKind(listed()) {
		t.Fatal(".list carries a kind it does not know")
	}
	if g := a.call(a.f, "app", "critical-secret-use.get", `{"request_id":"`+id+`"}`); g.Code != "" || hasKind(g.Body) {
		t.Fatalf(".get: %s %s", g.Code, g.Body)
	}
	if raw, _ := a.f.Save(); hasKindIn(t, raw, id) {
		t.Fatal("saved with a kind")
	}

	// Usable again: the vault fills in the field's current kind.
	b, _ := json.Marshal(map[string]any{"subject": map[string]any{"connection_id": "conn-b"}, "tags": []string{"signing"}, "mode": "auto"})
	if r := a.call(a.items, "app", "share.rule.set", string(b)); !r.OK() {
		t.Fatalf("rule: %s", r.Code)
	}
	if o, _ := strictjson.ParseObject(listed()); func() string { k, _ := o.String("kind"); return k }() != "password" {
		t.Fatalf("kind not filled in: %s", o)
	}

	// Expired within 24 h of its arrival, kind or not.
	clk.Advance(RequestTTL)
	a.h.Reset()
	a.call(a.f, "app", "critical-secret-use.list", `{}`)
	if len(a.f.Pending()) != 0 || field(t, a.h.SentOfType("critical-secret.result")[0].Body, "status") != StatusExpired {
		t.Fatal("not expired")
	}
}

func hasKindIn(t *testing.T, raw json.RawMessage, id string) bool {
	t.Helper()
	var st struct {
		In map[string]map[string]any `json:"in"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	_, ok := st.In[id]["kind"]
	return ok
}
