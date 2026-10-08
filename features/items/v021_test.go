package items_test

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/grants"
	"github.com/vettid/vettid-vault/features/items"
	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// VAULT-MESSAGING 0.21.0 (§15 item 29): kept values on every replacement,
// the item's size, dry runs, named limits, share.pending.list and
// share.decide{include, decline}.

// revealed returns a secret item's values: field id → value, and notes.
func (e *env) revealed(id string) (map[string]string, string) {
	e.t.Helper()
	o := e.ok(e.call("app", "item.reveal", js(map[string]any{"item_id": id})))
	return valuesOf(e.t, o["fields"]), notesOf(o)
}

func valuesOf(t *testing.T, raw []byte) map[string]string {
	t.Helper()
	var fs []struct {
		ID    string          `json:"field_id"`
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &fs); err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, f := range fs {
		m[f.ID] = string(f.Value)
	}
	return m
}

func notesOf(o strictjson.Object) string {
	n, _, _ := o.OptString("notes")
	return n
}

func (e *env) limit(r featuretest.Result, name string) strictjson.Object {
	e.t.Helper()
	if r.Code != "limit" {
		e.t.Fatalf("code %q, want limit %s", r.Code, name)
	}
	o, err := strictjson.ParseObject(r.Body)
	if err != nil {
		e.t.Fatalf("limit without a body: %s", r.Body)
	}
	if n, _ := o.String("limit"); n != name {
		e.t.Fatalf("limit %s, want %s: %s", n, name, r.Body)
	}
	if _, err := o.Uint("max", 1, 1<<53); err != nil {
		e.t.Fatalf("limit without max: %s", r.Body)
	}
	return o
}

// §10.7 Kept values: a data or secret replacement keeps the stored value
// of a field sent with its field_id and without value (its kind
// unchanged; label and position may change) and the notes with
// keep_notes; a secret edit is not a reveal.
func TestKeptValuesDataSecret(t *testing.T) {
	for _, sens := range []string{"data", "secret"} {
		t.Run(sens, func(t *testing.T) {
			e := newEnv(t)
			id := e.put(sens, "Login", nil, field{Label: "User", Kind: "text", Value: "ada"},
				field{Label: "Password", Kind: "password", Value: "old-pw"}, field{Label: "Site", Kind: "url", Value: "https://x.test"})
			e.ok(e.call("app", "item.put", js(map[string]any{"item_id": id, "version": 1, "name": "Login", "notes": "the old notes",
				"fields": []any{map[string]any{"field_id": "f1", "label": "User", "kind": "text"},
					map[string]any{"field_id": "f2", "label": "Password", "kind": "password"},
					map[string]any{"field_id": "f3", "label": "Site", "kind": "url"}}})))
			e.h.Reset()
			// Reorder, relabel f2 and keep it, replace f1, drop f3, add f4,
			// keep the notes.
			e.ok(e.call("app", "item.put", js(map[string]any{"item_id": id, "version": 2, "name": "Login", "keep_notes": true,
				"fields": []any{map[string]any{"field_id": "f2", "label": "Passphrase", "kind": "password"},
					map[string]any{"field_id": "f1", "label": "User", "kind": "text", "value": "ada2"},
					map[string]any{"label": "PIN", "kind": "number", "value": "1234"}}})))
			if e.h.HasActivity("item.revealed") || !e.h.HasActivity("item.updated") {
				t.Fatalf("activities: %+v", e.h.Activities)
			}
			for _, s := range e.h.Sent {
				if bytes.Contains(s.Body, []byte("old-pw")) {
					t.Fatalf("a kept value left the vault: %s %s", s.Type, s.Body)
				}
			}
			vals, notes := e.revealed(id)
			if vals["f2"] != `"old-pw"` || vals["f1"] != `"ada2"` || vals["f4"] != `"1234"` || len(vals) != 3 || notes != "the old notes" {
				t.Fatalf("after the edit: %v %q", vals, notes)
			}
			it := e.item(id)
			var fs []struct {
				ID    string `json:"field_id"`
				Label string `json:"label"`
			}
			_ = json.Unmarshal(it["fields"], &fs)
			if len(fs) != 3 || fs[0].ID != "f2" || fs[0].Label != "Passphrase" || fs[1].ID != "f1" || fs[2].ID != "f4" {
				t.Fatalf("order and labels: %s", it["fields"])
			}
			// Neither notes nor keep_notes: the notes go, as before.
			e.ok(e.call("app", "item.put", js(map[string]any{"item_id": id, "version": 3, "name": "Login",
				"fields": []any{map[string]any{"field_id": "f2", "label": "P", "kind": "password"}}})))
			if vals, notes := e.revealed(id); notes != "" || vals["f2"] != `"old-pw"` || len(vals) != 1 {
				t.Fatalf("notes removed: %v %q", vals, notes)
			}
			v := uint64(4)
			for _, bad := range []map[string]any{
				// A kept field must keep its kind.
				{"fields": []any{map[string]any{"field_id": "f2", "label": "P", "kind": "text"}}},
				// A field the item does not have.
				{"fields": []any{map[string]any{"field_id": "f9", "label": "P", "kind": "password"}}},
				// A new field needs a value.
				{"fields": []any{map[string]any{"label": "P", "kind": "password"}}},
				// notes and keep_notes together.
				{"notes": "n", "keep_notes": true},
				{"keep_notes": "yes"},
			} {
				body := map[string]any{"item_id": id, "version": v, "name": "Login"}
				for k, x := range bad {
					body[k] = x
				}
				e.code(e.call("app", "item.put", js(body)), "bad_request")
			}
			// A new item keeps nothing.
			e.code(e.call("app", "item.put", js(map[string]any{"name": "N", "sensitivity": sens, "keep_notes": true})), "bad_request")
			e.code(e.call("app", "item.put", js(map[string]any{"name": "N", "sensitivity": sens,
				"fields": []any{map[string]any{"field_id": "f1", "label": "P", "kind": "password"}}})), "bad_request")
			// keep_notes false is the default.
			e.ok(e.call("app", "item.put", js(map[string]any{"item_id": id, "version": v, "name": "Login", "keep_notes": false})))
			// The size limit counts the kept values.
			big := strings.Repeat("v", 16000)
			id2 := e.put(sens, "Big", nil, field{Label: "A", Kind: "multiline", Value: big}, field{Label: "B", Kind: "multiline", Value: big},
				field{Label: "C", Kind: "multiline", Value: big})
			o := e.limit(e.call("app", "item.put", js(map[string]any{"item_id": id2, "version": 1, "name": "Big",
				"fields": []any{map[string]any{"field_id": "f1", "label": "A", "kind": "multiline"},
					map[string]any{"field_id": "f2", "label": "B", "kind": "multiline"},
					map[string]any{"field_id": "f3", "label": "C", "kind": "multiline"},
					map[string]any{"label": "D", "kind": "multiline", "value": big},
					map[string]any{"label": "E", "kind": "multiline", "value": big}}})), "item_size")
			if size, err := o.Uint("size", 0, 1<<53); err != nil || size <= itemspec.MaxItemBytes {
				t.Fatalf("size: %d %v", size, err)
			}
			if max, _ := o.Uint("max", 0, 1<<53); max != itemspec.MaxItemBytes {
				t.Fatalf("max %d", max)
			}
		})
	}
}

// §10.7 Kept values, critical: one credential operation; the vault opens
// the stored values with the current key, merges, seals under the next
// generation and wipes the plaintext it opened.
func TestKeptValuesCritical(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	id := e.putCritical("Vault key", []string{"keys"}, field{Label: "Seed", Kind: "password", Value: "STORED-SEED-VALUE"},
		field{Label: "Hint", Kind: "text", Value: "old hint"}, field{Label: "Home", Kind: "address", Value: map[string]string{"city": "Oslo"}})
	// Give it notes (every value sent, as before 0.21.0).
	e.ok(e.sealed("app", "item.put", map[string]any{"sensitivity": "critical", "version": 1},
		map[string]any{"password": pw, "item_id": id, "item": map[string]any{"name": "Vault key", "notes": "stored notes",
			"fields": []field{{ID: "f1", Label: "Seed", Kind: "password", Value: "STORED-SEED-VALUE"},
				{ID: "f2", Label: "Hint", Kind: "text", Value: "old hint"}, {ID: "f3", Label: "Home", Kind: "address", Value: map[string]string{"city": "Oslo"}}}}},
		true, false))
	gen := func() uint64 {
		for _, it := range e.set.Items.Items() {
			if it.ID == id {
				return it.Gen
			}
		}
		t.Fatal("item gone")
		return 0
	}
	g0 := gen()
	var opened map[string][]byte
	items.SetKeptHook(func(m map[string][]byte) { opened = m })
	defer items.SetKeptHook(nil)
	e.h.Reset()
	// Only the hint changes; the seed, the address and the notes are kept;
	// the address field moves first.
	o := e.ok(e.sealed("app", "item.put", map[string]any{"sensitivity": "critical", "version": 2},
		map[string]any{"password": pw, "item_id": id, "item": map[string]any{"name": "Vault key", "keep_notes": true,
			"fields": []any{map[string]any{"field_id": "f3", "label": "Home", "kind": "address"},
				map[string]any{"field_id": "f1", "label": "Seed", "kind": "password"},
				map[string]any{"field_id": "f2", "label": "Hint", "kind": "text", "value": "new hint"}}}}, true, false))
	if !o.Has("credential_version") {
		t.Fatal("not one credential operation")
	}
	if gen() != g0+1 {
		t.Fatalf("generation %d → %d", g0, gen())
	}
	// The plaintext the vault opened is wiped.
	if len(opened) != 3 {
		t.Fatalf("opened: %d values", len(opened))
	}
	for fid, b := range opened {
		if len(b) == 0 || bytes.Count(b, []byte{0}) != len(b) {
			t.Fatalf("value of %s not wiped: %q", fid, b)
		}
	}
	if e.h.HasActivity("item.revealed") || !e.h.HasActivity("item.updated") {
		t.Fatalf("activities: %+v", e.h.Activities)
	}
	raw, _ := e.set.Items.Save()
	if bytes.Contains(raw, []byte("STORED-SEED")) || bytes.Contains(raw, []byte("new hint")) || bytes.Contains(raw, []byte("stored notes")) {
		t.Fatal("critical values in DEK state")
	}
	for _, s := range e.h.Sent {
		if bytes.Contains(s.Body, []byte("STORED-SEED")) {
			t.Fatalf("a kept value left the vault: %s", s.Type)
		}
	}
	// The reveal shows the merge.
	r := e.ok(e.sealed("app", "item.reveal", map[string]any{"item_id": id}, map[string]any{"password": pw, "item_id": id}, true, true))
	sv, _ := r.Base64("values_sealed", -1)
	pt, err := openReply(e, sv)
	if err != nil {
		t.Fatal(err)
	}
	v, err := items.ParseValues(pt)
	if err != nil || string(v.Fields["f1"]) != `"STORED-SEED-VALUE"` || string(v.Fields["f2"]) != `"new hint"` ||
		string(v.Fields["f3"]) != `{"city":"Oslo"}` || v.Notes != "stored notes" {
		t.Fatalf("merged values: %s", pt)
	}
	ver := e.version(id)
	put := func(item map[string]any) featuretest.Result {
		return e.sealed("app", "item.put", map[string]any{"sensitivity": "critical", "version": ver},
			map[string]any{"password": pw, "item_id": id, "item": item}, true, false)
	}
	// A kept field keeps its kind; notes with keep_notes; a new field
	// without value; keep_notes outside the sealed item.
	e.code(put(map[string]any{"name": "K", "fields": []any{map[string]any{"field_id": "f1", "label": "Seed", "kind": "text"}}}), "bad_request")
	e.code(put(map[string]any{"name": "K", "notes": "x", "keep_notes": true}), "bad_request")
	e.code(put(map[string]any{"name": "K", "fields": []any{map[string]any{"label": "New", "kind": "text"}}}), "bad_request")
	e.code(e.sealed("app", "item.put", map[string]any{"sensitivity": "critical", "version": ver, "keep_notes": true},
		map[string]any{"password": pw, "item_id": id, "item": map[string]any{"name": "K"}}, true, false), "bad_request")
	// A new critical item keeps nothing.
	e.code(e.sealed("app", "item.put", map[string]any{"sensitivity": "critical"},
		map[string]any{"password": pw, "item": map[string]any{"name": "N", "keep_notes": true}}, true, false), "bad_request")
	// The 12,288-byte limit counts the kept values.
	bigID := e.putCritical("Big", nil, field{Label: "A", Kind: "multiline", Value: strings.Repeat("x", 12000)})
	r2 := e.sealed("app", "item.put", map[string]any{"sensitivity": "critical", "version": 1},
		map[string]any{"password": pw, "item_id": bigID, "item": map[string]any{"name": "Big",
			"fields": []any{map[string]any{"field_id": "f1", "label": "A", "kind": "multiline"},
				map[string]any{"label": "B", "kind": "text", "value": strings.Repeat("y", 400)}}}}, true, false)
	lo := e.limit(r2, "item_size")
	if size, _ := lo.Uint("size", 0, 1<<53); size <= itemspec.MaxCritBytes {
		t.Fatalf("size %d", size)
	}
	if max, _ := lo.Uint("max", 0, 1<<53); max != itemspec.MaxCritBytes {
		t.Fatalf("max %d", max)
	}
}

// §10.7 Size (0.21.0): the content encoding without the members the vault
// assigns, with the exact escapes; item.get returns it for every
// sensitivity, item.list never.
func TestItemSize(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	val := "a\"b\\c\nd\te\u2028f\u2029g<&>é"
	want := `{"name":"Note","category":"note","sensitivity":"data","template":"note.v1","tags":["x"],` +
		`"fields":[{"label":"Body","kind":"multiline","value":"a\"b\\c\nd\te\u2028f\u2029g<&>é"},` +
		`{"label":"Home","kind":"address","value":{"street":"1 Main","city":"Oslo","country":"NO"}}],"notes":"n"}`
	body := map[string]any{"name": "Note", "category": "note", "template": "note.v1", "tags": []string{"x"}, "notes": "n",
		"fields": []any{map[string]any{"label": "Body", "kind": "multiline", "value": val},
			map[string]any{"label": "Home", "kind": "address", "value": map[string]string{"country": "NO", "city": "Oslo", "street": "1 Main", "region": ""}}}}
	o := e.ok(e.call("app", "item.put", js(body)))
	id, _ := o.String("item_id")
	size := func(id string) (uint64, bool) {
		it := e.item(id)
		n, present, err := it.OptUint("size", 0, 1<<53)
		if err != nil {
			t.Fatal(err)
		}
		return n, present
	}
	if n, ok := size(id); !ok || n != uint64(len(want)) {
		t.Fatalf("data size %d, want %d", n, len(want))
	}
	// An empty item: tags and fields always, template and notes not.
	id0 := e.put("secret", "E", nil)
	if n, _ := size(id0); n != uint64(len(`{"name":"E","category":"other","sensitivity":"secret","tags":[],"fields":[]}`)) {
		t.Fatalf("empty secret size %d", n)
	}
	// A critical item: recorded when written, kept across a tag change.
	cid := e.putCritical("C", nil, field{Label: "K", Kind: "password", Value: "v"})
	cwant := `{"name":"C","category":"other","sensitivity":"critical","tags":[],"fields":[{"label":"K","kind":"password","value":"v"}]}`
	if n, ok := size(cid); !ok || n != uint64(len(cwant)) {
		t.Fatalf("critical size %d, want %d", n, len(cwant))
	}
	e.retag(cid, "abc")
	if n, _ := size(cid); n != uint64(len(cwant)+len(`"abc"`)) {
		t.Fatalf("critical size after a tag change: %d", n)
	}
	// Not in item.list.
	l := e.ok(e.call("app", "item.list", `{}`))
	if bytes.Contains(l["items"], []byte(`"size"`)) {
		t.Fatalf("size in item.list: %s", l["items"])
	}
	// A critical item last written before 0.21.0 has no size until its
	// values open.
	raw, _ := e.set.Items.Save()
	var st map[string]any
	_ = json.Unmarshal(raw, &st)
	delete(st["items"].(map[string]any)[cid].(map[string]any), "size_no_tags")
	raw, _ = json.Marshal(st)
	if err := e.set.Items.Load(raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := size(cid); ok {
		t.Fatal("a size before the values opened")
	}
	e.ok(e.sealed("app", "item.reveal", map[string]any{"item_id": cid}, map[string]any{"password": pw, "item_id": cid}, true, true))
	if n, ok := size(cid); !ok || n != uint64(len(cwant)+len(`"abc"`)) {
		t.Fatalf("size recorded at the reveal: %d %v", n, ok)
	}
	// Never to a connection: a readable item's grant and profile.
	e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"x"}, "mode": "auto"})
	if len(e.sentTo("cA", "data.shared")) == 0 {
		t.Fatal("no grant")
	}
	for _, s := range e.h.Sent {
		if s.To == "cA" && bytes.Contains(s.Body, []byte(`"size"`)) {
			t.Fatalf("size sent in %s: %s", s.Type, s.Body)
		}
	}
	// The grants bound MaxGivenGrants mirrors.
	if items.MaxGivenGrants != grants.MaxGiven {
		t.Fatal("MaxGivenGrants")
	}
}

type dryAnswer struct {
	Version *uint64 `json:"version"`
	Shares  []struct {
		RuleID  string            `json:"rule_id"`
		Subject map[string]string `json:"subject"`
		Mode    string            `json:"mode"`
		Usable  *bool             `json:"usable"`
	} `json:"shares"`
	Withdrawals []struct {
		RuleID  string            `json:"rule_id"`
		Subject map[string]string `json:"subject"`
		State   string            `json:"state"`
	} `json:"withdrawals"`
}

func (e *env) dry(kind, typ string, body map[string]any) dryAnswer {
	e.t.Helper()
	body["dry_run"] = true
	r := e.call(kind, typ, js(body))
	if !r.OK() {
		e.t.Fatalf("%s dry run: %s", typ, r.Code)
	}
	var a dryAnswer
	if err := json.Unmarshal(r.Body, &a); err != nil || a.Shares == nil || a.Withdrawals == nil {
		e.t.Fatalf("dry run answer: %s", r.Body)
	}
	return a
}

// §10.7 Dry run (0.21.0): item.put and item.tag with dry_run answer the
// rules the item would gain or leave, change nothing and send nothing.
func TestDryRun(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	ask := e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"work"}})
	auto := e.rule(map[string]any{"subject": conn("cB"), "tags": []string{"work", "home"}, "mode": "auto"})
	id := e.put("data", "Doc", nil, field{Label: "N", Kind: "text", Value: "v"})
	snapshot := func() []byte { raw, _ := e.set.Items.Save(); return raw }
	before := snapshot()
	e.h.Reset()
	a := e.dry("app", "item.tag", map[string]any{"item_id": id, "version": 1, "tags": []string{"work"}})
	if a.Version == nil || *a.Version != 1 || len(a.Shares) != 2 || len(a.Withdrawals) != 0 {
		t.Fatalf("tag dry run: %+v", a)
	}
	ids := []string{ask, auto}
	sort.Strings(ids)
	modes := map[string]string{ask: "ask", auto: "auto"}
	for i, s := range a.Shares {
		if s.RuleID != ids[i] || s.Mode != modes[s.RuleID] || s.Usable != nil {
			t.Fatalf("share %d: %+v", i, s)
		}
	}
	if a.Shares[0].Subject["connection_id"] == "" {
		t.Fatalf("subject: %+v", a.Shares[0])
	}
	if !bytes.Equal(before, snapshot()) || len(e.h.Sent) != 0 || len(e.h.Activities) != 0 {
		t.Fatalf("a dry run changed something: %d sent, %d activities", len(e.h.Sent), len(e.h.Activities))
	}
	// item.put: a new item (no version), and the existing one (content
	// members ignored).
	n := e.dry("app", "item.put", map[string]any{"tags": []string{"home"}, "name": "ignored", "fields": "not even a list"})
	if n.Version != nil || len(n.Shares) != 1 || n.Shares[0].RuleID != auto || n.Shares[0].Mode != "auto" {
		t.Fatalf("new item dry run: %+v", n)
	}
	p := e.dry("app", "item.put", map[string]any{"item_id": id, "version": 1, "tags": []string{"work"}})
	if len(p.Shares) != 2 {
		t.Fatalf("put dry run: %+v", p)
	}
	if q := e.dry("app", "item.put", map[string]any{"item_id": id, "version": 1}); len(q.Shares) != 0 || len(q.Withdrawals) != 0 {
		t.Fatalf("tags absent: no change: %+v", q)
	}
	// Really tag it: cA pending, cB included; then a dry run of untagging.
	e.retag(id, "work")
	w := e.dry("app", "item.tag", map[string]any{"item_id": id, "version": 2, "tags": []string{}})
	if len(w.Withdrawals) != 2 || len(w.Shares) != 0 {
		t.Fatalf("withdrawals: %+v", w)
	}
	states := map[string]string{}
	for _, x := range w.Withdrawals {
		states[x.RuleID] = x.State
	}
	if states[ask] != "pending" || states[auto] != "included" || w.Withdrawals[0].RuleID > w.Withdrawals[1].RuleID {
		t.Fatalf("withdrawal states: %+v", w)
	}
	// A critical item is only usable through a connection rule.
	cid := e.putCritical("Key", nil, field{Label: "S", Kind: "password", Value: "x"})
	c := e.dry("app", "item.tag", map[string]any{"item_id": cid, "version": 1, "tags": []string{"home"}})
	if len(c.Shares) != 1 || c.Shares[0].Usable == nil || !*c.Shares[0].Usable {
		t.Fatalf("critical dry run: %+v", c)
	}
	if c2 := e.dry("app", "item.put", map[string]any{"item_id": cid, "version": 1, "tags": []string{"home"}}); len(c2.Shares) != 1 {
		t.Fatalf("critical put dry run: %+v", c2)
	}
	// Errors: stale version, unknown item, @profile on a non-data item, a
	// credential member, a sensitivity change, a desktop on a critical
	// item (critical forms stay app-only).
	for body, want := range map[string]string{
		`{"dry_run":true,"item_id":"` + id + `","version":1,"tags":[]}`:                       "conflict",
		`{"dry_run":true,"item_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","version":1}`:                 "not_found",
		`{"dry_run":true,"sensitivity":"secret","tags":["@profile"]}`:                         "bad_request",
		`{"dry_run":true,"sensitivity":"critical","credential":"x"}`:                          "bad_request",
		`{"dry_run":true,"sensitivity":"critical","utk_id":"x"}`:                              "bad_request",
		`{"dry_run":true,"item_id":"` + id + `","version":2,"sensitivity":"secret"}`:          "bad_request",
		`{"dry_run":true,"item_id":"` + id + `"}`:                                             "bad_request",
		`{"dry_run":"yes","name":"x"}`:                                                        "bad_request",
		`{"dry_run":true,"item_id":"` + cid + `","version":1,"sensitivity":"critical"}`:       "",
		`{"dry_run":true,"item_id":"` + cid + `","version":1,"sensitivity":"critical","x":1}`: "",
	} {
		if r := e.call("app", "item.put", body); r.Code != want {
			t.Errorf("%s: %q, want %q", body, r.Code, want)
		}
	}
	e.code(e.call("app", "item.tag", js(map[string]any{"item_id": id, "version": 2, "tags": []string{"x"}, "dry_run": 1})), "bad_request")
	e.code(e.call("desktop", "item.put", js(map[string]any{"dry_run": true, "item_id": cid, "version": 1})), "forbidden")
	e.code(e.call("desktop", "item.put", js(map[string]any{"dry_run": true, "sensitivity": "critical"})), "forbidden")
	if a := e.dry("desktop", "item.put", map[string]any{"item_id": id, "version": 2}); a.Version == nil {
		t.Fatal("desktop dry run")
	}
	// No step-up for a dry run (vault.ReadOnlyForms); the real request
	// still needs it.
	if !e.set.Items.ReadOnly("item.put", json.RawMessage(`{"dry_run":true,"name":"x"}`)) ||
		!e.set.Items.ReadOnly("item.tag", json.RawMessage(`{"dry_run":true}`)) ||
		e.set.Items.ReadOnly("item.put", json.RawMessage(`{"dry_run":false,"name":"x"}`)) ||
		e.set.Items.ReadOnly("item.put", json.RawMessage(`{"name":"x"}`)) ||
		e.set.Items.ReadOnly("item.delete", json.RawMessage(`{"dry_run":true}`)) {
		t.Fatal("ReadOnly")
	}
	if !e.set.Items.AppOnly("item.put", json.RawMessage(`{"dry_run":true,"sensitivity":"critical"}`)) {
		t.Fatal("a critical dry run from a desktop is held instead of refused")
	}
	// The profile limit: 32 @profile items, a 33rd in a dry run.
	for i := 0; i < items.MaxProfileItems; i++ {
		e.put("data", "P", []string{"@profile"})
	}
	e.limit(e.call("app", "item.put", `{"dry_run":true,"tags":["@profile"]}`), "profile_items")
	e.limit(e.call("app", "item.put", `{"name":"x","tags":["@profile"]}`), "profile_items")
}

// §10.1 (0.21.0): the sharing limits in dry runs and their real requests.
func TestDryRunSharingLimits(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 64; i++ {
		e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"t"}, "include_existing": false})
	}
	e.limit(e.call("app", "share.rule.set", js(map[string]any{"subject": conn("cA"), "tags": []string{"t"}})), "share_rules_subject")
	for i := 0; i < 64; i++ {
		e.put("data", "x", []string{"t"})
	}
	e.limit(e.call("app", "item.put", `{"dry_run":true,"tags":["t"]}`), "share_pending")
	o := e.limit(e.call("app", "item.put", `{"name":"x","tags":["t"]}`), "share_pending")
	if max, _ := o.Uint("max", 0, 1<<53); max != items.MaxPending || o.Has("size") {
		t.Fatalf("share_pending body: %v", o)
	}
}

// §10.12 (0.21.0): share.pending.list, sorted by rule then item, paged
// with an opaque cursor, filtered by rule or subject.
func TestSharePendingList(t *testing.T) {
	e := newEnv(t)
	r1 := e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"t"}})
	r2 := e.rule(map[string]any{"subject": conn("cB"), "tags": []string{"t"}})
	var ids []string
	for i := 0; i < 5; i++ {
		ids = append(ids, e.put("secret", "Item "+string(rune('a'+i)), []string{"t"}))
	}
	sort.Strings(ids)
	rules := []string{r1, r2}
	sort.Strings(rules)
	type entry struct {
		RuleID      string            `json:"rule_id"`
		Subject     map[string]string `json:"subject"`
		ItemID      string            `json:"item_id"`
		Name        string            `json:"name"`
		Category    string            `json:"category"`
		Sensitivity string            `json:"sensitivity"`
		At          string            `json:"at"`
	}
	page := func(body string) ([]entry, string) {
		o := e.ok(e.call("desktop", "share.pending.list", body))
		var es []entry
		if err := json.Unmarshal(o["pending"], &es); err != nil {
			t.Fatal(err)
		}
		next, _, _ := o.OptString("next")
		return es, next
	}
	all, next := page(`{}`)
	if len(all) != 10 || next != "" {
		t.Fatalf("all: %d %q", len(all), next)
	}
	for i, x := range all {
		if x.RuleID != rules[i/5] || x.ItemID != ids[i%5] || x.Sensitivity != "secret" || x.Category != "other" ||
			!strings.HasPrefix(x.Name, "Item ") || x.At == "" || len(x.Subject) != 1 {
			t.Fatalf("entry %d: %+v", i, x)
		}
	}
	// Paged: 3 + 3 + 3 + 1.
	var got []entry
	after := ""
	for n := 0; ; n++ {
		body := `{"limit":3}`
		if after != "" {
			body = `{"limit":3,"after":"` + after + `"}`
		}
		es, nx := page(body)
		got = append(got, es...)
		if nx == "" {
			break
		}
		after = nx
		if n > 5 {
			t.Fatal("paging does not end")
		}
	}
	if len(got) != 10 || got[3].ItemID != all[3].ItemID || got[9].ItemID != all[9].ItemID {
		t.Fatalf("paged: %d", len(got))
	}
	if es, _ := page(`{"rule_id":"` + r1 + `"}`); len(es) != 5 || es[0].RuleID != r1 {
		t.Fatalf("by rule: %+v", es)
	}
	if es, _ := page(`{"connection_id":"cB"}`); len(es) != 5 || es[0].RuleID != r2 {
		t.Fatalf("by connection: %+v", es)
	}
	if es, _ := page(`{"agent_id":"dev-agent"}`); len(es) != 0 {
		t.Fatalf("by agent: %+v", es)
	}
	for _, b := range []string{`{"rule_id":"` + r1 + `","connection_id":"cA"}`, `{"after":"x"}`, `{"limit":0}`, `{"limit":501}`,
		`{"rule_id":"nope"}`, `{"after":"` + r1 + `"}`} {
		e.code(e.call("app", "share.pending.list", b), "bad_request")
	}
	e.code(e.call("agent", "share.pending.list", `{}`), "forbidden")
	// A decision removes the entry.
	e.ok(e.call("app", "share.decide", js(map[string]any{"rule_id": r1, "items": []string{ids[0]}, "approve": false})))
	if es, _ := page(`{"rule_id":"` + r1 + `"}`); len(es) != 4 {
		t.Fatalf("after a decision: %d", len(es))
	}
}

// §10.12 (0.21.0): share.decide{include, decline} in one change: one
// response, one share.decided, no change on an error; the old form stays.
func TestShareDecideBoth(t *testing.T) {
	e := newEnv(t)
	r := e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"t"}})
	a := e.put("data", "A", []string{"t"})
	b := e.put("data", "B", []string{"t"})
	c := e.put("data", "C", []string{"t"})
	e.h.Reset()
	o := e.ok(e.call("app", "share.decide", js(map[string]any{"rule_id": r, "include": []string{a, c}, "decline": []string{b}})))
	inc, dec := strs(t, o, "included"), strs(t, o, "declined")
	sort.Strings(inc)
	want := []string{a, c}
	sort.Strings(want)
	if strings.Join(inc, ",") != strings.Join(want, ",") || len(dec) != 1 || dec[0] != b {
		t.Fatalf("decide: %v %v", inc, dec)
	}
	n := 0
	for _, s := range e.sentTo("devices", "sync.event") {
		if bytes.Contains(s.Body, []byte("share.decided")) {
			n++
		}
	}
	if n != 1 || len(e.grantsShared("cA")) != 2 {
		t.Fatalf("%d share.decided, %d grants", n, len(e.grantsShared("cA")))
	}
	rl := e.ok(e.call("app", "share.rule.list", `{}`))
	if !bytes.Contains(rl["rules"], []byte(`"declined":["`+b+`"]`)) {
		t.Fatalf("rule: %s", rl["rules"])
	}
	// Either list alone; items not pending ignored; none pending.
	d := e.put("data", "D", []string{"t"})
	o = e.ok(e.call("app", "share.decide", js(map[string]any{"rule_id": r, "decline": []string{d, a}})))
	if dec := strs(t, o, "declined"); len(dec) != 1 || dec[0] != d {
		t.Fatalf("decline alone: %v", dec)
	}
	e.code(e.call("app", "share.decide", js(map[string]any{"rule_id": r, "include": []string{a}})), "bad_request")
	x := e.put("data", "X", []string{"t"})
	for _, body := range []map[string]any{
		{"rule_id": r},
		{"rule_id": r, "include": []string{}, "decline": []string{}},
		{"rule_id": r, "include": []string{x}, "decline": []string{x}},
		{"rule_id": r, "include": []string{x, x}},
		{"rule_id": r, "include": []string{x}, "items": []string{x}},
		{"rule_id": r, "include": []string{x}, "approve": true},
		{"rule_id": r, "decline": []string{x}, "approve": false, "items": []string{x}},
		{"rule_id": r, "include": "x"},
		{"rule_id": r, "include": []string{"nope"}},
	} {
		e.code(e.call("app", "share.decide", js(body)), "bad_request")
	}
	many := make([]string, 501)
	for i := range many {
		many[i], _ = envelope.NewULID(e.clk.T.Add(time.Duration(i) * time.Millisecond))
	}
	e.code(e.call("app", "share.decide", js(map[string]any{"rule_id": r, "include": many[:300], "decline": many[300:]})), "bad_request")
	// The old form still works.
	e.ok(e.call("app", "share.decide", js(map[string]any{"rule_id": r, "items": []string{x}, "approve": true})))
}

// §10.12 (0.21.0): a mixed decision that reaches a limit changes nothing.
func TestShareDecideBothAtomic(t *testing.T) {
	e := newEnv(t)
	r := e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"t"}})
	a := e.put("data", "A", []string{"t"})
	b := e.put("data", "B", []string{"t"})
	// Fill the given grants up to one short of a and b both.
	e.rule(map[string]any{"subject": conn("cB"), "tags": []string{"g"}, "mode": "auto"})
	for i := 0; i < grants.MaxGiven-1; i++ {
		e.put("data", "g", []string{"g"})
	}
	before, _ := e.set.Items.Save()
	e.h.Reset()
	e.limit(e.call("app", "share.decide", js(map[string]any{"rule_id": r, "include": []string{a, b}, "decline": []string{}})), "grants_given")
	after, _ := e.set.Items.Save()
	if !bytes.Equal(before, after) || len(e.h.Sent) != 0 {
		t.Fatal("a refused decision changed something")
	}
	o := e.ok(e.call("app", "share.decide", js(map[string]any{"rule_id": r, "include": []string{a}, "decline": []string{b}})))
	if len(strs(t, o, "included")) != 1 || len(strs(t, o, "declined")) != 1 {
		t.Fatalf("within the limit: %v", o)
	}
	if vault.LimitName(vault.LimitError("grants_given", 1)) != "grants_given" {
		t.Fatal("LimitName")
	}
}

// §10.8 (0.21.0): the profile receiver's names exclude DEL too.
func TestProfileNamesExcludeDEL(t *testing.T) {
	ik := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	for _, n := range []string{"Bo\u007f", "Bo\u2028"} {
		u, err := items.ParseUpdate([]byte(`{"version":3,"first_name":` + js(n) + `,"last_name":"Berg","ik":"` + ik + `","items":[]}`))
		if err != nil || !u.Malformed {
			t.Fatalf("%q: %v %+v", n, err, u)
		}
	}
	if u, err := items.ParseUpdate([]byte(`{"version":3,"first_name":"Bö","last_name":"Berg","ik":"` + ik + `","items":[]}`)); err != nil || u.Malformed {
		t.Fatalf("a good core: %v", err)
	}
}
