package items_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/leashwire"
)

// secretTag is a tag name that must never reach a connection.
const secretTag = "zz private label"

func ruleState(t *testing.T, e *env, id string) (included, pending, declined []string) {
	t.Helper()
	o := e.ok(e.call("app", "share.rule.list", `{}`))
	var rules []map[string]json.RawMessage
	_ = json.Unmarshal(o["rules"], &rules)
	for _, r := range rules {
		var rid string
		_ = json.Unmarshal(r["rule_id"], &rid)
		if rid != id {
			continue
		}
		ro := strictjson.Object(r)
		return strs(t, ro, "included"), strs(t, ro, "pending"), strs(t, ro, "declined")
	}
	t.Fatalf("rule %s not listed", id)
	return
}

// §10.12: ask mode, the preview, share.pending, decisions, remembered
// declines, re-tag, withdrawal on tag removal and rule deletion.
func TestShareAsk(t *testing.T) {
	e := newEnv(t)
	allergy := e.put("data", "Allergy list", []string{"medical", secretTag}, field{Label: "Allergies", Kind: "multiline", Value: "penicillin"})
	blood := e.put("secret", "Blood type", []string{"medical"}, field{Label: "Type", Kind: "text", Value: "O-"})
	e.put("data", "Holiday", []string{"travel"})
	// The preview lists what the rule would match; nothing changes.
	o := e.ok(e.call("app", "share.rule.set", js(map[string]any{"subject": conn("cA"), "tags": []string{"Medical"}, "dry_run": true})))
	if !bytes.Contains(o["matches"], []byte(allergy)) || !bytes.Contains(o["matches"], []byte(blood)) || bytes.Contains(o["matches"], []byte("Holiday")) {
		t.Fatalf("preview: %s", o["matches"])
	}
	if o := e.ok(e.call("app", "share.rule.list", `{}`)); string(o["rules"]) != "[]" {
		t.Fatal("dry run stored a rule")
	}
	e.h.Reset()
	rid := e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"medical"}})
	// Ask (the default): the member is asked, nothing reaches cA yet.
	ps := e.sentTo("devices", "share.pending")
	if len(ps) != 1 || !bytes.Contains(ps[0].Body, []byte(`"reason":"rule"`)) || !bytes.Contains(ps[0].Body, []byte(allergy)) {
		t.Fatalf("share.pending: %v", ps)
	}
	if len(e.sentTo("cA", "data.shared")) != 0 {
		t.Fatal("shared before approval")
	}
	_, pending, _ := ruleState(t, e, rid)
	if len(pending) != 2 {
		t.Fatalf("pending: %v", pending)
	}
	// Approve one, decline the other.
	e.h.Reset()
	d := e.ok(e.call("app", "share.decide", js(map[string]any{"rule_id": rid, "items": []string{allergy}, "approve": true})))
	if strs(t, d, "included")[0] != allergy {
		t.Fatal("included")
	}
	e.ok(e.call("app", "share.decide", js(map[string]any{"rule_id": rid, "items": []string{blood}, "approve": false})))
	gs := e.grantsShared("cA")
	if len(gs) != 1 {
		t.Fatalf("data.shared: %v", gs)
	}
	shared := e.sentTo("cA", "data.shared")[0].Body
	if !bytes.Contains(shared, []byte("Allergy list")) || bytes.Contains(shared, []byte("penicillin")) || bytes.Contains(shared, []byte("medical")) {
		t.Fatalf("descriptor: %s", shared)
	}
	// cA fetches the content, sealed to its key.
	if er, pt := e.fetch("cA", gs[0]); er != "" || !bytes.Contains(pt, []byte("penicillin")) || bytes.Contains(pt, []byte(secretTag)) {
		t.Fatalf("fetch: %s %s", er, pt)
	}
	// Another connection cannot use the grant.
	if er, _ := e.fetch("cB", gs[0]); er != "not_found" {
		t.Fatalf("cB: %s", er)
	}
	// A declined item is remembered: an edit that gains no tag of the rule
	// does not ask again ...
	e.h.Reset()
	e.retag(blood, "medical", "lab")
	if len(e.sentTo("devices", "share.pending")) != 0 {
		t.Fatal("asked again without a re-tag")
	}
	// ... a re-tag (the tag removed, then added) does.
	e.retag(blood, "lab")
	e.retag(blood, "lab", "medical")
	ps = e.sentTo("devices", "share.pending")
	if len(ps) != 1 || !bytes.Contains(ps[0].Body, []byte(`"reason":"tagged"`)) {
		t.Fatalf("re-ask: %v", ps)
	}
	// A new item with the tag is asked about.
	e.h.Reset()
	e.put("data", "Vaccines", []string{"medical"})
	if len(e.sentTo("devices", "share.pending")) != 1 {
		t.Fatal("new item not asked")
	}
	// Removing the tag withdraws the item at once: the grant is revoked.
	e.h.Reset()
	e.retag(allergy, secretTag)
	if len(e.sentTo("cA", "data.revoked")) != 1 {
		t.Fatal("not revoked on tag removal")
	}
	if er, _ := e.fetch("cA", gs[0]); er != "revoked" {
		t.Fatalf("fetch after tag removal: %s", er)
	}
	included, _, _ := ruleState(t, e, rid)
	if len(included) != 0 {
		t.Fatal("still included")
	}
	// Re-tagged in ask mode: asked again, approved, a new grant.
	e.retag(allergy, "medical")
	e.ok(e.call("app", "share.decide", js(map[string]any{"rule_id": rid, "items": []string{allergy}, "approve": true})))
	gs = e.grantsShared("cA")
	// Deleting the rule revokes everything at once.
	e.h.Reset()
	e.ok(e.call("app", "share.rule.delete", js(map[string]any{"rule_id": rid})))
	if len(e.sentTo("cA", "data.revoked")) != 1 {
		t.Fatal("not revoked on rule delete")
	}
	if !e.h.HasActivity("share.rule.deleted") || !e.h.HasActivity("share.withdrawn") {
		t.Fatal("audit")
	}
	if er, _ := e.fetch("cA", gs[len(gs)-1]); er != "revoked" {
		t.Fatalf("fetch after rule delete: %s", er)
	}
	e.code(e.call("app", "share.decide", js(map[string]any{"rule_id": rid, "items": []string{allergy}, "approve": true})), "not_found")
}

// §10.12: auto mode, include_existing false, ask → auto, match all, uses.
func TestShareAuto(t *testing.T) {
	e := newEnv(t)
	old := e.put("data", "Old", []string{"family"})
	rid := e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"family"}, "mode": "auto", "include_existing": false, "uses": 2})
	if len(e.grantsShared("cA")) != 0 {
		t.Fatal("include_existing false shared an existing item")
	}
	// A new item gaining the tag is included at once, no prompt.
	e.h.Reset()
	n := e.put("data", "New", []string{"family"}, field{Label: "T", Kind: "text", Value: "hello"})
	if len(e.sentTo("devices", "share.pending")) != 0 || len(e.grantsShared("cA")) != 1 {
		t.Fatal("auto did not include")
	}
	g := e.grantsShared("cA")[0]
	// uses: 2 fetches, then exhausted.
	e.fetch("cA", g)
	if er, _ := e.fetch("cA", g); er != "" {
		t.Fatalf("second fetch: %s", er)
	}
	if er, _ := e.fetch("cA", g); er != "exhausted" {
		t.Fatalf("third fetch: %s", er)
	}
	// The existing item is included once re-tagged.
	e.retag(old)
	e.h.Reset()
	e.retag(old, "family")
	if len(e.grantsShared("cA")) != 1 {
		t.Fatal("re-tag under auto")
	}
	_ = n
	_ = rid
	// match all; ask replaced by auto includes the pending.
	a := e.put("data", "Both", []string{"medical", "dr lee"})
	e.put("data", "One", []string{"medical"})
	e.h.Reset()
	r2 := e.rule(map[string]any{"subject": conn("cB"), "tags": []string{"medical", "dr lee"}, "match": "all"})
	_, pending, _ := ruleState(t, e, r2)
	if len(pending) != 1 || pending[0] != a {
		t.Fatalf("match all: %v", pending)
	}
	e.h.Reset()
	e.ok(e.call("app", "share.rule.set", js(map[string]any{"rule_id": r2, "version": 1, "subject": conn("cB"),
		"tags": []string{"medical", "dr lee"}, "match": "all", "mode": "auto"})))
	if len(e.grantsShared("cB")) != 1 {
		t.Fatal("ask → auto did not include the pending item")
	}
	// The subject cannot change; versions are checked.
	e.code(e.call("app", "share.rule.set", js(map[string]any{"rule_id": r2, "version": 2, "subject": conn("cA"), "tags": []string{"x"}})), "bad_request")
	e.code(e.call("app", "share.rule.set", js(map[string]any{"rule_id": r2, "version": 1, "subject": conn("cB"), "tags": []string{"x"}})), "conflict")
	e.code(e.call("app", "share.rule.set", js(map[string]any{"subject": conn("nobody"), "tags": []string{"x"}})), "not_found")
	e.code(e.call("app", "share.rule.set", js(map[string]any{"subject": conn("cA"), "tags": []string{"@profile"}})), "bad_request")
	e.code(e.call("app", "share.rule.set", js(map[string]any{"subject": conn("cA"), "tags": []string{"x"}, "per_hour": 5})), "bad_request")
}

// §10.12: each connection sees only its own catalog; no tags or rules.
func TestCatalogIsolation(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	a := e.put("data", "For A", []string{"a-only", secretTag})
	b := e.put("secret", "For B", []string{"b-only"})
	c := e.putCritical("Signing key", []string{"b-only"}, field{Label: "Seed", Kind: "password", Value: base64.StdEncoding.EncodeToString(make([]byte, 32))})
	e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"a-only"}, "mode": "auto"})
	e.rule(map[string]any{"subject": conn("cB"), "tags": []string{"b-only"}, "mode": "auto"})
	catalog := func(cn string) []byte {
		e.h.Reset()
		rid, _ := envelope.NewULID(e.clk.T)
		e.call("connection:"+cn, "data.catalog.get", js(map[string]any{"request_id": rid}))
		cs := e.sentTo(cn, "data.catalog")
		if len(cs) != 1 {
			t.Fatalf("catalog to %s: %d", cn, len(cs))
		}
		return cs[0].Body
	}
	ca, cb := catalog("cA"), catalog("cB")
	if !bytes.Contains(ca, []byte(a)) || bytes.Contains(ca, []byte(b)) || bytes.Contains(ca, []byte(c)) {
		t.Fatalf("cA catalog: %s", ca)
	}
	if !bytes.Contains(cb, []byte(b)) || !bytes.Contains(cb, []byte(c)) || bytes.Contains(cb, []byte(a)) {
		t.Fatalf("cB catalog: %s", cb)
	}
	// The critical item is usable, never readable: no grant for it.
	var cat struct {
		Items []struct {
			ItemID  string `json:"item_id"`
			GrantID string `json:"grant_id"`
			Usable  bool   `json:"usable"`
		} `json:"items"`
	}
	_ = json.Unmarshal(cb, &cat)
	for _, it := range cat.Items {
		if it.ItemID == c && (it.GrantID != "" || !it.Usable) || it.ItemID == b && (it.GrantID == "" || it.Usable) {
			t.Fatalf("entry %+v", it)
		}
	}
	for _, body := range [][]byte{ca, cb} {
		for _, tag := range []string{"a-only", "b-only", secretTag} {
			if bytes.Contains(body, []byte(tag)) {
				t.Fatalf("tag %q in a catalog: %s", tag, body)
			}
		}
	}
}

// §10.8: tag names never reach a connection, whatever the flow.
func TestTagsNeverInPeerMessages(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	p := e.put("data", "Bio", []string{"@profile", secretTag}, field{Label: "City", Kind: "text", Value: "Oslo"})
	e.put("secret", "Shared", []string{secretTag}, field{Label: "K", Kind: "text", Value: "v"})
	crit := e.putCritical("Key", []string{secretTag}, field{Label: "Seed", Kind: "password", Value: base64.StdEncoding.EncodeToString(make([]byte, 32))})
	rid := e.rule(map[string]any{"subject": conn("cA"), "tags": []string{secretTag}})
	_, pending, _ := ruleState(t, e, rid)
	e.ok(e.call("app", "share.decide", js(map[string]any{"rule_id": rid, "items": pending, "approve": true})))
	e.ok(e.call("app", "profile.set", `{"version":0,"name":"Al"}`))
	e.set.Items.ConnectionAdded(vault.NewSession(context.TODO(), e.h, vault.PeerInfo{}, e.clk.T, nil), "cB")
	rq, _ := envelope.NewULID(e.clk.T)
	e.call("connection:cA", "data.catalog.get", js(map[string]any{"request_id": rq}))
	// A critical use request about the usable item.
	ur, _ := envelope.NewULID(e.clk.T.Add(time.Second))
	e.call("connection:cA", "critical-secret.use", js(map[string]any{"request_id": ur, "item_id": crit, "field_id": "f1", "operation": "sign",
		"payload": base64.StdEncoding.EncodeToString([]byte("hello"))}))
	e.ok(e.call("app", "tag.merge", js(map[string]any{"version": 0, "from": []string{secretTag}, "into": "zz renamed"})))
	n := 0
	for _, s := range e.h.Sent {
		if s.To != "cA" && s.To != "cB" {
			continue
		}
		n++
		for _, tag := range []string{secretTag, "zz renamed", "@profile"} {
			if bytes.Contains(s.Body, []byte(tag)) {
				t.Fatalf("%s to %s carries tag %q: %s", s.Type, s.To, tag, s.Body)
			}
		}
	}
	if n < 4 {
		t.Fatalf("only %d peer messages checked", n)
	}
	_ = p
}

// §10.8: the registry, normalisation, delete (in_use), merge (rename).
func TestTags(t *testing.T) {
	e := newEnv(t)
	x := e.put("data", "X", []string{"Old Name", "keep"})
	y := e.put("data", "Y", []string{"other"})
	e.ok(e.call("app", "tag.set", `{"version":0,"tag":"Old  NAME","color":"#ff0000","icon":"star","description":"d"}`))
	e.code(e.call("app", "tag.set", `{"version":0,"tag":"x"}`), "conflict")
	for _, b := range []string{`{"version":1,"tag":"x","color":"red"}`, `{"version":1,"tag":"x","icon":"A B"}`, `{"version":1,"tag":"@nope"}`} {
		e.code(e.call("app", "tag.set", b), "bad_request")
	}
	o := e.ok(e.call("app", "tag.list", `{}`))
	if v, _ := o.Uint("version", 0, 9); v != 1 || !bytes.Contains(o["tags"], []byte(`{"tag":"old name","color":"#ff0000","icon":"star","description":"d","items":1,"rules":[]}`)) {
		t.Fatalf("tag.list: %s", o["tags"])
	}
	// A rule names "other": deleting it is refused, it would widen nothing
	// but the rule would change meaning.
	rid := e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"other", "x"}, "match": "all", "mode": "auto"})
	e.code(e.call("app", "tag.delete", `{"version":1,"tag":"other"}`), "in_use")
	o = e.ok(e.call("app", "tag.delete", `{"version":1,"tag":"keep","dry_run":true}`))
	if n, _ := o.Uint("items", 0, 9); n != 1 || len(strs(t, e.item(x), "tags")) != 2 {
		t.Fatal("dry run")
	}
	e.ok(e.call("app", "tag.delete", `{"version":1,"tag":"keep"}`))
	if got := strs(t, e.item(x), "tags"); strings.Join(got, ",") != "old name" {
		t.Fatalf("after delete: %v", got)
	}
	// Merge "old name" into "x": X now carries x; the all-rule [other, x]
	// is unchanged; Y (other) does not match. Then merge "other" into "x":
	// the rule becomes [x] and both items newly match (shares listed).
	e.ok(e.call("app", "tag.merge", `{"version":2,"from":["old name"],"into":"x"}`))
	if got := strs(t, e.item(x), "tags"); strings.Join(got, ",") != "x" {
		t.Fatalf("after merge: %v", got)
	}
	o = e.ok(e.call("app", "tag.merge", `{"version":3,"from":["other"],"into":"x","dry_run":true}`))
	if !bytes.Contains(o["shares"], []byte(x)) || !bytes.Contains(o["shares"], []byte(y)) || len(e.grantsShared("cA")) != 0 {
		t.Fatalf("merge preview: %s", o["shares"])
	}
	e.h.Reset()
	e.ok(e.call("app", "tag.merge", `{"version":3,"from":["other"],"into":"x"}`))
	if len(e.grantsShared("cA")) != 2 {
		t.Fatal("merge: newly matching items under auto")
	}
	o = e.ok(e.call("app", "share.rule.list", `{}`))
	if !bytes.Contains(o["rules"], []byte(`"tags":["x"]`)) || !bytes.Contains(o["rules"], []byte(rid)) {
		t.Fatalf("rule rewritten: %s", o["rules"])
	}
	e.code(e.call("app", "tag.merge", `{"version":4,"from":["x"],"into":"x"}`), "bad_request")
	e.code(e.call("app", "tag.merge", `{"version":4,"from":["@profile"],"into":"x"}`), "bad_request")
}

// §10.8: the profile object and @profile items reach connections.
func TestProfile(t *testing.T) {
	e := newEnv(t)
	e.ok(e.call("app", "profile.set", `{"version":0,"name":"Al"}`))
	ups := e.sentTo("cA", "profile.update")
	if len(ups) != 1 || !bytes.Contains(ups[0].Body, []byte(`"name":"Al"`)) {
		t.Fatalf("profile.update: %v", ups)
	}
	e.h.Reset()
	p := e.put("data", "Contact", []string{"@profile"}, field{Label: "Email", Kind: "email", Value: "al@example.org"})
	ups = e.sentTo("cB", "profile.update")
	if len(ups) != 1 || !bytes.Contains(ups[0].Body, []byte("al@example.org")) || bytes.Contains(ups[0].Body, []byte("@profile")) {
		t.Fatalf("@profile item: %v", ups)
	}
	// A change outside the shared profile sends nothing.
	e.h.Reset()
	e.put("data", "Private", []string{"x"})
	if len(e.sentTo("cA", "profile.update")) != 0 {
		t.Fatal("update for a private item")
	}
	// Removing the tag removes it from the shared profile.
	e.h.Reset()
	e.retag(p)
	ups = e.sentTo("cA", "profile.update")
	if len(ups) != 1 || bytes.Contains(ups[0].Body, []byte("al@example.org")) {
		t.Fatalf("after untag: %v", ups)
	}
	o := e.ok(e.call("app", "profile.get", `{}`))
	if n, _ := o.String("name"); n != "Al" || o.Has("fields") {
		t.Fatalf("profile.get: %v", o)
	}
	e.code(e.call("app", "profile.set", `{"version":0,"name":"B"}`), "conflict")
	e.code(e.call("app", "profile.set", `{"version":1,"photo":"AAAA"}`), "bad_request")
	// At most 32 @profile items.
	for i := 0; i < 32; i++ {
		e.put("data", "P", []string{"@profile"})
	}
	e.code(e.call("app", "item.put", `{"name":"P","tags":["@profile"]}`), "limit")
	// A peer's update: strict, highest version wins.
	up := `{"version":3,"name":"Bo","items":[{"item_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","name":"Card","category":"contact",` +
		`"fields":[{"field_id":"f1","label":"Phone","kind":"phone","value":"+47 1234"}]}]}`
	e.ok(e.call("connection:cA", "profile.update", up))
	if !bytes.Contains(e.h.Profiles["cA"], []byte("+47 1234")) {
		t.Fatal("peer profile not stored")
	}
	e.ok(e.call("connection:cA", "profile.update", `{"version":2,"name":"Old","items":[]}`))
	if bytes.Contains(e.h.Profiles["cA"], []byte("Old")) {
		t.Fatal("older update applied")
	}
	for _, b := range []string{`{"version":4,"name":"x"}`, `{"version":4,"name":"x","items":[{"item_id":"bad","name":"n","category":"c","fields":[]}]}`,
		`{"version":4,"name":"x","items":[{"item_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","name":"n","category":"c","fields":[{"label":"L","kind":"text","value":"v"}]}]}`,
		`{"version":4,"name":"x","items":[{"item_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","name":"n","category":"c","fields":[{"field_id":"f1","label":"L","kind":"date","value":"no"}]}]}`} {
		e.code(e.call("connection:cA", "profile.update", b), "bad_request")
	}
}

// §10.13 through share rules: a critical item is never readable by a
// rule, only usable, and each use needs the member's password.
func TestCriticalUseThroughRule(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	seed := make([]byte, 32)
	seed[0] = 7
	key := e.putCritical("Signing key", []string{"sign"}, field{Label: "Seed", Kind: "password", Value: base64.StdEncoding.EncodeToString(seed)},
		field{Label: "Note", Kind: "text", Value: "not a seed"})
	other := e.putCritical("Other key", nil, field{Label: "Seed", Kind: "password", Value: base64.StdEncoding.EncodeToString(seed)})
	e.h.Reset()
	rid := e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"sign"}, "mode": "auto"})
	if len(e.grantsShared("cA")) != 0 {
		t.Fatal("a critical item was granted")
	}
	// A one-off grant of it is not available either.
	q, _ := envelope.NewULID(e.clk.T)
	e.call("connection:cA", "data.request", js(map[string]any{"request_id": q, "items": []map[string]any{{"kind": "item", "ref": key}},
		"uses": 1, "expires_in": 3600}))
	e.code(e.call("app", "grant.decide", js(map[string]any{"request_id": q, "approve": true})), "bad_request")
	use := func(item, fieldID string) string {
		rq, _ := envelope.NewULID(e.clk.T)
		e.h.Reset()
		e.call("connection:cA", "critical-secret.use", js(map[string]any{"request_id": rq, "item_id": item, "field_id": fieldID,
			"operation": "sign", "payload": base64.StdEncoding.EncodeToString([]byte("pay me"))}))
		return rq
	}
	// Not usable (no rule includes it) or another connection: unavailable
	// at once, without asking.
	use(other, "f1")
	if rs := e.sentTo("cA", "critical-secret.result"); len(rs) != 1 || !bytes.Contains(rs[0].Body, []byte("unavailable")) {
		t.Fatalf("not usable: %v", rs)
	}
	// Usable: the member is asked and consents with the password.
	rq := use(key, "f1")
	if len(e.sentTo("devices", "critical-secret-use.pending")) != 1 {
		t.Fatal("not asked")
	}
	h := sha256.Sum256([]byte("pay me"))
	e.ok(e.sealed("app", "critical-secret-use.approve", map[string]any{"request_id": rq},
		map[string]any{"password": pw, "request_id": rq, "payload_sha256": base64.StdEncoding.EncodeToString(h[:])}, true, false))
	rs := e.sentTo("cA", "critical-secret.result")
	if len(rs) != 1 || !bytes.Contains(rs[0].Body, []byte(`"status":"ok"`)) {
		t.Fatalf("result: %v", rs)
	}
	var res struct {
		Sig []byte `json:"signature"`
		Pub []byte `json:"public_key"`
	}
	_ = json.Unmarshal(rs[0].Body, &res)
	if !ed25519.Verify(res.Pub, []byte("pay me"), res.Sig) || !bytes.Equal(res.Pub, ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)) {
		t.Fatal("signature")
	}
	// A field that is not a seed: unsuitable.
	rq = use(key, "f2")
	e.ok(e.sealed("app", "critical-secret-use.approve", map[string]any{"request_id": rq},
		map[string]any{"password": pw, "request_id": rq, "payload_sha256": base64.StdEncoding.EncodeToString(h[:])}, true, false))
	if rs := e.sentTo("cA", "critical-secret.result"); !bytes.Contains(rs[0].Body, []byte("unsuitable")) {
		t.Fatalf("unsuitable: %s", rs[0].Body)
	}
	// Deleting the rule ends usability.
	e.ok(e.call("app", "share.rule.delete", js(map[string]any{"rule_id": rid})))
	use(key, "f1")
	if rs := e.sentTo("cA", "critical-secret.result"); len(rs) != 1 || !bytes.Contains(rs[0].Body, []byte("unavailable")) {
		t.Fatal("usable after the rule was deleted")
	}
}

// §10.11, §10.12: an agent's rule is a signed items.read delegation; its
// items are read without exposure of anything else; critical never.
func TestAgentRules(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	doc := e.put("data", "Doc", []string{"agent ok"}, field{Label: "Body", Kind: "multiline", Value: "contents"},
		field{Label: "Token", Kind: "password", Value: "tok"})
	e.putCritical("Never", []string{"agent ok"}, field{Label: "K", Kind: "password", Value: "x"})
	body := map[string]any{"subject": map[string]any{"agent_id": "dev-agent"}, "tags": []string{"agent ok"}, "mode": "auto", "uses": 3, "per_hour": 10}
	// Signed with the credential key: only inside the unlock window, only
	// from an app.
	e.code(e.call("app", "share.rule.set", js(body)), "credential_locked")
	e.unlock()
	e.code(e.call("desktop", "share.rule.set", js(body)), "forbidden")
	e.h.Reset()
	o := e.ok(e.call("app", "share.rule.set", js(body)))
	rid, _ := o.String("rule_id")
	del, err := o.Base64("delegation", -1)
	if err != nil {
		t.Fatal("no delegation")
	}
	d, err := leashwire.Parse(del)
	if err != nil || d.Scope != leashwire.ScopeItems || d.GrantID != rid || strings.Join(d.Tags, ",") != "agent ok" || d.Match != "any" ||
		d.Access != "read" || d.Uses != 3 || d.PerHour != 10 || d.PerDay != 1000 || d.Approval != "auto" {
		t.Fatalf("delegation: %+v %v", d, err)
	}
	key, _ := o.Base64("key", ed25519.PublicKeySize)
	sig, _ := o.Base64("delegation_sig", -1)
	if _, err := leashwire.Verify(key, del, sig, e.clk.T); err != nil {
		t.Fatalf("delegation does not verify: %v", err)
	}
	if len(e.sentTo("dev-agent", "leash.grant.updated")) != 1 {
		t.Fatal("agent not told")
	}
	included, _, _ := ruleState(t, e, rid)
	if len(included) != 1 || included[0] != doc {
		t.Fatalf("agent rule includes: %v (critical never)", included)
	}
	// The agent: the policy, then the request.
	agentCall := func(req map[string]any) featuretest.Result {
		b := js(req)
		s := vault.NewSession(context.TODO(), e.h, vault.PeerInfo{ID: "dev-agent", Kind: vault.KindAgent}, e.clk.T, nil)
		if dec := e.set.Leash.AgentDecision(s, "agent.request", json.RawMessage(b)); dec != vault.AgentAllow {
			return featuretest.Result{Code: "forbidden"}
		}
		return e.call("agent", "agent.request", b)
	}
	cat := e.ok(agentCall(map[string]any{"op": "catalog"}))
	if !bytes.Contains(cat["items"], []byte(doc)) || bytes.Contains(cat["items"], []byte("Never")) || bytes.Contains(cat["items"], []byte("agent ok")) {
		t.Fatalf("catalog: %s", cat["items"])
	}
	g := e.ok(agentCall(map[string]any{"op": "item.get", "item_id": doc, "fields": []string{"f1"}}))
	if !bytes.Contains(g["fields"], []byte("contents")) || bytes.Contains(g["fields"], []byte("tok")) {
		t.Fatalf("item.get: %s", g["fields"])
	}
	u := e.ok(agentCall(map[string]any{"op": "item.use", "item_id": doc, "field_id": "f2", "action": "hmac-sha256",
		"data": base64.StdEncoding.EncodeToString([]byte("d"))}))
	if bytes.Contains(u["result"], []byte("tok")) {
		t.Fatal("use exposed the value")
	}
	// Three uses: the next read is not covered any more.
	e.ok(agentCall(map[string]any{"op": "item.get", "item_id": doc}))
	e.code(agentCall(map[string]any{"op": "item.get", "item_id": doc}), "forbidden")
	// LEASH grant issue cannot make items.read; revoking it deletes the rule.
	e.code(e.call("app", "leash.grant.issue", js(map[string]any{"agent_id": "dev-agent", "scope": "items.read"})), "bad_request")
	e.ok(e.call("app", "leash.grant.revoke", js(map[string]any{"grant_id": rid})))
	if o := e.ok(e.call("app", "share.rule.list", `{"agent_id":"dev-agent"}`)); string(o["rules"]) != "[]" {
		t.Fatalf("rule after revoke: %s", o["rules"])
	}
	// Ask mode for agents too: pending until the member approves.
	body["mode"], body["uses"] = "ask", nil
	delete(body, "uses")
	o = e.ok(e.call("app", "share.rule.set", js(body)))
	rid, _ = o.String("rule_id")
	e.code(agentCall(map[string]any{"op": "item.get", "item_id": doc}), "forbidden")
	e.ok(e.call("app", "share.decide", js(map[string]any{"rule_id": rid, "items": []string{doc}, "approve": true})))
	e.ok(agentCall(map[string]any{"op": "item.get", "item_id": doc}))
	// A tag merge cannot touch an agent rule (its tags are signed).
	e.code(e.call("app", "tag.merge", `{"version":0,"from":["agent ok"],"into":"other"}`), "in_use")
	// Unlinking the agent drops its rules.
	s := vault.NewSession(context.TODO(), e.h, vault.PeerInfo{}, e.clk.T, nil)
	e.set.Leash.DeviceRemoved(s, "dev-agent")
	e.set.Items.DeviceRemoved(s, "dev-agent")
	if o := e.ok(e.call("app", "share.rule.list", `{}`)); string(o["rules"]) != "[]" {
		t.Fatal("agent rules after unlink")
	}
}

// §10.12: a rule ends at its expiry: its grants are revoked and it is
// deleted.
func TestRuleExpiry(t *testing.T) {
	e := newEnv(t)
	e.put("data", "x", []string{"t"})
	exp := e.clk.T.Add(time.Hour).Format("2006-01-02T15:04:05.000Z")
	e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"t"}, "mode": "auto", "expires_at": exp})
	g := e.grantsShared("cA")
	if len(g) != 1 || !bytes.Contains(e.sentTo("cA", "data.shared")[0].Body, []byte(`"expires_at":"`+exp+`"`)) {
		t.Fatal("rule grant without the rule's expiry")
	}
	e.clk.Advance(2 * time.Hour)
	e.h.Reset()
	if o := e.ok(e.call("app", "share.rule.list", `{}`)); string(o["rules"]) != "[]" {
		t.Fatalf("expired rule listed: %s", o["rules"])
	}
	if len(e.sentTo("cA", "data.revoked")) != 1 {
		t.Fatal("grant not revoked at expiry")
	}
	if er, _ := e.fetch("cA", g[0]); er != "revoked" && er != "expired" {
		t.Fatalf("fetch after expiry: %s", er)
	}
}

// Lists are paged and bounded to one message (§10.8, §10.12).
func TestPaging(t *testing.T) {
	e := newEnv(t)
	for _, tg := range []string{"a", "b", "c"} {
		e.put("data", "x", []string{tg})
		e.rule(map[string]any{"subject": conn("cA"), "tags": []string{tg}})
	}
	o := e.ok(e.call("app", "share.rule.list", `{"limit":2}`))
	next, err := o.String("next")
	if err != nil || strings.Count(string(o["rules"]), `"rule_id"`) != 2 {
		t.Fatalf("page 1: %s", o["rules"])
	}
	o = e.ok(e.call("app", "share.rule.list", js(map[string]any{"limit": 2, "after": next})))
	if o.Has("next") || strings.Count(string(o["rules"]), `"rule_id"`) != 1 {
		t.Fatalf("page 2: %s", o["rules"])
	}
	o = e.ok(e.call("app", "tag.list", `{"limit":2}`))
	if n, _ := o.String("next"); n != "b" || !bytes.Contains(o["tags"], []byte(`"tag":"a"`)) {
		t.Fatalf("tags page 1: %s", o["tags"])
	}
	o = e.ok(e.call("app", "tag.list", `{"after":"b"}`))
	if o.Has("next") || !bytes.Contains(o["tags"], []byte(`"tag":"c"`)) || bytes.Contains(o["tags"], []byte(`"tag":"a"`)) {
		t.Fatalf("tags page 2: %s", o["tags"])
	}
	o = e.ok(e.call("app", "share.rule.set", js(map[string]any{"subject": conn("cB"), "tags": []string{"a", "b"}, "dry_run": true})))
	if n, _ := o.Uint("total", 0, 9); n != 2 {
		t.Fatalf("preview total: %s", o["matches"])
	}
}

// §7.4: removing a connection removes its rules.
func TestConnectionRemoved(t *testing.T) {
	e := newEnv(t)
	e.put("data", "X", []string{"t"})
	e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"t"}})
	s := vault.NewSession(context.TODO(), e.h, vault.PeerInfo{}, e.clk.T, nil)
	e.set.Items.ConnectionRemoved(s, "cA")
	e.set.Grants.ConnectionRemoved(s, "cA")
	if o := e.ok(e.call("app", "share.rule.list", `{}`)); string(o["rules"]) != "[]" {
		t.Fatal("rule kept")
	}
}

func TestPendingAndRuleLimits(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 64; i++ {
		e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"t"}, "include_existing": false})
	}
	e.code(e.call("app", "share.rule.set", js(map[string]any{"subject": conn("cA"), "tags": []string{"t"}})), "limit")
	// 64 rules × 64 items reach the pending limit (4,096).
	for i := 0; i < 64; i++ {
		e.put("data", "x", []string{"t"})
	}
	e.code(e.call("app", "item.put", `{"name":"x","tags":["t"]}`), "limit")
}

func FuzzItemTypes(f *testing.F) {
	for _, s := range []string{`{"name":"x","tags":["a"],"fields":[{"label":"L","kind":"text","value":"v"}]}`,
		`{"subject":{"connection_id":"cA"},"tags":["a"],"mode":"auto"}`, `{"version":0,"from":["a"],"into":"b"}`,
		`{"rule_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","items":["01JB2Z6V9K3M4N5P6Q7R8S9T0V"],"approve":true}`} {
		f.Add(s)
	}
	types := []string{"item.put", "item.get", "item.reveal", "item.list", "item.tag", "item.sensitivity", "item.delete",
		"tag.list", "tag.set", "tag.delete", "tag.merge", "profile.get", "profile.set", "share.rule.set", "share.rule.list",
		"share.rule.delete", "share.decide"}
	f.Fuzz(func(t *testing.T, body string) {
		e := newEnv(t)
		e.put("data", "x", []string{"a"})
		for _, typ := range types {
			e.call("app", typ, body)
		}
		e.call("connection:cA", "profile.update", body)
	})
}
