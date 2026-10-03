package items_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/credwire"
)

// §10.7, §10.8, §10.12, §6.8: who may send what.
func TestAuthorization(t *testing.T) {
	e := newEnv(t)
	owner := []string{"item.put", "item.get", "item.reveal", "item.list", "item.tag", "item.sensitivity", "item.delete",
		"tag.list", "tag.set", "tag.delete", "tag.merge", "profile.get", "profile.set",
		"share.rule.set", "share.rule.list", "share.rule.delete", "share.decide"}
	stepUp := map[string]bool{"item.put": true, "item.reveal": true, "item.tag": true, "item.sensitivity": true, "item.delete": true,
		"tag.delete": true, "tag.merge": true, "profile.set": true, "share.rule.set": true, "share.decide": true}
	specs := map[string]vault.TypeSpec{}
	for _, ts := range e.set.Items.Types() {
		specs[ts.Type] = ts
	}
	for _, typ := range owner {
		ts, ok := specs[typ]
		if !ok {
			t.Fatalf("%s not registered", typ)
		}
		if !ts.Request || !ts.Allows(vault.KindApp) || !ts.Allows(vault.KindDesktop) || ts.Allows(vault.KindAgent) || ts.Allows(vault.KindConnection) {
			t.Errorf("%s: roles %v", typ, ts.From)
		}
		if ts.DesktopApproval != stepUp[typ] {
			t.Errorf("%s: step-up %v", typ, ts.DesktopApproval)
		}
		e.code(e.call("agent", typ, `{}`), "forbidden")
		e.code(e.call("connection:cA", typ, `{}`), "forbidden")
	}
	if ts := specs["profile.update"]; ts.Request || !ts.Allows(vault.KindConnection) || ts.Allows(vault.KindApp) {
		t.Errorf("profile.update: %+v", ts)
	}
	e.code(e.call("app", "profile.update", `{}`), "forbidden")
	// Critical forms are app-only (a credential operation).
	e.createCredential()
	e.code(e.sealed("desktop", "item.put", map[string]any{"sensitivity": "critical"},
		map[string]any{"password": pw, "item": map[string]any{"name": "x"}}, true, false), "forbidden")
	crit := e.putCritical("Seed", nil, field{Label: "Words", Kind: "multiline", Value: "a b c"})
	e.code(e.call("desktop", "item.reveal", js(map[string]any{"item_id": crit})), "forbidden")
	e.code(e.call("desktop", "item.delete", js(map[string]any{"item_id": crit})), "forbidden")
	e.code(e.call("desktop", "item.sensitivity", js(map[string]any{"item_id": crit, "version": 1, "sensitivity": "secret"})), "forbidden")
	// The runtime refuses those forms from a desktop at once instead of
	// holding them for an app's approval (vault.AppOnlyForms).
	for typ, body := range map[string]string{
		"item.put":         `{"sensitivity":"critical","name":"x"}`,
		"item.reveal":      js(map[string]any{"item_id": crit}),
		"item.delete":      js(map[string]any{"item_id": crit}),
		"item.sensitivity": `{"item_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","version":1,"sensitivity":"critical"}`,
		"share.rule.set":   `{"subject":{"agent_id":"dev-agent"},"tags":["a"]}`,
	} {
		if !e.set.Items.AppOnly(typ, json.RawMessage(body)) {
			t.Errorf("%s %s: not app-only", typ, body)
		}
	}
	for typ, body := range map[string]string{"item.put": `{"name":"x"}`, "item.reveal": `{"item_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V"}`,
		"share.rule.set": `{"subject":{"connection_id":"cA"},"tags":["a"]}`} {
		if e.set.Items.AppOnly(typ, json.RawMessage(body)) {
			t.Errorf("%s %s: app-only", typ, body)
		}
	}
	// A desktop reads data items and lists everything.
	d := e.put("data", "Note", nil, field{Label: "Text", Kind: "text", Value: "hi"})
	e.ok(e.call("desktop", "item.get", js(map[string]any{"item_id": d})))
	e.ok(e.call("desktop", "item.list", `{}`))
}

func TestItemsCRUD(t *testing.T) {
	e := newEnv(t)
	o := e.ok(e.call("app", "item.put", js(map[string]any{"name": "Passport", "category": "identity_document", "template": "passport",
		"tags": []string{" Travel", "identity", "TRAVEL"},
		"fields": []field{{Label: "Number", Kind: "text", Value: "X123"}, {Label: "Expires", Kind: "date", Value: "2031-04-30"},
			{Label: "Address", Kind: "address", Value: map[string]string{"city": "Oslo", "country": "NO"}}},
		"notes": "renew early"})))
	id, _ := o.String("item_id")
	if v, _ := o.Uint("version", 1, 9); v != 1 {
		t.Fatal("version 1")
	}
	it := e.item(id)
	if s, _ := it.String("sensitivity"); s != "data" {
		t.Fatal("default sensitivity data")
	}
	if got := strs(t, it, "tags"); strings.Join(got, ",") != "identity,travel" {
		t.Fatalf("tags normalised: %v", got)
	}
	var fs []map[string]any
	_ = json.Unmarshal(it["fields"], &fs)
	if len(fs) != 3 || fs[0]["field_id"] != "f1" || fs[2]["field_id"] != "f3" || fs[0]["value"] != "X123" {
		t.Fatalf("fields: %v", fs)
	}
	if n, _ := it.String("notes"); n != "renew early" {
		t.Fatal("notes")
	}
	// The sync event names the item, never values.
	ev := e.sentTo("devices", "sync.event")
	if len(ev) == 0 || !bytes.Contains(ev[len(ev)-1].Body, []byte(`"item.changed"`)) || bytes.Contains(ev[len(ev)-1].Body, []byte("X123")) {
		t.Fatalf("sync.event: %v", ev)
	}
	// Replace: keep f2, drop f1 and f3, add one (f4: ids are never reused).
	e.code(e.call("app", "item.put", js(map[string]any{"item_id": id, "version": 2, "name": "Passport"})), "conflict")
	e.code(e.call("app", "item.put", js(map[string]any{"item_id": id, "name": "Passport"})), "bad_request")
	e.code(e.call("app", "item.put", js(map[string]any{"item_id": id, "version": 1, "name": "P", "fields": []field{{ID: "f9", Label: "L", Kind: "text", Value: ""}}})), "bad_request")
	e.code(e.call("app", "item.put", js(map[string]any{"item_id": id, "version": 1, "name": "P", "sensitivity": "secret"})), "bad_request")
	e.ok(e.call("app", "item.put", js(map[string]any{"item_id": id, "version": 1, "name": "Passport",
		"fields": []field{{ID: "f2", Label: "Expiry", Kind: "date", Value: "2031-05-01"}, {Label: "Country", Kind: "text", Value: "NO"}}})))
	it = e.item(id)
	_ = json.Unmarshal(it["fields"], &fs)
	if len(fs) != 2 || fs[0]["field_id"] != "f2" || fs[1]["field_id"] != "f4" {
		t.Fatalf("replaced fields: %v", fs)
	}
	if got := strs(t, it, "tags"); len(got) != 2 {
		t.Fatal("tags absent: kept")
	}
	if c, _ := it.String("category"); c != "other" {
		t.Fatal("category defaults on replace")
	}
	// A secret item: values only through item.reveal, which is audited.
	s := e.put("secret", "Wi-Fi", []string{"home"}, field{Label: "Password", Kind: "password", Value: "hunter22"},
		field{Label: "SSID", Kind: "text", Value: "net"})
	g := e.item(s)
	if bytes.Contains(g["fields"], []byte("hunter22")) || bytes.Contains(g["fields"], []byte(`"value"`)) {
		t.Fatal("item.get returned a secret value")
	}
	e.h.Reset()
	r := e.ok(e.call("app", "item.reveal", js(map[string]any{"item_id": s, "fields": []string{"f1"}})))
	if !bytes.Contains(r["fields"], []byte("hunter22")) || bytes.Contains(r["fields"], []byte("net")) {
		t.Fatalf("reveal: %s", r["fields"])
	}
	if !e.h.HasActivity("item.revealed") {
		t.Fatal("reveal not audited")
	}
	e.code(e.call("app", "item.reveal", js(map[string]any{"item_id": s, "fields": []string{"f9"}})), "not_found")
	// Listing: filters, metadata only, pagination.
	e.put("data", "Card", []string{"travel", "money"})
	list := func(f map[string]any) []string {
		o := e.ok(e.call("app", "item.list", js(f)))
		var items []map[string]any
		_ = json.Unmarshal(o["items"], &items)
		var names []string
		for _, i := range items {
			names = append(names, i["name"].(string))
		}
		if bytes.Contains(o["items"], []byte("hunter22")) || bytes.Contains(o["items"], []byte(`"value"`)) {
			t.Fatal("values in item.list")
		}
		return names
	}
	if got := list(map[string]any{"tags": []string{"travel"}}); strings.Join(got, ",") != "Passport,Card" {
		t.Fatalf("any: %v", got)
	}
	if got := list(map[string]any{"tags": []string{"travel", "money"}, "match": "all"}); strings.Join(got, ",") != "Card" {
		t.Fatalf("all: %v", got)
	}
	if got := list(map[string]any{"sensitivity": "secret"}); strings.Join(got, ",") != "Wi-Fi" {
		t.Fatalf("sensitivity: %v", got)
	}
	if got := list(map[string]any{"category": "identity_document"}); len(got) != 0 {
		t.Fatalf("category (changed to other): %v", got)
	}
	o = e.ok(e.call("app", "item.list", `{"limit":2}`))
	next, err := o.String("next")
	if err != nil {
		t.Fatal("no next")
	}
	o = e.ok(e.call("app", "item.list", js(map[string]any{"limit": 2, "after": next})))
	if o.Has("next") || !bytes.Contains(o["items"], []byte("Card")) {
		t.Fatalf("page 2: %s", o["items"])
	}
	// Delete.
	e.ok(e.call("app", "item.delete", js(map[string]any{"item_id": s})))
	e.code(e.call("app", "item.get", js(map[string]any{"item_id": s})), "not_found")
	if !e.h.HasActivity("item.deleted") {
		t.Fatal("delete not audited")
	}
	for _, b := range []string{`{"name":"x","sensitivity":"other"}`, `{"name":"x","tags":["@nope"]}`, `{"name":"x","credential":"AA=="}`,
		`{"name":"x","fields":[{"label":"L","kind":"file","value":"b"}]}`, `{"name":"x","tags":["@profile"],"sensitivity":"secret"}`} {
		e.code(e.call("app", "item.put", b), "bad_request")
	}
}

func TestLimits(t *testing.T) {
	e := newEnv(t)
	many := make([]field, itemspec.MaxFields+1)
	for i := range many {
		many[i] = field{Label: "L", Kind: "text", Value: ""}
	}
	e.code(e.call("app", "item.put", js(map[string]any{"name": "x", "fields": many})), "bad_request")
	big := strings.Repeat("v", 16000)
	var heavy []field
	for i := 0; i < 5; i++ {
		heavy = append(heavy, field{Label: "L", Kind: "multiline", Value: big})
	}
	e.code(e.call("app", "item.put", js(map[string]any{"name": "x", "fields": heavy})), "limit")
	for i := 0; i < itemspec.MaxItems; i++ {
		e.ok(e.call("app", "item.put", `{"name":"n"}`))
	}
	e.code(e.call("app", "item.put", `{"name":"n"}`), "limit")
}

func TestSensitivityChanges(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	id := e.put("data", "Login", []string{"work"}, field{Label: "User", Kind: "text", Value: "al"},
		field{Label: "Password", Kind: "password", Value: "s3cret"})
	// data ↔ secret is metadata only.
	e.ok(e.call("app", "item.sensitivity", js(map[string]any{"item_id": id, "version": 1, "sensitivity": "secret"})))
	if s, _ := e.item(id).String("sensitivity"); s != "secret" {
		t.Fatal("secret")
	}
	e.code(e.call("app", "item.sensitivity", js(map[string]any{"item_id": id, "version": 1, "sensitivity": "data"})), "conflict")
	e.code(e.call("app", "item.sensitivity", js(map[string]any{"item_id": id, "version": 2, "sensitivity": "secret"})), "bad_request")
	// To critical: a credential operation; the values leave DEK state.
	before := e.blob
	o := e.ok(e.sealed("app", "item.sensitivity", map[string]any{"item_id": id, "version": 2, "sensitivity": "critical"},
		map[string]any{"password": pw, "item_id": id}, true, false))
	if !o.Has("credential_version") || e.blob == before {
		t.Fatal("no CEK rotation")
	}
	raw, _ := e.set.Items.Save()
	if bytes.Contains(raw, []byte("s3cret")) || bytes.Contains(raw, []byte(`"al"`)) {
		t.Fatal("critical values kept in DEK state")
	}
	// The old blob is dead (every use rotated the CEK).
	stale := e.blob
	e.ok(e.sealed("app", "item.reveal", map[string]any{"item_id": id}, map[string]any{"password": pw, "item_id": id}, true, true))
	e.blob, stale = stale, e.blob
	e.code(e.sealed("app", "item.reveal", map[string]any{"item_id": id}, map[string]any{"password": pw, "item_id": id}, true, true), "stale_credential")
	e.blob = stale
	// Back out of critical: the vault moves the values itself.
	e.ok(e.sealed("app", "item.sensitivity", map[string]any{"item_id": id, "version": 3, "sensitivity": "data"},
		map[string]any{"password": pw, "item_id": id}, true, false))
	if !bytes.Contains(e.item(id)["fields"], []byte("s3cret")) {
		t.Fatal("values not moved back")
	}
	// @profile only on data items.
	p := e.put("data", "Bio", []string{"@profile"})
	e.code(e.call("app", "item.sensitivity", js(map[string]any{"item_id": p, "version": 1, "sensitivity": "secret"})), "bad_request")
	q := e.put("secret", "S", nil)
	e.code(e.call("app", "item.tag", js(map[string]any{"item_id": q, "version": 1, "tags": []string{"@profile"}})), "bad_request")
}

func TestCriticalItems(t *testing.T) {
	e := newEnv(t)
	// (Without a credential the runtime refuses everything, §3.5.7.)
	e.createCredential()
	id := e.putCritical("Recovery phrase", []string{"crypto"}, field{Label: "Words", Kind: "multiline", Value: "abandon ability able"},
		field{Label: "Key", Kind: "password", Value: "AAAA"})
	it := e.item(id)
	if s, _ := it.String("sensitivity"); s != "critical" || bytes.Contains(it["fields"], []byte("abandon")) || bytes.Contains(it["fields"], []byte(`"value"`)) {
		t.Fatalf("critical item.get: %s", it["fields"])
	}
	raw, _ := e.set.Items.Save()
	if bytes.Contains(raw, []byte("abandon")) {
		t.Fatal("critical value in DEK state")
	}
	// Reveal: values sealed to the reply key.
	o := e.ok(e.sealed("app", "item.reveal", map[string]any{"item_id": id}, map[string]any{"password": pw, "item_id": id}, true, true))
	sv, _ := o.Base64("values_sealed", -1)
	pt, err := credwire.OpenValue(e.reply, e.h.VaultID(), e.lastI, sv)
	if err != nil || !bytes.Contains(pt, []byte("abandon ability able")) || bytes.Contains(o["values_sealed"], []byte("abandon")) {
		t.Fatalf("reveal: %s %v", pt, err)
	}
	if !e.h.HasActivity("item.revealed") {
		t.Fatal("not audited")
	}
	// Consent bound to the item: another item_id in the sealed payload.
	other := e.putCritical("Other", nil)
	e.code(e.sealed("app", "item.reveal", map[string]any{"item_id": id}, map[string]any{"password": pw, "item_id": other}, true, true), "bad_request")
	// A UTK works once.
	u := e.take()
	e.ok(e.sealedUTK("app", "item.reveal", map[string]any{"item_id": id}, map[string]any{"password": pw, "item_id": id}, true, true, u))
	e.code(e.sealedUTK("app", "item.reveal", map[string]any{"item_id": id}, map[string]any{"password": pw, "item_id": id}, true, true, u), "utk_invalid")
	// Wrong password.
	e.code(e.sealed("app", "item.reveal", map[string]any{"item_id": id}, map[string]any{"password": "wrong password", "item_id": id}, true, true), "bad_password")
	// Replace (the item id travels sealed) and tags without the password.
	e.code(e.sealed("app", "item.put", map[string]any{"sensitivity": "critical", "version": 9},
		map[string]any{"password": pw, "item_id": id, "item": map[string]any{"name": "R"}}, true, false), "conflict")
	e.ok(e.sealed("app", "item.put", map[string]any{"sensitivity": "critical", "version": 1},
		map[string]any{"password": pw, "item_id": id, "item": map[string]any{"name": "Recovery", "notes": "paper copy at home",
			"fields": []field{{ID: "f1", Label: "Words", Kind: "multiline", Value: "abandon ability able"}}}}, true, false))
	if !bytes.Contains(e.item(id)["has_notes"], []byte("true")) {
		t.Fatal("has_notes")
	}
	e.retag(id, "crypto", "backup")
	if got := strs(t, e.item(id), "tags"); strings.Join(got, ",") != "backup,crypto" {
		t.Fatalf("tags: %v", got)
	}
	// Limits: a critical item's encoding is at most 12,288 bytes (its
	// content travels in one UTK payload).
	e.code(e.sealed("app", "item.put", map[string]any{"sensitivity": "critical"},
		map[string]any{"password": pw, "item": map[string]any{"name": "x",
			"fields": []field{{Label: "L", Kind: "multiline", Value: strings.Repeat("x", 13000)}}}}, true, false), "limit")
	// Delete needs the password; credential.delete takes every critical item.
	e.code(e.call("app", "item.delete", js(map[string]any{"item_id": other})), "bad_request")
	e.ok(e.sealed("app", "item.delete", map[string]any{"item_id": other}, map[string]any{"password": pw, "item_id": other}, true, false))
	e.code(e.call("app", "item.get", js(map[string]any{"item_id": other})), "not_found")
	e.ok(e.sealed("app", "credential.delete", nil, map[string]any{"password": pw}, true, false))
	e.code(e.call("app", "item.get", js(map[string]any{"item_id": id})), "not_found")
}

func TestRoundTrip(t *testing.T) {
	e := newEnv(t)
	e.put("data", "x", []string{"a"})
	e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"a"}})
	e.ok(e.call("app", "tag.set", `{"version":0,"tag":"a","color":"#00ff00"}`))
	g := newEnv(t)
	featuretest.RoundTrip(t, e.set.Items, g.set.Items)
	a, _ := e.set.Items.Save()
	b, _ := g.set.Items.Save()
	if !bytes.Equal(a, b) {
		t.Fatal("state differs after a round trip")
	}
}
