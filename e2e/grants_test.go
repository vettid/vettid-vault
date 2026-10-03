//go:build devenclave && e2e

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
)

// V4 items, share rules (§10.7, §10.12) through the real relay: A holds
// items of each sensitivity; a rule in ask mode for B asks A's member
// (share.pending), who approves; B is told (data.shared) and fetches the
// content sealed to its device; removing the tag revokes the grant at once
// and B's next fetch is refused; an auto rule shares a newly tagged item
// without asking; B's catalog shows only what A shares with B, never tags;
// a critical item matched by a rule is usable, never readable.
func TestItemsShareRules(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 180*time.Second)
	aConn, bConn := connect(t, a, b, 600)

	allergy, av, err := a.app.ItemPut(ctx, "", 0, "data", []string{"medical", "zz private"}, client.ItemContent{Name: "Allergy list", Category: "health",
		Fields: []client.ItemField{{Label: "Allergies", Kind: "multiline", Value: "penicillin"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.app.ItemPut(ctx, "", 0, "secret", []string{"medical"}, client.ItemContent{Name: "Insurance login", Category: "login",
		Fields: []client.ItemField{{Label: "Password", Kind: "password", Value: "ins-pw"}}}); err != nil {
		t.Fatal(err)
	}
	seed := base64.StdEncoding.EncodeToString(make([]byte, 32))
	crit, _, err := a.app.ItemPutCritical(ctx, credPW, "", 0, []string{"medical"}, client.ItemContent{Name: "Health key", Category: "crypto_wallet",
		Fields: []client.ItemField{{Label: "Seed", Kind: "password", Value: seed}}})
	if err != nil {
		t.Fatal(err)
	}

	// Preview, then an ask rule for B: the member is asked.
	pv, err := a.app.ShareRuleSet(ctx, map[string]any{"subject": map[string]any{"connection_id": aConn}, "tags": []string{"medical"}, "dry_run": true})
	if err != nil || !strings.Contains(string(pv["matches"]), allergy) {
		t.Fatalf("preview: %v", err)
	}
	ro, err := a.app.ShareRuleSet(ctx, map[string]any{"subject": map[string]any{"connection_id": aConn}, "tags": []string{"medical"}})
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := ro.String("rule_id")
	pend := waitEvent(t, a.app, "share.pending", has("rule_id", rid))
	if !strings.Contains(string(pend.Body), allergy) || !strings.Contains(string(pend.Body), crit) {
		t.Fatalf("share.pending: %s", pend.Body)
	}
	if _, err := a.app.ShareDecide(ctx, rid, []string{allergy, crit}, true); err != nil {
		t.Fatal(err)
	}
	ev := waitEvent(t, b.app, "grant.event", has("event", "shared"))
	if strings.Contains(string(ev.Body), "medical") || strings.Contains(string(ev.Body), "penicillin") || strings.Contains(string(ev.Body), crit) {
		t.Fatalf("shared event: %s", ev.Body)
	}
	var shared struct {
		Grants []struct {
			ID  string `json:"grant_id"`
			Ref string `json:"ref"`
		} `json:"grants"`
	}
	if err := json.Unmarshal(ev.Body, &shared); err != nil || len(shared.Grants) != 1 || shared.Grants[0].Ref != allergy {
		t.Fatalf("shared: %s", ev.Body)
	}
	gid := shared.Grants[0].ID
	res, err := b.app.GrantFetch(ctx, gid)
	if err != nil || res.Error != "" || !strings.Contains(string(res.Value), "penicillin") || strings.Contains(string(res.Value), "zz private") {
		t.Fatalf("fetch: %+v %v", res, err)
	}
	// B's catalog: the allergy list (readable) and the critical item
	// (usable), never tags, never the declined-by-default secret item.
	cat, err := b.app.GrantCatalog(ctx, bConn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cat), allergy) || !strings.Contains(string(cat), `"usable":true`) || strings.Contains(string(cat), "Insurance") ||
		strings.Contains(string(cat), "medical\"") || strings.Contains(string(cat), "zz private") {
		t.Fatalf("catalog: %s", cat)
	}

	// The tag removed: revoked at once; B's next fetch is refused.
	if _, err := a.app.ItemTag(ctx, allergy, av, []string{"zz private"}); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, b.app, "grant.event", func(raw json.RawMessage) bool { return has("event", "revoked")(raw) && has("grant_id", gid)(raw) })
	if res, err := b.app.GrantFetch(ctx, gid); err != nil || res.Error != "revoked" {
		t.Fatalf("after untag: %+v %v", res, err)
	}

	// An auto rule: a newly tagged item is shared without asking.
	if _, err := a.app.ShareRuleSet(ctx, map[string]any{"subject": map[string]any{"connection_id": aConn}, "tags": []string{"family"}, "mode": "auto"}); err != nil {
		t.Fatal(err)
	}
	b.app.Events() // drain
	fam, _, err := a.app.ItemPut(ctx, "", 0, "data", []string{"family"}, client.ItemContent{Name: "Wi-Fi at home",
		Fields: []client.ItemField{{Label: "Password", Kind: "password", Value: "fam-pw"}}})
	if err != nil {
		t.Fatal(err)
	}
	ev = waitEvent(t, b.app, "grant.event", func(raw json.RawMessage) bool {
		return has("event", "shared")(raw) && strings.Contains(string(raw), fam)
	})
	_ = json.Unmarshal(ev.Body, &shared)
	if res, err := b.app.GrantFetch(ctx, shared.Grants[0].ID); err != nil || !strings.Contains(string(res.Value), "fam-pw") {
		t.Fatalf("auto fetch: %+v %v", res, err)
	}

	// Audit on both sides.
	au, err := a.app.AuditList(ctx, map[string]any{"kinds": []string{"share", "grant"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"share.rule.created", "share.included", "share.withdrawn", "grant.issued", "grant.fetched", "grant.revoked"} {
		if !strings.Contains(string(au["entries"]), `"`+k+`"`) {
			t.Errorf("audit lacks %s", k)
		}
	}
}

// V4 batch 3 grants (§10.12), one-off, through the real relay: B asks for
// a known item and for "your phone" by category; A's app answers the
// category with its item; B fetches both (sealed to its device); uses are
// counted; A revokes and B is told; B's next fetch is refused.
func TestGrantRequestAndRevoke(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 180*time.Second)
	_, bConn := connect(t, a, b, 600)

	wifi, _, err := a.app.ItemPut(ctx, "", 0, "secret", nil, client.ItemContent{Name: "wifi",
		Fields: []client.ItemField{{Label: "Password", Kind: "password", Value: "hunter22"}, {Label: "SSID", Kind: "text", Value: "home-net"}}})
	if err != nil {
		t.Fatal(err)
	}
	phone, _, err := a.app.ItemPut(ctx, "", 0, "data", nil, client.ItemContent{Name: "Phone", Category: "contact",
		Fields: []client.ItemField{{Label: "Number", Kind: "phone", Value: "+1 555 0100"}}})
	if err != nil {
		t.Fatal(err)
	}
	rid, err := b.app.GrantRequest(ctx, bConn, []client.GrantItem{{Kind: "item", Ref: wifi, Fields: []string{"f1"}},
		{Kind: "category", Ref: "contact", Label: "your phone"}}, 2, 0, "dinner")
	if err != nil {
		t.Fatal(err)
	}
	pend := waitEvent(t, a.app, "grant.pending", has("request_id", rid))
	if !strings.Contains(string(pend.Body), `"available":true`) || !strings.Contains(string(pend.Body), "dinner") {
		t.Fatalf("pending: %s", pend.Body)
	}
	if _, err := a.app.GrantDecideAnswers(ctx, rid, true, nil, []client.GrantAnswer{{Index: 1, ItemID: phone}}, 0, 0); err != nil {
		t.Fatal(err)
	}
	ev := waitEvent(t, b.app, "grant.event", has("event", "granted"))
	var granted struct {
		Grants []struct {
			ID  string `json:"grant_id"`
			Ref string `json:"ref"`
		} `json:"grants"`
	}
	if err := json.Unmarshal(ev.Body, &granted); err != nil || len(granted.Grants) != 2 {
		t.Fatalf("granted: %s", ev.Body)
	}
	ids := map[string]string{}
	for _, g := range granted.Grants {
		ids[g.Ref] = g.ID
	}
	res, err := b.app.GrantFetch(ctx, ids[wifi])
	if err != nil || res.Error != "" || !strings.Contains(string(res.Value), "hunter22") || strings.Contains(string(res.Value), "home-net") || res.UsesLeft != 1 {
		t.Fatalf("fetch secret: %+v %v", res, err)
	}
	res, err = b.app.GrantFetch(ctx, ids[phone])
	if err != nil || !strings.Contains(string(res.Value), "+1 555 0100") {
		t.Fatalf("fetch answered item: %+v %v", res, err)
	}
	gl, err := a.app.GrantList(ctx)
	if err != nil || !strings.Contains(string(gl["given"]), `"used":1`) {
		t.Fatalf("given: %s %v", gl["given"], err)
	}
	if err := a.app.GrantRevoke(ctx, ids[wifi]); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, b.app, "grant.event", func(raw json.RawMessage) bool {
		return has("event", "revoked")(raw) && has("grant_id", ids[wifi])(raw)
	})
	res, err = b.app.GrantFetch(ctx, ids[wifi])
	if err != nil || res.Error != "revoked" || res.Value != nil {
		t.Fatalf("after revoke: %+v %v", res, err)
	}
	au, err := a.app.AuditList(ctx, map[string]any{"kinds": []string{"grant"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"grant.requested", "grant.issued", "grant.fetched", "grant.revoked"} {
		if !strings.Contains(string(au["entries"]), `"`+k+`"`) {
			t.Errorf("audit lacks %s", k)
		}
	}
}
