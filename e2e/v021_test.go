//go:build devenclave && e2e

package e2e

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
)

// VAULT-MESSAGING 0.21.0 through the real relay and the reference client:
// a critical item edited with one password entry and a secret item
// without a reveal (kept values), the size in item.get, a desktop's dry
// run answered without step-up, and the named limit.
func TestKeptValuesAndDryRun(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	desk := pairDesktop(t, a, r.URL)
	ctx := ctxT(t, 180*time.Second)

	// Critical: one credential operation keeps the seed and the notes.
	id, v, err := a.app.ItemPutCritical(ctx, credPW, "", 0, []string{"keys"}, client.ItemContent{Name: "Signer", Notes: "kept notes",
		Fields: []client.ItemField{{Label: "Seed", Kind: "password", Value: "KEPT-SEED"}, {Label: "Hint", Kind: "text", Value: "old"}}})
	if err != nil {
		t.Fatal(err)
	}
	v0, _ := a.app.CredentialVersion(ctx)
	ver0, _ := v0.Uint("version", 1, 1<<40)
	if _, v, err = a.app.ItemPutCritical(ctx, credPW, id, v, nil, client.ItemContent{Name: "Signer", KeepNotes: true,
		Fields: []client.ItemField{{ID: "f2", Label: "Hint", Kind: "text", Value: "new"}, {ID: "f1", Label: "Seed", Kind: "password"}}}); err != nil {
		t.Fatal(err)
	}
	v1, _ := a.app.CredentialVersion(ctx)
	if ver1, _ := v1.Uint("version", 1, 1<<40); ver1 != ver0+1 {
		t.Fatalf("one password entry: credential %d -> %d", ver0, ver1)
	}
	vals, err := a.app.ItemRevealCritical(ctx, credPW, id)
	if err != nil || !bytes.Contains(vals, []byte(`"KEPT-SEED"`)) || !bytes.Contains(vals, []byte(`"new"`)) || !bytes.Contains(vals, []byte("kept notes")) {
		t.Fatalf("merged: %s %v", vals, err)
	}
	it, err := a.app.ItemGet(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if n, ok, _ := it.OptUint("size", 0, 1<<40); !ok || n == 0 {
		t.Fatalf("critical size: %s", it["fields"])
	}
	// Secret: edited without item.reveal; the audit has no reveal.
	sid, sv, err := a.app.ItemPut(ctx, "", 0, "secret", nil, client.ItemContent{Name: "Wi-Fi",
		Fields: []client.ItemField{{Label: "Password", Kind: "password", Value: "hunter22"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.app.ItemPut(ctx, sid, sv, "", nil, client.ItemContent{Name: "Home Wi-Fi",
		Fields: []client.ItemField{{ID: "f1", Label: "Password", Kind: "password"}}}); err != nil {
		t.Fatal(err)
	}
	rv, err := a.app.ItemReveal(ctx, sid, nil)
	if err != nil || !strings.Contains(string(rv["fields"]), "hunter22") {
		t.Fatalf("secret kept: %v", err)
	}
	au, err := a.app.AuditList(ctx, map[string]any{"kinds": []string{"item"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(au["entries"]), `"item.revealed"`); n != 2 { // the two reveals above, not the edits
		t.Fatalf("%d item.revealed entries: %s", n, au["entries"])
	}
	// A desktop's dry run is answered at once (no step-up) and changes
	// nothing.
	dr, err := desk.ItemTagDryRun(ctx, sid, sv+1, []string{"home"})
	if err != nil || string(dr["shares"]) != "[]" || string(dr["withdrawals"]) != "[]" {
		t.Fatalf("desktop dry run: %v %v", dr, err)
	}
	if _, err := desk.ItemPutDryRun(ctx, id, v, "", nil); client.Code(err) != "forbidden" {
		t.Fatalf("desktop critical dry run: %v", err)
	}
	if g, _ := a.app.ItemGet(ctx, sid); bytes.Contains(g["tags"], []byte("home")) {
		t.Fatal("the dry run changed the item")
	}
	// The limit names itself.
	big := strings.Repeat("x", 16000)
	var fs []client.ItemField
	for i := 0; i < 5; i++ {
		fs = append(fs, client.ItemField{Label: "L", Kind: "multiline", Value: big})
	}
	_, _, err = a.app.ItemPut(ctx, "", 0, "", nil, client.ItemContent{Name: "Big", Fields: fs})
	if l, ok := client.LimitOf(err); !ok || l.Name != "item_size" || l.Max != 65536 || !l.HasSize || l.Size <= 65536 {
		t.Fatalf("limit: %+v %v", l, err)
	}
}

// VAULT-MESSAGING 0.21.0 (§10.12, §10.13) between two vaults: pending
// share decisions listed and decided in one change, the received grants'
// labels, the member's item names on a grant request, and a critical-use
// request for an unsuitable field answered at once without the member.
func TestSharingAndSuitability(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 180*time.Second)
	aConn, bConn := connect(t, a, b, 600)

	var ids []string
	for _, n := range []string{"Passport", "Licence", "Insurance"} {
		id, _, err := a.app.ItemPut(ctx, "", 0, "", []string{"docs"}, client.ItemContent{Name: n, Category: "identity_document",
			Fields: []client.ItemField{{Label: "Number", Kind: "text", Value: n + "-123"}}})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	rule, err := a.app.ShareRuleSet(ctx, map[string]any{"subject": map[string]any{"connection_id": aConn}, "tags": []string{"docs"}})
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := rule.String("rule_id")
	pend, err := a.app.SharePendingAll(ctx, map[string]any{"limit": 2})
	if err != nil || len(pend) != 3 {
		t.Fatalf("pending: %d %v", len(pend), err)
	}
	o, err := a.app.ShareDecideBoth(ctx, rid, ids[:2], ids[2:])
	if err != nil || !bytes.Contains(o["declined"], []byte(ids[2])) {
		t.Fatalf("decide: %v %v", o, err)
	}
	if pend, _ := a.app.SharePendingAll(ctx, nil); len(pend) != 0 {
		t.Fatalf("still pending: %d", len(pend))
	}
	// B receives two grants, with their labels.
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		l, err := b.app.GrantList(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(l["received"]), `"labels":[{"field_id":"f1","label":"Number","kind":"text"}]`) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("received: %s", l["received"])
		}
	}
	// B asks for the declined item: A's app sees its name and labels.
	if _, err := b.app.GrantRequest(ctx, bConn, []client.GrantItem{{Kind: "item", Ref: ids[2], Label: "your insurance"}}, 1, 0, ""); err != nil {
		t.Fatal(err)
	}
	gp := waitEvent(t, a.app, "grant.pending", func(json.RawMessage) bool { return true })
	if !bytes.Contains(gp.Body, []byte(`"name":"Insurance"`)) || !bytes.Contains(gp.Body, []byte(`"labels":[{"field_id":"f1","label":"Number","kind":"text"}]`)) ||
		bytes.Contains(gp.Body, []byte("Insurance-123")) {
		t.Fatalf("grant.pending: %s", gp.Body)
	}

	// Critical-item use: a number field is unsuitable at once.
	cid, _, err := a.app.ItemPutCritical(ctx, credPW, "", 0, []string{"signing"}, client.ItemContent{Name: "Mixed",
		Fields: []client.ItemField{{Label: "Seed", Kind: "password", Value: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))},
			{Label: "Count", Kind: "number", Value: "42"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.app.ShareRuleSet(ctx, map[string]any{"subject": map[string]any{"connection_id": aConn}, "tags": []string{"signing"}, "mode": "auto"}); err != nil {
		t.Fatal(err)
	}
	v0, _ := a.app.CredentialVersion(ctx)
	req, err := b.app.CriticalUseRequest(ctx, bConn, cid, "f2", "sign", []byte("x"), "")
	if err != nil {
		t.Fatal(err)
	}
	waitEvent(t, b.app, "critical-secret-use.result", func(raw json.RawMessage) bool {
		return has("request_id", req)(raw) && has("status", "unsuitable")(raw)
	})
	cl, err := a.app.CriticalUseList(ctx)
	if err != nil || string(cl["incoming"]) != "[]" {
		t.Fatalf("listed: %s %v", cl["incoming"], err)
	}
	if v1, _ := a.app.CredentialVersion(ctx); string(v1["version"]) != string(v0["version"]) {
		t.Fatal("the credential was opened")
	}
	au, err := a.app.AuditList(ctx, map[string]any{"kinds": []string{"critical-secret"}}, false)
	if err != nil || !bytes.Contains(au["entries"], []byte(`"critical-secret.use.denied"`)) {
		t.Fatalf("audit: %s %v", au["entries"], err)
	}
	// The password field is asked, with its kind.
	req2, err := b.app.CriticalUseRequest(ctx, bConn, cid, "f1", "sign", []byte("y"), "")
	if err != nil {
		t.Fatal(err)
	}
	p := waitEvent(t, a.app, "critical-secret-use.pending", has("request_id", req2))
	if field(t, p.Body, "kind") != "password" {
		t.Fatalf("pending: %s", p.Body)
	}
}
