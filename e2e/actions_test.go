//go:build devenclave && e2e

package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/internal/strictjson"
)

// V4 batch 3, shared actions (§10.14) through the real relay: the
// built-in catalog run by A's vault, invoked by B under each permission
// mode (allowlist: items.share, with the content fetched through
// the one-use grant; prompt-each-time approved by A's app; default-allow;
// default-deny: no longer offered), and a critical action whose approval
// is refused without the credential's unlock window and then accepted
// with it (no wallet configured for the action: unavailable; the wallet's
// own flows are in wallet_test.go).
func TestSharedAction(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 180*time.Second)
	aConn, bConn := connect(t, a, b, 600)
	phone, _, err := a.app.ItemPut(ctx, "", 0, "", nil, client.ItemContent{Name: "Phone", Category: "contact",
		Fields: []client.ItemField{{Label: "Mobile", Kind: "phone", Value: "555-0100"}, {Label: "Home", Kind: "text", Value: "1 Main"}}})
	if err != nil {
		t.Fatal(err)
	}

	offered := func(action, want string) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for {
			l, err := b.app.ActionList(ctx, bConn)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(l["actions"]), want) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("offer of %s (%s) not seen: %s", action, want, l["actions"])
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	status := func(o strictjson.Object) string { s, _ := o.String("status"); return s }

	// allowlist: runs at once; the item (one field) comes through a
	// one-use grant.
	if _, err := a.app.ActionConfigure(ctx, client.ActionConfig{ActionID: "items.share", Mode: "allowlist",
		Connections: []string{aConn}, Items: []string{phone}}); err != nil {
		t.Fatal(err)
	}
	offered("items.share", `"items.share","version":1,"prompt":false`)
	id, err := b.app.ActionInvoke(ctx, bConn, "items.share", json.RawMessage(`{"item_id":"`+phone+`","fields":["f1"]}`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := b.app.ActionResult(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	// The field values themselves must not travel in the result, only the
	// grant (a bare "555" also matched an expires_at ending in .555Z).
	if status(res) != "ok" || strings.Contains(string(res["result"]), "555-0100") || strings.Contains(string(res["result"]), "1 Main") {
		t.Fatalf("allowlist: %v", res)
	}
	ro, _ := strictjson.ParseObject(res["result"])
	gs, _ := ro.Array("grants")
	gr, err := b.app.GrantFetch(ctx, field(t, gs[0], "grant_id"))
	if err != nil || !strings.Contains(string(gr.Value), "555-0100") || strings.Contains(string(gr.Value), "1 Main") {
		t.Fatalf("fetch: %v %+v", err, gr)
	}

	// prompt-each-time: held until A's app approves.
	if _, err := a.app.ActionConfigure(ctx, client.ActionConfig{ActionID: "audit.recent", Mode: "prompt-each-time"}); err != nil {
		t.Fatal(err)
	}
	offered("audit.recent", `"audit.recent","version":1,"prompt":true`)
	id, err = b.app.ActionInvoke(ctx, bConn, "audit.recent", json.RawMessage(`{"limit":5}`))
	if err != nil {
		t.Fatal(err)
	}
	p := waitEvent(t, a.app, "action.pending", has("invocation_id", id))
	if field(t, p.Body, "connection_id") != aConn {
		t.Fatalf("pending: %s", p.Body)
	}
	if st, err := a.app.ActionRespond(ctx, id, true); err != nil || st != "ok" {
		t.Fatalf("respond: %q %v", st, err)
	}
	if res, err = b.app.ActionResult(ctx, id); err != nil || status(res) != "ok" || !strings.Contains(string(res["result"]), `"entries"`) {
		t.Fatalf("prompt-each-time: %v %v", err, res)
	}

	// default-allow: at once, without asking.
	if _, err := a.app.ActionConfigure(ctx, client.ActionConfig{ActionID: "audit.recent", Mode: "default-allow"}); err != nil {
		t.Fatal(err)
	}
	offered("audit.recent", `"audit.recent","version":1,"prompt":false`)
	if id, err = b.app.ActionInvoke(ctx, bConn, "audit.recent", nil); err != nil {
		t.Fatal(err)
	}
	if res, err = b.app.ActionResult(ctx, id); err != nil || status(res) != "ok" {
		t.Fatalf("default-allow: %v %v", err, res)
	}

	// default-deny: no longer offered; B cannot invoke it.
	if _, err := a.app.ActionConfigure(ctx, client.ActionConfig{ActionID: "audit.recent", Mode: "default-deny"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		l, _ := b.app.ActionList(ctx, bConn)
		if !strings.Contains(string(l["actions"]), "audit.recent") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("offer not withdrawn")
		}
		time.Sleep(200 * time.Millisecond)
	}
	if _, err := b.app.ActionInvoke(ctx, bConn, "audit.recent", nil); client.Code(err) != "not_found" {
		t.Fatalf("default-deny: %v", err)
	}

	// A critical action: approved only by an app within the unlock window.
	if _, err := a.app.ActionConfigure(ctx, client.ActionConfig{ActionID: "wallet.request-payment", Mode: "default-allow"}); client.Code(err) != "bad_request" {
		t.Fatalf("critical default-allow: %v", err)
	}
	if _, err := a.app.ActionConfigure(ctx, client.ActionConfig{ActionID: "wallet.request-payment", Mode: "prompt-each-time"}); err != nil {
		t.Fatal(err)
	}
	offered("wallet.request-payment", `"wallet.request-payment","version":1,"prompt":true`)
	if id, err = b.app.ActionInvoke(ctx, bConn, "wallet.request-payment", json.RawMessage(`{"asset":"BTC","amount_sats":1000,"address":"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"}`)); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, a.app, "action.pending", has("invocation_id", id))
	if _, err := a.app.ActionRespond(ctx, id, true); client.Code(err) != "credential_locked" {
		t.Fatalf("critical outside the unlock window: %v", err)
	}
	if _, err := a.app.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	if st, err := a.app.ActionRespond(ctx, id, true); err != nil || st != "unavailable" {
		t.Fatalf("critical approved: %q %v", st, err)
	}
	if res, err = b.app.ActionResult(ctx, id); err != nil || status(res) != "unavailable" {
		t.Fatalf("wallet: %v %v", err, res)
	}

	au, err := a.app.AuditList(ctx, map[string]any{"kinds": []string{"action", "grant"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"action.configured", "action.invoked", "action.approved", "grant.issued", "grant.fetched"} {
		if !strings.Contains(string(au["entries"]), `"`+k+`"`) {
			t.Errorf("audit lacks %s", k)
		}
	}
}
