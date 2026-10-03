//go:build devenclave && e2e

package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
)

// V4 batch 3, shared actions (§10.14) through the real relay: A offers B
// a respond action and a fixed auto action; B's vault keeps the offers; B
// invokes the respond action, A's app answers it, and B's app gets the
// result; B invokes the auto action and gets the fixed result without A
// being asked.
func TestSharedAction(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 120*time.Second)
	aConn, bConn := connect(t, a, b, 600)

	respond, _, err := a.app.ActionDefine(ctx, client.ActionDef{Name: "Lunch?", Kind: "respond", Connections: []string{aConn}})
	if err != nil {
		t.Fatal(err)
	}
	fixed, _, err := a.app.ActionDefine(ctx, client.ActionDef{Name: "Address", Kind: "fixed", Mode: "auto",
		Result: json.RawMessage(`{"addr":"1 Main St"}`), Connections: []string{aConn}})
	if err != nil {
		t.Fatal(err)
	}
	// B's vault receives the offers (the second carries both actions).
	deadline := time.Now().Add(30 * time.Second)
	for {
		l, err := b.app.ActionList(ctx, bConn)
		if err != nil {
			t.Fatal(err)
		}
		if s := string(l["actions"]); strings.Contains(s, respond) && strings.Contains(s, fixed) {
			if strings.Contains(s, "1 Main St") {
				t.Fatal("offer reveals the fixed result")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("offers not received: %s", l["actions"])
		}
		time.Sleep(300 * time.Millisecond)
	}

	iid, err := b.app.ActionInvoke(ctx, bConn, respond, json.RawMessage(`{"when":"noon"}`))
	if err != nil {
		t.Fatal(err)
	}
	p := waitEvent(t, a.app, "action.pending", has("invocation_id", iid))
	if field(t, p.Body, "connection_id") != aConn || !strings.Contains(string(p.Body), `"when":"noon"`) {
		t.Fatalf("pending: %s", p.Body)
	}
	if err := a.app.ActionRespond(ctx, iid, true, json.RawMessage(`{"answer":"yes"}`)); err != nil {
		t.Fatal(err)
	}
	res, err := b.app.ActionResult(ctx, iid)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := res.String("status"); st != "ok" || !strings.Contains(string(res["result"]), `"answer":"yes"`) {
		t.Fatalf("result: %v", res)
	}

	iid2, err := b.app.ActionInvoke(ctx, bConn, fixed, nil)
	if err != nil {
		t.Fatal(err)
	}
	res2, err := b.app.ActionResult(ctx, iid2)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := res2.String("status"); st != "ok" || string(res2["result"]) != `{"addr":"1 Main St"}` {
		t.Fatalf("auto result: %v", res2)
	}
	for _, ev := range a.app.Events() {
		if ev.Type == "action.pending" && has("invocation_id", iid2)(ev.Body) {
			t.Fatal("auto action asked the member")
		}
	}
	au, err := a.app.AuditList(ctx, map[string]any{"kinds": []string{"action"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"action.defined", "action.invoked", "action.approved"} {
		if !strings.Contains(string(au["entries"]), `"`+k+`"`) {
			t.Errorf("audit lacks %s", k)
		}
	}
}
