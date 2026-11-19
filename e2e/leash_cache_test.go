//go:build devenclave && e2e

package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/vault"
)

// §8.2 Exception (owner decision a, #14595): an agent's answer that
// carries a secret value is sent once with it; a retransmission of the same
// request (same inner id) is answered from the response cache with a copy
// that holds no value, and is not referred or decided again. For item.get
// (reveal), item.run and item.proxy, through the relay.
func TestLeashValueNotCached(t *testing.T) {
	const secret = "sk_test_cache_1"
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	ctx := ctxT(t, 180*time.Second)
	item, _, err := a.app.ItemPut(ctx, "", 0, "secret", []string{"agent ok"}, client.ItemContent{Name: "api",
		Fields: []client.ItemField{{Label: "Key", Kind: "password", Value: secret}}, Notes: "notes-" + secret})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := client.New(ctx, client.Config{Role: vault.KindAgent, Name: "c-agent", RelayURL: r.URL, PollWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	pc := mustOK(t, a.request(a.app, "device.pair.create", `{"role":"agent"}`))
	link, _ := pc.String("link")
	pid, _ := pc.String("pairing_id")
	if _, err := agent.Pair(ctx, link); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, a.app, "device.pair.pending", has("pairing_id", pid))
	if _, err := a.app.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	mustOK(t, a.request(a.app, "device.pair.approve", `{"pairing_id":"`+pid+`","session_seconds":600,"grants":[{"scope":"connection.list","approval":"auto"}]}`))
	if err := agent.AwaitPaired(ctx); err != nil {
		t.Fatal(err)
	}
	ro, err := a.app.ShareRuleSet(ctx, map[string]any{"subject": map[string]any{"agent_id": agent.DeviceID()}, "tags": []string{"agent ok"}, "mode": "auto"})
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := ro.String("rule_id")
	waitEvent(t, agent, "leash.grant.updated", func(b json.RawMessage) bool { return strings.Contains(string(b), rid) })
	if _, err := a.app.LeashItemSet(ctx, agent.DeviceID(), item, 0, map[string]any{"ways": []string{"use", "run", "proxy", "reveal"},
		"run":   map[string]any{"programs": []any{map[string]any{"program": "git"}}, "each": false},
		"proxy": map[string]any{"hosts": []string{"api.example.com"}, "header": "Authorization", "prefix": "Bearer "}}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		op      string
		members map[string]any
		cached  []string // members the cached copy keeps
	}{
		{"item.get", map[string]any{"item_id": item}, []string{`"name":"api"`, `"label":"Key"`}},
		{"item.run", map[string]any{"item_id": item, "field_id": "f1", "program": "/usr/bin/git", "sha256": strings.Repeat("a", 64),
			"argv": []string{"git", "push"}, "cwd": "/home/a", "how": "env", "name": "TOKEN"}, []string{`"field_id":"f1"`}},
		{"item.proxy", map[string]any{"item_id": item, "field_id": "f1", "host": "api.example.com"},
			[]string{`"header":"Authorization"`, `"prefix":"Bearer "`, `"expires_at"`}},
	}
	for _, c := range cases {
		body := map[string]any{"op": c.op}
		for k, v := range c.members {
			body[k] = v
		}
		raw, _ := json.Marshal(body)
		id, err := agent.Send(ctx, "agent.request", raw)
		if err != nil {
			t.Fatal(err)
		}
		ap := waitEvent(t, a.app, "approval.pending", has("type", "agent.request"))
		if result, err := a.app.ApprovalDecide(ctx, field(t, ap.Body, "approval_id"), true); err != nil || result != "ok" {
			t.Fatalf("%s: approve: %q %v", c.op, result, err)
		}
		first, err := agent.AwaitResponse(ctx, id)
		if err != nil || !first.OK() || !strings.Contains(string(first.Body()), secret) {
			t.Fatalf("%s: first answer: %v %+v", c.op, err, first)
		}
		// The same request again: the cached copy, without the value or the
		// notes, and no new approval.
		if _, err := agent.SendWithID(ctx, id, "agent.request", raw); err != nil {
			t.Fatal(err)
		}
		again, err := agent.AwaitResponse(ctx, id)
		if err != nil || !again.OK() || strings.Contains(string(again.Body()), secret) || strings.Contains(string(again.Body()), `"value"`) ||
			!strings.Contains(string(again.Body()), `"item_id":"`+item+`"`) {
			t.Fatalf("%s: retransmission: %v %+v", c.op, err, again)
		}
		for _, m := range c.cached {
			if !strings.Contains(string(again.Body()), m) {
				t.Fatalf("%s: cached copy lacks %s: %s", c.op, m, again.Body())
			}
		}
		time.Sleep(2 * time.Second)
		for _, ev := range a.app.Events() {
			if ev.Type == "approval.pending" {
				t.Fatalf("%s: the retransmission was referred again", c.op)
			}
		}
	}
}
