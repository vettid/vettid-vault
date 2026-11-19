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
	"github.com/vettid/vettid-vault/vms/envelope"
)

// §10.11 item.proxy (0.42.0) through the real relay: refused without the
// proxy way and for a host the item does not bind; always referred, even
// under an auto rule; approved, answered the value with the header, the
// prefix, the host and expires_at cut to the agent's access session; a
// header changed while it waits is referred again, the new approval
// replacing the old.
func TestLeashItemProxy(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	ctx := ctxT(t, 180*time.Second)
	api, _, err := a.app.ItemPut(ctx, "", 0, "secret", []string{"agent ok"}, client.ItemContent{Name: "api",
		Fields: []client.ItemField{{Label: "Key", Kind: "password", Value: "sk_test_1"}}})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := client.New(ctx, client.Config{Role: vault.KindAgent, Name: "p-agent", RelayURL: r.URL, PollWait: time.Second})
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
	approved := mustOK(t, a.request(a.app, "device.pair.approve", `{"pairing_id":"`+pid+`","session_seconds":600,"grants":[{"scope":"connection.list","approval":"auto"}]}`))
	if err := agent.AwaitPaired(ctx); err != nil {
		t.Fatal(err)
	}
	sessionEnd := time.Now().Add(600 * time.Second)
	if exp, err := approved.String("session_expires_at"); err == nil {
		if ts, err := envelope.ParseTS(exp); err == nil {
			sessionEnd = ts
		}
	}
	ro, err := a.app.ShareRuleSet(ctx, map[string]any{"subject": map[string]any{"agent_id": agent.DeviceID()}, "tags": []string{"agent ok"}, "mode": "auto"})
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := ro.String("rule_id")
	waitEvent(t, agent, "leash.grant.updated", func(b json.RawMessage) bool { return strings.Contains(string(b), rid) })

	proxy := func(host string) map[string]any {
		return map[string]any{"item_id": api, "field_id": "f1", "host": host, "seconds": 3600}
	}
	type res struct {
		r   *client.Response
		err error
	}
	async := func(m map[string]any) chan res {
		ch := make(chan res, 1)
		go func() {
			rr, err := agent.AgentRequest(ctxT(t, 90*time.Second), "item.proxy", m)
			ch <- res{rr, err}
		}()
		return ch
	}
	cool := func() { time.Sleep(4200 * time.Millisecond) } // past a refusal's cooldown (1 s, 2 s, then 4 s)

	// Without the proxy way: way_not_allowed.
	if rr, err := agent.AgentRequest(ctx, "item.proxy", proxy("api.example.com")); err != nil || rr.ErrorCode() != "way_not_allowed" {
		t.Fatalf("without proxy: %v %+v", err, rr)
	}
	if _, err := a.app.LeashItemSet(ctx, agent.DeviceID(), api, 0, map[string]any{"ways": []string{"use", "proxy"},
		"proxy": map[string]any{"hosts": []string{"api.example.com"}, "header": "Authorization", "prefix": "Bearer "}}); err != nil {
		t.Fatal(err)
	}
	cool()
	// A host the item does not bind: bad_request.
	if rr, err := agent.AgentRequest(ctx, "item.proxy", proxy("evil.example.com")); err != nil || rr.ErrorCode() != "bad_request" {
		t.Fatalf("other host: %v %+v", err, rr)
	}
	cool()

	// Referred under an auto rule; approved: the value, its header and the
	// expiry cut to the session's end (asked 3,600 s, session 600 s).
	ch := async(proxy("api.example.com"))
	ap := waitEvent(t, a.app, "approval.pending", has("type", "agent.request"))
	if !strings.Contains(string(ap.Body), `"op":"item.proxy"`) || strings.Contains(string(ap.Body), "sk_test_1") {
		t.Fatalf("approval: %s", ap.Body)
	}
	if result, err := a.app.ApprovalDecide(ctx, field(t, ap.Body, "approval_id"), true); err != nil || result != "ok" {
		t.Fatalf("approve: %q %v", result, err)
	}
	got := <-ch
	if got.err != nil || !got.r.OK() {
		t.Fatalf("approved proxy: %+v", got)
	}
	var body map[string]string
	if err := json.Unmarshal(got.r.Body(), &body); err != nil || body["value"] != "sk_test_1" || body["header"] != "Authorization" ||
		body["prefix"] != "Bearer " || body["host"] != "api.example.com" {
		t.Fatalf("answer: %v %s", err, got.r.Body())
	}
	exp, err := envelope.ParseTS(body["expires_at"])
	if err != nil || exp.After(sessionEnd.Add(time.Second)) || exp.Before(time.Now().Add(500*time.Second)) {
		t.Fatalf("expires_at %s, session ends %s: %v", body["expires_at"], sessionEnd, err)
	}

	// A header changed while it waits: referred again, never the value on
	// the old approval.
	ch = async(proxy("api.example.com"))
	ap = waitEvent(t, a.app, "approval.pending", has("type", "agent.request"))
	first := field(t, ap.Body, "approval_id")
	if _, err := a.app.LeashItemSet(ctx, agent.DeviceID(), api, 1, map[string]any{"ways": []string{"use", "proxy"},
		"proxy": map[string]any{"hosts": []string{"api.example.com"}, "header": "X-Api-Key"}}); err != nil {
		t.Fatal(err)
	}
	if result, err := a.app.ApprovalDecide(ctx, first, true); err != nil || result != "referred" {
		t.Fatalf("approve after the change: %q %v", result, err)
	}
	ap = waitEvent(t, a.app, "approval.pending", has("replaces", first))
	if result, err := a.app.ApprovalDecide(ctx, field(t, ap.Body, "approval_id"), true); err != nil || result != "ok" {
		t.Fatalf("approve again: %q %v", result, err)
	}
	if got := <-ch; got.err != nil || !got.r.OK() || !strings.Contains(string(got.r.Body()), `"header":"X-Api-Key","prefix":""`) {
		t.Fatalf("referred-again proxy: %+v", got)
	}
}
