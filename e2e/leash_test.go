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
	"github.com/vettid/vettid-vault/vault"
)

// V4 batch 3 and V4 items, LEASH (§6.7, §6.8, §10.11, §10.12) through the
// real relay: an agent paired with initial grants has a profile read
// referred to the app and approved, and is refused what no grant covers;
// an agent share rule (a signed items.read delegation carrying the rule)
// lets it read and use the items the rule includes, never a critical one;
// in ask mode the member approves each item first; deleting the rule stops
// it at once; spam suspends it; unlinking revokes everything.
func TestLeashAgent(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	ctx := ctxT(t, 180*time.Second)

	wifi, _, err := a.app.ItemPut(ctx, "", 0, "secret", []string{"agent ok"}, client.ItemContent{Name: "wifi",
		Fields: []client.ItemField{{Label: "Password", Kind: "password", Value: "hunter22"}}})
	if err != nil {
		t.Fatal(err)
	}
	bank, _, err := a.app.ItemPut(ctx, "", 0, "secret", []string{"money"}, client.ItemContent{Name: "bank",
		Fields: []client.ItemField{{Label: "PIN", Kind: "password", Value: "s3cret"}}})
	if err != nil {
		t.Fatal(err)
	}
	crit, _, err := a.app.ItemPutCritical(ctx, credPW, "", 0, []string{"agent ok"}, client.ItemContent{Name: "seed",
		Fields: []client.ItemField{{Label: "Words", Kind: "multiline", Value: "never for agents"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.app.ProfileSet(ctx, map[string]any{"version": 0, "name": "Ada"}); err != nil {
		t.Fatal(err)
	}

	// Pairing with initial grants and a first access session (§6.7).
	agent, err := client.New(ctx, client.Config{Role: vault.KindAgent, Name: "a-agent", RelayURL: r.URL, PollWait: time.Second})
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
	grants := `[{"scope":"connection.list","approval":"auto"},{"scope":"profile.get"}]`
	approve := `{"pairing_id":"` + pid + `","session_seconds":600,"grants":` + grants + `}`
	// Every grant is a delegation signed by the member's credential key:
	// the app must open the unlock window first (§10.11).
	if rr := a.request(a.app, "device.pair.approve", approve); rr.ErrorCode() != "credential_locked" {
		t.Fatalf("pairing grants outside the unlock window: %q", rr.ErrorCode())
	}
	if _, err := a.app.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	// items.read is a share rule, never a pairing grant.
	if rr := a.request(a.app, "device.pair.approve", `{"pairing_id":"`+pid+`","grants":[{"scope":"items.read"}]}`); rr.ErrorCode() != "bad_request" {
		t.Fatalf("items.read at pairing: %q", rr.ErrorCode())
	}
	mustOK(t, a.request(a.app, "device.pair.approve", approve))
	if err := agent.AwaitPaired(ctx); err != nil {
		t.Fatal(err)
	}
	up := waitEvent(t, agent, "leash.grant.updated", nil)
	if n := strings.Count(string(up.Body), `"grant_id"`); n != 2 {
		t.Fatalf("initial grants: %s", up.Body)
	}
	cv, err := a.app.CredentialVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	memberKey, _ := cv.Base64("key", 32)
	for _, g := range agent.LeashGrants() {
		d, err := client.VerifyDelegation(g, memberKey, time.Now())
		if err != nil || string(d.Sub) != string(agent.IdentityKey()) || string(d.Iss) != string(memberKey) {
			t.Fatalf("delegation: %v", err)
		}
		// 0.12.0: the grant object carries sig and no key.
		if strings.Contains(string(g), `"key"`) || strings.Contains(string(g), `"delegation_sig"`) || !strings.Contains(string(g), `"sig"`) {
			t.Fatalf("grant object: %s", g)
		}
	}

	// No rule yet: the catalog is refused.
	if rr, err := agent.AgentRequest(ctx, "catalog", nil); err != nil || rr.ErrorCode() != "forbidden" {
		t.Fatalf("catalog without a rule: %v %q", err, rr.ErrorCode())
	}
	// An agent share rule (auto): a signed items.read delegation that
	// carries the rule.
	rule := map[string]any{"subject": map[string]any{"agent_id": agent.DeviceID()}, "tags": []string{"agent ok"}, "mode": "auto"}
	ro, err := a.app.ShareRuleSet(ctx, rule)
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := ro.String("rule_id")
	waitEvent(t, agent, "leash.grant.updated", func(b json.RawMessage) bool { return strings.Contains(string(b), rid) })
	var mine json.RawMessage
	for _, g := range agent.LeashGrants() {
		if strings.Contains(string(g), rid) {
			mine = g
		}
	}
	d, err := client.VerifyDelegation(mine, memberKey, time.Now())
	if err != nil || d.Scope.Op != "items.read" || strings.Join(d.Scope.Tags, ",") != "agent ok" || d.Approval != "auto" || d.Limits == nil || d.Limits.PerHour != 60 {
		t.Fatalf("items.read delegation: %+v %v", d, err)
	}
	if !strings.Contains(string(ro["included"]), wifi) || strings.Contains(string(ro["included"]), crit) {
		t.Fatalf("rule includes: %s", ro["included"])
	}
	cat, err := agent.AgentRequest(ctx, "catalog", nil)
	if err != nil || !cat.OK() || !strings.Contains(string(cat.Body()), wifi) || strings.Contains(string(cat.Body()), bank) ||
		strings.Contains(string(cat.Body()), crit) || strings.Contains(string(cat.Body()), "agent ok") {
		t.Fatalf("catalog: %v %s", err, cat.Body())
	}
	get, err := agent.AgentRequest(ctx, "item.get", map[string]any{"item_id": wifi})
	if err != nil || !get.OK() || !strings.Contains(string(get.Body()), `"value":"hunter22"`) {
		t.Fatalf("item.get: %v %+v", err, get)
	}
	for _, id := range []string{bank, crit} { // not included / critical: never
		if rr, err := agent.AgentRequest(ctx, "item.get", map[string]any{"item_id": id}); err != nil || rr.ErrorCode() != "forbidden" {
			t.Fatalf("item.get %s: %v %q", id, err, rr.ErrorCode())
		}
		time.Sleep(1100 * time.Millisecond) // past the refusal cooldown
	}
	time.Sleep(2100 * time.Millisecond)
	use, err := agent.AgentRequest(ctx, "item.use", map[string]any{"item_id": wifi, "field_id": "f1", "action": "hmac-sha256", "data": "aGk="})
	if err != nil || !use.OK() || strings.Contains(string(use.Body()), "hunter22") {
		t.Fatalf("item.use: %v %+v", err, use)
	}

	// Referred to the app (an ask grant), approved, then answered.
	type res struct {
		r   *client.Response
		err error
	}
	done := make(chan res, 1)
	go func() {
		rr, err := agent.Request(ctxT(t, 60*time.Second), "profile.get", json.RawMessage(`{}`))
		done <- res{rr, err}
	}()
	ap := waitEvent(t, a.app, "approval.pending", has("type", "profile.get"))
	if field(t, ap.Body, "role") != vault.KindAgent || field(t, ap.Body, "device_id") != agent.DeviceID() {
		t.Fatalf("approval.pending: %s", ap.Body)
	}
	if result, err := a.app.ApprovalDecide(ctx, field(t, ap.Body, "approval_id"), true); err != nil || result != "ok" {
		t.Fatalf("decide: %q %v", result, err)
	}
	got := <-done
	if got.err != nil || !got.r.OK() || !strings.Contains(string(got.r.Body()), `"name":"Ada"`) {
		t.Fatalf("referred profile.get: %v %+v", got.err, got.r)
	}

	// Refused: no grant covers these.
	if rr := a.request(agent, "settings.get", `{}`); rr.ErrorCode() != "forbidden" {
		t.Fatalf("settings.get: %q", rr.ErrorCode())
	}
	if rr := a.request(agent, "share.rule.set", `{}`); rr.ErrorCode() != "forbidden" {
		t.Fatalf("agent set itself a rule: %q", rr.ErrorCode())
	}

	// Deleting the rule stops it at once.
	if err := a.app.ShareRuleDelete(ctx, rid); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, agent, "leash.grant.updated", func(b json.RawMessage) bool { return !strings.Contains(string(b), rid) })
	time.Sleep(2100 * time.Millisecond)
	if rr, err := agent.AgentRequest(ctx, "item.get", map[string]any{"item_id": wifi}); err != nil || rr.ErrorCode() != "forbidden" {
		t.Fatalf("after delete: %v %q", err, rr.ErrorCode())
	}

	// An ask rule: nothing readable until the member approves the item.
	// Signing needs the unlock window.
	if err := a.app.CredentialLock(ctx); err != nil {
		t.Fatal(err)
	}
	rule["mode"] = "ask"
	if _, err := a.app.ShareRuleSet(ctx, rule); client.Code(err) != "credential_locked" {
		t.Fatalf("rule outside the window: %v", err)
	}
	if _, err := a.app.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	ro, err = a.app.ShareRuleSet(ctx, rule)
	if err != nil {
		t.Fatal(err)
	}
	rid, _ = ro.String("rule_id")
	pend := waitEvent(t, a.app, "share.pending", has("rule_id", rid))
	if !strings.Contains(string(pend.Body), wifi) || strings.Contains(string(pend.Body), crit) {
		t.Fatalf("share.pending: %s", pend.Body)
	}
	// (The new rule ended the scope's refusal cooldown, §10.11.)
	if rr, err := agent.AgentRequest(ctx, "item.get", map[string]any{"item_id": wifi}); err != nil || rr.ErrorCode() != "forbidden" {
		t.Fatalf("before approval: %v %q", err, rr.ErrorCode())
	}
	if _, err := a.app.ShareDecide(ctx, rid, []string{wifi}, true); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if rr, err := agent.AgentRequest(ctx, "item.get", map[string]any{"item_id": wifi}); err != nil || !rr.OK() {
		t.Fatalf("after approval: %v %+v", err, rr)
	}

	// Spam after refusals: the agent hammers a type no grant covers; it
	// is throttled and, past the limit, suspended until an app resumes it.
	for i := 0; i < 40; i++ {
		if rr := a.request(agent, "settings.get", `{}`); rr.ErrorCode() != "forbidden" {
			t.Fatalf("hammer %d: %q", i, rr.ErrorCode())
		}
	}
	waitEvent(t, agent, "leash.grant.updated", func(b json.RawMessage) bool { return strings.Contains(string(b), `"suspended":true`) })
	waitEvent(t, a.app, "sync.event", syncKind("leash.agent.suspended"))
	useBody := map[string]any{"item_id": wifi, "field_id": "f1", "action": "hmac-sha256", "data": base64.StdEncoding.EncodeToString([]byte("hi"))}
	if rr, err := agent.AgentRequest(ctx, "item.use", useBody); err != nil || rr.ErrorCode() != "forbidden" {
		t.Fatalf("suspended agent: %v %q", err, rr.ErrorCode())
	}
	mustOK(t, a.request(a.app, "leash.agent.resume", `{"agent_id":"`+agent.DeviceID()+`"}`))
	waitEvent(t, agent, "leash.grant.updated", func(b json.RawMessage) bool { return strings.Contains(string(b), `"suspended":false`) })
	if rr, err := agent.AgentRequest(ctx, "item.use", useBody); err != nil || !rr.OK() {
		t.Fatalf("after resume: %v %+v", err, rr)
	}

	// Audit (§10.9): refusals and throttling summarised, not one entry each.
	au, err := a.app.AuditList(ctx, map[string]any{"kinds": []string{"leash", "approval", "share"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(au["entries"]), `"kind":"leash.refused"`); n > 3 {
		t.Errorf("%d single refusal entries", n)
	}
	for _, k := range []string{"leash.grant.issued", "leash.allowed", "leash.item.read", "leash.item.used", "leash.grant.revoked",
		"leash.refused", "leash.agent.suspended", "leash.agent.resumed", "leash.throttled.summary", "approval.granted",
		"share.rule.created", "share.included", "share.rule.deleted"} {
		if !strings.Contains(string(au["entries"]), `"`+k+`"`) {
			t.Errorf("audit lacks %s", k)
		}
	}

	// Unlinking revokes every grant and rule (§7.4).
	mustOK(t, a.request(a.app, "device.unlink", `{"device_id":"`+agent.DeviceID()+`"}`))
	o := mustOK(t, a.request(a.app, "leash.grant.list", `{}`))
	if gs, _ := o.Array("grants"); len(gs) != 0 {
		t.Fatalf("grants after unlink: %d", len(gs))
	}
	if o := mustOK(t, a.request(a.app, "share.rule.list", `{}`)); string(o["rules"]) != "[]" {
		t.Fatalf("rules after unlink: %s", o["rules"])
	}
}
