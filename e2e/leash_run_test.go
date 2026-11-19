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

// §10.11 item.run (0.42.0, 0.85.3) through the real relay: refused without
// the run way, for a program the item is not bound to and for a variable
// the entry does not list; a first run is referred, flagged
// program_unrecorded, and a denied approval records nothing; an approved
// one is answered the value and records the pin, after which the same run
// is answered at once; a changed file is referred, flagged program_changed
// with the previous pin, and its approval replaces the pin; of two runs
// held with different files, the second approved is referred again
// against the pin the first recorded.
func TestLeashItemRun(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	ctx := ctxT(t, 180*time.Second)
	wifi, _, err := a.app.ItemPut(ctx, "", 0, "secret", []string{"agent ok"}, client.ItemContent{Name: "wifi",
		Fields: []client.ItemField{{Label: "Password", Kind: "password", Value: "hunter22"}}})
	if err != nil {
		t.Fatal(err)
	}
	gh, _, err := a.app.ItemPut(ctx, "", 0, "secret", []string{"agent ok"}, client.ItemContent{Name: "gh",
		Fields: []client.ItemField{{Label: "Token", Kind: "password", Value: "ghp_x"}}})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := client.New(ctx, client.Config{Role: vault.KindAgent, Name: "r-agent", RelayURL: r.URL, PollWait: time.Second})
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

	shaA, shaB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	run := func(item, program, sha string, env map[string]any) map[string]any {
		m := map[string]any{"item_id": item, "field_id": "f1", "program": program, "sha256": sha, "argv": []string{"git", "push"},
			"cwd": "/home/a", "how": "env", "name": "TOKEN"}
		if env != nil {
			m["env"] = env
		}
		return m
	}
	type res struct {
		r   *client.Response
		err error
	}
	async := func(m map[string]any) chan res {
		ch := make(chan res, 1)
		go func() {
			rr, err := agent.AgentRequest(ctxT(t, 90*time.Second), "item.run", m)
			ch <- res{rr, err}
		}()
		return ch
	}
	cool := func() { time.Sleep(4200 * time.Millisecond) } // past a refusal's cooldown (1 s, 2 s, then 4 s)

	// Without the run way: way_not_allowed.
	if rr, err := agent.AgentRequest(ctx, "item.run", run(wifi, "/usr/bin/git", shaA, nil)); err != nil || rr.ErrorCode() != "way_not_allowed" {
		t.Fatalf("without run: %v %+v", err, rr)
	}
	if _, err := a.app.LeashItemSet(ctx, agent.DeviceID(), wifi, 0, map[string]any{"ways": []string{"use", "run"},
		"run": map[string]any{"programs": []any{map[string]any{"program": "git", "env": []string{"GH_HOST"}}}, "each": false}}); err != nil {
		t.Fatal(err)
	}
	cool()
	if rr, err := agent.AgentRequest(ctx, "item.run", run(wifi, "/usr/bin/gh", shaA, nil)); err != nil || rr.ErrorCode() != "program_not_allowed" {
		t.Fatalf("other program: %v %+v", err, rr)
	}
	cool()
	if rr, err := agent.AgentRequest(ctx, "item.run", run(wifi, "/usr/bin/git", shaA, map[string]any{"GH_HOST": "x", "GH_TOKEN": "y"})); err != nil ||
		rr.ErrorCode() != "env_not_allowed" || string(rr.Body()) != `{"names":["GH_TOKEN"]}` {
		t.Fatalf("env: %v %+v", err, rr)
	}
	cool()

	// A first run: referred, program_unrecorded. Denied: nothing recorded.
	ch := async(run(wifi, "/usr/bin/git", shaA, map[string]any{"GH_HOST": "x"}))
	ap := waitEvent(t, a.app, "approval.pending", has("type", "agent.request"))
	if !strings.Contains(string(ap.Body), `"flags":["program_unrecorded"]`) || strings.Contains(string(ap.Body), "previous_") ||
		!strings.Contains(string(ap.Body), `"argv":["git","push"]`) {
		t.Fatalf("first run approval: %s", ap.Body)
	}
	if result, err := a.app.ApprovalDecide(ctx, field(t, ap.Body, "approval_id"), false); err != nil || result != "denied" {
		t.Fatalf("deny: %q %v", result, err)
	}
	if got := <-ch; got.err != nil || got.r.ErrorCode() != "denied" {
		t.Fatalf("denied run: %+v", got)
	}
	if l, err := a.app.LeashItemList(ctx, agent.DeviceID(), wifi); err != nil || strings.Contains(string(l[0]), "sha256") || !strings.Contains(string(l[0]), `"version":1`) {
		t.Fatalf("pin after a denial: %v %s", err, l)
	}

	// Approved: the value, and the pin recorded.
	ch = async(run(wifi, "/usr/bin/git", shaA, nil))
	ap = waitEvent(t, a.app, "approval.pending", has("type", "agent.request"))
	if result, err := a.app.ApprovalDecide(ctx, field(t, ap.Body, "approval_id"), true); err != nil || result != "ok" {
		t.Fatalf("approve: %q %v", result, err)
	}
	if got := <-ch; got.err != nil || !got.r.OK() || string(got.r.Body()) != `{"item_id":"`+wifi+`","field_id":"f1","value":"hunter22"}` {
		t.Fatalf("approved run: %+v", got)
	}
	if l, err := a.app.LeashItemList(ctx, agent.DeviceID(), wifi); err != nil || !strings.Contains(string(l[0]), `"sha256":"`+shaA+`","path":"/usr/bin/git"`) ||
		!strings.Contains(string(l[0]), `"version":2`) {
		t.Fatalf("pin: %v %s", err, l)
	}
	// The same run: answered at once.
	if rr, err := agent.AgentRequest(ctx, "item.run", run(wifi, "/usr/bin/git", shaA, nil)); err != nil || !rr.OK() || !strings.Contains(string(rr.Body()), "hunter22") {
		t.Fatalf("pinned run: %v %+v", err, rr)
	}

	// A changed file: program_changed with the previous pin; approved, the
	// pin is replaced.
	ch = async(run(wifi, "/usr/bin/git", shaB, nil))
	ap = waitEvent(t, a.app, "approval.pending", has("type", "agent.request"))
	if !strings.Contains(string(ap.Body), `"flags":["program_changed"]`) || field(t, ap.Body, "previous_sha256") != shaA ||
		field(t, ap.Body, "previous_path") != "/usr/bin/git" {
		t.Fatalf("changed approval: %s", ap.Body)
	}
	if result, err := a.app.ApprovalDecide(ctx, field(t, ap.Body, "approval_id"), true); err != nil || result != "ok" {
		t.Fatalf("approve changed: %q %v", result, err)
	}
	if got := <-ch; got.err != nil || !got.r.OK() {
		t.Fatalf("changed run: %+v", got)
	}
	if l, _ := a.app.LeashItemList(ctx, agent.DeviceID(), wifi); !strings.Contains(string(l[0]), `"sha256":"`+shaB+`"`) {
		t.Fatalf("pin not replaced: %s", l)
	}

	// Two runs held with different files: the first approved records its
	// pin; the second is referred again against it, then approved.
	if _, err := a.app.LeashItemSet(ctx, agent.DeviceID(), gh, 0, map[string]any{"ways": []string{"use", "run"},
		"run": map[string]any{"programs": []any{map[string]any{"program": "git", "env": []string{}}}, "each": false}}); err != nil {
		t.Fatal(err)
	}
	r1 := run(gh, "/usr/bin/git", shaA, nil)
	c1 := async(r1)
	ap1 := waitEvent(t, a.app, "approval.pending", has("type", "agent.request"))
	r2 := run(gh, "/usr/bin/git", shaB, nil)
	c2 := async(r2)
	ap2 := waitEvent(t, a.app, "approval.pending", func(b json.RawMessage) bool {
		return strings.Contains(string(b), `"type":"agent.request"`) && !strings.Contains(string(b), field(t, ap1.Body, "approval_id"))
	})
	if result, err := a.app.ApprovalDecide(ctx, field(t, ap1.Body, "approval_id"), true); err != nil || result != "ok" {
		t.Fatalf("approve first: %q %v", result, err)
	}
	if got := <-c1; got.err != nil || !got.r.OK() || !strings.Contains(string(got.r.Body()), "ghp_x") {
		t.Fatalf("first: %+v", got)
	}
	if result, err := a.app.ApprovalDecide(ctx, field(t, ap2.Body, "approval_id"), true); err != nil || result != "referred" {
		t.Fatalf("approve second: %q %v", result, err)
	}
	ap3 := waitEvent(t, a.app, "approval.pending", func(b json.RawMessage) bool {
		return strings.Contains(string(b), gh) && strings.Contains(string(b), `"flags":["program_changed"]`) && strings.Contains(string(b), `"previous_sha256":"`+shaA+`"`)
	})
	if field(t, ap3.Body, "approval_id") == field(t, ap2.Body, "approval_id") {
		t.Fatal("same approval id")
	}
	if result, err := a.app.ApprovalDecide(ctx, field(t, ap2.Body, "approval_id"), true); err == nil && result == "ok" {
		t.Fatal("the old approval decided again")
	}
	select {
	case got := <-c2:
		t.Fatalf("answered before the new approval: %+v", got)
	default:
	}
	if result, err := a.app.ApprovalDecide(ctx, field(t, ap3.Body, "approval_id"), true); err != nil || result != "ok" {
		t.Fatalf("approve again: %q %v", result, err)
	}
	if got := <-c2; got.err != nil || !got.r.OK() || !strings.Contains(string(got.r.Body()), "ghp_x") {
		t.Fatalf("second: %+v", got)
	}
	if l, _ := a.app.LeashItemList(ctx, agent.DeviceID(), gh); !strings.Contains(string(l[0]), `"sha256":"`+shaB+`"`) || !strings.Contains(string(l[0]), `"version":3`) {
		t.Fatalf("second pin: %s", l)
	}
}
