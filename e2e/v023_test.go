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

// VAULT-MESSAGING 0.23.0 end to end: a connection's asks (§10.4.1), rate
// limits on connection rules and overlapping rules (§10.12), through the
// reference client.

// A declined grant request starts a cooldown: the same request is
// suppressed (never shown to A's member, audited drop.ask_cooldown) and
// B's vault gets A's decline-shaped answer only after the delay; A's
// member sees the cooldown on the connection, mutes and resumes.
func TestConnectionAsksE2E(t *testing.T) {
	r := relaytest.Start(t, nil)
	// A's neutral answers wait the minimum delay (1 minute).
	a := newTestVault(t, r.URL, "a", func(o *vault.Options) { o.AskRand = func(int64) int64 { return 0 } })
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 240*time.Second)
	aConn, bConn := connect(t, a, b, 600)
	ask := func() string {
		t.Helper()
		rid, err := b.app.GrantRequest(ctx, bConn, []client.GrantItem{{Kind: "category", Ref: "medical"}}, 1, 0, "")
		if err != nil {
			t.Fatal(err)
		}
		return rid
	}
	rid := ask()
	waitEvent(t, a.app, "grant.pending", has("request_id", rid))
	if _, err := a.app.GrantDecide(ctx, rid, false, nil, 0, 0); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, b.app, "grant.event", func(m json.RawMessage) bool { return has("event", "denied")(m) && has("request_id", rid)(m) })
	st, err := a.app.ConnectionAsks(ctx, aConn)
	if err != nil || st.Muted || st.Paused || st.Cooldowns != 1 {
		t.Fatalf("asks after a decline: %+v %v", st, err)
	}
	// The same request again: suppressed, answered later as declined.
	sent := time.Now()
	rid2 := ask()
	ev, err := b.app.WaitEvent(ctxT(t, 150*time.Second), "grant.event", func(m json.RawMessage) bool {
		return has("event", "denied")(m) && has("request_id", rid2)(m)
	})
	if err != nil {
		t.Fatalf("no neutral answer: %v", err)
	}
	if d := time.Since(sent); d < vault.AskDelayMin {
		t.Fatalf("answered after %v (before the delay)", d)
	}
	if strings.Contains(string(ev.Body), "cooldown") || strings.Contains(string(ev.Body), "retry_after") {
		t.Fatalf("the answer tells the mechanism: %s", ev.Body)
	}
	au, err := a.app.AuditList(ctx, map[string]any{"kinds": []string{"drop"}}, false)
	if err != nil || !strings.Contains(string(au["entries"]), `"drop.ask_cooldown"`) || !strings.Contains(string(au["entries"]), rid2) {
		t.Fatalf("audit: %s %v", au["entries"], err)
	}
	pl, err := a.app.GrantList(ctx)
	if err != nil || strings.Contains(string(pl["pending"]), rid2) {
		t.Fatalf("a suppressed request is pending: %s %v", pl["pending"], err)
	}
	// Mute, unmute, resume: the state on the connection, audited.
	if err := a.app.ConnectionAsksMute(ctx, aConn, true); err != nil {
		t.Fatal(err)
	}
	if st, _ := a.app.ConnectionAsks(ctx, aConn); !st.Muted {
		t.Fatalf("not muted: %+v", st)
	}
	if err := a.app.ConnectionAsksMute(ctx, aConn, false); err != nil {
		t.Fatal(err)
	}
	if err := a.app.ConnectionAsksResume(ctx, aConn); err != nil {
		t.Fatal(err)
	}
	if st, _ := a.app.ConnectionAsks(ctx, aConn); st.Muted || st.Paused || st.Cooldowns != 0 {
		t.Fatalf("after resume: %+v", st)
	}
	au, _ = a.app.AuditList(ctx, map[string]any{"kinds": []string{"connection"}}, false)
	for _, k := range []string{"connection.asks_muted", "connection.asks_unmuted", "connection.asks_resumed"} {
		if !strings.Contains(string(au["entries"]), `"`+k+`"`) {
			t.Errorf("audit lacks %s", k)
		}
	}
	// After the resume the same request reaches A's member again.
	rid3 := ask()
	waitEvent(t, a.app, "grant.pending", has("request_id", rid3))
	if err := client.Code(a.app.ConnectionAsksMute(ctx, "nope", true)); err != "not_found" {
		t.Fatalf("unknown connection: %q", err)
	}
}

// A connection rule's rate limits reach the connection with its grants,
// and past them a fetch is refused rate_limited with retry_after; an item
// two rules of the same connection cover, one asking, is asked once
// (ask_rule_id, shared, the dry run's outcome) and shared after one
// answer.
func TestRuleLimitsAndOverlapE2E(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 180*time.Second)
	aConn, bConn := connect(t, a, b, 600)
	put := func(name string, tags ...string) string {
		t.Helper()
		id, _, err := a.app.ItemPut(ctx, "", 0, "data", tags, client.ItemContent{Name: name,
			Fields: []client.ItemField{{Label: "V", Kind: "text", Value: name + "-value"}}})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	x := put("x", "lim")
	if _, err := a.app.ShareRuleSet(ctx, map[string]any{"subject": map[string]any{"connection_id": aConn}, "tags": []string{"lim"},
		"mode": "auto", "per_hour": 1}); err != nil {
		t.Fatal(err)
	}
	ev := waitEvent(t, b.app, "grant.event", has("event", "shared"))
	if !strings.Contains(string(ev.Body), `"limits":{"per_hour":1}`) {
		t.Fatalf("shared without limits: %s", ev.Body)
	}
	gid := between(string(ev.Body), `"grant_id":"`, `"`)
	if res, err := b.app.GrantFetch(ctx, gid); err != nil || res.Error != "" || !strings.Contains(string(res.Value), "x-value") {
		t.Fatalf("fetch: %+v %v", res, err)
	}
	res, err := b.app.GrantFetch(ctx, gid)
	if err != nil || res.Error != "rate_limited" || res.RetryAfter < 3500 || res.RetryAfter > 3600 || res.Value != nil {
		t.Fatalf("second fetch in the hour: %+v %v", res, err)
	}
	fl, err := a.app.FeedList(ctx, map[string]any{})
	if err != nil || !strings.Contains(string(fl["items"]), `"kind":"share.rate_limited"`) {
		t.Fatalf("feed: %s %v", fl["items"], err)
	}
	_ = x
	// Overlap: an ask rule and an auto rule of the same connection.
	ask, err := a.app.ShareRuleSet(ctx, map[string]any{"subject": map[string]any{"connection_id": aConn}, "tags": []string{"medical"}})
	if err != nil {
		t.Fatal(err)
	}
	askID, _ := ask.String("rule_id")
	y := put("y", "medical", "insurance")
	dry, err := a.app.ShareRuleDryRun(ctx, map[string]any{"subject": map[string]any{"connection_id": aConn}, "tags": []string{"insurance"}, "mode": "auto"})
	if err != nil || len(dry.Matches) != 1 || dry.Matches[0].Outcome != "ask" || dry.Matches[0].AskRuleID != askID {
		t.Fatalf("dry run: %+v %v", dry, err)
	}
	auto, err := a.app.ShareRuleSet(ctx, map[string]any{"subject": map[string]any{"connection_id": aConn}, "tags": []string{"insurance"}, "mode": "auto"})
	if err != nil {
		t.Fatal(err)
	}
	autoID, _ := auto.String("rule_id")
	pend, err := a.app.SharePendingAll(ctx, map[string]any{"connection_id": aConn})
	if err != nil || len(pend) != 2 {
		t.Fatalf("pending: %s %v", pend, err)
	}
	found := false
	for _, p := range pend {
		if strings.Contains(string(p), `"rule_id":"`+autoID+`"`) {
			found = strings.Contains(string(p), `"ask_rule_id":"`+askID+`"`)
		}
	}
	if !found {
		t.Fatalf("no ask_rule_id on the auto rule's entry: %s", pend)
	}
	if client.RuleName([]string{"medical", "id"}, "all", nil) != "medical + id" || client.RuleName([]string{"medical", "id"}, "any", nil) != "medical or id" {
		t.Fatal("RuleName")
	}
	o, err := a.app.ShareDecideBoth(ctx, askID, []string{y}, nil)
	if err != nil || !strings.Contains(string(o["included"]), y) {
		t.Fatalf("decide: %v %v", o, err)
	}
	if rest, err := a.app.SharePendingAll(ctx, map[string]any{"connection_id": aConn}); err != nil || len(rest) != 0 {
		t.Fatalf("one answer left pending entries: %s %v", rest, err)
	}
	waitEvent(t, b.app, "grant.event", func(m json.RawMessage) bool { return has("event", "shared")(m) && strings.Contains(string(m), y) })
	_ = bConn
}
