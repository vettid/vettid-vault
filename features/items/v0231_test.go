package items_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/feed"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// VAULT-MESSAGING 0.23.1: errata to 0.23.0 from its implementation
// (vettid-vault #52).

// tag.merge's shares carry ask_rule_id as item.put's and item.tag's dry
// runs do (§10.8, §10.12): a merge can leave an auto entry pending.
func TestMergeSharesAskRuleID(t *testing.T) {
	e := newEnv(t)
	d := e.put("data", "D", []string{"old"})
	askM := e.rule(map[string]any{"subject": conn("cB"), "tags": []string{"old"}, "include_existing": false})
	autoM := e.rule(map[string]any{"subject": conn("cB"), "tags": []string{"new"}, "mode": "auto"})
	free := e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"new"}, "mode": "auto"})
	tv, _ := e.ok(e.call("app", "tag.list", `{}`)).Uint("version", 0, 1<<53)
	for _, dry := range []bool{true, false} {
		body := map[string]any{"version": tv, "from": []string{"old"}, "into": "new"}
		if dry {
			body["dry_run"] = true
		}
		r := e.ok(e.call("app", "tag.merge", js(body)))
		var shares []map[string]any
		_ = json.Unmarshal(r["shares"], &shares)
		if len(shares) != 2 {
			t.Fatalf("dry %v: shares %v", dry, shares)
		}
		for _, s := range shares {
			want := ""
			if s["rule_id"] == autoM {
				want = askM
			}
			if got, _ := s["ask_rule_id"].(string); s["item_id"] != d || s["mode"] != "auto" || got != want {
				t.Fatalf("dry %v: %v, want ask_rule_id %q", dry, s, want)
			}
		}
	}
	if x := entryFor(e.pendingList(), autoM, d); x == nil || x["ask_rule_id"] != askM {
		t.Fatalf("after the merge: %v", x)
	}
	if in, _, _ := ruleState(t, e, free); !contains(in, d) {
		t.Fatal("the other subject's rule did not include the item")
	}
}

// fetchID fetches a grant with a given fetch_id and returns the
// data.value body.
func (e *env) fetchID(conn, grantID, fid string) map[string]json.RawMessage {
	e.t.Helper()
	k, _ := suite.GeneratePrivateKey()
	defer k.Destroy()
	e.h.Reset()
	e.call("connection:"+conn, "data.fetch", js(map[string]any{"fetch_id": fid, "grant_id": grantID,
		"reply_key": base64.StdEncoding.EncodeToString(k.Public().Bytes())}))
	vs := e.sentTo(conn, "data.value")
	if len(vs) != 1 {
		e.t.Fatalf("data.value: %d", len(vs))
	}
	var o map[string]json.RawMessage
	_ = json.Unmarshal(vs[0].Body, &o)
	return o
}

// §10.12 Rate limits for connections: the windows count a rule's fetches
// even while it has no limits, so a limit set later applies to the open
// window; a repeated fetch_id is answered again, uncounted, even while a
// window is full.
func TestRuleWindowsWithoutLimits(t *testing.T) {
	e := newEnv(t)
	e.put("data", "X", []string{"t"}, field{Label: "V", Kind: "text", Value: "x"})
	rid := e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"t"}, "mode": "auto"})
	g := e.grantsShared("cA")[0]
	var last string
	for i := 0; i < 3; i++ {
		last, _ = envelope.NewULID(e.clk.T)
		if o := e.fetchID("cA", g, last); o["value_sealed"] == nil {
			t.Fatalf("fetch %d: %v", i, o)
		}
		e.clk.Advance(time.Millisecond)
	}
	e.ok(e.call("app", "share.rule.set", js(map[string]any{"rule_id": rid, "version": 1, "subject": conn("cA"), "tags": []string{"t"},
		"mode": "auto", "per_hour": 3})))
	if er, _ := e.fetch("cA", g); er != "rate_limited" {
		t.Fatalf("a limit set later did not apply to the open window: %q", er)
	}
	// The window is full: a repeat of an answered fetch_id is answered
	// again (a value, not rate_limited) and counts nothing.
	o := e.fetchID("cA", g, last)
	if o["value_sealed"] == nil || o["error"] != nil {
		t.Fatalf("repeated fetch_id while the window is full: %v", o)
	}
	e.clk.Advance(time.Hour)
	if er, _ := e.fetch("cA", g); er != "" {
		t.Fatalf("new window: %q", er)
	}
}

// §10.4.1 Batching: an ask that joins a batch whose feed item the member
// has read or archived updates its count and seq and keeps its status; a
// deleted item ends the batch, and the ask starts a new one.
func TestBatchReadArchivedDeleted(t *testing.T) {
	e := newEnv(t)
	e.asksOn()
	e.h.Sinks = append(e.h.Sinks, e.set.Feed)
	ks := askKinds()
	batchItem := func() []feed.Item {
		var out []feed.Item
		for _, it := range e.set.Feed.Items() {
			if it.ConnectionID == "cA" && it.Status != feed.StatusDeleted {
				out = append(out, it)
			}
		}
		return out
	}
	ks[4].send(e, e.newID()) // an introduction offer
	first := batchItem()
	if len(first) != 1 {
		t.Fatalf("first %v", first)
	}
	id := first[0].ID
	count := 1
	for _, status := range []string{feed.StatusRead, feed.StatusArchived} {
		e.ok(e.call("app", "feed.update", js(map[string]any{"item_id": id, "status": status})))
		seq := batchItem()[0].Seq
		e.clk.Advance(time.Minute)
		ks[0].send(e, e.newID()) // a grant request
		count++
		b := batchItem()
		if len(b) != 1 || b[0].ID != id || b[0].Count != count || b[0].Status != status || b[0].Seq <= seq {
			t.Fatalf("%s: %+v", status, b)
		}
	}
	e.ok(e.call("app", "feed.delete", js(map[string]any{"item_id": id})))
	e.clk.Advance(time.Minute)
	e.h.Reset()
	ks[0].send(e, e.newID())
	b := batchItem()
	if len(b) != 1 || b[0].ID == id || b[0].Count != 0 || b[0].Status != feed.StatusActive {
		t.Fatalf("after delete: %+v", b)
	}
	if fe := e.sentTo("devices", "feed.event"); len(fe) != 1 || strings.Contains(string(fe[0].Body), `"count"`) {
		t.Fatalf("new batch: %v", fe)
	}
}

// §10.4.1, §10.16: a suppressed location request does not use location's
// own allowance of one request per connection per 10 minutes.
func TestSuppressedLocationKeepsAllowance(t *testing.T) {
	e := newEnv(t)
	e.asksOn()
	loc := askKinds()[5]
	e.h.Asks = map[string]*vault.AskState{"cA": {Muted: true}}
	e.h.Reset()
	loc.send(e, e.newID())
	if len(e.activity("drop.ask_muted")) != 1 || e.pendingSent(loc.pending) != 0 {
		t.Fatalf("muted: %v", e.h.Activities)
	}
	e.h.Asks["cA"].Muted = false
	e.h.Reset()
	loc.send(e, e.newID())
	if e.pendingSent(loc.pending) != 1 || len(e.activity("drop.location_rate")) != 0 {
		t.Fatalf("the suppressed request used the allowance: %v %v", e.h.Sent, e.h.Activities)
	}
	e.h.Reset()
	loc.send(e, e.newID())
	if len(e.activity("drop.location_rate")) != 1 {
		t.Fatalf("allowance: %v", e.h.Activities)
	}
}
