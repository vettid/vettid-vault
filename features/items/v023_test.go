package items_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// VAULT-MESSAGING 0.23.0 §10.12: rate limits on connection rules,
// overlapping rules (ask wins, one answer per item and subject, no silent
// withdrawal, removing an ask rule never shares anything, the strictest
// limits), the previews and pending entries.

// fetchValue fetches and returns the data.value body.
func (e *env) fetchValue(conn, grantID string) strictjson.Object {
	e.t.Helper()
	er, _ := e.fetch(conn, grantID)
	vs := e.sentTo(conn, "data.value")
	o := obj(e.t, vs[0].Body)
	if got, _, _ := o.OptString("error"); got != er {
		e.t.Fatal("fetch mismatch")
	}
	return o
}

func (e *env) feedKinds() []vault.Activity {
	var out []vault.Activity
	for _, a := range e.h.Activities {
		if a.Feed {
			out = append(out, a)
		}
	}
	return out
}

func (e *env) activity(kind string) []vault.Activity {
	var out []vault.Activity
	for _, a := range e.h.Activities {
		if a.Kind == kind {
			out = append(out, a)
		}
	}
	return out
}

// pendingOf returns the items of the share.pending messages for a rule
// since the last reset.
func (e *env) pendingOf(rule string) []map[string]any {
	var out []map[string]any
	for _, s := range e.sentTo("devices", "share.pending") {
		var b struct {
			RuleID string           `json:"rule_id"`
			Items  []map[string]any `json:"items"`
		}
		_ = json.Unmarshal(s.Body, &b)
		if b.RuleID == rule {
			out = append(out, b.Items...)
		}
	}
	return out
}

// pendingList returns share.pending.list's entries.
func (e *env) pendingList() []map[string]any {
	o := e.ok(e.call("app", "share.pending.list", `{}`))
	var out []map[string]any
	_ = json.Unmarshal(o["pending"], &out)
	return out
}

func entryFor(es []map[string]any, rule, item string) map[string]any {
	for _, x := range es {
		if x["rule_id"] == rule && x["item_id"] == item || rule == "" && x["item_id"] == item {
			return x
		}
	}
	return nil
}

// §10.12 Rate limits for connections: per_hour and per_day on a
// connection rule (shown on the rule, its grants and descriptors), the
// connection's fetches of the rule's items in total, in fixed windows
// from the first counted fetch; past a limit rate_limited with
// retry_after, audited drop.grant_rate_limited, no use counted, at most
// one share.rate_limited feed item per rule per 24 hours; the windows are
// kept when the rule is replaced (a lowered limit applies at once).
func TestConnRuleRateLimits(t *testing.T) {
	e := newEnv(t)
	x := e.put("data", "X", []string{"t"}, field{Label: "V", Kind: "text", Value: "x"})
	y := e.put("data", "Y", []string{"t"}, field{Label: "V", Kind: "text", Value: "y"})
	e.h.Reset()
	o := e.ok(e.call("app", "share.rule.set", js(map[string]any{"subject": conn("cA"), "tags": []string{"t"}, "mode": "auto",
		"per_hour": 2, "per_day": 3, "uses": 50})))
	rid, _ := o.String("rule_id")
	if ph, _ := o.Uint("per_hour", 1, 3600); ph != 2 {
		t.Fatalf("rule without per_hour: %s", o["per_hour"])
	}
	if pd, _ := o.Uint("per_day", 1, 86400); pd != 3 || o.Has("status_ttl") {
		t.Fatal("per_day / status_ttl on a connection rule")
	}
	shared := e.sentTo("cA", "data.shared")
	if len(shared) != 1 || strings.Count(string(shared[0].Body), `"limits":{"per_hour":2,"per_day":3}`) != 2 {
		t.Fatalf("descriptors without limits: %v", shared)
	}
	gs := e.grantsShared("cA")
	gx, gy := gs[0], gs[1]
	list := e.ok(e.call("app", "grant.list", `{}`))
	if strings.Count(string(list["given"]), `"limits":{"per_hour":2,"per_day":3}`) != 2 {
		t.Fatalf("given grants without limits: %s", list["given"])
	}
	// The rule's items in total: x then y fill the hour.
	if er, _ := e.fetch("cA", gx); er != "" {
		t.Fatal(er)
	}
	first := e.clk.T
	if er, _ := e.fetch("cA", gy); er != "" {
		t.Fatal(er)
	}
	v := e.fetchValue("cA", gx)
	if er, _ := v.String("error"); er != "rate_limited" {
		t.Fatalf("third in the hour: %s", er)
	}
	ra, err := v.Uint("retry_after", 1, 86400)
	if want := uint64(first.Add(time.Hour).Sub(e.clk.T) / time.Second); err != nil || ra < want || ra > want+1 {
		t.Fatalf("retry_after %d (want ~%d): %v", ra, want, err)
	}
	if v.Has("value_sealed") || v.Has("uses_left") {
		t.Fatal("refusal carries a value")
	}
	if a := e.activity("drop.grant_rate_limited"); len(a) != 1 || a[0].Ref != gx || a[0].ConnectionID != "cA" || !a[0].Audit {
		t.Fatalf("audit %+v", a)
	}
	if f := e.activity("share.rate_limited"); len(f) != 1 || !f[0].Feed || f[0].Ref != rid || f[0].ConnectionID != "cA" || f[0].Priority != "" || f[0].Audit {
		t.Fatalf("feed %+v", f)
	}
	// The member is not asked: nothing to the devices but the feed item.
	if len(e.sentTo("devices", "approval.pending")) != 0 {
		t.Fatal("referred to the apps")
	}
	// A second refusal: audited, no second feed item within 24 h.
	e.fetch("cA", gy)
	if len(e.activity("share.rate_limited")) != 0 || len(e.activity("drop.grant_rate_limited")) != 1 {
		t.Fatal("second refusal")
	}
	// No use counted on a refusal.
	if strings.Count(string(e.ok(e.call("app", "grant.list", `{}`))["given"]), `"used":1,`) != 2 {
		t.Fatal("uses after refusals")
	}
	// A new hour: one fetch fits (the day's third), then the day is full.
	e.clk.T = first.Add(time.Hour)
	if er, _ := e.fetch("cA", gx); er != "" {
		t.Fatalf("new hour: %s", er)
	}
	v = e.fetchValue("cA", gy)
	if er, _ := v.String("error"); er != "rate_limited" {
		t.Fatalf("day full: %s", er)
	}
	if ra, _ := v.Uint("retry_after", 1, 86400); ra < 22*3600 || ra > 23*3600 {
		t.Fatalf("day retry_after %d", ra)
	}
	// Replacing the rule keeps the windows: per_day 2 refuses at once
	// (3 counted), and the given grants carry the new limits.
	e.clk.T = first.Add(2 * time.Hour)
	e.h.Reset()
	e.ok(e.call("app", "share.rule.set", js(map[string]any{"rule_id": rid, "version": 1, "subject": conn("cA"), "tags": []string{"t"},
		"mode": "auto", "per_day": 2})))
	if er, _ := e.fetch("cA", gx); er != "rate_limited" {
		t.Fatalf("lowered limit: %s", er)
	}
	if g := string(e.ok(e.call("app", "grant.list", `{}`))["given"]); strings.Count(g, `"limits":{"per_day":2}`) != 2 {
		t.Fatalf("given limits after replacement: %s", g)
	}
	// After 24 h: fetched again, and a later refusal is a new feed item.
	e.clk.T = first.Add(25 * time.Hour)
	e.fetch("cA", gx)
	e.fetch("cA", gy)
	e.h.Reset()
	if er, _ := e.fetch("cA", gx); er != "rate_limited" || len(e.activity("share.rate_limited")) != 1 {
		t.Fatalf("next day: %s %v", er, e.activity("share.rate_limited"))
	}
	// Without limits a rule behaves as before (no rate limit).
	z := e.put("data", "Z", []string{"z"})
	e.rule(map[string]any{"subject": conn("cB"), "tags": []string{"z"}, "mode": "auto"})
	gz := e.grantsShared("cB")
	if len(gz) != 1 || strings.Contains(string(e.sentTo("cB", "data.shared")[0].Body), "limits") {
		t.Fatal("limits on a rule without them")
	}
	for i := 0; i < 10; i++ {
		if er, _ := e.fetch("cB", gz[0]); er != "" {
			t.Fatalf("unlimited fetch %d: %s", i, er)
		}
	}
	_, _ = x, y
	_ = z
}

// §10.12 Overlapping rules: an item that gains an auto rule while an ask
// rule of the same subject covers it is pending there with ask_rule_id
// (the lowest holding ask rule) — on a new item, a tag change, a rule's
// creation, a merge; share.pending and share.pending.list carry
// ask_rule_id and shared; one answer per item and subject; a decline
// withdraws what other rules of the subject included.
func TestOverlapAskWins(t *testing.T) {
	e := newEnv(t)
	ask := e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"medical"}})
	auto := e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"insurance"}, "mode": "auto"})
	other := e.rule(map[string]any{"subject": conn("cB"), "tags": []string{"insurance"}, "mode": "auto"}) // another subject
	e.h.Reset()
	// A new item covered by both: asked, in both, not shared with cA.
	both := e.put("data", "Policy", []string{"medical", "insurance"})
	if len(e.grantsShared("cA")) != 0 || len(e.grantsShared("cB")) != 1 {
		t.Fatalf("auto shared despite the ask rule (cA %d), or another subject affected (cB %d)", len(e.grantsShared("cA")), len(e.grantsShared("cB")))
	}
	if p := e.pendingOf(auto); len(p) != 1 || p[0]["ask_rule_id"] != ask || p[0]["shared"] != nil {
		t.Fatalf("share.pending of the auto rule: %v", p)
	}
	if p := e.pendingOf(ask); len(p) != 1 || p[0]["ask_rule_id"] != nil {
		t.Fatalf("share.pending of the ask rule: %v", p)
	}
	pl := e.pendingList()
	if x := entryFor(pl, auto, both); x == nil || x["ask_rule_id"] != ask {
		t.Fatalf("pending.list auto entry %v", x)
	}
	if x := entryFor(pl, ask, both); x == nil || x["ask_rule_id"] != nil || x["shared"] != nil {
		t.Fatalf("pending.list ask entry %v", x)
	}
	// One answer: including it in the ask rule includes it in the auto
	// rule too (one share.decided per rule).
	e.h.Reset()
	o := e.ok(e.call("app", "share.decide", js(map[string]any{"rule_id": ask, "include": []string{both}})))
	if strs(t, o, "included")[0] != both || len(strs(t, o, "included")) != 1 {
		t.Fatalf("decide: %s", o["included"])
	}
	inA, pA, _ := ruleState(t, e, ask)
	inB, pB, _ := ruleState(t, e, auto)
	if len(inA) != 1 || len(inB) != 1 || len(pA)+len(pB) != 0 {
		t.Fatalf("one answer: ask %v/%v auto %v/%v", inA, pA, inB, pB)
	}
	n := 0
	for _, s := range e.sentTo("devices", "sync.event") {
		if strings.Contains(string(s.Body), `"kind":"share.decided"`) {
			n++
		}
	}
	if n != 2 || len(e.grantsShared("cA")) != 2 {
		t.Fatalf("%d share.decided, %d grants", n, len(e.grantsShared("cA")))
	}
	// An item only the auto rule covers is included at once.
	e.h.Reset()
	solo := e.put("data", "Card", []string{"insurance"})
	if len(e.grantsShared("cA")) != 1 {
		t.Fatal("auto alone did not include")
	}
	// No silent withdrawal: gaining the ask rule's tag asks, the item
	// stays shared (pending entry shared: true).
	e.h.Reset()
	e.retag(solo, "insurance", "medical")
	if len(e.sentTo("cA", "data.revoked")) != 0 {
		t.Fatal("silently withdrawn")
	}
	if p := e.pendingOf(ask); len(p) != 1 || p[0]["shared"] != true || p[0]["item_id"] != solo {
		t.Fatalf("pending with shared: %v", p)
	}
	if x := entryFor(e.pendingList(), ask, solo); x == nil || x["shared"] != true {
		t.Fatalf("pending.list shared %v", x)
	}
	// Declining stops the sharing with that subject: withdrawn from the
	// auto rule (data.revoked) and declined in both.
	e.h.Reset()
	o = e.ok(e.call("app", "share.decide", js(map[string]any{"rule_id": ask, "decline": []string{solo}})))
	if d := strs(t, o, "declined"); len(d) != 1 || d[0] != solo {
		t.Fatalf("declined %v", d)
	}
	if len(e.sentTo("cA", "data.revoked")) != 1 {
		t.Fatal("decline did not withdraw the auto rule's grant")
	}
	_, _, dA := ruleState(t, e, ask)
	inB, _, dB := ruleState(t, e, auto)
	if !contains(dA, solo) || !contains(dB, solo) || contains(inB, solo) {
		t.Fatalf("declined: ask %v auto %v/%v", dA, inB, dB)
	}
	// include_existing: false — a new ask rule covering a shared item does
	// not ask, and it stays shared.
	e.h.Reset()
	e.rule(map[string]any{"subject": conn("cB"), "tags": []string{"insurance"}, "include_existing": false})
	if len(e.sentTo("devices", "share.pending")) != 0 || len(e.sentTo("cB", "data.revoked")) != 0 {
		t.Fatal("include_existing false asked or withdrew")
	}
	_ = other
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// §10.12: coverage is evaluated on every planning: a rule's creation (the
// dry run's outcome and ask_rule_id), a replacement from ask to auto (only
// the pending items no other ask rule holds, in every rule where pending),
// a rule's deletion and expiry (items held pending stay pending, the
// ask_rule_id dropped or another named), a merge, a move across critical.
func TestOverlapPlanning(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	a := e.put("data", "A", []string{"med", "ins"})
	b := e.put("data", "B", []string{"ins"})
	ask1 := e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"med"}})
	// Dry run of an auto rule: a held item would be asked (ask_rule_id),
	// the other included; nothing changes.
	e.h.Reset()
	r := e.ok(e.call("app", "share.rule.set", js(map[string]any{"subject": conn("cA"), "tags": []string{"ins"}, "mode": "auto", "dry_run": true})))
	var dry struct {
		Matches []map[string]any `json:"matches"`
	}
	_ = json.Unmarshal(r["matches"], &dry.Matches)
	if x := entryFor(dry.Matches, "", a); x == nil || x["outcome"] != "ask" || x["ask_rule_id"] != ask1 {
		t.Fatalf("dry run held: %v", x)
	}
	if x := entryFor(dry.Matches, "", b); x == nil || x["outcome"] != "include" || x["ask_rule_id"] != nil {
		t.Fatalf("dry run free: %v", x)
	}
	if len(e.h.Sent) != 0 {
		t.Fatal("dry run sent")
	}
	auto := e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"ins"}, "mode": "auto"})
	if _, p, _ := ruleState(t, e, auto); len(p) != 1 || p[0] != a {
		t.Fatalf("creation: pending %v", p)
	}
	// Dry run of a replacement: an item whose state would not change has
	// no outcome (already included, pending).
	r = e.ok(e.call("app", "share.rule.set", js(map[string]any{"rule_id": auto, "version": 1, "subject": conn("cA"), "tags": []string{"ins"},
		"mode": "auto", "dry_run": true})))
	dry.Matches = nil // Unmarshal merges into existing maps
	_ = json.Unmarshal(r["matches"], &dry.Matches)
	for _, x := range dry.Matches {
		if x["outcome"] != nil {
			t.Fatalf("unchanged item with an outcome: %v", x)
		}
	}
	// A second ask rule on "med": the lowest id names the holder.
	ask2 := e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"med"}})
	if x := entryFor(e.pendingList(), auto, a); x == nil || x["ask_rule_id"] != ask1 {
		t.Fatalf("two holders: %v", x)
	}
	// Deleting an ask rule never shares anything: still pending, held by
	// the other.
	e.h.Reset()
	e.ok(e.call("app", "share.rule.delete", js(map[string]any{"rule_id": ask1})))
	if len(e.grantsShared("cA")) != 0 {
		t.Fatal("deleting an ask rule shared")
	}
	if x := entryFor(e.pendingList(), auto, a); x == nil || x["ask_rule_id"] != ask2 {
		t.Fatalf("after delete: %v", x)
	}
	// Replacing ask2 by auto includes the pending item in every rule where
	// it is pending (no other ask rule holds it).
	e.h.Reset()
	e.ok(e.call("app", "share.rule.set", js(map[string]any{"rule_id": ask2, "version": 1, "subject": conn("cA"), "tags": []string{"med"}, "mode": "auto"})))
	inA, pA, _ := ruleState(t, e, ask2)
	inB, pB, _ := ruleState(t, e, auto)
	if !contains(inA, a) || !contains(inB, a) || len(pA)+len(pB) != 0 {
		t.Fatalf("ask→auto: %v/%v %v/%v", inA, pA, inB, pB)
	}
	// Expiry of an ask rule: the item it holds stays pending, without an
	// ask_rule_id.
	c := e.put("data", "C", []string{"exp", "ins2"})
	exp := e.clk.T.Add(time.Hour).Format("2006-01-02T15:04:05.000Z")
	askE := e.rule(map[string]any{"subject": conn("cB"), "tags": []string{"exp"}, "expires_at": exp})
	autoE := e.rule(map[string]any{"subject": conn("cB"), "tags": []string{"ins2"}, "mode": "auto"})
	if x := entryFor(e.pendingList(), autoE, c); x == nil || x["ask_rule_id"] != askE {
		t.Fatalf("before expiry: %v", x)
	}
	e.clk.Advance(2 * time.Hour)
	e.h.Reset()
	pl := e.pendingList()
	if x := entryFor(pl, autoE, c); x == nil || x["ask_rule_id"] != nil {
		t.Fatalf("after expiry: %v", x)
	}
	if len(e.grantsShared("cB")) != 0 {
		t.Fatal("expiry shared")
	}
	// A merge that lets an item gain an auto rule while an ask rule covers
	// it asks.
	d := e.put("data", "D", []string{"old"})
	askM := e.rule(map[string]any{"subject": conn("cB"), "tags": []string{"old"}, "include_existing": false})
	autoM := e.rule(map[string]any{"subject": conn("cB"), "tags": []string{"new"}, "mode": "auto"})
	e.h.Reset()
	tv, _ := e.ok(e.call("app", "tag.list", `{}`)).Uint("version", 0, 1<<53)
	e.ok(e.call("app", "tag.merge", js(map[string]any{"version": tv, "from": []string{"old"}, "into": "new"})))
	if x := entryFor(e.pendingList(), autoM, d); x == nil || x["ask_rule_id"] != askM || len(e.grantsShared("cB")) != 0 {
		t.Fatalf("merge: %v", x)
	}
	// A move to critical withdraws the item from every rule and lets it
	// gain them: with an ask rule covering it, the auto rule asks.
	f := e.put("data", "F", []string{"crit-ask", "crit-auto"}, field{Label: "K", Kind: "password", Value: "v"})
	cAsk := e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"crit-ask"}})
	cAuto := e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"crit-auto"}, "mode": "auto"})
	e.ok(e.call("app", "share.decide", js(map[string]any{"rule_id": cAsk, "include": []string{f}})))
	if in, _, _ := ruleState(t, e, cAuto); !contains(in, f) {
		t.Fatal("setup: not included")
	}
	e.ok(e.sealed("app", "item.sensitivity", map[string]any{"item_id": f, "version": e.version(f), "sensitivity": "critical"},
		map[string]any{"password": pw, "item_id": f}, true, false))
	_, pAsk, _ := ruleState(t, e, cAsk)
	_, pAuto, _ := ruleState(t, e, cAuto)
	if !contains(pAsk, f) || !contains(pAuto, f) {
		t.Fatalf("critical move: ask %v auto %v", pAsk, pAuto)
	}
	if x := entryFor(e.pendingList(), cAuto, f); x == nil || x["ask_rule_id"] != cAsk {
		t.Fatalf("critical move entry %v", x)
	}
}

// §10.7 (0.23.0): item.put and item.tag dry runs name the ask rule that
// holds an item an auto rule would otherwise include.
func TestOverlapItemDryRun(t *testing.T) {
	e := newEnv(t)
	ask := e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"medical"}})
	auto := e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"insurance"}, "mode": "auto"})
	free := e.rule(map[string]any{"subject": conn("cB"), "tags": []string{"insurance"}, "mode": "auto"})
	r := e.ok(e.call("app", "item.put", js(map[string]any{"dry_run": true, "tags": []string{"medical", "insurance"}})))
	var a struct {
		Shares []map[string]any `json:"shares"`
	}
	_ = json.Unmarshal(r["shares"], &a.Shares)
	if len(a.Shares) != 3 {
		t.Fatalf("shares %v", a.Shares)
	}
	for _, s := range a.Shares {
		want := ""
		if s["rule_id"] == auto {
			want = ask
		}
		if got, _ := s["ask_rule_id"].(string); got != want {
			t.Fatalf("%v: ask_rule_id %q, want %q", s, got, want)
		}
	}
	id := e.put("data", "X", []string{"insurance"})
	r = e.ok(e.call("app", "item.tag", js(map[string]any{"dry_run": true, "item_id": id, "version": e.version(id), "tags": []string{"insurance", "medical"}})))
	a.Shares = nil
	_ = json.Unmarshal(r["shares"], &a.Shares)
	if len(a.Shares) != 1 || a.Shares[0]["rule_id"] != ask || a.Shares[0]["ask_rule_id"] != nil {
		t.Fatalf("item.tag dry run: %v (an included item gains only the ask rule)", a.Shares)
	}
	_ = free
}

// §10.12 (owner's review of #181): uses across overlapping rules: a fetch
// through a rule grant counts one use on every rule grant of the item
// that has uses; exhausted if any has none left; spending the last use of
// one spends them all (used); uses_left is the least; the rate limits of
// every including rule apply.
func TestOverlapUsesAndRates(t *testing.T) {
	e := newEnv(t)
	x := e.put("data", "X", []string{"a", "b", "c"}, field{Label: "V", Kind: "text", Value: "x"})
	e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"a"}, "mode": "auto", "uses": 2})
	e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"b"}, "mode": "auto", "uses": 5})
	e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"c"}, "mode": "auto"})
	gs := e.grantsShared("cA")
	if len(gs) != 3 {
		t.Fatalf("%d grants", len(gs))
	}
	gA, gB, gC := gs[0], gs[1], gs[2]
	v := e.fetchValue("cA", gB)
	if left, err := v.Uint("uses_left", 0, 10000); err != nil || left != 1 {
		t.Fatalf("uses_left %d (the least)", left)
	}
	// The catalog: the least too.
	rid, _ := envelope.NewULID(e.clk.T)
	e.h.Reset()
	e.call("connection:cA", "data.catalog.get", js(map[string]any{"request_id": rid}))
	if cat := string(e.sentTo("cA", "data.catalog")[0].Body); strings.Count(cat, `"uses_left":1`) != 3 {
		t.Fatalf("catalog: %s", cat)
	}
	// The rule without uses counts nothing on the others' behalf... and
	// its fetch counts one on each that has uses: the last of A's.
	v = e.fetchValue("cA", gC)
	if left, _ := v.Uint("uses_left", 0, 10000); left != 0 {
		t.Fatalf("uses_left after the last %d", left)
	}
	for _, g := range []string{gA, gB, gC} {
		if er, _ := e.fetch("cA", g); er != "exhausted" {
			t.Fatalf("%s after the last use: %q", g, er)
		}
	}
	if gl := string(e.ok(e.call("app", "grant.list", `{}`))["given"]); strings.Count(gl, `"state":"used"`) != 3 {
		t.Fatalf("not all used: %s", gl)
	}
	_ = x
	// Rate limits combine: a fetch through a rule without limits counts in
	// the including rule that has one.
	y := e.put("data", "Y", []string{"p", "q"})
	e.rule(map[string]any{"subject": conn("cB"), "tags": []string{"p"}, "mode": "auto", "per_hour": 1})
	e.rule(map[string]any{"subject": conn("cB"), "tags": []string{"q"}, "mode": "auto"})
	gy := e.grantsShared("cB")
	if len(gy) != 2 {
		t.Fatalf("%d grants", len(gy))
	}
	if er, _ := e.fetch("cB", gy[1]); er != "" {
		t.Fatal(er)
	}
	if er, _ := e.fetch("cB", gy[1]); er != "rate_limited" {
		t.Fatalf("second fetch through the unlimited rule: %q", er)
	}
	_ = y
}

// §10.11, §10.12 (0.23.0): agents: ask wins over an agent's auto rule; a
// read counts in every including rule's windows and is referred while
// any is full; a read counts one use in every including rule that has
// uses, and with none left in one the item is included in none.
func TestOverlapAgents(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	e.unlock()
	agent := map[string]any{"agent_id": "dev-agent"}
	doc := e.put("data", "Doc", []string{"x", "y"}, field{Label: "Body", Kind: "text", Value: "c"})
	r1 := e.rule(map[string]any{"subject": agent, "tags": []string{"x"}, "mode": "auto", "per_hour": 1, "uses": 3})
	r2 := e.rule(map[string]any{"subject": agent, "tags": []string{"y"}, "mode": "auto", "per_hour": 10})
	in1, _, _ := ruleState(t, e, r1)
	in2, _, _ := ruleState(t, e, r2)
	if !contains(in1, doc) || !contains(in2, doc) {
		t.Fatal("setup")
	}
	decide := func(req map[string]any) vault.AgentDecision {
		s := vault.NewSession(context.TODO(), e.h, vault.PeerInfo{ID: "dev-agent", Kind: vault.KindAgent}, e.clk.T, nil)
		return e.set.Leash.AgentDecision(s, "agent.request", json.RawMessage(js(req)))
	}
	get := map[string]any{"op": "item.get", "item_id": doc}
	if d := decide(get); d != vault.AgentAllow {
		t.Fatalf("first read: %v", d)
	}
	e.ok(e.call("agent", "agent.request", js(get)))
	if d := decide(get); d != vault.AgentAsk {
		t.Fatalf("second read within r1's hour: %v (the strictest applies)", d)
	}
	// Uses: 3 on r1 (counted by every read, also through r2's coverage).
	e.clk.Advance(time.Hour)
	for i := 0; i < 2; i++ {
		e.clk.Advance(time.Hour)
		if d := decide(get); d != vault.AgentAllow {
			t.Fatalf("read %d: %v", i, d)
		}
		e.ok(e.call("agent", "agent.request", js(get)))
	}
	if d := decide(get); d == vault.AgentAllow {
		t.Fatal("no use left in r1, still included through r2")
	}
	cat := e.ok(e.call("agent", "agent.request", `{"op":"catalog"}`))
	if strings.Contains(string(cat["items"]), doc) {
		t.Fatalf("catalog after r1's uses: %s", cat["items"])
	}
	// Ask wins for agents: an agent's ask rule holds an item its auto rule
	// would include.
	e.unlock()
	o := e.put("data", "Other", []string{"aa", "bb"})
	askR := e.rule(map[string]any{"subject": agent, "tags": []string{"aa"}})
	autoR := e.rule(map[string]any{"subject": agent, "tags": []string{"bb"}, "mode": "auto"})
	if x := entryFor(e.pendingList(), autoR, o); x == nil || x["ask_rule_id"] != askR {
		t.Fatalf("agent overlap: %v", x)
	}
}
