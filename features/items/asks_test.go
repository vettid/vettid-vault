package items_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/feed"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// VAULT-MESSAGING 0.23.0 §10.4.1 through the features that receive asks:
// grant requests, critical-item uses, prompt-each-time invocations,
// authentication challenges, introduction offers and location requests,
// on a host that keeps the §10.4.1 state as the vault does.

type askKind struct {
	name     string
	setup    func(e *env)
	send     func(e *env, id string) // the ask, from cA
	decline  func(e *env, id string) // the member's decline
	answer   string                  // the decline answer's type ("" none)
	pending  string                  // the per-type .pending event
	feedKind string                  // its feed item
	idKey    string                  // the answer's id member
	exp      time.Duration           // the ask's exp (0: none within 20 min)
}

func (e *env) newID() string {
	e.clk.Advance(time.Millisecond)
	id, _ := envelope.NewULID(e.clk.T)
	return id
}

func askKinds() []askKind {
	var crit string
	return []askKind{
		{name: "grant", pending: "grant.pending", feedKind: "grant.request", answer: "data.decided", idKey: "request_id",
			send: func(e *env, id string) {
				e.call("connection:cA", "data.request", js(map[string]any{"request_id": id,
					"items": []map[string]any{{"kind": "category", "ref": "medical"}}, "uses": 1, "expires_in": 3600}))
			},
			decline: func(e *env, id string) {
				e.ok(e.call("app", "grant.decide", js(map[string]any{"request_id": id, "approve": false})))
			}},
		{name: "critical", pending: "critical-secret-use.pending", feedKind: "critical-secret.use.request", answer: "critical-secret.result",
			idKey: "request_id",
			setup: func(e *env) {
				e.createCredential()
				crit = e.putCritical("Key", []string{"sign"}, field{Label: "Seed", Kind: "password", Value: base64.StdEncoding.EncodeToString(make([]byte, 32))})
				e.rule(map[string]any{"subject": conn("cA"), "tags": []string{"sign"}, "mode": "auto"})
			},
			send: func(e *env, id string) {
				e.call("connection:cA", "critical-secret.use", js(map[string]any{"request_id": id, "item_id": crit, "field_id": "f1",
					"operation": "sign", "payload": base64.StdEncoding.EncodeToString([]byte("p"))}))
			},
			decline: func(e *env, id string) {
				e.ok(e.call("app", "critical-secret-use.deny", js(map[string]any{"request_id": id})))
			}},
		{name: "action", pending: "action.pending", feedKind: "action.request", answer: "action.result", idKey: "invocation_id",
			setup: func(e *env) {
				e.ok(e.call("app", "action.configure", `{"action_id":"audit.recent","mode":"prompt-each-time"}`))
			},
			send: func(e *env, id string) {
				e.call("connection:cA", "action.invocation", js(map[string]any{"invocation_id": id, "action_id": "audit.recent", "version": 1,
					"params": map[string]any{}}))
			},
			decline: func(e *env, id string) {
				e.ok(e.call("app", "action.respond", js(map[string]any{"invocation_id": id, "approve": false})))
			}},
		{name: "auth", pending: "connection.authenticate.pending", feedKind: "connection.authenticate.requested",
			answer: "connection.authenticate.response", idKey: "request_id", exp: 10 * time.Minute,
			send: func(e *env, id string) {
				e.call("connection:cA", "connection.authenticate.challenge", js(map[string]any{"request_id": id,
					"nonce": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))}))
			},
			decline: func(e *env, id string) {
				e.ok(e.call("app", "connection.authenticate.deny", js(map[string]any{"request_id": id})))
			}},
		{name: "intro", pending: "intro.pending", feedKind: "intro.request", answer: "intro.answer", idKey: "intro_id",
			send: func(e *env, id string) {
				e.call("connection:cA", "intro.offer", js(map[string]any{"intro_id": id, "peer": map[string]any{"name": "Carol"},
					"exp": envelope.FormatTS(e.clk.T.Add(48 * time.Hour))}))
			},
			decline: func(e *env, id string) {
				e.ok(e.call("app", "intro.decline", js(map[string]any{"intro_id": id})))
			}},
		{name: "location", pending: "location.request.pending", feedKind: "location.request",
			send: func(e *env, id string) {
				e.call("connection:cA", "location.requested", js(map[string]any{"request_id": id}))
			}},
	}
}

func (e *env) pendingSent(typ string) int { return len(e.sentTo("devices", typ)) }

// asksOn keeps the §10.4.1 state on the host, counting every feature's
// pending asks.
func (e *env) asksOn() {
	e.h.AsksOn = true
	e.h.AskSources = map[string]vault.AskSource{}
	for _, f := range e.set.List() {
		if src, ok := f.(vault.AskSource); ok {
			e.h.AskSources[f.Name()] = src
		}
	}
}

// Every ask kind: it reaches the member (the .pending event, a feed item
// marked for batching); after the member's decline the same ask is in
// cooldown: suppressed (no .pending, no feed item), audited
// drop.ask_cooldown, and answered — not at once, after the random delay
// — with exactly the decline's answer (the same type and members); muted
// it is suppressed the same way (drop.ask_muted). A location request has
// no decline and gets no answer.
func TestAsksEveryKind(t *testing.T) {
	for _, k := range askKinds() {
		t.Run(k.name, func(t *testing.T) {
			e := newEnv(t)
			if k.setup != nil {
				k.setup(e)
			}
			e.asksOn()
			e.h.Reset()
			id1 := e.newID()
			k.send(e, id1)
			if e.pendingSent(k.pending) != 1 {
				t.Fatalf("not asked: %v", e.h.Sent)
			}
			fa := e.activity(k.feedKind)
			if len(fa) != 1 || !fa[0].Feed || !fa[0].AskBatch || fa[0].ConnectionID != "cA" {
				t.Fatalf("feed item %+v", fa)
			}
			var declined []byte
			if k.decline != nil {
				e.h.Reset()
				k.decline(e, id1)
				ds := e.sentTo("cA", k.answer)
				if len(ds) != 1 {
					t.Fatalf("decline answer: %v", e.h.Sent)
				}
				declined = ds[0].Body
				// The same ask again: cooldown.
				e.h.Reset()
				id2 := e.newID()
				k.send(e, id2)
				at := e.clk.T // when the ask was handled
				if e.pendingSent(k.pending) != 0 || len(e.feedKinds()) != 0 {
					t.Fatalf("a suppressed ask reached the member: %v", e.h.Sent)
				}
				if a := e.activity("drop.ask_cooldown"); len(a) != 1 || a[0].Ref != id2 || a[0].ConnectionID != "cA" {
					t.Fatalf("audit %+v", a)
				}
				if len(e.sentTo("cA", k.answer)) != 0 {
					t.Fatal("answered at once")
				}
				if got := e.h.ReleaseAsks(at.Add(vault.AskDelayMin - time.Millisecond)); len(got) != 0 {
					t.Fatal("answered within a minute")
				}
				got := e.h.ReleaseAsks(at.Add(vault.AskDelayMax))
				if len(got) != 1 || got[0].Type != k.answer {
					t.Fatalf("held: %+v", got)
				}
				if k.exp > 0 && got[0].Due.After(at.Add(k.exp-time.Minute)) {
					t.Fatalf("due %v after exp - 1 min", got[0].Due)
				}
				// Byte for byte the decline's answer, but for the id.
				if want := bytes.Replace(declined, []byte(id1), []byte(id2), 1); !bytes.Equal(got[0].Body, want) {
					t.Fatalf("suppressed answer %s, decline %s", got[0].Body, declined)
				}
				if len(e.sentTo("cA", k.answer)) != 1 {
					t.Fatal("held answer not sent")
				}
			}
			// Muted: suppressed silently, answered as a decline (none for a
			// location request). A day later: past the per-type limits.
			e.clk.Advance(24 * time.Hour)
			e.h.Asks["cA"].Muted = true
			e.h.Asks["cA"].Cooldowns = nil
			e.h.Reset()
			id3 := e.newID()
			k.send(e, id3)
			if e.pendingSent(k.pending) != 0 || len(e.feedKinds()) != 0 || len(e.activity("drop.ask_muted")) != 1 {
				t.Fatalf("muted: %v %v", e.h.Sent, e.h.Activities)
			}
			got := e.h.ReleaseAsks(e.clk.T.Add(time.Hour))
			if k.answer == "" && len(got) != 0 || k.answer != "" && (len(got) != 1 || !bytes.Contains(got[0].Body, []byte(id3))) {
				t.Fatalf("muted answer %+v", got)
			}
		})
	}
}

// A grant request in which some entries are in cooldown reaches the
// member without them (drop.ask_cooldown per entry, the request's ref);
// all in cooldown: suppressed.
func TestAsksGrantPartialCooldown(t *testing.T) {
	e := newEnv(t)
	e.asksOn()
	a := e.put("data", "A", nil)
	b := e.put("data", "B", nil)
	req := func(id string, refs ...string) {
		var items []map[string]any
		for _, r := range refs {
			items = append(items, map[string]any{"kind": "item", "ref": r, "fields": []string{}})
			delete(items[len(items)-1], "fields")
		}
		e.call("connection:cA", "data.request", js(map[string]any{"request_id": id, "items": items, "uses": 1, "expires_in": 3600}))
	}
	id1 := e.newID()
	req(id1, a)
	e.ok(e.call("app", "grant.decide", js(map[string]any{"request_id": id1, "approve": false})))
	e.h.Reset()
	id2 := e.newID()
	req(id2, a, b)
	ps := e.sentTo("devices", "grant.pending")
	if len(ps) != 1 || bytes.Contains(ps[0].Body, []byte(a)) || !bytes.Contains(ps[0].Body, []byte(b)) {
		t.Fatalf("partial: %v", ps)
	}
	if d := e.activity("drop.ask_cooldown"); len(d) != 1 || d[0].Ref != id2 {
		t.Fatalf("removed entry not audited: %+v", d)
	}
	// Declining it cools b too; a request for a and b is suppressed.
	e.ok(e.call("app", "grant.decide", js(map[string]any{"request_id": id2, "approve": false})))
	e.h.Reset()
	id3 := e.newID()
	req(id3, a, b)
	if len(e.sentTo("devices", "grant.pending")) != 0 || len(e.activity("drop.ask_cooldown")) != 1 {
		t.Fatalf("all in cooldown: %v", e.h.Activities)
	}
	// A partial approval is not a decline: no cooldown.
	if st := e.h.Asks["cA"]; len(st.Declines) != 2 {
		t.Fatalf("declines %v", st.Declines)
	}
}

// The pending cap counts the connection's asks of every kind; the rate
// is 5 that reach the member per fixed 24 hours; 3 declines in 30 days
// pause the connection's asks with one feed item (high); resume clears.
func TestAsksPendingRatePause(t *testing.T) {
	e := newEnv(t)
	e.asksOn()
	grant := askKinds()[0]
	loc := askKinds()[5]
	var ids []string
	for i := 0; i < vault.AskRate; i++ {
		id := e.newID()
		ids = append(ids, id)
		grant.send(e, id)
	}
	e.h.Reset()
	loc.send(e, e.newID())
	if len(e.activity("drop.ask_rate")) != 1 || e.pendingSent(loc.pending) != 0 {
		t.Fatalf("6th ask in the window: %v", e.h.Activities)
	}
	// The next day 3 more grant requests: 8 pending, all kinds together.
	e.clk.Advance(vault.AskRateWindow)
	for i := 0; i < 3; i++ {
		grant.send(e, e.newID())
	}
	e.h.Reset()
	loc.send(e, e.newID())
	if len(e.activity("drop.ask_pending")) != 1 {
		t.Fatalf("9th pending: %v", e.h.Activities)
	}
	// Three declines: paused, one feed item.
	e.h.Reset()
	for _, id := range ids[:3] {
		e.ok(e.call("app", "grant.decide", js(map[string]any{"request_id": id, "approve": false})))
	}
	if p := e.activity("connection.asks_paused"); len(p) != 1 || !p[0].Feed || p[0].Priority != "high" || p[0].ConnectionID != "cA" {
		t.Fatalf("pause %+v", p)
	}
	e.ok(e.call("app", "grant.decide", js(map[string]any{"request_id": ids[3], "approve": false})))
	if len(e.activity("connection.asks_paused")) != 1 {
		t.Fatal("paused twice")
	}
	e.h.Reset()
	loc.send(e, e.newID())
	if len(e.activity("drop.ask_paused")) != 1 {
		t.Fatalf("paused ask: %v", e.h.Activities)
	}
}

// Batching (§10.4.1): asks of one connection within 10 minutes of the
// first form one feed item whose count is the number of asks (from 2),
// updated with a new seq and the same item_id (sync.event feed.updated);
// the per-type .pending events are still sent; after 10 minutes a new
// batch starts.
func TestAsksBatching(t *testing.T) {
	e := newEnv(t)
	e.asksOn()
	e.h.Sinks = append(e.h.Sinks, e.set.Feed)
	ks := askKinds()
	ks[4].send(e, e.newID()) // an introduction offer
	e.clk.Advance(4 * time.Minute)
	e.h.Reset()
	ks[0].send(e, e.newID()) // a grant request
	e.clk.Advance(5 * time.Minute)
	ks[5].send(e, e.newID()) // a location request
	items := e.set.Feed.Items()
	var batch []feed.Item
	for _, it := range items {
		if it.ConnectionID == "cA" {
			batch = append(batch, it)
		}
	}
	if len(batch) != 1 || batch[0].Kind != "intro.request" || batch[0].Count != 3 {
		t.Fatalf("batch %+v", batch)
	}
	if e.pendingSent("grant.pending") != 1 || e.pendingSent("location.request.pending") != 1 {
		t.Fatal("per-type .pending not sent")
	}
	n := 0
	for _, s := range e.sentTo("devices", "sync.event") {
		if strings.Contains(string(s.Body), `"kind":"feed.updated","item_id":"`+batch[0].ID+`"`) {
			n++
		}
	}
	if n != 2 || len(e.sentTo("devices", "feed.event")) != 0 {
		t.Fatalf("%d feed.updated, %d feed.event", n, len(e.sentTo("devices", "feed.event")))
	}
	got := e.ok(e.call("app", "feed.get", js(map[string]any{"item_id": batch[0].ID})))
	if c, _ := got.Uint("count", 2, 100); c != 3 {
		t.Fatalf("feed.get count: %s", got["count"])
	}
	// More than 10 minutes after the first: a new item, without count.
	e.clk.Advance(2 * time.Minute)
	e.h.Reset()
	ks[0].send(e, e.newID())
	fe := e.sentTo("devices", "feed.event")
	if len(fe) != 1 || bytes.Contains(fe[0].Body, []byte(`"count"`)) {
		t.Fatalf("new batch: %v", fe)
	}
	var one map[string]any
	_ = json.Unmarshal(fe[0].Body, &one)
	if one["kind"] != "grant.request" {
		t.Fatalf("new batch item %v", one)
	}
}
