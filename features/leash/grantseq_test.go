package leash

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// grantSeq reads a body's grant_seq (0 if absent or invalid).
func grantSeq(t *testing.T, body []byte) uint64 {
	t.Helper()
	o, err := strictjson.ParseObject(body)
	if err != nil {
		t.Fatalf("body: %v", err)
	}
	n, present, err := o.OptUint("grant_seq", 1, strictjson.MaxSafeInteger)
	if err != nil || !present {
		return 0
	}
	return n
}

// lastUpdate is the grant_seq of the newest leash.grant.updated sent to
// the agent, and how many were sent.
func lastUpdate(t *testing.T, r *rig, to string) (uint64, int) {
	t.Helper()
	var n uint64
	count := 0
	for _, m := range r.h.SentOfType("leash.grant.updated") {
		if m.To == to {
			n = grantSeq(t, m.Body)
			count++
		}
	}
	return n, count
}

// agentList is the agent's own leash.grant.list answer's grant_seq.
func agentListSeq(t *testing.T, r *rig, now time.Time) uint64 {
	t.Helper()
	res := featuretest.Call(r.f, r.h, now, vault.KindAgent, "leash.grant.list", `{}`)
	if !res.OK() {
		t.Fatalf("list: %s", res.Code)
	}
	return grantSeq(t, res.Body)
}

// listAs is the leash.grant.list answer to a device other than the rig's
// agent (featuretest.Call sends as "dev-<kind>").
func listAs(t *testing.T, r *rig, now time.Time, from vault.PeerInfo) []byte {
	t.Helper()
	in := &envelope.Inner{ID: "01JB2Z6V9K3M4N5P6Q7R8S9L1S", Type: "leash.grant.list", TS: now, Body: json.RawMessage(`{}`)}
	out, err := r.f.Handle(context.Background(), vault.NewSession(context.Background(), r.h, from, now, in), in)
	if err != nil {
		t.Fatalf("list as %s: %v", from.ID, err)
	}
	return out
}

func appSession(r *rig, now time.Time) *vault.Session {
	return vault.NewSession(context.Background(), r.h, vault.PeerInfo{ID: "dev-app", Kind: vault.KindApp}, now, nil)
}

// §10.11 "Grant-set sequence" (0.41.0): every change to the agent's set
// takes a higher number, carried by leash.grant.updated and the agent's
// list; what is not a change keeps it.
func TestGrantSeqEachChange(t *testing.T) {
	r := newRig(t)
	var last uint64
	step := func(name string) {
		t.Helper()
		n, _ := lastUpdate(t, r, agent)
		if n == 0 || n <= last {
			t.Fatalf("%s: grant_seq %d after %d", name, n, last)
		}
		if l := agentListSeq(t, r, t0); l != n {
			t.Fatalf("%s: list says %d, the update %d", name, l, n)
		}
		last = n
	}

	_, gid := r.issue(t, `{"agent_id":"dev-agent","scope":"profile.get"}`)
	step("issued")
	r.issue(t, `{"agent_id":"dev-agent","grant_id":"`+gid+`","version":1,"scope":"connection.list"}`)
	step("replaced")
	rid := r.rule(t, "auto", 0, 60, r.wifi)
	step("share rule set")
	if !r.f.DeleteAgentRule(appSession(r, t0), rid) {
		t.Fatal("rule not deleted")
	}
	step("share rule deleted")
	if res := featuretest.Call(r.f, r.h, t0, vault.KindApp, "leash.grant.revoke", `{"grant_id":"`+gid+`"}`); !res.OK() {
		t.Fatalf("revoke: %s", res.Code)
	}
	step("revoked")
	r.issue(t, `{"agent_id":"dev-agent","scope":"message.send","connections":["`+r.c1+`"]}`)
	step("issued with a connection")
	before := len(r.h.SentOfType("leash.grant.updated"))
	r.f.ConnectionRemoved(vault.NewSession(context.Background(), r.h, vault.PeerInfo{}, t0, nil), r.c1)
	if len(r.h.SentOfType("leash.grant.updated")) != before+1 {
		t.Fatal("one update per agent at a connection's removal")
	}
	step("revoked with its connection")
	// A connection no grant names changes nothing.
	r.f.ConnectionRemoved(vault.NewSession(context.Background(), r.h, vault.PeerInfo{}, t0, nil), r.c2)
	if n, _ := lastUpdate(t, r, agent); n != last || agentListSeq(t, r, t0) != last {
		t.Fatal("an unrelated connection's removal took a number")
	}

	// Suspension (refusals past the limit), then resumption.
	for i := 0; i < SuspendAfter; i++ {
		r.decide(t0.Add(time.Duration(i)*time.Second), "connection.list", `{}`)
	}
	if st := r.f.d.Agents[agent]; st == nil || !st.Suspended {
		t.Fatal("not suspended")
	}
	step("suspended")
	if res := featuretest.Call(r.f, r.h, t0, vault.KindApp, "leash.agent.resume", `{"agent_id":"dev-agent"}`); !res.OK() {
		t.Fatalf("resume: %s", res.Code)
	}
	step("resumed")

	// Not changes: a list, fresh statements at a hold's end, an expiry.
	r.issue(t, `{"agent_id":"dev-agent","scope":"profile.get","expires_at":"2026-10-03T13:00:00.000Z"}`)
	step("issued with an expiry")
	_, sent := lastUpdate(t, r, agent)
	r.f.OwnerHoldEnded(appSession(r, t0))
	n, sentAfter := lastUpdate(t, r, agent)
	if sentAfter != sent+1 || n != last {
		t.Fatalf("hold end: %d updates, grant_seq %d, want the same %d", sentAfter-sent, n, last)
	}
	if l := agentListSeq(t, r, t0.Add(2*time.Hour)); l != last {
		t.Fatalf("expiry took a number: %d, want %d", l, last)
	}
}

// §10.11, §6.7: the set a pairing completes with takes the counter's next
// value; unlinking ends the set and the counter goes on; a re-paired agent
// (a new device) starts from the vault's current value, and no number is
// used twice.
func TestGrantSeqPairingAndRepairing(t *testing.T) {
	r := newRig(t)
	seen := map[uint64]string{}
	note := func(n uint64, what string) {
		t.Helper()
		if n == 0 {
			t.Fatalf("%s: no grant_seq", what)
		}
		if prev, ok := seen[n]; ok {
			t.Fatalf("%s: grant_seq %d used again (first by %s)", what, n, prev)
		}
		seen[n] = what
	}
	sess := appSession(r, t0)
	ag, _ := r.h.Device(agent)
	prepared, err := r.f.PrepareAgentGrants(sess, ag.IK, json.RawMessage(`[{"scope":"profile.get"}]`))
	if err != nil {
		t.Fatal(err)
	}
	r.f.AgentPaired(sess, agent, prepared)
	first, _ := lastUpdate(t, r, agent)
	note(first, "pairing with grants")
	r.issue(t, `{"agent_id":"dev-agent","scope":"connection.list"}`)
	second, _ := lastUpdate(t, r, agent)
	note(second, "issue")

	r.f.DeviceRemoved(vault.NewSession(context.Background(), r.h, vault.PeerInfo{}, t0, nil), agent)
	if _, ok := r.f.d.GrantSeq[agent]; ok {
		t.Fatal("an unlinked agent's set kept its number")
	}
	if r.f.d.Seq != second {
		t.Fatalf("unlinking moved the counter: %d, want %d", r.f.d.Seq, second)
	}

	// Re-paired with initial grants: a new device id, its numbers above
	// every earlier one.
	r.h.AddDevice("dev-agent-new", vault.KindAgent)
	nag, _ := r.h.Device("dev-agent-new")
	prepared, err = r.f.PrepareAgentGrants(sess, nag.IK, json.RawMessage(`[{"scope":"profile.get"}]`))
	if err != nil {
		t.Fatal(err)
	}
	r.f.AgentPaired(sess, "dev-agent-new", prepared)
	repaired, _ := lastUpdate(t, r, "dev-agent-new")
	note(repaired, "re-pairing")
	if repaired <= second {
		t.Fatalf("a re-paired agent's set took %d, at or below the vault's %d", repaired, second)
	}

	// Paired without initial grants: the vault core still calls AgentPaired
	// (with nothing prepared), and the empty set takes its number then, not
	// in a later read. The agent is told.
	r.h.AddDevice("dev-agent-bare", vault.KindAgent)
	bare, _ := r.h.Device("dev-agent-bare")
	r.f.AgentPaired(sess, "dev-agent-bare", nil)
	empty, told := lastUpdate(t, r, "dev-agent-bare")
	note(empty, "pairing without grants")
	if told != 1 || empty <= repaired || r.f.d.GrantSeq["dev-agent-bare"] != empty {
		t.Fatalf("pairing without grants: %d updates, grant_seq %d (stored %d), after %d",
			told, empty, r.f.d.GrantSeq["dev-agent-bare"], repaired)
	}
	body := listAs(t, r, t0, bare)
	if grantSeq(t, body) != empty || !strings.Contains(string(body), `"grants":[]`) {
		t.Fatalf("empty set: %s", body)
	}
	// An agent with no number yet (paired before this build, or before
	// 0.41.0): numbered the first time it's described, from the counter.
	// AgentPaired is deliberately not called for it (the harness's
	// AddDevice doesn't), which is what such an agent looks like.
	r.h.AddDevice("dev-agent-old", vault.KindAgent)
	old, _ := r.h.Device("dev-agent-old")
	if n := grantSeq(t, listAs(t, r, t0, old)); n <= empty {
		t.Fatalf("an older agent's first list took %d, not above %d", n, empty)
	} else {
		note(n, "an older agent's first list")
	}
	// Described again: the same number.
	if again := grantSeq(t, listAs(t, r, t0, bare)); again != empty {
		t.Fatalf("the same empty set took a new number: %d, then %d", empty, again)
	}

	// An agent that lists before its initial grants take effect: the empty
	// set it was told about has a number, so the set the pairing completes
	// with must take a higher one, or the agent (keeping its set on an equal
	// number) would keep the empty one.
	r.h.AddDevice("dev-agent-early", vault.KindAgent)
	early, _ := r.h.Device("dev-agent-early")
	before := grantSeq(t, listAs(t, r, t0, early))
	note(before, "an early list")
	prepared, err = r.f.PrepareAgentGrants(sess, early.IK, json.RawMessage(`[{"scope":"profile.get"}]`))
	if err != nil {
		t.Fatal(err)
	}
	r.f.AgentPaired(sess, "dev-agent-early", prepared)
	paired, _ := lastUpdate(t, r, "dev-agent-early")
	note(paired, "pairing after an early list")
	if paired <= before {
		t.Fatalf("initial grants took %d, not above the early list's %d", paired, before)
	}
}

// The counter and each agent's number are in the sealed state: a flush
// and load keeps them, and the next change goes on from there. A vault that
// ran before 0.41.0 (no counter in its state) numbers its agents' sets from
// 1 up the first time they're described.
func TestGrantSeqStateAndMigration(t *testing.T) {
	r := newRig(t)
	r.issue(t, `{"agent_id":"dev-agent","scope":"profile.get"}`)
	r.issue(t, `{"agent_id":"dev-agent","scope":"connection.list"}`)
	before, _ := lastUpdate(t, r, agent)
	g2 := New(r.w, r.it)
	featuretest.RoundTrip(t, r.f, g2)
	if g2.d.Seq != before || g2.d.GrantSeq[agent] != before {
		t.Fatalf("after a flush: counter %d, agent %d, want %d", g2.d.Seq, g2.d.GrantSeq[agent], before)
	}
	r.f = g2
	r.issue(t, `{"agent_id":"dev-agent","scope":"message.list"}`)
	if after, _ := lastUpdate(t, r, agent); after != before+1 {
		t.Fatalf("after a flush the next change took %d, want %d", after, before+1)
	}

	// The state of a vault before 0.41.0: grants, no seq or grant_seq.
	old := New(r.w, r.it)
	raw, err := r.f.Save()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "seq")
	delete(m, "grant_seq")
	raw, _ = json.Marshal(m)
	if err := old.Load(raw); err != nil {
		t.Fatal(err)
	}
	r.f = old
	if n := agentListSeq(t, r, t0); n != 1 {
		t.Fatalf("an upgraded vault's first number: %d, want 1", n)
	}
	r.issue(t, `{"agent_id":"dev-agent","scope":"profile.get"}`)
	if n, _ := lastUpdate(t, r, agent); n != 2 {
		t.Fatalf("then a change: %d, want 2", n)
	}
}

// Apps' and desktops' leash.grant.list answers don't carry grant_seq: they
// follow sync.event (§10.11).
func TestGrantSeqOnlyForAgents(t *testing.T) {
	r := newRig(t)
	r.issue(t, `{"agent_id":"dev-agent","scope":"profile.get"}`)
	for _, c := range []struct{ kind, body string }{
		{vault.KindApp, `{}`}, {vault.KindApp, `{"agent_id":"dev-agent"}`}, {vault.KindDesktop, `{"agent_id":"dev-agent"}`},
	} {
		res := featuretest.Call(r.f, r.h, t0, c.kind, "leash.grant.list", c.body)
		if !res.OK() || strings.Contains(string(res.Body), "grant_seq") {
			t.Fatalf("%s %s: %s", c.kind, c.body, res.Body)
		}
	}
}

// A hold drops leash.grant.updated to agents without queueing it
// (holdDelivers). If the agent's last grant is revoked during the hold, the
// hold's end must still tell it: the empty set, with the revocation's number.
func TestGrantSeqHoldEndTellsEmptiedSet(t *testing.T) {
	r := newRig(t)
	_, gid := r.issue(t, `{"agent_id":"dev-agent","scope":"profile.get"}`)
	if res := featuretest.Call(r.f, r.h, t0, vault.KindApp, "leash.grant.revoke", `{"grant_id":"`+gid+`"}`); !res.OK() {
		t.Fatalf("revoke: %s", res.Code)
	}
	revoked, sent := lastUpdate(t, r, agent)
	r.f.OwnerHoldEnded(appSession(r, t0))
	n, sentAfter := lastUpdate(t, r, agent)
	if sentAfter != sent+1 {
		t.Fatalf("hold end sent %d updates to an agent with no grant left, want 1", sentAfter-sent)
	}
	if n != revoked {
		t.Fatalf("hold end: grant_seq %d, want the revocation's %d", n, revoked)
	}
	msgs := r.h.SentOfType("leash.grant.updated")
	o, err := strictjson.ParseObject(msgs[len(msgs)-1].Body)
	if err != nil {
		t.Fatal(err)
	}
	if gs, _ := o.Array("grants"); len(gs) != 0 {
		t.Fatalf("hold end: %d grants, want none", len(gs))
	}
}

// A damaged state whose counter is below an agent's number: Load raises the
// counter, so no number is given out twice.
func TestGrantSeqLoadCounterFloor(t *testing.T) {
	r := newRig(t)
	r.issue(t, `{"agent_id":"dev-agent","scope":"profile.get"}`)
	raw, err := r.f.Save()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["seq"] = json.RawMessage(`1`)
	m["grant_seq"] = json.RawMessage(`{"dev-agent":7}`)
	raw, _ = json.Marshal(m)
	g := New(r.w, r.it)
	if err := g.Load(raw); err != nil {
		t.Fatal(err)
	}
	r.f = g
	r.issue(t, `{"agent_id":"dev-agent","scope":"connection.list"}`)
	if n, _ := lastUpdate(t, r, agent); n != 8 {
		t.Fatalf("next change after a damaged counter: %d, want 8", n)
	}
}

// An agent's leash.grant.list can take a new grant_seq (seqOf, for a set
// with no number yet). That is safe only while the answer is durable: a
// queued request answer is sent after the write that stores it (the vault
// outbox; TestFailedWriteThenLaterWriteSendsStored), while a volatile or
// ephemeral answer is deposited from memory. This pins the type's spec.
func TestGrantSeqListAnswerIsDurable(t *testing.T) {
	r := newRig(t)
	for _, ts := range r.f.Types() {
		if ts.Type != "leash.grant.list" {
			continue
		}
		if !ts.Request || ts.Volatile || ts.Ephemeral {
			t.Fatalf("leash.grant.list: request %v, volatile %v, ephemeral %v; it must be a durable, queued request",
				ts.Request, ts.Volatile, ts.Ephemeral)
		}
		return
	}
	t.Fatal("leash.grant.list not registered")
}

// Damaged initial grants (the sealed PairGrants does not decode): none of
// them is installed, not even one that decoded before the error, and the
// pairing still completes with the empty set: it takes its grant_seq and
// the agent is told (§10.11).
func TestGrantSeqDamagedPairGrants(t *testing.T) {
	for _, c := range []struct {
		name   string
		damage func(t *testing.T, prepared json.RawMessage) json.RawMessage
	}{
		// A good grant, then one whose id has the wrong type: encoding/json
		// fills the first before it reports the error.
		{"a damaged second grant", func(t *testing.T, p json.RawMessage) json.RawMessage {
			return append(append(json.RawMessage(nil), p[:len(p)-1]...), []byte(`,{"id":5}]`)...)
		}},
		// Damage inside the grant itself: its id and signature decode, the
		// wrongly typed field stays zero, which could be wider than what the
		// member approved.
		{"a damaged field in the grant", func(t *testing.T, p json.RawMessage) json.RawMessage {
			var gs []map[string]json.RawMessage
			if err := json.Unmarshal(p, &gs); err != nil || len(gs) == 0 {
				t.Fatalf("prepared: %v", err)
			}
			gs[0]["approval"] = json.RawMessage(`5`)
			out, err := json.Marshal(gs)
			if err != nil {
				t.Fatal(err)
			}
			return out
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			sess := appSession(r, t0)
			ag, _ := r.h.Device(agent)
			prepared, err := r.f.PrepareAgentGrants(sess, ag.IK, json.RawMessage(`[{"scope":"profile.get"}]`))
			if err != nil {
				t.Fatal(err)
			}
			damaged := c.damage(t, prepared)
			var probe []*Grant
			if json.Unmarshal(damaged, &probe) == nil || len(probe) == 0 || probe[0] == nil || probe[0].ID == "" {
				t.Fatalf("the damaged value does not exercise a partial decode: %s", damaged)
			}
			r.f.AgentPaired(sess, agent, damaged)
			if n := r.f.count(agent); n != 0 {
				t.Fatalf("%d grants installed from damaged initial grants", n)
			}
			n, told := lastUpdate(t, r, agent)
			if told != 1 || n == 0 || r.f.d.GrantSeq[agent] != n {
				t.Fatalf("damaged pairing: %d updates, grant_seq %d (stored %d)", told, n, r.f.d.GrantSeq[agent])
			}
			msgs := r.h.SentOfType("leash.grant.updated")
			o, err := strictjson.ParseObject(msgs[len(msgs)-1].Body)
			if err != nil {
				t.Fatal(err)
			}
			if gs, _ := o.Array("grants"); len(gs) != 0 {
				t.Fatalf("the agent was told of %d grants, want none", len(gs))
			}
		})
	}
}

// An initial grant whose id is already in use (only damaged state could
// make one) is skipped: it never replaces another agent's grant, which
// keeps its agent and its number.
func TestGrantSeqPairGrantIDTaken(t *testing.T) {
	r := newRig(t)
	sess := appSession(r, t0)
	_, gid := r.issue(t, `{"agent_id":"dev-agent","scope":"profile.get"}`)
	before, _ := lastUpdate(t, r, agent)
	r.h.AddDevice("dev-agent-new", vault.KindAgent)
	nag, _ := r.h.Device("dev-agent-new")
	prepared, err := r.f.PrepareAgentGrants(sess, nag.IK, json.RawMessage(`[{"scope":"connection.list"}]`))
	if err != nil {
		t.Fatal(err)
	}
	var gs []map[string]json.RawMessage
	if err := json.Unmarshal(prepared, &gs); err != nil || len(gs) != 1 {
		t.Fatalf("prepared: %v", err)
	}
	gs[0]["id"], _ = json.Marshal(gid)
	collide, _ := json.Marshal(gs)
	r.f.AgentPaired(sess, "dev-agent-new", collide)
	if g := r.f.d.Grants[gid]; g == nil || g.AgentID != agent || g.Scope != "profile.get" {
		if g == nil {
			t.Fatal("the existing grant is gone")
		}
		t.Fatalf("the existing grant was replaced: agent %s, scope %s", g.AgentID, g.Scope)
	}
	if n := r.f.count("dev-agent-new"); n != 0 {
		t.Fatalf("%d grants installed under a taken id", n)
	}
	if n, _ := lastUpdate(t, r, agent); n != before || r.f.d.GrantSeq[agent] != before {
		t.Fatalf("the other agent's number moved: %d, want %d", n, before)
	}
	// The new agent's pairing still completes, with the empty set.
	if n, told := lastUpdate(t, r, "dev-agent-new"); told != 1 || n <= before {
		t.Fatalf("the new agent: %d updates, grant_seq %d, after %d", told, n, before)
	}

	// A duplicate id within one PairGrants: the first copy is installed,
	// the second skipped.
	r.h.AddDevice("dev-agent-dup", vault.KindAgent)
	dag, _ := r.h.Device("dev-agent-dup")
	two, err := r.f.PrepareAgentGrants(sess, dag.IK, json.RawMessage(`[{"scope":"profile.get"},{"scope":"connection.list"}]`))
	if err != nil {
		t.Fatal(err)
	}
	gs = nil
	if err := json.Unmarshal(two, &gs); err != nil || len(gs) != 2 {
		t.Fatalf("prepared: %v", err)
	}
	gs[1]["id"] = gs[0]["id"]
	dup, _ := json.Marshal(gs)
	r.f.AgentPaired(sess, "dev-agent-dup", dup)
	if n := r.f.count("dev-agent-dup"); n != 1 {
		t.Fatalf("a duplicate id: %d grants installed, want 1", n)
	}
	var firstID string
	_ = json.Unmarshal(gs[0]["id"], &firstID)
	if g := r.f.d.Grants[firstID]; g == nil || g.Scope != "profile.get" {
		t.Fatal("a duplicate id: the first copy was not the one kept")
	}
}
