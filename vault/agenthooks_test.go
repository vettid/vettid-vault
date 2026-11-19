package vault

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/strictjson"
)

// hookPolicy is a LEASH stand-in that names its refusal error and its
// approval flags (VAULT-MESSAGING §10.11, 0.42.0).
type hookPolicy struct {
	recSink
	decide  map[string]AgentDecision
	refusal error
	flags   []string
}

func (h *hookPolicy) AgentDecision(s *Session, typ string, _ json.RawMessage) AgentDecision {
	if h.refusal != nil {
		s.RefuseAgentWith(h.refusal)
	}
	if h.flags != nil {
		s.FlagApproval(h.flags)
	}
	return h.decide[typ]
}

func flagsOf(t *testing.T, in *envelope.Inner) (string, bool) {
	t.Helper()
	o, err := strictjson.ParseObject(in.Body)
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := o["flags"]
	return string(raw), ok
}

// §10.11 (0.42.0): a refusal the policy names is answered with its code and
// body instead of forbidden; a refusal it does not name stays forbidden; a
// name set alongside another decision changes nothing.
func TestAgentRefusalNamed(t *testing.T) {
	d := newDevFixture(t)
	ag := d.addDevice(t, "agent1", KindAgent, 0x70)
	ag.peer.Access = &AccessSession{ID: "s", Expires: time.Now().Add(time.Hour)}
	pol := &hookPolicy{decide: map[string]AgentDecision{"settings.get": AgentDeny, "settings.list": AgentAllow},
		refusal: &HandlerError{Code: "way_not_allowed", Body: json.RawMessage(`{"ways":["use"]}`)}}
	d.m.addFeature(pol)
	id := d.sendAs(ag, "settings.get", `{}`)
	r := find(d.inbox(ag)["agent1"], reply(id))
	if errCode(r) != "way_not_allowed" || string(r.Body) != `{"ways":["use"]}` {
		t.Fatalf("named refusal: %+v", r)
	}
	// Not a HandlerError: ignored, the answer stays forbidden.
	pol.refusal = json.Unmarshal([]byte("x"), &struct{}{})
	id = d.sendAs(ag, "settings.get", `{}`)
	if r := find(d.inbox(ag)["agent1"], reply(id)); errCode(r) != "forbidden" {
		t.Fatalf("unnamed refusal: %+v", r)
	}
	pol.refusal = nil
	id = d.sendAs(ag, "settings.get", `{}`)
	if r := find(d.inbox(ag)["agent1"], reply(id)); errCode(r) != "forbidden" {
		t.Fatalf("plain refusal: %+v", r)
	}
	// A name with an allow decision: the request runs.
	pol.refusal = &HandlerError{Code: "way_not_allowed"}
	pol.decide["settings.get"] = AgentAllow
	id = d.sendAs(ag, "settings.get", `{}`)
	if r := find(d.inbox(ag)["agent1"], reply(id)); r == nil || r.Status != envelope.StatusOK {
		t.Fatalf("allowed request: %+v", r)
	}
}

// §10.11 (0.42.0): a referral's flags are carried by approval.pending and
// pending.list, and survive a reload; without flags there is no member;
// flags set alongside a refusal hold nothing.
func TestAgentApprovalFlags(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	ag := d.addDevice(t, "agent1", KindAgent, 0x70)
	ag.peer.Access = &AccessSession{ID: "s", Expires: time.Now().Add(time.Hour)}
	pol := &hookPolicy{decide: map[string]AgentDecision{"settings.set": AgentAsk}, flags: []string{"history"}}
	d.m.addFeature(pol)
	d.sendAs(ag, "settings.set", `{"version":0,"set":{"app.x":"1"}}`)
	ap := find(d.inbox(app, ag)["dev1"], ofType("approval.pending"))
	if ap == nil {
		t.Fatal("not referred")
	}
	if f, ok := flagsOf(t, ap); !ok || f != `["history"]` {
		t.Fatalf("approval.pending flags: %q %v", f, ok)
	}
	d.m.mu.Lock()
	var held *HeldRequest
	for _, h := range d.m.st.Held {
		held = h
	}
	raw, err := json.Marshal(held)
	d.m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var back HeldRequest
	if err := json.Unmarshal(raw, &back); err != nil || len(back.Flags) != 1 || back.Flags[0] != "history" {
		t.Fatalf("flags not stored: %s", raw)
	}
	id := d.sendAs(app, "pending.list", `{}`)
	pl := find(d.inbox(app)["dev1"], reply(id))
	if pl == nil || pl.Status != envelope.StatusOK {
		t.Fatalf("pending.list: %+v", pl)
	}
	var list struct {
		Items []struct {
			Kind string          `json:"kind"`
			Body json.RawMessage `json:"body"`
		} `json:"asks"`
	}
	if err := json.Unmarshal(pl.Body, &list); err != nil {
		t.Fatalf("%s: %v", pl.Body, err)
	}
	found := false
	for _, it := range list.Items {
		var b struct {
			Flags []string `json:"flags"`
		}
		if json.Unmarshal(it.Body, &b) == nil && len(b.Flags) == 1 && b.Flags[0] == "history" {
			found = true
		}
	}
	if !found {
		t.Fatalf("pending.list lacks the flags: %s", pl.Body)
	}
	// Without flags: no member.
	pol.flags = nil
	d.sendAs(ag, "settings.set", `{"version":0,"set":{"app.y":"1"}}`)
	ap = find(d.inbox(app, ag)["dev1"], ofType("approval.pending"))
	if ap == nil {
		t.Fatal("second not referred")
	}
	if f, ok := flagsOf(t, ap); ok {
		t.Fatalf("flags without any: %s", f)
	}
	// Flags with a refusal: nothing held.
	pol.flags = []string{"history"}
	pol.decide["settings.set"] = AgentDeny
	d.m.mu.Lock()
	n := len(d.m.st.Held)
	d.m.mu.Unlock()
	id = d.sendAs(ag, "settings.set", `{"version":0,"set":{"app.z":"1"}}`)
	in := d.inbox(app, ag)
	if r := find(in["agent1"], reply(id)); errCode(r) != "forbidden" || find(in["dev1"], ofType("approval.pending")) != nil {
		t.Fatalf("refused request held: %+v", r)
	}
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	if len(d.m.st.Held) != n {
		t.Fatal("refused request held")
	}
}

// Flags, the previous pin and the note are an agent request's only: a
// desktop's held step-up request never carries any, whatever is passed.
func TestApprovalFlagsAgentsOnly(t *testing.T) {
	d := newDevFixture(t)
	desk := d.addDevice(t, "desk1", KindDesktop, 0x72)
	rid, _ := envelope.NewULID(time.Now())
	d.m.mu.Lock()
	d.m.hold(desk.peer, &envelope.Inner{ID: rid, Type: "settings.set", TS: time.Now(), Body: []byte(`{}`)},
		"desk1/"+rid, false, Approval{Flags: []string{"history"}, PreviousSHA256: "ab", PreviousPath: "/x", Note: json.RawMessage(`{"v":1}`)}, time.Now())
	var held *HeldRequest
	for _, h := range d.m.st.Held {
		held = h
	}
	d.m.mu.Unlock()
	if held == nil || held.Flags != nil || held.PreviousSHA256 != "" || held.PreviousPath != "" || held.Note != nil {
		t.Fatalf("desktop hold: %+v", held)
	}
	if body := approvalPendingBody(held, desk.peer, &envelope.Inner{Type: "settings.set", Body: []byte(`{}`)}); strings.Contains(string(body), "flags") || strings.Contains(string(body), "previous") {
		t.Fatalf("desktop approval.pending: %s", body)
	}
}
