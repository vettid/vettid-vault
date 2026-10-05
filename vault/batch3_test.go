package vault

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// policyType is a LEASH-like feature: an agent-only type decided by the
// policy (TypeSpec.AgentPolicy), the decision, and the initial grants.
type policyType struct {
	recSink
	decision AgentDecision
	asked    int
	ran      int
	valid    bool
	locked   bool
	paired   map[string]json.RawMessage
	removed  []string
}

func (p *policyType) Types() []TypeSpec {
	return []TypeSpec{{Type: "test.agent", Request: true, From: []string{KindAgent}, AgentPolicy: true}}
}

func (p *policyType) Handle(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) {
	p.ran++
	return json.RawMessage(`{"ran":true}`), nil
}

func (p *policyType) AgentDecision(*Session, string, json.RawMessage) AgentDecision {
	p.asked++
	return p.decision
}

func (p *policyType) PrepareAgentGrants(_ *Session, ik []byte, g json.RawMessage) (json.RawMessage, error) {
	if p.locked {
		return nil, NewError("credential_locked", "")
	}
	if !p.valid || string(g) == `[]` || len(ik) != 32 {
		return nil, errBadRequest
	}
	return json.RawMessage(`["signed"]`), nil
}

func (p *policyType) AgentPaired(_ *Session, id string, g json.RawMessage) {
	if p.paired == nil {
		p.paired = map[string]json.RawMessage{}
	}
	p.paired[id] = g
}

func (p *policyType) DeviceRemoved(_ *Session, id string) { p.removed = append(p.removed, id) }

// §6.8, §10.11: an AgentPolicy type is decided for every agent request,
// even though agents may send it: refuse, allow, refer; a referred request
// runs on approval only while a grant still covers it.
func TestAgentPolicyType(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	pol := &policyType{}
	d.m.addFeature(pol)
	ag := d.addDevice(t, "agent1", KindAgent, 0x70)
	id := d.sendAs(ag, "test.agent", `{}`)
	if r := find(d.inbox(ag)["agent1"], reply(id)); errCode(r) != "session_required" || pol.asked != 0 {
		t.Fatalf("without a session: %+v (asked %d)", r, pol.asked)
	}
	ag.peer.Access = &AccessSession{ID: "s", Expires: time.Now().Add(time.Hour)}
	pol.decision = AgentDeny
	id = d.sendAs(ag, "test.agent", `{}`)
	if r := find(d.inbox(ag)["agent1"], reply(id)); errCode(r) != "forbidden" || pol.ran != 0 {
		t.Fatalf("refused: %+v", r)
	}
	pol.decision = AgentAllow
	id = d.sendAs(ag, "test.agent", `{}`)
	if r := find(d.inbox(ag)["agent1"], reply(id)); r == nil || r.Status != envelope.StatusOK || pol.ran != 1 {
		t.Fatalf("allowed: %+v", r)
	}
	// Referred, then the grant goes away before the app approves.
	pol.decision = AgentAsk
	id = d.sendAs(ag, "test.agent", `{}`)
	ap := find(d.inbox(app, ag)["dev1"], ofType("approval.pending"))
	if ap == nil || bodyStr(t, ap, "type") != "test.agent" {
		t.Fatal("not referred")
	}
	pol.decision = AgentDeny
	d.sendAs(app, "approval.decide", `{"approval_id":"`+bodyStr(t, ap, "approval_id")+`","approve":true}`)
	in := d.inbox(app, ag)
	if r := find(in["agent1"], reply(id)); errCode(r) != "forbidden" || pol.ran != 1 {
		t.Fatalf("approved after revocation: %+v", r)
	}
	if r := find(in["dev1"], ofType("approval.decide")); r != nil {
		t.Fatal("unexpected event")
	}
	// Referred and still covered: executed on approval.
	pol.decision = AgentAsk
	id = d.sendAs(ag, "test.agent", `{}`)
	ap = find(d.inbox(app, ag)["dev1"], ofType("approval.pending"))
	d.sendAs(app, "approval.decide", `{"approval_id":"`+bodyStr(t, ap, "approval_id")+`","approve":true}`)
	if r := find(d.inbox(ag)["agent1"], reply(id)); r == nil || r.Status != envelope.StatusOK || pol.ran != 2 {
		t.Fatalf("approved: %+v", r)
	}
	// Other principals never reach the policy for it.
	asked := pol.asked
	if id := d.sendAs(app, "test.agent", `{}`); errCode(find(d.inbox(app)["dev1"], reply(id))) != "forbidden" || pol.asked != asked {
		t.Fatal("an app's request reached the policy")
	}
	// Unlinking tells DeviceRemovedObserver features (§7.4: grants go).
	d.sendAs(app, "device.unlink", `{"device_id":"agent1"}`)
	if len(pol.removed) != 1 || pol.removed[0] != "agent1" {
		t.Fatalf("removed: %v", pol.removed)
	}
}

// §6.7, §10.3: device.pair.approve{grants} only for agents, validated by
// the grantor, installed when the pairing completes.
func TestPairingGrants(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	pol := &policyType{valid: true}
	d.m.addFeature(pol)
	approve := func(kind string, base byte, grants string) (string, *envelope.Inner) {
		inv := d.invite(t, kind, PairingApprovalTTL)
		n := newNewcomer(t, base)
		n.hsInit(t, d.m, handshake.Purpose(kind), inv.ID, "p"+string(rune('a'+base%20)))
		n.finish(t, d)
		d.inbox(app)
		id := d.sendAs(app, "device.pair.approve", `{"pairing_id":"`+inv.ID+`","grants":`+grants+`}`)
		return inv.ID, find(d.inbox(app)["dev1"], reply(id))
	}
	if _, r := approve(KindDesktop, 0x40, `[{"scope":"x"}]`); errCode(r) != "bad_request" {
		t.Fatalf("grants for a desktop: %+v", r)
	}
	if _, r := approve(KindAgent, 0x44, `[]`); errCode(r) != "bad_request" {
		t.Fatalf("invalid grants: %+v", r)
	}
	pol.locked = true // grants are signed at the approval: the unlock window is needed
	if _, r := approve(KindAgent, 0x46, `[{"scope":"profile.get"}]`); errCode(r) != "credential_locked" {
		t.Fatalf("outside the unlock window: %+v", r)
	}
	pol.locked = false
	_, r := approve(KindAgent, 0x48, `[{"scope":"profile.get"}]`)
	if r == nil || r.Status != envelope.StatusOK {
		t.Fatalf("agent grants: %+v", r)
	}
	// The approval activates the pairing: the grants are installed (after
	// device.paired) and forgotten.
	var p *Peer
	for _, x := range d.m.st.Devices {
		if x.Kind == KindAgent {
			p = x
		}
	}
	if p == nil || p.Access != nil {
		t.Fatalf("agent: %+v", p)
	}
	if string(pol.paired[p.ID]) != `["signed"]` || p.PairGrants != nil {
		t.Fatalf("initial grants not installed: %v", pol.paired)
	}
	// Without a grantor, grants are refused.
	d2 := newDevFixture(t)
	inv := d2.invite(t, KindAgent, PairingApprovalTTL)
	n2 := newNewcomer(t, 0x50)
	n2.hsInit(t, d2.m, handshake.PurposeAgent, inv.ID, "q1")
	n2.finish(t, d2)
	id := d2.sendAs(d2.self(), "device.pair.approve", `{"pairing_id":"`+inv.ID+`","grants":[{"scope":"profile.get"}]}`)
	if r := find(d2.inbox(d2.self())["dev1"], reply(id)); errCode(r) != "bad_request" {
		t.Fatalf("no grantor: %+v", r)
	}
}

// §10.1: PairedDevice sees devices with or without an access session;
// Device only those that may receive now.
func TestPairedDevice(t *testing.T) {
	d := newDevFixture(t)
	d.addDevice(t, "agent1", KindAgent, 0x70)
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	h := managerHost{d.m}
	if _, ok := h.Device("agent1"); ok {
		t.Fatal("an agent without a session is reachable")
	}
	if p, ok := h.PairedDevice("agent1"); !ok || p.Kind != KindAgent {
		t.Fatal("paired agent not found")
	}
	if _, ok := h.PairedDevice("nobody"); ok {
		t.Fatal("unknown device found")
	}
}
