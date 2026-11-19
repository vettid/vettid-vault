package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// referType is an AgentPolicy type whose policy refers each request with a
// previous pin and a note, and whose handler, run on approval, records
// what the session told it and returns what the test sets: an answer, or
// a ReferAgain (VAULT-MESSAGING §10.11, 0.85.3).
type referType struct {
	recSink
	decision AgentDecision
	again    *Approval // returned by the handler while set
	ran      int
	approved []bool
	notes    []string
}

func (p *referType) Types() []TypeSpec {
	return []TypeSpec{{Type: "test.refer", Request: true, From: []string{KindAgent}, AgentPolicy: true}}
}

func (p *referType) AgentDecision(s *Session, _ string, _ json.RawMessage) AgentDecision {
	if p.decision == AgentAsk {
		s.FlagApproval([]string{"program_unrecorded"})
		s.ApprovalPrevious("aa", "/usr/bin/a")
		s.NoteApproval(json.RawMessage(`{"v":1}`))
	}
	return p.decision
}

func (p *referType) Handle(_ context.Context, s *Session, _ *envelope.Inner) (json.RawMessage, error) {
	p.ran++
	p.approved = append(p.approved, s.Approved())
	p.notes = append(p.notes, string(s.HeldNote()))
	if p.again != nil {
		return nil, ReferAgain(*p.again)
	}
	return json.RawMessage(`{"ran":true}`), nil
}

func heldOnly(t *testing.T, d *devFixture) *HeldRequest {
	t.Helper()
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	if len(d.m.st.Held) != 1 {
		t.Fatalf("held: %d", len(d.m.st.Held))
	}
	for _, h := range d.m.st.Held {
		c := *h
		return &c
	}
	return nil
}

// §10.11 (0.85.3): the referral carries the previous pin to the app and
// keeps the note for the handler; on approval the handler sees Approved
// and the note; a ReferAgain holds the same request, byte for byte, under
// a new approval (with the new flags, pin and note) and answers the agent
// nothing; the old approval cannot be decided again; the new one, once
// approved, runs and answers.
func TestReferAgain(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	pol := &referType{decision: AgentAsk}
	d.m.addFeature(pol)
	ag := d.addDevice(t, "agent1", KindAgent, 0x70)
	ag.peer.Access = &AccessSession{ID: "s", Expires: time.Now().Add(time.Hour)}

	id := d.sendAs(ag, "test.refer", `{"x":1}`)
	ap := find(d.inbox(app, ag)["dev1"], ofType("approval.pending"))
	if ap == nil || bodyStr(t, ap, "previous_sha256") != "aa" || bodyStr(t, ap, "previous_path") != "/usr/bin/a" {
		t.Fatalf("approval.pending: %+v", ap)
	}
	if f, _ := flagsOf(t, ap); f != `["program_unrecorded"]` {
		t.Fatalf("flags: %s", f)
	}
	if bytes.Contains(ap.Body, []byte("note")) || bytes.Contains(ap.Body, []byte(`"v"`)) {
		t.Fatalf("the note reached the app: %s", ap.Body)
	}
	first := heldOnly(t, d)
	if string(first.Note) != `{"v":1}` {
		t.Fatalf("note: %s", first.Note)
	}
	raw, _ := json.Marshal(first)
	var back HeldRequest
	if err := json.Unmarshal(raw, &back); err != nil || back.PreviousSHA256 != "aa" || back.PreviousPath != "/usr/bin/a" || string(back.Note) != `{"v":1}` {
		t.Fatalf("not stored: %s", raw)
	}

	// Approved: the handler refers it again.
	pol.again = &Approval{Flags: []string{"program_changed"}, PreviousSHA256: "bb", PreviousPath: "/usr/bin/b", Note: json.RawMessage(`{"v":2}`)}
	oldID := bodyStr(t, ap, "approval_id")
	did := d.sendAs(app, "approval.decide", `{"approval_id":"`+oldID+`","approve":true}`)
	in := d.inbox(app, ag)
	if r := find(in["dev1"], reply(did)); r == nil || bodyStr(t, r, "result") != "referred" {
		t.Fatalf("decide: %+v", r)
	}
	if pol.ran != 1 || !pol.approved[0] || pol.notes[0] != `{"v":1}` {
		t.Fatalf("handler saw approved=%v note=%q", pol.approved, pol.notes)
	}
	if r := find(in["agent1"], reply(id)); r != nil {
		t.Fatalf("answered on a re-referral: %+v", r)
	}
	ap2 := find(in["dev1"], ofType("approval.pending"))
	if ap2 == nil || bodyStr(t, ap2, "approval_id") == oldID || bodyStr(t, ap2, "previous_sha256") != "bb" || bodyStr(t, ap2, "previous_path") != "/usr/bin/b" {
		t.Fatalf("second approval.pending: %+v", ap2)
	}
	if f, _ := flagsOf(t, ap2); f != `["program_changed"]` {
		t.Fatalf("second flags: %s", f)
	}
	if find(in["agent1"], ofType("approval.waiting")) == nil {
		t.Fatal("the agent was not told of the new approval")
	}
	second := heldOnly(t, d)
	if !bytes.Equal(second.Inner, first.Inner) || second.Key != first.Key || second.DeviceID != first.DeviceID || string(second.Note) != `{"v":2}` {
		t.Fatalf("re-held request differs: %+v vs %+v", second, first)
	}

	// The old approval is gone.
	did = d.sendAs(app, "approval.decide", `{"approval_id":"`+oldID+`","approve":true}`)
	if r := find(d.inbox(app)["dev1"], reply(did)); errCode(r) != "not_found" || pol.ran != 1 {
		t.Fatalf("old approval decided again: %+v (ran %d)", r, pol.ran)
	}

	// The new one runs and answers.
	pol.again = nil
	did = d.sendAs(app, "approval.decide", `{"approval_id":"`+bodyStr(t, ap2, "approval_id")+`","approve":true}`)
	in = d.inbox(app, ag)
	if r := find(in["dev1"], reply(did)); r == nil || bodyStr(t, r, "result") != "ok" {
		t.Fatalf("second decide: %+v", r)
	}
	if r := find(in["agent1"], reply(id)); r == nil || r.Status != envelope.StatusOK || pol.notes[1] != `{"v":2}` {
		t.Fatalf("not answered: %+v (notes %q)", r, pol.notes)
	}
}

// A request allowed at once runs with Approved false and no note; a
// ReferAgain there is answered internal and holds nothing; a denied
// re-referral is answered denied.
func TestReferAgainOnlyOnApproval(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	pol := &referType{decision: AgentAllow, again: &Approval{Flags: []string{"shell"}}}
	d.m.addFeature(pol)
	ag := d.addDevice(t, "agent1", KindAgent, 0x70)
	ag.peer.Access = &AccessSession{ID: "s", Expires: time.Now().Add(time.Hour)}

	id := d.sendAs(ag, "test.refer", `{}`)
	in := d.inbox(app, ag)
	if r := find(in["agent1"], reply(id)); errCode(r) != "internal" || pol.approved[0] || pol.notes[0] != "" {
		t.Fatalf("allowed request: %+v approved=%v note=%q", r, pol.approved, pol.notes)
	}
	if find(in["dev1"], ofType("approval.pending")) != nil {
		t.Fatal("held without a referral")
	}
	d.m.mu.Lock()
	n := len(d.m.st.Held)
	d.m.mu.Unlock()
	if n != 0 {
		t.Fatal("held")
	}

	// Referred, re-referred, then denied.
	pol.decision = AgentAsk
	id = d.sendAs(ag, "test.refer", `{}`)
	ap := find(d.inbox(app, ag)["dev1"], ofType("approval.pending"))
	d.sendAs(app, "approval.decide", `{"approval_id":"`+bodyStr(t, ap, "approval_id")+`","approve":true}`)
	ap2 := find(d.inbox(app, ag)["dev1"], ofType("approval.pending"))
	if ap2 == nil {
		t.Fatal("not referred again")
	}
	did := d.sendAs(app, "approval.decide", `{"approval_id":"`+bodyStr(t, ap2, "approval_id")+`","approve":false}`)
	in = d.inbox(app, ag)
	if r := find(in["dev1"], reply(did)); r == nil || bodyStr(t, r, "result") != "denied" {
		t.Fatalf("deny: %+v", r)
	}
	if r := find(in["agent1"], reply(id)); errCode(r) != "denied" {
		t.Fatalf("agent: %+v", r)
	}
}
