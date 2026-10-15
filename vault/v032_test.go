package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// bigFeature answers with a body of the size its request names: test.big
// is cached like any answer, test.bigv is volatile and a desktop's
// test.bigv is held for an app's approval.
type bigFeature struct {
	recSink
	calls int
}

func (f *bigFeature) Types() []TypeSpec {
	return []TypeSpec{
		{Type: "test.big", Request: true, From: []string{KindApp}},
		{Type: "test.bigv", Request: true, Volatile: true, From: []string{KindApp, KindDesktop}, DesktopApproval: true},
	}
}

func (f *bigFeature) Handle(_ context.Context, _ *Session, in *envelope.Inner) (json.RawMessage, error) {
	f.calls++
	var r struct{ N int }
	_ = json.Unmarshal(in.Body, &r)
	return json.RawMessage(`{"v":"` + strings.Repeat("a", r.N) + `"}`), nil
}

// sendID sends a request with a given inner id (a retransmission).
func (d *devFixture) sendID(td *tdev, id, typ, body string) {
	d.seq++
	raw, err := td.ep.Seal(&envelope.Inner{ID: id, Type: typ, TS: time.Now(), Body: []byte(body)})
	if err != nil {
		panic(err)
	}
	msg := Message{MsgID: fmt.Sprintf("x%d", d.seq), Sender: relayauth.EncodeKey(td.peer.Relay.PK), Payload: raw}
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg})
}

func (d *devFixture) cached(id string) bool {
	for k := range d.m.st.Responses {
		if strings.HasSuffix(k, "|"+id) {
			return true
		}
	}
	return false
}

// §8.1 (0.32.0): a response that cannot be sealed within §5.5's bound is
// answered response_too_large, never silence; the error is cached like any
// answer, so a retransmission gets it again without re-execution. A
// response just within the bound is sent as it is.
func TestResponseTooLarge(t *testing.T) {
	d := newDevFixture(t)
	f := &bigFeature{}
	d.m.addFeature(f)
	app := d.self()
	id := d.sendAs(app, "test.big", `{"n":250000}`)
	r := find(d.inbox(app)["dev1"], reply(id))
	if errCode(r) != ErrResponseTooLarge || r.Type != "test.big" || len(r.Body) > 2 || !d.cached(id) {
		t.Fatalf("oversized answer: %+v", r)
	}
	if c := string(d.m.st.Responses["dev1|"+id].Inner); strings.Contains(c, "aaaa") || len(c) > 1024 {
		t.Fatalf("cached the oversized body: %d bytes", len(c))
	}
	d.sendID(app, id, "test.big", `{"n":250000}`)
	if r := find(d.inbox(app)["dev1"], reply(id)); errCode(r) != ErrResponseTooLarge || f.calls != 1 {
		t.Fatalf("retransmission: %+v (calls %d)", r, f.calls)
	}
	// Just within the bound: about 245,000 bytes of body are sent.
	id = d.sendAs(app, "test.big", `{"n":245000}`)
	if r := find(d.inbox(app)["dev1"], reply(id)); r == nil || r.Status != envelope.StatusOK || len(r.Body) < 245000 {
		t.Fatalf("answer within the bound: %+v", errCode(r))
	}
	// Every response path: a volatile answer too (not cached, §8.2).
	id = d.sendAs(app, "test.bigv", `{"n":250000}`)
	if r := find(d.inbox(app)["dev1"], reply(id)); errCode(r) != ErrResponseTooLarge || d.cached(id) {
		t.Fatalf("oversized volatile answer: %+v", r)
	}
	if len(d.m.st.Outbox) != 0 && !allDone(d.m.st.Outbox) {
		t.Fatal("volatile answer in the outbox")
	}
}

func allDone(es []*OutboxEntry) bool {
	for _, e := range es {
		if !e.Done {
			return false
		}
	}
	return true
}

// §8.2 (0.32.0): a volatile request held for an app's approval (a
// desktop's step-up, an agent's referral) is kept; a retransmission while
// it waits is a duplicate; approved, it is answered volatile, not cached,
// and a later retransmission is executed again. An agent whose grant
// covers a volatile type gets a volatile answer too.
func TestVolatileHeldAndAgents(t *testing.T) {
	f := newOCFixture(t)
	big := &bigFeature{}
	f.m.addFeature(big)
	id := f.sendAs(f.desk, "test.bigv", `{"n":10}`)
	ap := find(f.inbox(f.app, f.desk)["dev1"], ofType("approval.pending"))
	if ap == nil || len(f.m.st.Held) != 1 || big.calls != 0 {
		t.Fatalf("not held: %d", len(f.m.st.Held))
	}
	f.sendID(f.desk, id, "test.bigv", `{"n":10}`)
	if len(f.m.st.Held) != 1 {
		t.Fatalf("retransmission held again: %d", len(f.m.st.Held))
	}
	f.sendAs(f.app, "approval.decide", `{"approval_id":"`+bodyStr(t, ap, "approval_id")+`","approve":true}`)
	if r := find(f.inbox(f.app, f.desk)["desk1"], reply(id)); r == nil || r.Status != envelope.StatusOK || big.calls != 1 {
		t.Fatalf("approved: %+v", r)
	}
	if f.cached(id) {
		t.Fatal("approved volatile answer cached")
	}
	f.sendID(f.desk, id, "test.bigv", `{"n":10}`)
	if len(f.m.st.Held) != 1 {
		t.Fatal("retransmission after the answer not executed again (held for approval)")
	}

	// An agent: allowed by its policy, answered volatile; referred, held.
	pol := &policyType{decision: AgentAllow}
	f.m.addFeature(pol)
	id = f.sendAs(f.agent, "test.bigv", `{"n":10}`)
	if r := find(f.inbox(f.agent)["agent1"], reply(id)); r == nil || r.Status != envelope.StatusOK || f.cached(id) {
		t.Fatalf("agent's volatile answer: %+v cached %v", r, f.cached(id))
	}
	calls := big.calls
	f.sendID(f.agent, id, "test.bigv", `{"n":10}`)
	if r := find(f.inbox(f.agent)["agent1"], reply(id)); r == nil || big.calls != calls+1 {
		t.Fatal("agent's retransmission not executed again")
	}
	pol.decision = AgentAsk
	id = f.sendAs(f.agent, "test.bigv", `{"n":10}`)
	ap = find(f.inbox(f.app, f.agent)["dev1"], ofType("approval.pending"))
	if ap == nil {
		t.Fatal("agent's referral not held")
	}
	f.sendAs(f.app, "approval.decide", `{"approval_id":"`+bodyStr(t, ap, "approval_id")+`","approve":true}`)
	if r := find(f.inbox(f.app, f.agent)["agent1"], reply(id)); r == nil || r.Status != envelope.StatusOK || f.cached(id) {
		t.Fatalf("agent's approved answer: %+v", r)
	}
}
