package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/internal/strictjson"
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

// §8.2: no answer to a volatile request is cached, errors included. A
// request refused once and then held under the same id (an agent's policy
// changed from deny to ask) is never answered from a cache: one answer
// while it waits would contradict the answer after the approval.
func TestVolatileErrorsNotCached(t *testing.T) {
	f := newOCFixture(t)
	big := &bigFeature{}
	f.m.addFeature(big)
	pol := &policyType{decision: AgentDeny}
	f.m.addFeature(pol)
	id := f.sendAs(f.agent, "test.bigv", `{"n":10}`)
	if r := find(f.inbox(f.agent)["agent1"], reply(id)); errCode(r) != "forbidden" || f.cached(id) {
		t.Fatalf("refused: %+v cached %v", r, f.cached(id))
	}
	if _, seen := f.m.st.SeenInner["agent1|"+id]; seen {
		t.Fatal("refused volatile request remembered")
	}
	pol.decision = AgentAsk
	f.sendID(f.agent, id, "test.bigv", `{"n":10}`)
	in := f.inbox(f.app, f.agent)
	ap := find(in["dev1"], ofType("approval.pending"))
	if ap == nil || find(in["agent1"], reply(id)) != nil {
		t.Fatal("retransmission not held, or answered")
	}
	f.sendID(f.agent, id, "test.bigv", `{"n":10}`)
	if r := find(f.inbox(f.agent)["agent1"], reply(id)); r != nil || len(f.m.st.Held) != 1 {
		t.Fatalf("retransmission while held answered: %+v", r)
	}
	f.sendAs(f.app, "approval.decide", `{"approval_id":"`+bodyStr(t, ap, "approval_id")+`","approve":true}`)
	var answers []*envelope.Inner
	for _, r := range f.inbox(f.app, f.agent)["agent1"] {
		if r.Re == id {
			answers = append(answers, r)
		}
	}
	if len(answers) != 1 || answers[0].Status != envelope.StatusOK || f.cached(id) {
		t.Fatalf("answers after approval: %d", len(answers))
	}

	// Denied: answered denied, not cached, the id forgotten, so a
	// retransmission is executed again (held again).
	id = f.sendAs(f.agent, "test.bigv", `{"n":10}`)
	ap = find(f.inbox(f.app, f.agent)["dev1"], ofType("approval.pending"))
	f.sendAs(f.app, "approval.decide", `{"approval_id":"`+bodyStr(t, ap, "approval_id")+`","approve":false}`)
	if r := find(f.inbox(f.app, f.agent)["agent1"], reply(id)); errCode(r) != "denied" || f.cached(id) {
		t.Fatalf("denied: %+v cached %v", r, f.cached(id))
	}
	f.sendID(f.agent, id, "test.bigv", `{"n":10}`)
	if ap = find(f.inbox(f.app, f.agent)["dev1"], ofType("approval.pending")); ap == nil {
		t.Fatal("retransmission after a denial not executed again")
	}

	// Timed out: approval_timeout, not cached, the id forgotten.
	for _, h := range f.m.st.Held {
		h.Expires = time.Now().Add(-time.Second)
	}
	f.sendAs(f.app, "vault.status", `{}`) // housekeeping runs before the batch
	if r := find(f.inbox(f.app, f.agent)["agent1"], reply(id)); errCode(r) != "approval_timeout" || f.cached(id) {
		t.Fatalf("timed out: %+v cached %v", r, f.cached(id))
	}
	if _, seen := f.m.st.SeenInner["agent1|"+id]; seen || len(f.m.st.Held) != 0 {
		t.Fatal("timed-out volatile request remembered")
	}

	// The held-approvals limit: answered, not cached, not remembered.
	pol.decision = AgentAllow
	for range MaxHeldPerDevice {
		f.sendAs(f.desk, "test.bigv", `{"n":10}`)
	}
	f.inbox(f.app, f.desk)
	id = f.sendAs(f.desk, "test.bigv", `{"n":10}`)
	if r := find(f.inbox(f.desk)["desk1"], reply(id)); errCode(r) != "limit" || f.cached(id) {
		t.Fatalf("limit: %+v cached %v", r, f.cached(id))
	}
	if _, seen := f.m.st.SeenInner["desk1|"+id]; seen {
		t.Fatal("volatile request refused by the limit remembered")
	}
}

// §8.1: a response cached by a release before 0.32.0 that cannot be sealed
// (a message.list page of that release, cached for 24 hours) is answered
// response_too_large when the request is retransmitted, not dropped again.
func TestResendCachedTooLarge(t *testing.T) {
	d := newDevFixture(t)
	big := &bigFeature{}
	d.m.addFeature(big)
	app := d.self()
	id, _ := envelope.NewULID(time.Now())
	rid, _ := envelope.NewULID(time.Now())
	old := &envelope.Inner{ID: rid, TS: time.Now(), Type: "test.bigv", Re: id, Status: envelope.StatusOK,
		Body: json.RawMessage(`{"v":"` + strings.Repeat("a", 300000) + `"}`)}
	raw, err := old.Marshal(envelope.ModeSealed)
	if err != nil {
		t.Fatal(err)
	}
	key := "dev1|" + id
	d.withLock(func(m *Manager) {
		m.st.SeenInner[key] = time.Now()
		m.st.Responses[key] = CachedResponse{Inner: raw, Expires: time.Now().Add(ResponseRetention)}
	})
	d.sendID(app, id, "test.bigv", `{"n":10}`)
	if r := find(d.inbox(app)["dev1"], reply(id)); errCode(r) != ErrResponseTooLarge || big.calls != 0 {
		t.Fatalf("old cached answer: %+v (calls %d)", r, big.calls)
	}
}

// §8.1: the bound is checked with the widest seq, so that a response
// that fits now also fits when sealed again for a retransmission later in
// the epoch: one that would fit at seq 1 but not at the largest seq is
// answered response_too_large.
func TestResponseTooLargeAtMaxSeq(t *testing.T) {
	d := newDevFixture(t)
	big := &bigFeature{}
	d.m.addFeature(big)
	app := d.self()
	// The largest body that fits at seq 1, with ids and ts of their fixed
	// lengths, as the vault builds the answer.
	id, _ := envelope.NewULID(time.Now())
	size := func(n int, seq uint64) int {
		in := &envelope.Inner{ID: id, TS: time.Now(), Seq: seq, Type: "test.big", Re: id, Status: envelope.StatusOK,
			Body: json.RawMessage(`{"v":"` + strings.Repeat("a", n) + `"}`)}
		j, err := in.Marshal(envelope.ModeSession)
		if err != nil {
			t.Fatal(err)
		}
		return len(j)
	}
	fits1 := func(n int) bool { _, err := envelope.PaddedLen(size(n, 1)); return err == nil }
	lo, hi := 200000, envelope.MaxPadded // fits1(lo), !fits1(hi)
	for hi-lo > 1 {
		if mid := (lo + hi) / 2; fits1(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	n := lo
	if _, err := envelope.PaddedLen(size(n, 1)); err != nil {
		t.Fatal("search")
	}
	if _, err := envelope.PaddedLen(size(n, strictjson.MaxSafeInteger)); err == nil {
		t.Fatal("fits at the largest seq too")
	}
	rid := d.sendAs(app, "test.big", `{"n":`+fmt.Sprint(n)+`}`)
	if r := find(d.inbox(app)["dev1"], reply(rid)); errCode(r) != ErrResponseTooLarge {
		t.Fatalf("fits at seq 1 only: %+v", errCode(r))
	}
	// 16 bytes fewer fit at every seq.
	rid = d.sendAs(app, "test.big", `{"n":`+fmt.Sprint(n-16)+`}`)
	if r := find(d.inbox(app)["dev1"], reply(rid)); r == nil || r.Status != envelope.StatusOK {
		t.Fatalf("fits at every seq: %+v", errCode(r))
	}
}
