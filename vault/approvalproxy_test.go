package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// proxyRefer is an AgentPolicy type that refers each request with the
// proxy values it is given (approval.pending{proxy}, §10.11, 0.92.0), and
// whose handler, run on approval, refers it again with again's values
// while set.
type proxyRefer struct {
	recSink
	proxy *ApprovalProxy
	again *ApprovalProxy
}

func (p *proxyRefer) Types() []TypeSpec {
	return []TypeSpec{{Type: "test.proxy", Request: true, From: []string{KindAgent}, AgentPolicy: true}}
}

func (p *proxyRefer) AgentDecision(s *Session, _ string, _ json.RawMessage) AgentDecision {
	s.NoteApproval(json.RawMessage(`{"n":1}`))
	if p.proxy != nil {
		s.ProxyApproval(*p.proxy)
	}
	return AgentAsk
}

func (p *proxyRefer) Handle(_ context.Context, _ *Session, _ *envelope.Inner) (json.RawMessage, error) {
	if p.again != nil {
		return nil, ReferAgain(Approval{Note: json.RawMessage(`{"n":2}`), Proxy: p.again})
	}
	return json.RawMessage(`{"ran":true}`), nil
}

// pendingListBodies returns the bodies of the approvals pending.list lists.
func pendingListBodies(t *testing.T, d *devFixture, app *tdev) []json.RawMessage {
	t.Helper()
	id := d.sendAs(app, "pending.list", `{}`)
	pl := find(d.inbox(app)["dev1"], reply(id))
	if pl == nil || pl.Status != envelope.StatusOK {
		t.Fatalf("pending.list: %+v", pl)
	}
	var list struct {
		Asks []struct {
			Body json.RawMessage `json:"body"`
		} `json:"asks"`
	}
	if err := json.Unmarshal(pl.Body, &list); err != nil {
		t.Fatalf("%s: %v", pl.Body, err)
	}
	var out []json.RawMessage
	for _, a := range list.Asks {
		out = append(out, a.Body)
	}
	return out
}

// §6.8, §10.11 (0.92.0): an item.proxy's approval carries proxy {host,
// header, prefix}, the prefix present when empty, in approval.pending and
// its pending.list entry, and stored with the held request (its JSON round
// trip, which is what the state saves); a referral again
// carries the new values; the note is still never sent.
func TestApprovalProxy(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	pol := &proxyRefer{proxy: &ApprovalProxy{Host: "api.example.com:443", Header: "Authorization", Prefix: ""}}
	d.m.addFeature(pol)
	sinkOf(d)
	ag := d.addDevice(t, "agent1", KindAgent, 0x70)
	ag.peer.Access = &AccessSession{ID: "s", Expires: time.Now().Add(time.Hour)}

	d.sendAs(ag, "test.proxy", `{"x":1}`)
	ap := find(d.inbox(app, ag)["dev1"], ofType("approval.pending"))
	const want = `"proxy":{"host":"api.example.com:443","header":"Authorization","prefix":""}`
	if ap == nil || !bytes.Contains(ap.Body, []byte(want)) {
		t.Fatalf("approval.pending: %+v", ap)
	}
	if bytes.Contains(ap.Body, []byte(`"n"`)) {
		t.Fatalf("the note reached the app: %s", ap.Body)
	}
	raw, _ := json.Marshal(heldOnly(t, d))
	var back HeldRequest
	if err := json.Unmarshal(raw, &back); err != nil || back.Proxy == nil || *back.Proxy != *pol.proxy {
		t.Fatalf("not stored: %s", raw)
	}
	if l := pendingListBodies(t, d, app); len(l) != 1 || !bytes.Contains(l[0], []byte(want)) {
		t.Fatalf("pending.list: %s", l)
	}

	// Approved, the handler refers it again with the item's new values.
	pol.again = &ApprovalProxy{Host: "api.example.com", Header: "X-Api-Key", Prefix: "Key "}
	d.sendAs(app, "approval.decide", `{"approval_id":"`+bodyStr(t, ap, "approval_id")+`","approve":true}`)
	ap2 := find(d.inbox(app, ag)["dev1"], ofType("approval.pending"))
	const want2 = `"proxy":{"host":"api.example.com","header":"X-Api-Key","prefix":"Key "}`
	if ap2 == nil || !bytes.Contains(ap2.Body, []byte(want2)) {
		t.Fatalf("second approval.pending: %+v", ap2)
	}
	if l := pendingListBodies(t, d, app); len(l) != 1 || !bytes.Contains(l[0], []byte(want2)) {
		t.Fatalf("second pending.list: %s", l)
	}
}

// §10.11 (0.92.0): no other approval carries proxy.
func TestApprovalWithoutProxy(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	d.m.addFeature(&proxyRefer{})
	sinkOf(d)
	ag := d.addDevice(t, "agent1", KindAgent, 0x70)
	ag.peer.Access = &AccessSession{ID: "s", Expires: time.Now().Add(time.Hour)}
	d.sendAs(ag, "test.proxy", `{"x":1}`)
	ap := find(d.inbox(app, ag)["dev1"], ofType("approval.pending"))
	if ap == nil || bytes.Contains(ap.Body, []byte(`"proxy"`)) {
		t.Fatalf("approval.pending: %+v", ap)
	}
	if l := pendingListBodies(t, d, app); len(l) != 1 || bytes.Contains(l[0], []byte(`"proxy"`)) {
		t.Fatalf("pending.list: %s", l)
	}
}
