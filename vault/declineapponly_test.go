package vault

import (
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// accessed adds a desktop and an agent with an access session to d.
func accessed(t *testing.T, d *devFixture) (desk, ag *tdev) {
	t.Helper()
	desk = d.addDevice(t, "desk1", KindDesktop, 0x71)
	ag = d.addDevice(t, "agent1", KindAgent, 0x72)
	for _, td := range []*tdev{desk, ag} {
		td.peer.Access = &AccessSession{ID: "s-" + td.peer.ID, Expires: time.Now().Add(time.Hour)}
	}
	return desk, ag
}

// (0.95.0, §6.4 "Who approves", §10.4 Block list) Declining a connection
// request, incoming or the member's own outgoing one, is the app's alone,
// and so are the forms of block.add and connection.remove that decline or
// withdraw one: a desktop's or an agent's is answered forbidden at once,
// never held, never put to an agent's policy, and changes nothing. The app
// declines as before.
func TestDeclinesAreAppOnly(t *testing.T) {
	a, b, pid, cid := requested(t)
	// A policy that would allow anything an agent asks: app-only forms
	// never reach it.
	polA, polB := &policyType{decision: AgentAllow}, &policyType{decision: AgentAllow}
	a.m.addFeature(polA)
	b.m.addFeature(polB)
	deskA, agA := accessed(t, a)
	deskB, agB := accessed(t, b)
	a.inbox(a.self(), deskA, agA)
	b.inbox(b.self(), deskB, agB)

	for _, c := range []struct {
		d         *devFixture
		devs      []*tdev
		typ, body string
	}{
		// a holds the incoming request pid.
		{a, []*tdev{deskA, agA}, "connection.decline", `{"pending_id":"` + pid + `"}`},
		{a, []*tdev{deskA, agA}, "block.add", `{"pending_id":"` + pid + `"}`},
		// b holds its own outgoing request cid, not yet a connection.
		{b, []*tdev{deskB, agB}, "connection.decline", `{"connection_id":"` + cid + `"}`},
		{b, []*tdev{deskB, agB}, "block.add", `{"connection_id":"` + cid + `"}`},
		{b, []*tdev{deskB, agB}, "connection.remove", `{"connection_id":"` + cid + `"}`},
	} {
		for _, td := range c.devs {
			id := c.d.sendAs(td, c.typ, c.body)
			in := c.d.inbox(c.d.self(), td)
			if r := find(in[td.peer.ID], reply(id)); errCode(r) != "forbidden" {
				t.Errorf("%s %s %s: %+v", td.peer.Kind, c.typ, c.body, r)
			}
			if find(in["dev1"], ofType("approval.pending")) != nil || len(c.d.m.st.Held) != 0 {
				t.Errorf("%s %s was held for an app", td.peer.Kind, c.typ)
			}
		}
	}
	if polA.asked != 0 || polB.asked != 0 {
		t.Error("an app-only form reached the agent policy")
	}
	if a.m.st.Requests[pid] == nil || len(a.m.st.Blocks) != 0 {
		t.Fatal("a refused decline or block changed the incoming request")
	}
	if r, waiting := b.m.connRequest(cid, ReqOut); r == nil && !waiting || len(b.m.st.Blocks) != 0 {
		t.Fatal("a refused withdrawal changed the outgoing request")
	}

	// The app declines both.
	id := a.sendAs(a.self(), "connection.decline", `{"pending_id":"`+pid+`"}`)
	if r := find(a.inbox(a.self())["dev1"], reply(id)); r == nil || r.Status != envelope.StatusOK || a.m.st.Requests[pid] != nil {
		t.Fatalf("app decline: %+v", r)
	}
	id = b.sendAs(b.self(), "connection.decline", `{"connection_id":"`+cid+`"}`)
	if r := find(b.inbox(b.self())["dev1"], reply(id)); r == nil || r.Status != envelope.StatusOK {
		t.Fatalf("app withdrawal: %+v", r)
	}
	if r, waiting := b.m.connRequest(cid, ReqOut); r != nil || waiting {
		t.Fatal("the app's withdrawal left the outgoing request")
	}
}

// On an active connection, block.add{connection_id} and connection.remove
// are as before: a desktop's connection.remove is held for an app (step-up),
// and nothing is refused as app-only.
func TestActiveConnectionRemoveUnchanged(t *testing.T) {
	_, b := firstContact(t, connected)
	desk, _ := accessed(t, b)
	b.inbox(b.self(), desk)
	var cid string
	for id := range b.m.st.Connections {
		cid = id
	}
	if cid == "" {
		t.Fatal("no connection")
	}
	b.m.mu.Lock()
	appOnly := b.m.appOnlyCore("connection.remove", []byte(`{"connection_id":"`+cid+`"}`)) ||
		b.m.appOnlyCore("block.add", []byte(`{"connection_id":"`+cid+`"}`))
	b.m.mu.Unlock()
	if appOnly {
		t.Fatal("an active connection's remove or block judged app-only")
	}
	id := b.sendAs(desk, "connection.remove", `{"connection_id":"`+cid+`"}`)
	in := b.inbox(b.self(), desk)
	if find(in["dev1"], ofType("approval.pending")) == nil || errCode(find(in["desk1"], reply(id))) == "forbidden" {
		t.Fatalf("desktop remove of an active connection: not held as before: %+v", find(in["desk1"], reply(id)))
	}
}

// An outgoing request still waiting (accepted, before the inviter's
// hs.resp): its withdrawal is the app's too.
func TestWaitingWithdrawalIsAppOnly(t *testing.T) {
	a, b := newVaultPair(t)
	_, link := a.linkFor(t, time.Hour)
	r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
	cid := bodyStr(t, r, "connection_id")
	if r, waiting := b.m.connRequest(cid, ReqOut); r != nil || !waiting {
		t.Fatal("not a waiting outgoing request")
	}
	desk, ag := accessed(t, b)
	b.inbox(b.self(), desk, ag)
	for _, td := range []*tdev{desk, ag} {
		for _, typ := range []string{"connection.remove", "block.add", "connection.decline"} {
			id := b.sendAs(td, typ, `{"connection_id":"`+cid+`"}`)
			in := b.inbox(b.self(), td)
			if errCode(find(in[td.peer.ID], reply(id))) != "forbidden" || len(b.m.st.Held) != 0 {
				t.Errorf("%s %s of a waiting request: %+v", td.peer.Kind, typ, find(in[td.peer.ID], reply(id)))
			}
		}
	}
}

// An agent's block.add{pending_id} held (its policy referred it) before the
// form became the app's alone is never run, even when the app approves it.
func TestHeldBlockOfPendingRequestNotRun(t *testing.T) {
	a, _, pid, _ := requested(t)
	// The policy that referred it, and would still cover it.
	a.m.addFeature(&policyType{decision: AgentAllow})
	_, ag := accessed(t, a)
	rid, _ := envelope.NewULID(time.Now())
	a.m.mu.Lock()
	a.m.hold(ag.peer, &envelope.Inner{ID: rid, Type: "block.add", TS: time.Now(), Body: []byte(`{"pending_id":"` + pid + `"}`)},
		"agent1/"+rid, false, Approval{}, time.Now())
	a.m.mu.Unlock()
	aid := ""
	for id := range a.m.st.Held {
		aid = id
	}
	if aid == "" {
		t.Fatal("not held")
	}
	did := a.sendAs(a.self(), "approval.decide", `{"approval_id":"`+aid+`","approve":true}`)
	in := a.inbox(a.self(), ag)
	if r := find(in["dev1"], reply(did)); r == nil || bodyStr(t, r, "result") != "forbidden" {
		t.Fatalf("decide: %+v", r)
	}
	if len(a.m.st.Blocks) != 0 || a.m.st.Requests[pid] == nil {
		t.Fatal("the held block ran")
	}
}

// Without an access session, a desktop or an agent learns nothing of what
// the vault holds: a withdrawal of an outgoing request and one of an id it
// does not know get the same answer (a desktop's session_required). The block of a pending request,
// decided by its body alone, is forbidden either way.
func TestWithdrawalWithoutSessionIsSessionRequired(t *testing.T) {
	a, b, _, cid := requested(t)
	deskB := b.addDevice(t, "desk1", KindDesktop, 0x71)
	agB := b.addDevice(t, "agent1", KindAgent, 0x72)
	deskA := a.addDevice(t, "desk1", KindDesktop, 0x71)
	b.inbox(b.self(), deskB, agB)
	a.inbox(a.self(), deskA)
	// The same answer for the outgoing request and an unknown id: a desktop's
	// session_required; an agent's forbidden, as it may send neither type.
	for _, td := range []*tdev{deskB, agB} {
		want := map[string]string{KindDesktop: "session_required", KindAgent: "forbidden"}[td.peer.Kind]
		for _, id := range []string{cid, "01JZZZZZZZZZZZZZZZZZZZZZZZ"} {
			for _, typ := range []string{"connection.remove", "block.add"} {
				rid := b.sendAs(td, typ, `{"connection_id":"`+id+`"}`)
				if code := errCode(find(b.inbox(b.self(), td)[td.peer.ID], reply(rid))); code != want {
					t.Errorf("%s %s %s without a session: %q, want %q", td.peer.Kind, typ, id, code, want)
				}
			}
		}
	}
	// Nothing was withdrawn or blocked.
	if rq, _ := b.m.connRequest(cid, ReqOut); rq == nil || len(b.m.st.Blocks) != 0 {
		t.Fatal("a session-less withdrawal changed the request or the blocks")
	}
	rid := a.sendAs(deskA, "block.add", `{"pending_id":"x"}`)
	if code := errCode(find(a.inbox(a.self(), deskA)["desk1"], reply(rid))); code != "forbidden" {
		t.Errorf("block of a pending request without a session: %q", code)
	}
}

// An id the vault knows as neither a connection nor an outgoing request is
// not app-only: a desktop's connection.remove of it is held for an app, as
// any step-up request (the handler answers not_found then).
func TestUnknownIDIsNotAppOnly(t *testing.T) {
	_, b, _, _ := requested(t)
	desk, _ := accessed(t, b)
	b.inbox(b.self(), desk)
	b.sendAs(desk, "connection.remove", `{"connection_id":"01JZZZZZZZZZZZZZZZZZZZZZZZ"}`)
	if find(b.inbox(b.self(), desk)["dev1"], ofType("approval.pending")) == nil {
		t.Fatal("an unknown id's remove was not held as before")
	}
}

// A desktop's connection.remove of an outgoing request held before this
// release is never run, even when the app approves it.
func TestHeldWithdrawalNotRun(t *testing.T) {
	_, b, _, cid := requested(t)
	desk, _ := accessed(t, b)
	rid, _ := envelope.NewULID(time.Now())
	b.m.mu.Lock()
	b.m.hold(desk.peer, &envelope.Inner{ID: rid, Type: "connection.remove", TS: time.Now(), Body: []byte(`{"connection_id":"` + cid + `"}`)},
		"desk1/"+rid, false, Approval{}, time.Now())
	b.m.mu.Unlock()
	aid := ""
	for id := range b.m.st.Held {
		aid = id
	}
	did := b.sendAs(b.self(), "approval.decide", `{"approval_id":"`+aid+`","approve":true}`)
	if r := find(b.inbox(b.self(), desk)["dev1"], reply(did)); r == nil || bodyStr(t, r, "result") != "forbidden" {
		t.Fatalf("decide: %+v", r)
	}
	if r, waiting := b.m.connRequest(cid, ReqOut); r == nil && !waiting {
		t.Fatal("the held withdrawal ran")
	}
}

// On an active connection a desktop's block.add runs as before (not a
// step-up type, not app-only); an agent's is forbidden, as before.
func TestActiveConnectionBlockUnchanged(t *testing.T) {
	_, b := firstContact(t, connected)
	desk, ag := accessed(t, b)
	b.inbox(b.self(), desk, ag)
	var cid string
	for id := range b.m.st.Connections {
		cid = id
	}
	id := b.sendAs(ag, "block.add", `{"connection_id":"`+cid+`"}`)
	if code := errCode(find(b.inbox(b.self(), ag)["agent1"], reply(id))); code != "forbidden" {
		t.Fatalf("agent block of an active connection: %q", code)
	}
	id = b.sendAs(desk, "block.add", `{"connection_id":"`+cid+`"}`)
	if r := find(b.inbox(b.self(), desk)["desk1"], reply(id)); r == nil || r.Status != envelope.StatusOK || len(b.m.st.Blocks) != 1 {
		t.Fatalf("desktop block of an active connection: %+v", r)
	}
}
