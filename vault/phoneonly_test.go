package vault

import (
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// Only the member's phone creates or accepts connections (owner decision
// 2026-10-13, §6.8): connection.invite.create, connection.invite.accept
// and connection.approve from a desktop or an agent are refused with
// forbidden at once, never held for an app, and change nothing; a desktop
// may still decline an incoming request. The app's paths are unchanged.
func TestOnlyPhoneCreatesOrAcceptsConnections(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	// A policy that would allow anything an agent asks: app-only types
	// never reach it.
	pol := &policyType{decision: AgentAllow}
	d.m.addFeature(pol)
	desk := d.addDevice(t, "desk1", KindDesktop, 0x71)
	ag := d.addDevice(t, "agent1", KindAgent, 0x72)
	for _, td := range []*tdev{desk, ag} {
		td.peer.Access = &AccessSession{ID: "s-" + td.peer.ID, Expires: time.Now().Add(time.Hour)}
	}

	// Two pending incoming requests.
	pending := func(seed byte, name string) string {
		inv := d.invite(t, KindConnection, 7*24*time.Hour)
		before := map[string]bool{}
		for id := range d.m.st.Requests {
			before[id] = true
		}
		n := newNewcomer(t, seed)
		n.hsInit(t, d.m, handshake.PurposeConnection, inv.ID, name)
		n.finish(t, d)
		for id := range d.m.st.Requests {
			if !before[id] {
				return id
			}
		}
		t.Fatal("no pending request")
		return ""
	}
	pid := pending(0x50, "c1")
	pid2 := pending(0x60, "c2")
	d.inbox(app, desk, ag)
	invites := len(d.m.st.Invites)

	bodies := map[string]string{
		"connection.invite.create": `{"ttl_seconds":600}`,
		"connection.invite.accept": `{"link":"https://example.invalid/i#x"}`,
		"connection.approve":       `{"pending_id":"` + pid + `"}`,
	}
	for _, td := range []*tdev{desk, ag} {
		for typ, body := range bodies {
			id := d.sendAs(td, typ, body)
			in := d.inbox(app, td)
			if r := find(in[td.peer.ID], reply(id)); errCode(r) != "forbidden" {
				t.Errorf("%s %s: %+v", td.peer.Kind, typ, r)
			}
			if find(in["dev1"], ofType("approval.pending")) != nil || len(d.m.st.Held) != 0 {
				t.Errorf("%s %s was held for an app", td.peer.Kind, typ)
			}
		}
	}
	if pol.asked != 0 {
		t.Error("an app-only type reached the agent policy")
	}
	if r := d.m.st.Requests[pid]; r == nil || r.Approved {
		t.Fatal("a refused approval changed the request")
	}
	if len(d.m.st.Invites) != invites {
		t.Fatal("a refused invitation was created")
	}

	// A desktop may decline.
	id := d.sendAs(desk, "connection.decline", `{"pending_id":"`+pid2+`"}`)
	if r := find(d.inbox(app, desk)["desk1"], reply(id)); r == nil || r.Status != envelope.StatusOK || d.m.st.Requests[pid2] != nil {
		t.Fatalf("desktop decline: %+v", r)
	}

	// The app approves, and creates an invitation.
	id = d.sendAs(app, "connection.approve", `{"pending_id":"`+pid+`"}`)
	if r := find(d.inbox(app, desk)["dev1"], reply(id)); r == nil || r.Status != envelope.StatusOK || !d.m.st.Requests[pid].Approved {
		t.Fatalf("app approve: %+v", r)
	}
	id = d.sendAs(app, "connection.invite.create", `{"ttl_seconds":600}`)
	if r := find(d.inbox(app)["dev1"], reply(id)); r == nil || r.Status != envelope.StatusOK || len(d.m.st.Invites) != invites+1 {
		t.Fatalf("app invite: %+v", r)
	}
}

// A desktop request held before a type became app-only (a stored
// connection.invite.create from an older release) is never run for the
// desktop, even when an app approves it.
func TestHeldRequestOfAppOnlyTypeNotRun(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	desk := d.addDevice(t, "desk1", KindDesktop, 0x71)
	desk.peer.Access = &AccessSession{ID: "s", Expires: time.Now().Add(time.Hour)}
	rid, _ := envelope.NewULID(time.Now())
	d.m.mu.Lock()
	d.m.hold(desk.peer, &envelope.Inner{ID: rid, Type: "connection.invite.create", TS: time.Now(), Body: []byte(`{"ttl_seconds":600}`)},
		"desk1/"+rid, time.Now())
	d.m.mu.Unlock()
	aid := ""
	for id := range d.m.st.Held {
		aid = id
	}
	if aid == "" {
		t.Fatal("not held")
	}
	invites := len(d.m.st.Invites)
	did := d.sendAs(app, "approval.decide", `{"approval_id":"`+aid+`","approve":true}`)
	in := d.inbox(app, desk)
	if r := find(in["dev1"], reply(did)); r == nil || bodyStr(t, r, "result") != "forbidden" {
		t.Fatalf("decide: %+v", r)
	}
	if r := find(in["desk1"], reply(rid)); errCode(r) != "forbidden" || len(d.m.st.Invites) != invites {
		t.Fatalf("held app-only request ran: %+v", r)
	}
}
