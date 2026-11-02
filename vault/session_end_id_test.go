package vault

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// VAULT-MESSAGING 0.82.5 §6.8 "Ending": device.session.end may name the
// session it ends; and 0.41.0: vault.status returns a desktop's or
// agent's own session.

// endReply sends an end as td and returns the vault's answer.
func endReply(t *testing.T, d *devFixture, td *tdev, body string) *envelope.Inner {
	t.Helper()
	id := d.sendAs(td, "device.session.end", body)
	r := find(d.inbox(td)[td.peer.ID], reply(id))
	if r == nil {
		t.Fatalf("no answer to the end %s", body)
	}
	return r
}

// assertNoEnd fails if anything was audited or sent as for an end.
func assertNoEnd(t *testing.T, r *accessRig) {
	t.Helper()
	in := r.d.inbox(r.a, r.b, r.desk)
	for dev, ins := range in {
		for _, e := range ins {
			if e.Type == "device.session.ended" || e.Type == "sync.event" || e.Type == "approval.pending" {
				t.Fatalf("%s got %s after a no-op end", dev, e.Type)
			}
		}
	}
	for _, k := range []string{"device.session.ended", "approval.denied"} {
		if n := len(r.d.audits(k)); n != 0 {
			t.Fatalf("%d %s audits after a no-op end", n, k)
		}
	}
}

// sessionRig is a granted desktop with one pending renewal request and two
// held requests.
func sessionRig(t *testing.T) (*accessRig, string) {
	r := newAccessRig(t)
	r.grant(t)
	r.d.m.st.AccessRequests["r1"] = &AccessRequest{ID: "r1", DeviceID: "desk1", Seconds: 60, Created: time.Now(), Expires: time.Now().Add(time.Minute)}
	r.hold(t, 2)
	return r, r.desk.peer.Access.ID
}

func TestSessionEndIDMatchEnds(t *testing.T) {
	for _, app := range []bool{true, false} {
		r, sid := sessionRig(t)
		var resp *envelope.Inner
		if app {
			resp = endReply(t, r.d, r.a, `{"device_id":"desk1","session_id":"`+sid+`"}`)
		} else {
			resp = endReply(t, r.d, r.desk, `{"session_id":"`+sid+`"}`)
		}
		if resp.Status != envelope.StatusOK {
			t.Fatalf("app=%v: %+v", app, resp)
		}
		if r.desk.peer.Access != nil || len(r.d.m.st.AccessRequests) != 0 || len(r.d.m.st.Held) != 0 {
			t.Fatalf("app=%v: not ended", app)
		}
		if n := len(r.d.audits("device.session.ended")); n != 1 {
			t.Fatalf("app=%v: %d end audits", app, n)
		}
		if n := len(r.d.audits("approval.denied")); n != 2 {
			t.Fatalf("app=%v: %d approval.denied audits", app, n)
		}
	}
}

func TestSessionEndIDMismatchChangesNothing(t *testing.T) {
	for _, app := range []bool{true, false} {
		r, sid := sessionRig(t)
		var resp *envelope.Inner
		if app {
			resp = endReply(t, r.d, r.a, `{"device_id":"desk1","session_id":"other"}`)
		} else {
			resp = endReply(t, r.d, r.desk, `{"session_id":"other"}`)
		}
		if resp.Status != envelope.StatusOK || string(resp.Body) != "{}" {
			t.Fatalf("app=%v: %+v", app, resp)
		}
		if r.desk.peer.Access == nil || r.desk.peer.Access.ID != sid || len(r.d.m.st.AccessRequests) != 1 || len(r.d.m.st.Held) != 2 {
			t.Fatalf("app=%v: state changed", app)
		}
		assertNoEnd(t, r)
	}
}

func TestSessionEndIDNoSessionKeepsRequest(t *testing.T) {
	r := newAccessRig(t)
	r.request(t)
	r.d.inbox(r.a, r.b, r.desk)
	for _, resp := range []*envelope.Inner{
		endReply(t, r.d, r.a, `{"device_id":"desk1","session_id":"s1"}`),
		endReply(t, r.d, r.desk, `{"session_id":"s1"}`),
	} {
		if resp.Status != envelope.StatusOK || string(resp.Body) != "{}" {
			t.Fatalf("%+v", resp)
		}
	}
	if len(r.d.m.st.AccessRequests) != 1 {
		t.Fatal("the pending request was dropped")
	}
	assertNoEnd(t, r)
	// Without an id the request is dropped, as before.
	endReply(t, r.d, r.a, `{"device_id":"desk1"}`)
	if len(r.d.m.st.AccessRequests) != 0 {
		t.Fatal("end without id kept the request")
	}
}

func TestSessionEndIDExpiredNoop(t *testing.T) {
	r, sid := sessionRig(t)
	// Housekeeping drops an expired session before a handler runs, so the
	// handler's own check is tested directly, at the boundary: now equal to
	// Expires is expired (as hasAccess).
	exp := r.desk.peer.Access.Expires
	s := &Session{peer: r.desk.peer, from: info(r.desk.peer), now: exp}
	in := &envelope.Inner{Type: "device.session.end", Body: []byte(`{"session_id":"` + sid + `"}`)}
	out, err := r.d.m.hSessionEnd(context.Background(), s, in)
	if err != nil || len(out) != 0 {
		t.Fatalf("%s %v", out, err)
	}
	if r.desk.peer.Access == nil || len(r.d.m.st.AccessRequests) != 1 || len(r.d.m.st.Held) != 2 {
		t.Fatal("an expired session's end changed state")
	}
	assertNoEnd(t, r)
	// One instant earlier it ends.
	s.now = exp.Add(-time.Nanosecond)
	if _, err := r.d.m.hSessionEnd(context.Background(), s, in); err != nil || r.desk.peer.Access != nil {
		t.Fatalf("not ended before expiry: %v", err)
	}
	// Through a batch the expired session is already gone; a named end
	// leaves the pending request and the held requests.
	r, sid = sessionRig(t)
	r.desk.peer.Access.Expires = time.Now().Add(-time.Second)
	endReply(t, r.d, r.a, `{"device_id":"desk1","session_id":"`+sid+`"}`)
	if len(r.d.m.st.AccessRequests) != 1 || len(r.d.m.st.Held) != 2 {
		t.Fatal("a named end of an expired session dropped requests")
	}
	assertNoEnd(t, r)
}

func TestSessionEndIDAppUnknownDevice(t *testing.T) {
	r := newAccessRig(t)
	if resp := endReply(t, r.d, r.a, `{"device_id":"nope","session_id":"s"}`); errCode(resp) != "not_found" {
		t.Fatalf("%+v", resp)
	}
	if resp := endReply(t, r.d, r.a, `{"device_id":"nope","session_id":5}`); errCode(resp) != "not_found" {
		t.Fatalf("not_found comes first: %+v", resp)
	}
	// An app is no target of an end.
	if resp := endReply(t, r.d, r.a, `{"device_id":"dev2","session_id":"s"}`); errCode(resp) != "not_found" {
		t.Fatalf("%+v", resp)
	}
}

func TestSessionEndIDBadAndNull(t *testing.T) {
	for _, bad := range []string{`5`, `true`, `""`, `{}`, `[]`, `["s"]`} {
		r, _ := sessionRig(t)
		if resp := endReply(t, r.d, r.desk, `{"session_id":`+bad+`}`); errCode(resp) != "bad_request" {
			t.Fatalf("desktop %s: %+v", bad, resp)
		}
		if resp := endReply(t, r.d, r.a, `{"device_id":"desk1","session_id":`+bad+`}`); errCode(resp) != "bad_request" {
			t.Fatalf("app %s: %+v", bad, resp)
		}
		if r.desk.peer.Access == nil || len(r.d.m.st.Held) != 2 {
			t.Fatalf("%s: state changed", bad)
		}
	}
	r, _ := sessionRig(t)
	if resp := endReply(t, r.d, r.desk, `{"session_id":null}`); resp.Status != envelope.StatusOK {
		t.Fatalf("%+v", resp)
	}
	if r.desk.peer.Access != nil || len(r.d.m.st.AccessRequests) != 0 || len(r.d.m.st.Held) != 0 {
		t.Fatal("null did not end like an absent id")
	}
}

// §3.6.3: the end with an id passes while the vault is held.
func TestSessionEndIDWhileHeld(t *testing.T) {
	f := newOCFixture(t)
	f.pastDeadline()
	f.sendAs(f.app, "test.req", `{}`) // the hold begins
	f.inbox(f.app, f.desk, f.agent)
	if r := f.req(t, f.agent, "device.session.end", `{"session_id":"nope"}`); r.Status != envelope.StatusOK || f.agent.peer.Access == nil {
		t.Fatalf("mismatch while held: %+v", r)
	}
	if r := f.req(t, f.agent, "device.session.end", `{"session_id":"s2"}`); r.Status != envelope.StatusOK || f.agent.peer.Access != nil {
		t.Fatalf("match while held: %+v", r)
	}
	if r := f.req(t, f.desk, "device.session.end", `{"session_id":"s1"}`); r.Status != envelope.StatusOK || f.desk.peer.Access != nil {
		t.Fatalf("desktop match while held: %+v", r)
	}
}

// statusSession returns the "session" member of a vault.status answer.
func statusSession(t *testing.T, f *ocFixture, td *tdev) (strictjson.Object, bool, bool) {
	t.Helper()
	r := f.req(t, td, "vault.status", `{}`)
	o, err := strictjson.ParseObject(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	raw, present := o["session"]
	if !present {
		return nil, false, false
	}
	if string(raw) == "null" {
		return nil, true, true
	}
	so, err := o.Object("session")
	if err != nil {
		t.Fatalf("session: %s", raw)
	}
	return so, true, false
}

// 0.41.0: vault.status returns the calling desktop's or agent's own
// current session or null; the app gets no member.
func TestStatusOwnSession(t *testing.T) {
	f := newOCFixture(t)
	for _, c := range []struct {
		td  *tdev
		sid string
	}{{f.desk, "s1"}, {f.agent, "s2"}} {
		so, present, null := statusSession(t, f, c.td)
		if !present || null {
			t.Fatalf("%s: no session", c.td.peer.ID)
		}
		if id, _ := so.String("session_id"); id != c.sid {
			t.Fatalf("%s: session_id %q, the other device's or wrong", c.td.peer.ID, id)
		}
		if ea, _ := so.String("expires_at"); ea != envelope.FormatTS(c.td.peer.Access.Expires) || len(so) != 2 {
			t.Fatalf("%s: %v", c.td.peer.ID, so)
		}
	}
	// Expired: null.
	f.desk.peer.Access.Expires = time.Now().Add(-time.Second)
	if _, present, null := statusSession(t, f, f.desk); !present || !null {
		t.Fatal("expired session not null")
	}
	// None: null.
	f.agent.peer.Access = nil
	if _, present, null := statusSession(t, f, f.agent); !present || !null {
		t.Fatal("no session not null")
	}
	// The app gets no session member.
	if _, present, _ := statusSession(t, f, f.app); present {
		t.Fatal("the app got session")
	}
}

// 0.41.0: vault.status is answered while the vault is held and still
// returns the session.
func TestStatusSessionWhileHeld(t *testing.T) {
	f := newOCFixture(t)
	f.pastDeadline()
	f.sendAs(f.app, "test.req", `{}`)
	f.inbox(f.app, f.desk, f.agent)
	so, present, null := statusSession(t, f, f.desk)
	if !present || null {
		t.Fatal("no session while held")
	}
	if id, _ := so.String("session_id"); id != "s1" {
		t.Fatalf("%q", id)
	}
}
