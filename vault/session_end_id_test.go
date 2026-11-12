package vault

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/strictjson"
)

// VAULT-MESSAGING 0.82.5 §6.8 "Ending": device.session.end may name the
// session it ends; and 0.41.0: vault.status returns a desktop's or
// agent's own session.

// endReply sends an end as td and returns the vault's answer and everything
// the vault sent to the rig's devices in that batch (by device id, the
// answer included). It drains the inbox once, so the caller sees every
// device's messages.
func endReply(t *testing.T, r *accessRig, td *tdev, body string) (*envelope.Inner, map[string][]*envelope.Inner) {
	t.Helper()
	id := r.d.sendAs(td, "device.session.end", body)
	all := r.d.inbox(r.a, r.b, r.desk)
	resp := find(all[td.peer.ID], reply(id))
	if resp == nil {
		t.Fatalf("no answer to the end %s", body)
	}
	return resp, all
}

// assertNoEnd fails if the batch sent anything but the answer (no
// device.session.ended, no sync.event, nothing else) or recorded any
// audit entry since before (the count of entries then).
func assertNoEnd(t *testing.T, r *accessRig, all map[string][]*envelope.Inner, before int) {
	t.Helper()
	for dev, ins := range all {
		for _, e := range ins {
			if e.Re == "" {
				t.Fatalf("%s got %s after a no-op end", dev, e.Type)
			}
		}
	}
	if n := len(sinkOf(r.d).got); n != before {
		t.Fatalf("%d audit entries after a no-op end, %d before", n, before)
	}
}

// acts is the number of audit entries the rig has recorded.
func acts(r *accessRig) int { return len(sinkOf(r.d).got) }

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
		var all map[string][]*envelope.Inner
		if app {
			resp, all = endReply(t, r, r.a, `{"device_id":"desk1","session_id":"`+sid+`"}`)
		} else {
			resp, all = endReply(t, r, r.desk, `{"session_id":"`+sid+`"}`)
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
		// The events are as for an end without an id (§6.8 "Ending"): the
		// device is told only when an app ended it; every device but the
		// sender gets device.session and one approval.decided per held request.
		ended := find(all["desk1"], ofType("device.session.ended"))
		if app != (ended != nil) || ended != nil && bodyStr(t, ended, "reason") != "ended" {
			t.Fatalf("app=%v: device.session.ended: %+v", app, ended)
		}
		others := []string{"dev2"}
		if app {
			if len(syncEvents(t, all["dev1"], "device.session"))+len(syncEvents(t, all["dev1"], "approval.decided")) != 0 {
				t.Fatalf("app=%v: the sender got sync.event", app)
			}
		} else {
			others = append(others, "dev1")
		}
		for _, dev := range others {
			if len(syncEvents(t, all[dev], "device.session")) != 1 || len(syncEvents(t, all[dev], "approval.decided")) != 2 {
				t.Fatalf("app=%v: %s sync.event: %+v", app, dev, all[dev])
			}
		}
	}
}

func TestSessionEndIDMismatchChangesNothing(t *testing.T) {
	for _, app := range []bool{true, false} {
		r, sid := sessionRig(t)
		var resp *envelope.Inner
		var all map[string][]*envelope.Inner
		before := acts(r)
		if app {
			resp, all = endReply(t, r, r.a, `{"device_id":"desk1","session_id":"other"}`)
		} else {
			resp, all = endReply(t, r, r.desk, `{"session_id":"other"}`)
		}
		if resp.Status != envelope.StatusOK || string(resp.Body) != "{}" {
			t.Fatalf("app=%v: %+v", app, resp)
		}
		if r.desk.peer.Access == nil || r.desk.peer.Access.ID != sid || len(r.d.m.st.AccessRequests) != 1 || len(r.d.m.st.Held) != 2 {
			t.Fatalf("app=%v: state changed", app)
		}
		assertNoEnd(t, r, all, before)
	}
}

// The race the id is for: a delayed end of session A arrives after a
// renewal replaced it with B; B stays.
func TestSessionEndIDDelayedEndOfReplacedSession(t *testing.T) {
	for _, app := range []bool{true, false} {
		r := newAccessRig(t)
		r.grant(t)
		a := r.desk.peer.Access.ID
		r.d.m.st.AccessRequests["r0"] = &AccessRequest{ID: "r0", DeviceID: "desk1", Seconds: 600, Created: time.Now(), Expires: time.Now().Add(time.Minute)}
		r.d.sendAs(r.a, "device.session.approve", `{"request_id":"r0"}`) // the renewal: a new grant
		r.d.inbox(r.a, r.b, r.desk)
		b := r.desk.peer.Access.ID
		if b == "" || b == a {
			t.Fatalf("renewal kept session id %q", b)
		}
		r.d.m.st.AccessRequests["r1"] = &AccessRequest{ID: "r1", DeviceID: "desk1", Seconds: 60, Created: time.Now(), Expires: time.Now().Add(time.Minute)}
		r.hold(t, 2)
		before := acts(r)
		var resp *envelope.Inner
		var all map[string][]*envelope.Inner
		if app {
			resp, all = endReply(t, r, r.a, `{"device_id":"desk1","session_id":"`+a+`"}`)
		} else {
			resp, all = endReply(t, r, r.desk, `{"session_id":"`+a+`"}`)
		}
		if resp.Status != envelope.StatusOK || string(resp.Body) != "{}" {
			t.Fatalf("app=%v: %+v", app, resp)
		}
		if r.desk.peer.Access == nil || r.desk.peer.Access.ID != b || len(r.d.m.st.AccessRequests) != 1 || len(r.d.m.st.Held) != 2 {
			t.Fatalf("app=%v: the newer session or the requests were touched", app)
		}
		assertNoEnd(t, r, all, before)
		// The newer session ends by its own id.
		if resp, _ := endReply(t, r, r.a, `{"device_id":"desk1","session_id":"`+b+`"}`); resp.Status != envelope.StatusOK || r.desk.peer.Access != nil {
			t.Fatalf("app=%v: B did not end by its id", app)
		}
	}
}

func TestSessionEndIDNoSessionKeepsRequest(t *testing.T) {
	r := newAccessRig(t)
	r.request(t)
	r.d.inbox(r.a, r.b, r.desk)
	for _, c := range []struct {
		td   *tdev
		body string
	}{{r.a, `{"device_id":"desk1","session_id":"s1"}`}, {r.desk, `{"session_id":"s1"}`}} {
		before := acts(r)
		resp, all := endReply(t, r, c.td, c.body)
		if resp.Status != envelope.StatusOK || string(resp.Body) != "{}" {
			t.Fatalf("%+v", resp)
		}
		if len(r.d.m.st.AccessRequests) != 1 {
			t.Fatal("the pending request was dropped")
		}
		assertNoEnd(t, r, all, before)
	}
	// Without an id the request is dropped, as before.
	endReply(t, r, r.a, `{"device_id":"desk1"}`)
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
	before := acts(r)
	out, err := r.d.m.hSessionEnd(context.Background(), s, in)
	if err != nil || len(out) != 0 {
		t.Fatalf("%s %v", out, err)
	}
	if r.desk.peer.Access == nil || len(r.d.m.st.AccessRequests) != 1 || len(r.d.m.st.Held) != 2 {
		t.Fatal("an expired session's end changed state")
	}
	assertNoEnd(t, r, r.d.inbox(r.a, r.b, r.desk), before)
	// One instant earlier it ends.
	s.now = exp.Add(-time.Nanosecond)
	if _, err := r.d.m.hSessionEnd(context.Background(), s, in); err != nil || r.desk.peer.Access != nil {
		t.Fatalf("not ended before expiry: %v", err)
	}
	// Through a batch the expired session is already gone; a named end
	// leaves the pending request and the held requests.
	r, sid = sessionRig(t)
	r.desk.peer.Access.Expires = time.Now().Add(-time.Second)
	before = acts(r)
	_, all := endReply(t, r, r.a, `{"device_id":"desk1","session_id":"`+sid+`"}`)
	if len(r.d.m.st.AccessRequests) != 1 || len(r.d.m.st.Held) != 2 {
		t.Fatal("a named end of an expired session dropped requests")
	}
	assertNoEnd(t, r, all, before)
}

func TestSessionEndIDAppUnknownDevice(t *testing.T) {
	r := newAccessRig(t)
	for _, body := range []string{
		`{"device_id":"nope","session_id":"s"}`,
		`{"device_id":"nope","session_id":5}`,   // not_found comes first
		`{"device_id":"dev2","session_id":"s"}`, // an app is no target of an end
	} {
		if resp, _ := endReply(t, r, r.a, body); errCode(resp) != "not_found" {
			t.Fatalf("%s: %+v", body, resp)
		}
	}
}

func TestSessionEndIDBadAndNull(t *testing.T) {
	// Over 4096 bytes is over the repo's id cap (str).
	long := `"` + strings.Repeat("a", 4097) + `"`
	for _, bad := range []string{`5`, `true`, `""`, `{}`, `[]`, `["s"]`, long} {
		r, sid := sessionRig(t)
		for _, c := range []struct {
			td   *tdev
			body string
		}{{r.desk, `{"session_id":` + bad + `}`}, {r.a, `{"device_id":"desk1","session_id":` + bad + `}`}} {
			resp, all := endReply(t, r, c.td, c.body)
			if errCode(resp) != "bad_request" {
				t.Fatalf("%.40s: %+v", c.body, resp)
			}
			if r.desk.peer.Access == nil || r.desk.peer.Access.ID != sid || len(r.d.m.st.Held) != 2 || len(r.d.m.st.AccessRequests) != 1 {
				t.Fatalf("%.40s: state changed", c.body)
			}
			for dev, ins := range all {
				for _, e := range ins {
					if e.Re == "" {
						t.Fatalf("%s got %s after bad_request", dev, e.Type)
					}
				}
			}
		}
	}
	// An id of exactly 4096 bytes is a string like any other (no match).
	r, _ := sessionRig(t)
	if resp, _ := endReply(t, r, r.desk, `{"session_id":"`+strings.Repeat("a", 4096)+`"}`); resp.Status != envelope.StatusOK || r.desk.peer.Access == nil {
		t.Fatalf("%+v", resp)
	}
	r, _ = sessionRig(t)
	if resp, _ := endReply(t, r, r.desk, `{"session_id":null}`); resp.Status != envelope.StatusOK {
		t.Fatalf("%+v", resp)
	}
	if r.desk.peer.Access != nil || len(r.d.m.st.AccessRequests) != 0 || len(r.d.m.st.Held) != 0 {
		t.Fatal("null did not end like an absent id")
	}
}

// §3.6.3: the end with an id passes while the vault is held. Entering the
// hold answers the held requests and drops the pending ones, so a pending
// request is added after it began.
func TestSessionEndIDWhileHeld(t *testing.T) {
	f := newOCFixture(t)
	f.m.st.AccessRequests["r0"] = &AccessRequest{ID: "r0", DeviceID: "agent1", Seconds: 60, Created: time.Now(), Expires: time.Now().Add(time.Minute)}
	f.pastDeadline()
	f.sendAs(f.app, "test.req", `{}`) // the hold begins
	f.inbox(f.app, f.desk, f.agent)
	if !f.audited("owner_check.held") || len(f.m.st.AccessRequests) != 0 {
		t.Fatal("the hold did not begin")
	}
	pend := func() {
		f.m.st.AccessRequests["r1"] = &AccessRequest{ID: "r1", DeviceID: "agent1", Seconds: 60, Created: time.Now(), Expires: time.Now().Add(time.Minute)}
		f.m.st.AccessRequests["r2"] = &AccessRequest{ID: "r2", DeviceID: "desk1", Seconds: 60, Created: time.Now(), Expires: time.Now().Add(time.Minute)}
	}
	pend()
	// A mismatch from either changes nothing.
	for _, td := range []*tdev{f.agent, f.desk} {
		if r := f.req(t, td, "device.session.end", `{"session_id":"nope"}`); r.Status != envelope.StatusOK || td.peer.Access == nil || len(f.m.st.AccessRequests) != 2 {
			t.Fatalf("mismatch while held, %s: %+v", td.peer.ID, r)
		}
	}
	// A match ends, audited once per end; while held no sync.event goes
	// out (§6.8, as for an end without an id).
	for i, c := range []struct {
		td  *tdev
		sid string
	}{{f.agent, "s2"}, {f.desk, "s1"}} {
		id := f.sendAs(c.td, "device.session.end", `{"session_id":"`+c.sid+`"}`)
		all := f.inbox(f.app, f.desk, f.agent)
		if r := find(all[c.td.peer.ID], reply(id)); r == nil || r.Status != envelope.StatusOK || c.td.peer.Access != nil {
			t.Fatalf("match while held, %s: %+v", c.td.peer.ID, r)
		}
		n := 0
		for _, a := range f.oc.got {
			if a.Kind == "device.session.ended" && a.DeviceID == c.td.peer.ID && a.Audit {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("%s: %d device.session.ended audits", c.td.peer.ID, n)
		}
		for dev, ins := range all {
			if len(syncEvents(t, ins, "device.session"))+len(syncEvents(t, ins, "approval.decided")) != 0 {
				t.Fatalf("%s got sync.event while held (end %d)", dev, i)
			}
		}
	}
	if len(f.m.st.AccessRequests) != 0 {
		t.Fatal("the pending requests stayed after the ends")
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
