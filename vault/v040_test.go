package vault

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// VAULT-MESSAGING 0.40.0 §6.8 step 2, §10.3: the vault accepts at most one
// device.session.request per desktop or agent every 10 minutes, counted
// from the last one it accepted whatever became of it (approved, denied,
// replaced or dropped). One within that time is answered too_soon with
// {allowed_after}, reaches no app, does not replace the pending request
// and does not move the window.
func TestAccessRequestBound(t *testing.T) {
	d := newDevFixture(t)
	sinkOf(d)
	app := d.self()
	desk := d.addDevice(t, "desk1", KindDesktop, 0x60)
	desk2 := d.addDevice(t, "desk2", KindDesktop, 0x64)
	ag := d.addDevice(t, "agent1", KindAgent, 0x70)

	base := time.Now().UTC().Truncate(time.Millisecond)
	now := base
	d.m.now = func() time.Time { return now }
	defer func() { d.m.now = time.Now }()
	at := func(off time.Duration) { now = base.Add(off) }
	pendings := func() int { return len(d.audits("device.session.pending")) }

	// accepted sends a request from td and returns the request id the apps
	// were asked with.
	accepted := func(td *tdev, body string) string {
		t.Helper()
		id := d.sendAs(td, "device.session.request", body)
		in := d.inbox(app, td)
		if r := find(in[td.peer.ID], reply(id)); r == nil || r.Status != envelope.StatusOK {
			t.Fatalf("%s at %v: request refused: %+v", td.peer.ID, now.Sub(base), r)
		}
		p := find(in["dev1"], ofType("device.session.pending"))
		if p == nil || bodyStr(t, p, "device_id") != td.peer.ID {
			t.Fatalf("%s at %v: apps not asked", td.peer.ID, now.Sub(base))
		}
		return bodyStr(t, p, "request_id")
	}
	// tooSoon sends a request from td and wants too_soon with allowed_after
	// = want, nothing for the apps, no feed item and the pending requests
	// unchanged.
	tooSoon := func(td *tdev, want time.Time) {
		t.Helper()
		before := map[string]AccessRequest{}
		for k, r := range d.m.st.AccessRequests {
			before[k] = *r
		}
		n := pendings()
		id := d.sendAs(td, "device.session.request", `{"seconds":120}`)
		in := d.inbox(app, td)
		r := find(in[td.peer.ID], reply(id))
		if errCode(r) != "too_soon" {
			t.Fatalf("%s at %v: want too_soon, got %+v", td.peer.ID, now.Sub(base), r)
		}
		if got := bodyStr(t, r, "allowed_after"); got != envelope.FormatTS(want) {
			t.Fatalf("%s at %v: allowed_after %s, want %s", td.peer.ID, now.Sub(base), got, envelope.FormatTS(want))
		}
		if len(in["dev1"]) != 0 {
			t.Fatalf("%s at %v: a refused request reached the app: %+v", td.peer.ID, now.Sub(base), in["dev1"])
		}
		if pendings() != n {
			t.Fatalf("%s at %v: a refused request made a feed item", td.peer.ID, now.Sub(base))
		}
		if len(d.m.st.AccessRequests) != len(before) {
			t.Fatalf("%s at %v: pending requests changed", td.peer.ID, now.Sub(base))
		}
		for k, r := range d.m.st.AccessRequests {
			if b, ok := before[k]; !ok || b != *r {
				t.Fatalf("%s at %v: pending request %s replaced or changed", td.peer.ID, now.Sub(base), k)
			}
		}
	}
	every := AccessRequestEvery

	// Accepted at 0; within 10 minutes too_soon, the pending one kept.
	rid := accepted(desk, `{"seconds":600}`)
	at(5 * time.Minute)
	tooSoon(desk, base.Add(every))
	if r := d.m.st.AccessRequests[rid]; r == nil || r.Seconds != 600 {
		t.Fatal("the pending request was replaced")
	}
	// Per device: another desktop and an agent are not affected.
	accepted(desk2, `{}`)
	accepted(ag, `{}`)
	// A refused request does not move the window: still allowed at 10
	// minutes after the accepted one, not 10 after the refused one.
	at(every - time.Millisecond)
	tooSoon(desk, base.Add(every))
	at(every)
	rid2 := accepted(desk, `{}`)
	if d.m.st.AccessRequests[rid] != nil || d.m.st.AccessRequests[rid2] == nil {
		t.Fatal("the accepted request did not replace the pending one")
	}
	// The other devices count from their own requests.
	tooSoon(desk2, base.Add(5*time.Minute+every))
	tooSoon(ag, base.Add(5*time.Minute+every))

	// Approved: counted from the request, not from the approval.
	at(every + 2*time.Minute)
	d.sendAs(app, "device.session.approve", `{"request_id":"`+rid2+`"}`)
	if find(d.inbox(app, desk)["desk1"], ofType("device.session.granted")) == nil {
		t.Fatal("not granted")
	}
	tooSoon(desk, base.Add(2*every))
	at(2 * every)
	rid3 := accepted(desk, `{}`)

	// Denied: still counted.
	at(2*every + time.Minute)
	d.sendAs(app, "device.session.deny", `{"request_id":"`+rid3+`"}`)
	if e := find(d.inbox(desk)["desk1"], ofType("device.session.ended")); e == nil || bodyStr(t, e, "reason") != "denied" {
		t.Fatal("denial not sent")
	}
	tooSoon(desk, base.Add(3*every))
	at(3 * every)
	rid4 := accepted(desk, `{}`)

	// Dropped (no app decided within AccessRequestTTL): counted from the
	// request; the next one is accepted once both have passed.
	at(3*every + AccessRequestTTL - time.Second)
	tooSoon(desk, base.Add(4*every))
	at(3*every + AccessRequestTTL)
	id := d.sendAs(app, "device.session.approve", `{"request_id":"`+rid4+`"}`)
	if r := find(d.inbox(app)["dev1"], reply(id)); errCode(r) != "not_found" {
		t.Fatalf("dropped request approved: %+v", r)
	}
	at(4 * every)
	accepted(desk, `{}`)
}

// The time of the last accepted request is in the device's record in the
// sealed state, so neither a lock and unlock nor a restart resets it.
func TestAccessRequestBoundPersists(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	desk := d.addDevice(t, "desk1", KindDesktop, 0x60)
	base := time.Now().UTC().Truncate(time.Millisecond)
	d.m.now = func() time.Time { return base }
	id := d.sendAs(desk, "device.session.request", `{}`)
	if r := find(d.inbox(app, desk)["desk1"], reply(id)); r == nil || r.Status != envelope.StatusOK {
		t.Fatalf("request refused: %+v", r)
	}
	if err := d.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	m, _, err := d.unlock(testPIN, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	p := m.st.Devices["desk1"]
	if p == nil || !p.AccessRequestedAt.Equal(base) {
		t.Fatalf("last accepted request not kept across a lock and unlock: %+v", p)
	}
	d.m = m
	later := base.Add(3 * time.Minute)
	m.now = func() time.Time { return later }
	id = d.sendAs(desk, "device.session.request", `{}`)
	r := find(d.inbox(app, desk)["desk1"], reply(id))
	if errCode(r) != "too_soon" || bodyStr(t, r, "allowed_after") != envelope.FormatTS(base.Add(AccessRequestEvery)) {
		t.Fatalf("after unlock: %+v", r)
	}
}
