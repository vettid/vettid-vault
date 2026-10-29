package vault

import (
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// §6.8 (0.77.0): grants, denials, ends and unlinks are audited and reach
// the owner's other devices as sync.event.

// syncEvents returns the sync.event bodies of one kind in ins.
func syncEvents(t *testing.T, ins []*envelope.Inner, kind string) []string {
	t.Helper()
	var out []string
	for _, in := range ins {
		if in.Type == "sync.event" && in.Re == "" && bodyStr(t, in, "kind") == kind {
			out = append(out, string(in.Body))
		}
	}
	return out
}

type accessRig struct {
	d          *devFixture
	a, b, desk *tdev
	rec        *recSink
}

func newAccessRig(t *testing.T) *accessRig {
	d := newDevFixture(t)
	r := &accessRig{d: d, a: d.self(), b: d.addDevice(t, "dev2", KindApp, 0x80), desk: d.addDevice(t, "desk1", KindDesktop, 0x60)}
	r.rec = sinkOf(d)
	return r
}

// request makes the desktop's session request and returns its id.
func (r *accessRig) request(t *testing.T) string {
	r.d.sendAs(r.desk, "device.session.request", `{"seconds":600}`)
	rid := bodyStr(t, find(r.d.inbox(r.a, r.b, r.desk)["dev1"], ofType("device.session.pending")), "request_id")
	return rid
}

func (r *accessRig) grant(t *testing.T) {
	rid := r.request(t)
	r.d.sendAs(r.a, "device.session.approve", `{"request_id":"`+rid+`"}`)
	r.d.inbox(r.a, r.b, r.desk)
}

func (r *accessRig) hold(t *testing.T, n int) []string {
	var ids []string
	for i := 0; i < n; i++ {
		r.d.sendAs(r.desk, "settings.set", `{"version":0,"set":{"app.theme":"dark"}}`)
	}
	for _, e := range r.d.inbox(r.a, r.b, r.desk)["dev1"] {
		if e.Type == "approval.pending" {
			ids = append(ids, bodyStr(t, e, "approval_id"))
		}
	}
	if len(ids) != n {
		t.Fatalf("held %d, want %d", len(ids), n)
	}
	return ids
}

func TestAccessDenySyncsAndAudits(t *testing.T) {
	r := newAccessRig(t)
	rid := r.request(t)
	r.d.sendAs(r.a, "device.session.deny", `{"request_id":"`+rid+`"}`)
	in := r.d.inbox(r.a, r.b, r.desk)
	if ev := syncEvents(t, in["dev2"], "device.session"); len(ev) != 1 || strings.Contains(ev[0], "expires_at") || !strings.Contains(ev[0], `"device_id":"desk1"`) {
		t.Fatalf("app B: %v", ev)
	}
	if len(syncEvents(t, in["dev1"], "device.session")) != 0 {
		t.Fatal("the deciding app got the event")
	}
	if e := find(in["desk1"], ofType("device.session.ended")); e == nil || bodyStr(t, e, "reason") != "denied" {
		t.Fatal("device not told")
	}
	au := r.d.audits("device.session.denied")
	if len(au) != 1 || au[0].DeviceID != "desk1" || au[0].Ref != rid || !au[0].Audit {
		t.Fatalf("audit: %+v", au)
	}
}

func TestAccessDenyKeepsCurrentSession(t *testing.T) {
	r := newAccessRig(t)
	rid0 := r.request(t)
	r.d.sendAs(r.a, "device.session.approve", `{"request_id":"`+rid0+`","seconds":7200}`)
	r.d.inbox(r.a, r.b, r.desk)
	exp := r.desk.peer.Access.Expires
	// A renewal request within the session, then denied.
	r.d.m.now = func() time.Time { return time.Now().Add(AccessRequestEvery + time.Minute) }
	defer func() { r.d.m.now = time.Now }()
	rid := r.request(t)
	r.d.sendAs(r.a, "device.session.deny", `{"request_id":"`+rid+`"}`)
	in := r.d.inbox(r.a, r.b, r.desk)
	ev := syncEvents(t, in["dev2"], "device.session")
	if len(ev) != 1 || !strings.Contains(ev[0], `"expires_at":"`+envelope.FormatTS(exp)+`"`) {
		t.Fatalf("app B: %v", ev)
	}
	if r.desk.peer.Access == nil || !r.desk.peer.Access.Expires.Equal(exp) {
		t.Fatal("deny ended the current session")
	}
}

func TestAccessEndHeldApprovals(t *testing.T) {
	r := newAccessRig(t)
	r.grant(t)
	ids := r.hold(t, 3)
	r.d.sendAs(r.a, "device.session.end", `{"device_id":"desk1"}`)
	in := r.d.inbox(r.a, r.b, r.desk)
	got := syncEvents(t, in["dev2"], "approval.decided")
	if len(got) != 3 {
		t.Fatalf("approval.decided on B: %v", got)
	}
	for _, id := range ids {
		n := 0
		for _, g := range got {
			if strings.Contains(g, `"approval_id":"`+id+`"`) && strings.Contains(g, `"approved":false`) {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("approval %s: %d events in %v", id, n, got)
		}
	}
	if len(syncEvents(t, in["dev2"], "device.session")) != 1 {
		t.Fatal("device.session missing on B")
	}
	if len(syncEvents(t, in["dev1"], "approval.decided"))+len(syncEvents(t, in["dev1"], "device.session")) != 0 {
		t.Fatal("the ending app got events")
	}
	denied := 0
	for _, e := range in["desk1"] {
		if e.Re != "" && e.Status != envelope.StatusOK && errCode(e) == "denied" {
			denied++
		}
	}
	if denied != 3 {
		t.Fatalf("%d held answers", denied)
	}
	if n := len(r.d.audits("approval.denied")); n != 3 {
		t.Fatalf("%d approval.denied audits", n)
	}
	if n := len(r.d.audits("device.session.ended")); n != 1 {
		t.Fatalf("%d device.session.ended audits", n)
	}
}

func TestAccessEndPendingRequestOnly(t *testing.T) {
	r := newAccessRig(t)
	r.request(t)
	r.d.sendAs(r.a, "device.session.end", `{"device_id":"desk1"}`)
	in := r.d.inbox(r.a, r.b, r.desk)
	if ev := syncEvents(t, in["dev2"], "device.session"); len(ev) != 1 || strings.Contains(ev[0], "expires_at") {
		t.Fatalf("app B: %v", ev)
	}
	if len(r.d.m.st.AccessRequests) != 0 {
		t.Fatal("request kept")
	}
	// Nothing to end: no event.
	r.d.sendAs(r.a, "device.session.end", `{"device_id":"desk1"}`)
	if ev := syncEvents(t, r.d.inbox(r.a, r.b, r.desk)["dev2"], "device.session"); len(ev) != 0 {
		t.Fatalf("event for nothing: %v", ev)
	}
}

func TestAccessDesktopEndsOwn(t *testing.T) {
	r := newAccessRig(t)
	r.grant(t)
	ids := r.hold(t, 1)
	r.d.sendAs(r.desk, "device.session.end", `{}`)
	in := r.d.inbox(r.a, r.b, r.desk)
	for _, app := range []string{"dev1", "dev2"} {
		if ev := syncEvents(t, in[app], "approval.decided"); len(ev) != 1 || !strings.Contains(ev[0], ids[0]) {
			t.Fatalf("%s: %v", app, ev)
		}
		if len(syncEvents(t, in[app], "device.session")) != 1 {
			t.Fatalf("%s: no device.session", app)
		}
	}
}

func TestAccessUnlinkSyncs(t *testing.T) {
	r := newAccessRig(t)
	r.grant(t)
	r.hold(t, 2)
	r.d.sendAs(r.a, "device.unlink", `{"device_id":"desk1"}`)
	in := r.d.inbox(r.a, r.b)
	if len(syncEvents(t, in["dev2"], "approval.decided")) != 2 || len(syncEvents(t, in["dev2"], "device.session")) != 1 {
		t.Fatalf("app B: %+v", in["dev2"])
	}
	if len(syncEvents(t, in["dev1"], "approval.decided"))+len(syncEvents(t, in["dev1"], "device.session")) != 0 {
		t.Fatal("the unlinking app got events")
	}
	if len(r.d.audits("approval.denied")) != 2 || len(r.d.audits("device.unlinked")) != 1 || len(r.d.audits("device.session.ended")) != 0 {
		t.Fatalf("audits: %+v", r.rec.got)
	}
}

func TestAccessPairingGrantSyncs(t *testing.T) {
	d := newDevFixture(t)
	a := d.self()
	b := d.addDevice(t, "dev2", KindApp, 0x80)
	rec := sinkOf(d)
	inv := d.invite(t, KindDesktop, PairingApprovalTTL)
	n := newNewcomer(t, 0x40)
	n.hsInit(t, d.m, handshake.Purpose(KindDesktop), inv.ID, "pd")
	n.finish(t, d)
	d.inbox(a, b)
	id := d.sendAs(a, "device.pair.approve", `{"pairing_id":"`+inv.ID+`","session_seconds":600}`)
	in := d.inbox(a, b)
	if r := find(in["dev1"], reply(id)); r == nil || r.Status != envelope.StatusOK {
		t.Fatalf("approve: %+v", r)
	}
	ev := syncEvents(t, in["dev2"], "device.session")
	if len(ev) != 1 || !strings.Contains(ev[0], `"expires_at"`) {
		t.Fatalf("app B: %v", ev)
	}
	if len(syncEvents(t, in["dev1"], "device.session")) != 0 {
		t.Fatal("the approving app got the event")
	}
	var g []Activity
	for _, x := range rec.got {
		if x.Kind == "device.session.granted" {
			g = append(g, x)
		}
	}
	if len(g) != 1 || g[0].Ref == "" || g[0].DeviceID == "" || !g[0].Audit {
		t.Fatalf("audit: %+v", g)
	}
}

func TestAccessApproveUnchanged(t *testing.T) {
	r := newAccessRig(t)
	rid := r.request(t)
	r.d.sendAs(r.a, "device.session.approve", `{"request_id":"`+rid+`"}`)
	in := r.d.inbox(r.a, r.b, r.desk)
	ev := syncEvents(t, in["dev2"], "device.session")
	if len(ev) != 1 || !strings.Contains(ev[0], `"expires_at"`) || len(syncEvents(t, in["dev1"], "device.session")) != 0 {
		t.Fatalf("sync: %v", ev)
	}
	if len(r.d.audits("device.session.granted")) != 1 || len(r.d.audits("device.session.denied")) != 0 {
		t.Fatal("audits")
	}
}
