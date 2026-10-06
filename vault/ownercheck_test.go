package vault

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// ocFeature stands in for the credential feature in the runtime's owner
// check tests: a credential gate, a clone-alarm state, a vault.owner_check
// that passes or fails as its body says, and test types.
type ocFeature struct {
	recSink
	noCred  bool
	alarm   string
	started int
	ended   int
}

func (f *ocFeature) Name() string { return "oc" }
func (f *ocFeature) Types() []TypeSpec {
	return []TypeSpec{
		{Type: TypeOwnerCheck, Request: true, From: []string{KindApp}},
		{Type: "test.req", Request: true, From: []string{KindApp, KindDesktop, KindAgent}},
		{Type: "test.event", From: []string{KindApp, KindDesktop}},
		{Type: "test.stepup", Request: true, From: []string{KindApp, KindDesktop}, DesktopApproval: true},
	}
}
func (f *ocFeature) CredentialReady() bool     { return !f.noCred }
func (f *ocFeature) CredentialExists() bool    { return !f.noCred }
func (f *ocFeature) AlarmState() string        { return f.alarm }
func (f *ocFeature) OwnerHoldStarted(*Session) { f.started++ }
func (f *ocFeature) OwnerHoldEnded(*Session)   { f.ended++ }
func (f *ocFeature) Handle(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	if in.Type != TypeOwnerCheck {
		return nil, nil
	}
	o, err := strictjson.ParseObject(in.Body)
	if err != nil {
		return nil, errBadRequest
	}
	if ok, _ := o.Bool("ok"); !ok {
		s.OwnerCheckFailed("pin")
		return nil, NewError("bad_pin", "")
	}
	var c *HoldChange
	if o.Has("hold") {
		on, _ := o.Bool("hold")
		c = &HoldChange{On: on}
		if u, ok, _ := o.OptString("until"); ok {
			c.Until, _ = time.Parse(time.RFC3339, u)
		}
	}
	info, err := s.OwnerCheckPassed(c, true)
	if err != nil {
		return nil, err
	}
	b := strictjson.NewBuilder()
	info.Members(b)
	return b.Bytes(), nil
}

type ocFixture struct {
	*devFixture
	oc        *ocFeature
	app, desk *tdev
	agent     *tdev
}

func newOCFixture(t *testing.T) *ocFixture {
	d := newDevFixture(t)
	f := &ocFixture{devFixture: d, oc: &ocFeature{}}
	d.m.addFeature(f.oc)
	f.app = d.self()
	f.desk = d.addDevice(t, "desk1", KindDesktop, 0x60)
	f.agent = d.addDevice(t, "agent1", KindAgent, 0x70)
	f.desk.peer.Access = &AccessSession{ID: "s1", Expires: time.Now().Add(time.Hour)}
	f.agent.peer.Access = &AccessSession{ID: "s2", Expires: time.Now().Add(time.Hour)}
	d.m.ownerCheckInit(time.Now()) // what Start does at the unlock
	return f
}

// pastDeadline moves the record's deadline into the past.
func (f *ocFixture) pastDeadline() {
	rec := f.m.st.OwnerCheck
	rec.LastAt, rec.Deadline = time.Now().Add(-25*time.Hour), time.Now().Add(-time.Hour)
}

func (f *ocFixture) req(t *testing.T, td *tdev, typ, body string) *envelope.Inner {
	t.Helper()
	id := f.sendAs(td, typ, body)
	r := find(f.inbox(td)[td.peer.ID], reply(id))
	if r == nil {
		t.Fatalf("no response to %s", typ)
	}
	return r
}

func (f *ocFixture) status(t *testing.T, td *tdev) strictjson.Object {
	t.Helper()
	r := f.req(t, td, "vault.status", `{}`)
	o, err := strictjson.ParseObject(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	oc, err := o.Object("owner_check")
	if err != nil {
		t.Fatalf("vault.status without owner_check: %s", r.Body)
	}
	return oc
}

func (f *ocFixture) audited(kind string) bool {
	return f.oc.has(kind)
}

// §3.6.3: past the deadline with the hold on, every owner device may send
// only its row of the allow list (owner_check_required; other messages
// dropped and audited drop.owner_check); entering the hold answers held
// approvals, drops access requests, runs the features' hold start, audits
// owner_check.held and sends vault.held to the app and desktops in a
// session; fan-out stops except the listed types; counts reach vault.held
// at most every 10 minutes; a check ends it all.
func TestOwnerCheckHold(t *testing.T) {
	f := newOCFixture(t)
	if st, _ := f.status(t, f.app).String("state"); st != OwnerCheckOK {
		t.Fatalf("state %q", st)
	}
	if d := f.m.st.OwnerCheck.Deadline; d.Before(time.Now().Add(23*time.Hour)) || d.After(time.Now().Add(25*time.Hour)) {
		t.Fatalf("deadline %v", d)
	}
	// A desktop's step-up request held for approval, and an agent's
	// pending access request, before the deadline.
	stepID := f.sendAs(f.desk, "test.stepup", `{}`)
	if len(f.m.st.Held) != 1 {
		t.Fatal("step-up not held")
	}
	f.m.st.AccessRequests["r1"] = &AccessRequest{ID: "r1", DeviceID: "agent1", Seconds: 60, Created: time.Now(), Expires: time.Now().Add(time.Minute)}
	f.inbox(f.app, f.desk, f.agent)

	f.pastDeadline()
	reqID := f.sendAs(f.app, "test.req", `{}`)
	if f.oc.started != 1 || !f.audited("owner_check.held") || len(f.m.st.Held) != 0 || len(f.m.st.AccessRequests) != 0 {
		t.Fatalf("entering the hold: started %d held %d access %d", f.oc.started, len(f.m.st.Held), len(f.m.st.AccessRequests))
	}
	in := f.inbox(f.app, f.desk, f.agent)
	if r := find(in["dev1"], reply(reqID)); errCode(r) != "owner_check_required" {
		t.Fatalf("app request while held: %+v", r)
	}
	if r := find(in["desk1"], reply(stepID)); errCode(r) != "owner_check_required" {
		t.Fatalf("held approval: %+v", r)
	}
	if find(in["dev1"], ofType("vault.held")) == nil || find(in["desk1"], ofType("vault.held")) == nil || find(in["agent1"], ofType("vault.held")) != nil {
		t.Fatalf("vault.held: app %v desk %v agent %v", in["dev1"], in["desk1"], in["agent1"])
	}
	// The allow list, by sender.
	f.sendAs(f.app, "test.event", `{}`)
	if !f.audited("drop.owner_check") {
		t.Fatal("dropped message not audited")
	}
	for _, c := range []struct {
		td   *tdev
		typ  string
		want string
	}{
		{f.app, "settings.get", "owner_check_required"},
		{f.app, "vault.lock", ""},
		{f.desk, "test.req", "owner_check_required"},
		{f.desk, "settings.set", "owner_check_required"},
		{f.agent, "test.req", "owner_check_required"},
	} {
		if c.typ == "vault.lock" {
			continue // (would lock the fixture)
		}
		if r := f.req(t, c.td, c.typ, `{}`); errCode(r) != c.want {
			t.Fatalf("%s %s: %q", c.td.peer.ID, c.typ, errCode(r))
		}
	}
	oc := f.status(t, f.app)
	if st, _ := oc.String("state"); st != OwnerCheckHeld || !oc.Has("deadline") || !oc.Has("failures") || !oc.Has("hold") {
		t.Fatalf("app status %v", oc)
	}
	if st, _ := f.status(t, f.desk).String("state"); st != OwnerCheckHeld {
		t.Fatal("desktop status")
	}
	if a := f.status(t, f.agent); len(a) != 1 || !a.Has("state") {
		t.Fatalf("agent status %v (state only)", a)
	}
	// Fan-out stops, except the clone alarm's events.
	f.m.mu.Lock()
	f.m.notifyDevices("sync.event", []byte(`{"kind":"settings.changed","version":1}`), "", time.Now())
	f.m.notifyDevices("feed.event", []byte(`{"kind":"message.received"}`), "", time.Now())
	f.m.notifyDevices("sync.event", []byte(`{"kind":"credential.alarm","alarm_id":"a","state":"frozen"}`), "", time.Now())
	f.m.drainOutbox(context.Background())
	f.m.mu.Unlock()
	in = f.inbox(f.app, f.desk)
	if len(in["dev1"]) != 1 || len(in["desk1"]) != 1 || !strings.Contains(string(in["dev1"][0].Body), "credential.alarm") {
		t.Fatalf("fan-out while held: %d %d", len(in["dev1"]), len(in["desk1"]))
	}
	// Counts: what would have made a feed item, sent at most every 10 min.
	f.m.mu.Lock()
	for _, k := range []string{"message.received", "message.received", "connection.request", "call.missed", "grant.request"} {
		f.m.record(Activity{Kind: k, Feed: true}, time.Now())
	}
	f.m.record(Activity{Kind: "message.sent", Audit: true}, time.Now()) // no feed item: not counted
	f.m.mu.Unlock()
	_ = f.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	if ev := find(f.inbox(f.app)["dev1"], ofType("vault.held")); ev != nil {
		t.Fatal("vault.held within 10 minutes")
	}
	for id, n := range f.m.st.OwnerCheck.Notices {
		n.At = n.At.Add(-11 * time.Minute)
		f.m.st.OwnerCheck.Notices[id] = n
	}
	_ = f.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	ev := find(f.inbox(f.app)["dev1"], ofType("vault.held"))
	if ev == nil {
		t.Fatal("no vault.held after the counts changed")
	}
	if w := string(ev.Body); !strings.Contains(w, `"waiting":{"messages":2,"requests":1,"calls":1,"other":1}`) || !strings.Contains(w, `"deadline"`) {
		t.Fatalf("vault.held %s", w)
	}
	// The check ends the hold: the other devices learn it.
	checkID := f.sendAs(f.app, TypeOwnerCheck, `{"ok":true}`)
	in = f.inbox(f.app, f.desk)
	if r := find(in["dev1"], reply(checkID)); errCode(r) != "" || !strings.Contains(string(r.Body), `"deadline"`) {
		t.Fatalf("check: %+v", r)
	}
	if f.oc.ended != 1 || !f.audited("owner_check.passed") {
		t.Fatalf("hold end: ended %d", f.oc.ended)
	}
	if ev := find(in["desk1"], ofType("sync.event")); ev == nil || !strings.Contains(string(ev.Body), `"kind":"owner_check"`) {
		t.Fatalf("desktop not told: %+v", ev)
	}
	if r := f.req(t, f.app, "test.req", `{}`); errCode(r) != "" {
		t.Fatalf("after the check: %q", errCode(r))
	}
	if rec := f.m.st.OwnerCheck; rec.Gate != "" || rec.Waiting != (HeldCounts{}) || rec.Deadline.Before(time.Now().Add(23*time.Hour)) {
		t.Fatalf("record after the check %+v", rec)
	}
}

// §3.6.3, §3.6.7: with the hold off the app is still gated past the
// deadline (vault.status "due"), but desktops and agents are not, and no
// hold begins; vault.held goes to the app alone. At hold_off_until the
// hold comes back on by itself (audit and feed on:expired) and the vault
// is held at once.
func TestOwnerCheckDue(t *testing.T) {
	f := newOCFixture(t)
	until := time.Now().Add(time.Hour)
	f.m.st.Settings.HoldOff, f.m.st.Settings.HoldOffUntil = true, &until
	f.pastDeadline()
	reqID := f.sendAs(f.app, "test.req", `{}`)
	in := f.inbox(f.app, f.desk)
	if r := find(in["dev1"], reply(reqID)); errCode(r) != "owner_check_required" {
		t.Fatalf("app: %q", errCode(r))
	}
	if find(in["dev1"], ofType("vault.held")) == nil || find(in["desk1"], ofType("vault.held")) != nil {
		t.Fatal("vault.held with the hold off: to the app only")
	}
	if r := f.req(t, f.desk, "test.req", `{}`); errCode(r) != "" {
		t.Fatalf("desktop with the hold off: %q", errCode(r))
	}
	if r := f.req(t, f.agent, "test.req", `{}`); errCode(r) != "" {
		t.Fatalf("agent with the hold off: %q", errCode(r))
	}
	if f.oc.started != 0 || f.audited("owner_check.held") {
		t.Fatal("hold entered with the hold off")
	}
	oc := f.status(t, f.desk)
	if st, _ := oc.String("state"); st != OwnerCheckDue || !oc.Has("hold_off_until") {
		t.Fatalf("status %v", oc)
	}
	// Fan-out: desktops as usual, the app nothing.
	f.m.mu.Lock()
	f.m.notifyDevices("sync.event", []byte(`{"kind":"settings.changed","version":1}`), "", time.Now())
	f.m.drainOutbox(context.Background())
	f.m.mu.Unlock()
	in = f.inbox(f.app, f.desk)
	if len(in["dev1"]) != 0 || len(in["desk1"]) != 1 {
		t.Fatalf("fan-out with the hold off: app %d desk %d", len(in["dev1"]), len(in["desk1"]))
	}
	v := f.m.st.Settings.Version
	until = time.Now().Add(-time.Second)
	f.m.st.Settings.HoldOffUntil = &until
	if r := f.req(t, f.desk, "test.req", `{}`); errCode(r) != "owner_check_required" {
		t.Fatalf("desktop after hold_off_until: %q", errCode(r))
	}
	if f.m.st.Settings.HoldOff || f.m.st.Settings.HoldOffUntil != nil || f.m.st.Settings.Version != v+1 || f.oc.started != 1 {
		t.Fatalf("hold not back on: %+v", f.m.st.Settings)
	}
	found := false
	for _, a := range f.oc.got {
		found = found || a.Kind == "owner_check.hold_changed" && a.Ref == "on:expired" && a.Audit && a.Feed && a.Priority == "high"
	}
	if !found {
		t.Fatal("on:expired not audited")
	}
}

// §3.6.2, §3.6.7: the interval setting (1–24 h; app only; shorter at once,
// longer from the next check) and the hold switch (on by settings.set,
// off only within a check; a desktop's change forbidden).
func TestOwnerCheckSettings(t *testing.T) {
	f := newOCFixture(t)
	set := func(td *tdev, v uint64, kv string) string {
		return errCode(f.req(t, td, "settings.set", `{"version":`+uitoa(v)+`,"set":{`+kv+`}}`))
	}
	for _, kv := range []string{`"owner_check.interval_seconds":3600`, `"owner_check.hold":true`, `"owner_check.hold_off_until":"2026-10-07T00:00:00Z"`} {
		if c := set(f.desk, 0, kv); c != "forbidden" {
			t.Fatalf("desktop %s: %q", kv, c)
		}
	}
	for kv, want := range map[string]string{
		`"owner_check.interval_seconds":3599`:                 "bad_request",
		`"owner_check.interval_seconds":86401`:                "bad_request",
		`"owner_check.hold":false`:                            "owner_check_required",
		`"owner_check.hold_off_until":"2026-10-07T00:00:00Z"`: "owner_check_required",
	} {
		if c := set(f.app, 0, kv); c != want {
			t.Fatalf("%s: %q", kv, c)
		}
	}
	r := f.req(t, f.app, "settings.get", `{}`)
	if b := string(r.Body); !strings.Contains(b, `"owner_check.hold":true`) || !strings.Contains(b, `"owner_check.interval_seconds":86400`) {
		t.Fatalf("settings.get %s", b)
	}
	rec := f.m.st.OwnerCheck
	last, dl := rec.LastAt, rec.Deadline
	if c := set(f.app, 0, `"owner_check.interval_seconds":7200`); c != "" {
		t.Fatal(c)
	}
	if !rec.Deadline.Equal(last.Add(2 * time.Hour)) {
		t.Fatalf("shorter interval: deadline %v", rec.Deadline)
	}
	if c := set(f.app, 1, `"owner_check.interval_seconds":86400`); c != "" {
		t.Fatal(c)
	}
	if !rec.Deadline.Equal(last.Add(2*time.Hour)) || rec.Deadline.Equal(dl) {
		t.Fatal("a longer interval moved the deadline")
	}
	// Shortening below the time since the last check holds at once.
	rec.LastAt = time.Now().Add(-90 * time.Minute)
	if c := set(f.app, 2, `"owner_check.interval_seconds":3600`); c != "" {
		t.Fatal(c)
	}
	if f.m.ownerCheckState(time.Now()) != OwnerCheckHeld || f.oc.started != 1 {
		t.Fatal("not held at once")
	}
	if r := f.req(t, f.app, TypeOwnerCheck, `{"ok":true,"hold":false,"until":"`+time.Now().Add(48*time.Hour).UTC().Format(time.RFC3339)+`"}`); errCode(r) != "" {
		t.Fatal(errCode(r))
	}
	if !f.m.st.Settings.HoldOff || f.m.st.Settings.HoldOffUntil == nil {
		t.Fatal("hold not off")
	}
	found := false
	for _, a := range f.oc.got {
		found = found || a.Kind == "owner_check.hold_changed" && strings.HasPrefix(a.Ref, "off_until:")
	}
	if !found {
		t.Fatal("off_until not audited")
	}
	v := f.m.st.Settings.Version
	if c := set(f.app, v, `"owner_check.hold":true`); c != "" {
		t.Fatal(c)
	}
	if f.m.st.Settings.HoldOff || f.m.st.Settings.HoldOffUntil != nil {
		t.Fatal("hold not on")
	}
	n := 0
	for _, a := range f.oc.got {
		if a.Kind == "owner_check.hold_changed" && a.Ref == "on" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("on audited %d times", n)
	}
}

// §3.6.4: failures count across locks; the tenth consecutive failed check
// audits owner_check.locked, answers, sends vault.locking{owner_check} and
// locks; the count survives and only a success resets it.
func TestOwnerCheckTenFailuresLock(t *testing.T) {
	f := newOCFixture(t)
	for i := 1; i <= 9; i++ {
		if r := f.req(t, f.app, TypeOwnerCheck, `{"ok":false}`); errCode(r) != "bad_pin" {
			t.Fatal(errCode(r))
		}
		if f.m.Locked() {
			t.Fatalf("locked after %d", i)
		}
	}
	if fs, _ := f.status(t, f.app).Uint("failures", 0, 100); fs != 9 {
		t.Fatalf("failures %d", fs)
	}
	id := f.sendAs(f.app, TypeOwnerCheck, `{"ok":false}`)
	if !f.m.Locked() {
		t.Fatal("not locked at the tenth failure")
	}
	in := f.inbox(f.app)["dev1"]
	if r := find(in, reply(id)); errCode(r) != "bad_pin" {
		t.Fatal("tenth failure not answered")
	}
	if l := find(in, ofType("vault.locking")); l == nil || !strings.Contains(string(l.Body), `"reason":"owner_check"`) {
		t.Fatalf("vault.locking %+v", l)
	}
	found := false
	for _, a := range f.oc.got {
		found = found || a.Kind == "owner_check.locked" && a.Ref == "10" && a.Priority == "urgent" && a.Feed && a.Audit
	}
	if !found {
		t.Fatal("owner_check.locked not audited")
	}
	m, _, err := f.unlock(testPIN, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if m.st.OwnerCheck.Failures != 10 {
		t.Fatalf("failures after the lock %d", m.st.OwnerCheck.Failures)
	}
}

// §3.6.1: a vault from before 0.13.0 starts its clock at its first start
// if it has a credential; without one, the first credential.create starts
// it (a new credential would start it fresh and end a hold). A vault
// without a credential is
// never gated.
func TestOwnerCheckClockStart(t *testing.T) {
	d := newDevFixture(t)
	oc := &ocFeature{noCred: true}
	d.m.addFeature(oc)
	d.m.ownerCheckInit(time.Now())
	if rec := d.m.st.OwnerCheck; rec == nil || !rec.Deadline.IsZero() {
		t.Fatalf("clock started without a credential: %+v", rec)
	}
	d.m.ownerCheckEnrolled(time.Now().Add(-48 * time.Hour))
	if d.m.ownerCheckState(time.Now()) != OwnerCheckOK {
		t.Fatal("a vault without a credential is gated")
	}
	oc.noCred = false
	d.m.refreshOwnerCred()
	if d.m.ownerCheckState(time.Now()) != OwnerCheckHeld {
		t.Fatal("not held")
	}
	d.m.ownerCheckTick(time.Now())
	d.m.st.OwnerCheck.Failures = 3
	d.m.ownerCheckEnrolled(time.Now())
	if rec := d.m.st.OwnerCheck; rec.Deadline.Before(time.Now().Add(23*time.Hour)) || rec.Failures != 0 || rec.Gate != "" ||
		d.m.ownerCheckState(time.Now()) != OwnerCheckOK {
		t.Fatalf("a new credential did not start the clock fresh: %+v", rec)
	}
	d2 := newDevFixture(t)
	d2.m.addFeature(&ocFeature{})
	d2.m.st.OwnerCheck = nil
	if err := d2.m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rec := d2.m.st.OwnerCheck; rec == nil || rec.Deadline.Before(time.Now().Add(23*time.Hour)) {
		t.Fatalf("existing vault: %+v", rec)
	}
	// Without a credential feature at all (no gate) there is no clock.
	d3 := newDevFixture(t)
	d3.m.ownerCheckInit(time.Now())
	if d3.m.st.OwnerCheck != nil {
		t.Fatal("record without a credential feature")
	}
}

// §3.6.3: the allow list's conditional rows: the alarm's path, an open
// transfer, a call answered before the deadline; the transport types.
func TestHoldAllowList(t *testing.T) {
	f := newOCFixture(t)
	f.pastDeadline()
	m := f.m
	app, desk, agent := f.app.peer, f.desk.peer, f.agent.peer
	for _, typ := range []string{TypeOwnerCheck, "vault.status", "vault.lock", "credential.utk.get", "credential.get",
		"credential.ack", "credential.version", "credential.lock", "call.end", tokenIssuedType, tokenRefreshType, "relay.address.update"} {
		if !m.holdAllows(app, typ, OwnerCheckHeld) || !m.holdAllows(app, typ, OwnerCheckDue) {
			t.Fatalf("app %s", typ)
		}
	}
	for _, typ := range []string{"credential.alarm.confirm", "credential.rotate", "device.transfer.approve", "device.transfer.reject",
		"call.ice", "call.answer", "credential.unlock", "credential.reset", "device.transfer.create", "settings.set", "vault.delete", "pin.change",
		"approval.decide", "device.session.approve", "account.get", "message.send", "location.update", "device.unlink"} {
		if m.holdAllows(app, typ, OwnerCheckHeld) {
			t.Fatalf("app %s allowed", typ)
		}
	}
	f.oc.alarm = "frozen"
	if !m.holdAllows(app, "credential.alarm.confirm", OwnerCheckHeld) || m.holdAllows(app, "credential.rotate", OwnerCheckHeld) {
		t.Fatal("frozen alarm path")
	}
	f.oc.alarm = "rotation_required"
	if !m.holdAllows(app, "credential.rotate", OwnerCheckHeld) {
		t.Fatal("rotation path")
	}
	m.st.Transfer = &Transfer{ID: "x"}
	if !m.holdAllows(app, "device.transfer.approve", OwnerCheckHeld) || !m.holdAllows(app, "device.transfer.reject", OwnerCheckHeld) {
		t.Fatal("open transfer")
	}
	for _, typ := range []string{"vault.status", "vault.lock", "device.session.end", tokenRefreshType} {
		if !m.holdAllows(desk, typ, OwnerCheckHeld) {
			t.Fatalf("desktop %s", typ)
		}
	}
	if m.holdAllows(desk, "call.ice", OwnerCheckHeld) || m.holdAllows(desk, "call.end", OwnerCheckHeld) || !m.holdAllows(desk, "message.send", OwnerCheckDue) {
		t.Fatal("desktop calls / due")
	}
	cg := &callGate{device: "desk1", at: m.st.OwnerCheck.Deadline.Add(-time.Minute)}
	m.addFeature(cg)
	if !m.holdAllows(desk, "call.ice", OwnerCheckHeld) || !m.holdAllows(desk, "call.end", OwnerCheckHeld) {
		t.Fatal("desktop's call answered before the deadline")
	}
	cg.at = m.st.OwnerCheck.Deadline.Add(time.Minute)
	if m.holdAllows(desk, "call.ice", OwnerCheckHeld) {
		t.Fatal("call answered after the deadline")
	}
	for _, typ := range []string{"vault.status", "device.session.end", "relay.address.update"} {
		if !m.holdAllows(agent, typ, OwnerCheckHeld) {
			t.Fatalf("agent %s", typ)
		}
	}
	if m.holdAllows(agent, "leash.status.get", OwnerCheckHeld) || !m.holdAllows(agent, "leash.status.get", OwnerCheckDue) {
		t.Fatal("agent leash.status.get")
	}
	// What still reaches the owner's devices while held.
	now := time.Now()
	for _, typ := range []string{"vault.held", "vault.locking", "credential.alarm", "device.transfer.pending", "device.unlinked",
		"relay.token.issued", "relay.token.refresh", "relay.address.update", "identity.rotate", "call.end", "call.ice"} {
		if !m.holdDelivers(app, typ, []byte(`{}`), now) {
			t.Fatalf("%s not delivered", typ)
		}
	}
	for _, typ := range []string{"call.offer", "message.new", "leash.grant.updated", "approval.pending", "device.pair.pending", "account.changed"} {
		if m.holdDelivers(app, typ, []byte(`{}`), now) || m.holdDelivers(agent, typ, []byte(`{}`), now) {
			t.Fatalf("%s delivered", typ)
		}
	}
	if m.holdDelivers(app, "sync.event", []byte(`{"kind":"account.changed","version":1}`), now) ||
		!m.holdDelivers(app, "feed.event", []byte(`{"kind":"credential.alarm"}`), now) {
		t.Fatal("sync/feed filter")
	}
}

type callGate struct {
	recSink
	device string
	at     time.Time
}

func (c *callGate) Name() string { return "callgate" }
func (c *callGate) CallAnsweredBefore(device string, t time.Time) bool {
	return device == c.device && c.at.Before(t)
}

// §3.6.3, §6.4: while held an incoming connection request completes its
// handshake but stays pending: in-person auto-approval does not apply, and
// the owner's devices are not told (vault.held counts it).
func TestHeldRequestNotAutoApproved(t *testing.T) {
	f := newOCFixture(t)
	f.m.st.Settings.AutoApproveInPerson = true
	f.pastDeadline()
	_ = f.m.ProcessBatch(context.Background(), &fakeCollector{}, nil) // enter the hold
	f.inbox(f.app, f.desk)
	inv := f.invite(t, KindConnection, 10*time.Minute)
	n := newNewcomer(t, 0x90)
	n.hsInit(t, f.m, handshake.PurposeConnection, inv.ID, "c2")
	n.finish(t, f.devFixture)
	if got := n.received(f.devFixture); len(got) != 0 {
		t.Fatalf("auto-approved while held: %+v", got)
	}
	if len(f.m.st.Requests) != 1 || f.m.st.OwnerCheck.Waiting.Requests != 1 {
		t.Fatalf("request not kept pending and counted: %d %+v", len(f.m.st.Requests), f.m.st.OwnerCheck.Waiting)
	}
	if ev := find(f.inbox(f.app)["dev1"], ofType("connection.request.pending")); ev != nil {
		t.Fatal("app told while held")
	}
}

// §11.13 with §3.6.3 (0.15.0): while held the op account is still stored,
// but account.get is not on the allow list and account.changed waits for
// the check.
func TestHeldAccountSnapshot(t *testing.T) {
	f := newOCFixture(t)
	f.pastDeadline()
	_ = f.m.ProcessBatch(context.Background(), &fakeCollector{}, nil) // enter the hold
	f.inbox(f.app, f.desk)
	snap := `{"v":1,"as_of":"` + envelope.FormatTS(time.Now()) + `","state":"member"}`
	if err := f.m.SetAccount(context.Background(), []byte(snap)); err != nil {
		t.Fatal(err)
	}
	if f.m.AccountVersion() != 1 {
		t.Fatal("snapshot not stored while held")
	}
	in := f.inbox(f.app, f.desk)
	if find(in["dev1"], ofType("sync.event")) != nil || find(in["desk1"], ofType("sync.event")) != nil {
		t.Fatal("account.changed delivered while held")
	}
	id := f.sendAs(f.app, "account.get", `{}`)
	if r := find(f.inbox(f.app)["dev1"], reply(id)); errCode(r) != "owner_check_required" {
		t.Fatalf("account.get while held: %+v", r)
	}
}
