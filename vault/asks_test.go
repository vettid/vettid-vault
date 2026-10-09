package vault

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// VAULT-MESSAGING 0.23.0 §10.4.1: asks from a connection.

var askT0 = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

type recorded []Activity

func (r *recorded) rec(a Activity) { *r = append(*r, a) }

func (r recorded) kinds() []string {
	var out []string
	for _, a := range r {
		out = append(out, a.Kind)
	}
	return out
}

func grantAsk(ref string, idents ...string) Ask {
	return Ask{Source: "grants", Ref: ref, Idents: idents, AnswerType: "data.decided",
		Answer: json.RawMessage(`{"request_id":"` + ref + `","approved":false}`)}
}

// The checks in order: muted, paused, cooldown, pending, rate; the first
// that applies suppresses the ask and names it in drop.ask_<reason>
// (connection_id, ref = the ask's id).
func TestAskCheckOrder(t *testing.T) {
	st := &AskState{}
	now := askT0
	// Fill the rate window first (5 asks reach the member).
	var r recorded
	for i := 0; i < AskRate; i++ {
		if v := CheckAsk(st, "c1", grantAsk("r", "grant:item:x"), 0, now, time.Minute, r.rec); !v.Passed() {
			t.Fatalf("ask %d: %+v", i, v)
		}
	}
	DeclineAsk(st, []string{"grant:item:a"}, now)
	DeclineAsk(st, []string{"grant:item:b"}, now)
	DeclineAsk(st, []string{"grant:item:c"}, now) // the third: paused
	st.Muted = true
	all := grantAsk("R1", "grant:item:a")
	all.Pending = AskMaxPending
	steps := []struct {
		reason string
		lift   func()
	}{
		{AskMuted, func() { st.Muted = false }},
		{AskPaused, func() { st.PausedAt = time.Time{} }},
		{AskCooldown, func() { st.Cooldowns = nil }},
		{AskPending, func() { all.Pending = 0 }},
		{AskRated, func() { st.WindowStart = now.Add(-AskRateWindow) }},
		{"", nil},
	}
	for i, s := range steps {
		r = nil
		all.Ref = "R" + string(rune('1'+i))
		v := CheckAsk(st, "c1", all, 0, now, time.Minute, r.rec)
		if v.Reason != s.reason {
			t.Fatalf("step %d: reason %q, want %q", i, v.Reason, s.reason)
		}
		if s.reason != "" {
			if len(r) != 1 || r[0].Kind != "drop.ask_"+s.reason || r[0].ConnectionID != "c1" || r[0].Ref != all.Ref || !r[0].Audit || r[0].Feed {
				t.Fatalf("step %d: audit %+v", i, r)
			}
			s.lift()
		} else if len(r) != 0 || st.WindowN != 1 {
			t.Fatalf("a passed ask audited %v or not counted (%d)", r.kinds(), st.WindowN)
		}
	}
}

// The pending cap counts all kinds together: the source's own and the
// other features'.
func TestAskPendingCap(t *testing.T) {
	st := &AskState{}
	a := grantAsk("r1", "grant:item:x")
	a.Pending = 3
	var r recorded
	if v := CheckAsk(st, "c1", a, AskMaxPending-4, askT0, time.Minute, r.rec); !v.Passed() {
		t.Fatalf("7 pending: %+v", v)
	}
	if v := CheckAsk(st, "c1", a, AskMaxPending-3, askT0, time.Minute, r.rec); v.Reason != AskPending {
		t.Fatalf("8 pending: %+v", v)
	}
}

// The rate: 5 asks per fixed 24-hour window from the first that reached
// the member; suppressed asks do not count.
func TestAskRateWindow(t *testing.T) {
	st := &AskState{}
	var r recorded
	now := askT0
	for i := 0; i < AskRate; i++ {
		CheckAsk(st, "c1", grantAsk("r", "x"), 0, now.Add(time.Duration(i)*time.Hour), time.Minute, r.rec)
	}
	st.Muted = true
	CheckAsk(st, "c1", grantAsk("m", "x"), 0, now.Add(6*time.Hour), time.Minute, r.rec) // suppressed: not counted
	st.Muted = false
	if st.WindowN != AskRate || !st.WindowStart.Equal(now) {
		t.Fatalf("window %v %d", st.WindowStart, st.WindowN)
	}
	if v := CheckAsk(st, "c1", grantAsk("r6", "x"), 0, now.Add(AskRateWindow-time.Millisecond), time.Minute, r.rec); v.Reason != AskRated {
		t.Fatalf("6th in the window: %+v", v)
	}
	// Fixed, not sliding: a new window starts at the first ask after the
	// old one ended.
	later := now.Add(AskRateWindow)
	if v := CheckAsk(st, "c1", grantAsk("r7", "x"), 0, later, time.Minute, r.rec); !v.Passed() || !st.WindowStart.Equal(later) || st.WindowN != 1 {
		t.Fatalf("new window: %+v %v %d", v, st.WindowStart, st.WindowN)
	}
}

// The cooldown: 7 days after a decline of the same ask; a grant request
// in which only some entries are in cooldown passes without them (each
// removed entry audited drop.ask_cooldown with the request's ref); at
// most 64 cooldowns, the oldest dropped first.
func TestAskCooldown(t *testing.T) {
	st := &AskState{}
	DeclineAsk(st, []string{"grant:item:A", "grant:category:medical"}, askT0)
	var r recorded
	v := CheckAsk(st, "c1", grantAsk("r1", "grant:item:A", "grant:item:B", "grant:category:medical"), 0, askT0.Add(time.Hour), time.Minute, r.rec)
	if !v.Passed() || len(v.Cooled) != 3 || !v.Cooled[0] || v.Cooled[1] || !v.Cooled[2] {
		t.Fatalf("partial: %+v", v)
	}
	if len(r) != 2 || r[0].Kind != "drop.ask_cooldown" || r[0].Ref != "r1" || r[1].Ref != "r1" {
		t.Fatalf("removed entries audited %+v", r)
	}
	r = nil
	if v := CheckAsk(st, "c1", grantAsk("r2", "grant:item:A"), 0, askT0.Add(AskCooldownTTL-time.Millisecond), time.Minute, r.rec); v.Reason != AskCooldown {
		t.Fatalf("within 7 days: %+v", v)
	}
	if v := CheckAsk(st, "c1", grantAsk("r3", "grant:item:A"), 0, askT0.Add(AskCooldownTTL), time.Minute, r.rec); !v.Passed() {
		t.Fatalf("after 7 days: %+v", v)
	}
	if n := st.cooldownsInForce(askT0.Add(AskCooldownTTL)); n != 0 {
		t.Fatalf("%d cooldowns after they ended", n)
	}
	// 64 at most, the oldest dropped first.
	st = &AskState{}
	for i := 0; i < AskMaxCooldowns+2; i++ {
		DeclineAsk(st, []string{"action:" + string(rune('A'+i))}, askT0.Add(time.Duration(i)*time.Second))
	}
	if len(st.Cooldowns) != AskMaxCooldowns || st.Cooldowns[0].ID != "action:C" || st.cooled("action:A", askT0) {
		t.Fatalf("cap: %d, first %s", len(st.Cooldowns), st.Cooldowns[0].ID)
	}
	// A location request has no identities: no cooldown.
	st = &AskState{}
	DeclineAsk(st, []string{"x"}, askT0)
	if v := CheckAsk(st, "c1", Ask{Source: "location", Ref: "q1"}, 0, askT0, time.Minute, r.rec); !v.Passed() {
		t.Fatalf("location: %+v", v)
	}
}

// The pause: when the third decline falls within 30 days of the first of
// those three (sliding); once. Resume ends it and clears the decline
// times and cooldowns; on a connection neither paused nor in cooldown it
// changes nothing.
func TestAskPauseResume(t *testing.T) {
	st := &AskState{}
	if DeclineAsk(st, []string{"auth"}, askT0) || DeclineAsk(st, []string{"auth"}, askT0.Add(10*24*time.Hour)) {
		t.Fatal("paused before the third decline")
	}
	if DeclineAsk(st, []string{"intro"}, askT0.Add(30*24*time.Hour+time.Millisecond)) || st.Paused() {
		t.Fatal("three declines over more than 30 days paused")
	}
	if !DeclineAsk(st, []string{"intro"}, askT0.Add(31*24*time.Hour)) || !st.Paused() {
		t.Fatal("the third of three within 30 days did not pause (the window slides)")
	}
	if DeclineAsk(st, []string{"auth"}, askT0.Add(32*24*time.Hour)) {
		t.Fatal("paused twice")
	}
	if len(st.Declines) != AskPauseDeclines {
		t.Fatalf("%d decline times kept", len(st.Declines))
	}
	now := askT0.Add(32 * 24 * time.Hour)
	if !ResumeAsks(st, now) || st.Paused() || st.Declines != nil || st.Cooldowns != nil {
		t.Fatalf("resume: %+v", st)
	}
	st.Declines = []time.Time{now}
	if ResumeAsks(st, now) || len(st.Declines) != 1 {
		t.Fatal("resume changed a connection that was neither paused nor in cooldown")
	}
}

// No oracle: a suppressed ask's answer is the decline's, held for 1–20
// minutes (uniformly; at most until 1 minute before the ask's exp); at
// most 16 held per connection (beyond: no answer); a repeat of a held ask
// is ignored; a location request gets none.
func TestAskHeldAnswers(t *testing.T) {
	if d := AskDelay(func(int64) int64 { return 0 }); d != AskDelayMin {
		t.Fatalf("min %v", d)
	}
	if d := AskDelay(func(n int64) int64 { return n - 1 }); d != AskDelayMax {
		t.Fatalf("max %v", d)
	}
	for i := 0; i < 200; i++ {
		if d := AskDelay(nil); d < AskDelayMin || d > AskDelayMax {
			t.Fatalf("delay %v", d)
		}
	}
	st := &AskState{Muted: true}
	var r recorded
	a := grantAsk("r1", "x")
	CheckAsk(st, "c1", a, 0, askT0, 7*time.Minute, r.rec)
	if len(st.Held) != 1 || !st.Held[0].Due.Equal(askT0.Add(7*time.Minute)) || st.Held[0].Type != "data.decided" ||
		string(st.Held[0].Body) != string(a.Answer) {
		t.Fatalf("held %+v", st.Held)
	}
	if v := CheckAsk(st, "c1", a, 0, askT0, 7*time.Minute, r.rec); !v.Repeat || v.Passed() || len(st.Held) != 1 {
		t.Fatalf("repeat: %+v", v)
	}
	// exp: at most until 1 minute before it.
	b := grantAsk("r2", "x")
	b.Exp = askT0.Add(5 * time.Minute)
	CheckAsk(st, "c1", b, 0, askT0, 19*time.Minute, r.rec)
	if !st.Held[1].Due.Equal(askT0.Add(4 * time.Minute)) {
		t.Fatalf("clamped due %v", st.Held[1].Due)
	}
	// A location request: suppressed, audited, no answer held.
	CheckAsk(st, "c1", Ask{Source: "location", Ref: "q1"}, 0, askT0, time.Minute, r.rec)
	if len(st.Held) != 2 {
		t.Fatal("an answer held for a location request")
	}
	for i := 0; len(st.Held) < AskMaxHeld; i++ {
		CheckAsk(st, "c1", grantAsk("h"+string(rune('a'+i)), "x"), 0, askT0, time.Hour, r.rec)
	}
	r = nil
	if v := CheckAsk(st, "c1", grantAsk("over", "x"), 0, askT0, time.Hour, r.rec); v.Reason != AskMuted || len(st.Held) != AskMaxHeld || len(r) != 1 {
		t.Fatalf("17th: %+v, %d held", v, len(st.Held))
	}
	if due := DueAnswers(st, askT0.Add(7*time.Minute)); len(due) != 2 || len(st.Held) != AskMaxHeld-2 {
		t.Fatalf("due: %d, left %d", len(due), len(st.Held))
	}
}

// <connection>.asks, connection.asks.mute and .resume (app and desktop,
// no step-up, not delegable), their audit entries and sync events, and
// the held answers sent by housekeeping once due.
func TestAsksTypes(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	rec := &actSink{}
	d.m.addFeature(rec)
	d.addConnection("c1", 0x80)
	get := func() string {
		id := d.sendAs(app, "connection.get", `{"connection_id":"c1"}`)
		r := find(d.inbox(app)["dev1"], reply(id))
		if r == nil {
			t.Fatal("no connection.get answer")
		}
		o := string(r.Body)
		return o[strings.Index(o, `"asks":`):]
	}
	if s := get(); !strings.HasPrefix(s, `"asks":{"muted":false,"paused":false,"cooldowns":0}`) {
		t.Fatalf("asks %s", s)
	}
	for body, code := range map[string]string{`{"connection_id":"c1"}`: "bad_request", `{"connection_id":"c1","muted":"yes"}`: "bad_request",
		`{"connection_id":"nope","muted":true}`: "not_found"} {
		id := d.sendAs(app, "connection.asks.mute", body)
		if r := find(d.inbox(app)["dev1"], reply(id)); errCode(r) != code {
			t.Fatalf("%s: %+v", body, r)
		}
	}
	id := d.sendAs(app, "connection.asks.resume", `{"connection_id":"nope"}`)
	if r := find(d.inbox(app)["dev1"], reply(id)); errCode(r) != "not_found" {
		t.Fatalf("resume unknown: %+v", r)
	}
	id = d.sendAs(app, "connection.asks.mute", `{"connection_id":"c1","muted":true}`)
	in := d.inbox(app)["dev1"]
	if r := find(in, reply(id)); r == nil || r.Status != envelope.StatusOK || string(r.Body) != `{}` {
		t.Fatalf("mute: %+v", r)
	}
	if find(in, func(e *envelope.Inner) bool {
		return e.Type == "sync.event" && strings.Contains(string(e.Body), `"kind":"connection.changed","connection_id":"c1"`)
	}) == nil {
		t.Fatal("no connection.changed")
	}
	if !rec.has("connection.asks_muted") || !strings.HasPrefix(get(), `"asks":{"muted":true,"paused":false,"cooldowns":0}`) {
		t.Fatal("mute not audited or not shown")
	}
	// Resume on a connection neither paused nor in cooldown changes
	// nothing (no audit entry).
	d.sendAs(app, "connection.asks.resume", `{"connection_id":"c1"}`)
	d.inbox(app)
	if rec.has("connection.asks_resumed") {
		t.Fatal("a resume that changed nothing was audited")
	}
	// Three declines pause: one connection.asks_paused (high, feed).
	d.m.mu.Lock()
	h := managerHost{d.m}
	now := time.Now()
	for i := 0; i < 3; i++ {
		h.AskDeclined("c1", []string{"auth"}, now)
	}
	d.m.mu.Unlock()
	d.inbox(app)
	paused := 0
	for _, a := range rec.kinds {
		if a == "connection.asks_paused" {
			paused++
		}
	}
	if paused != 1 {
		t.Fatalf("%d connection.asks_paused", paused)
	}
	if s := get(); !strings.Contains(s, `"paused":true,"paused_at":"`) || !strings.Contains(s, `"cooldowns":1}`) {
		t.Fatalf("paused asks %s", s)
	}
	// Unmuting does not resume a pause; resume does, and clears.
	d.sendAs(app, "connection.asks.mute", `{"connection_id":"c1","muted":false}`)
	d.sendAs(app, "connection.asks.resume", `{"connection_id":"c1"}`)
	d.inbox(app)
	if !rec.has("connection.asks_unmuted") || !rec.has("connection.asks_resumed") ||
		!strings.HasPrefix(get(), `"asks":{"muted":false,"paused":false,"cooldowns":0}`) {
		t.Fatal("unmute / resume")
	}
	// Neither type is delegable: no agent may send them.
	for _, typ := range []string{"connection.asks.mute", "connection.asks.resume"} {
		if e := d.m.registry[typ]; e == nil || e.allows(KindAgent) || e.allows(KindConnection) || !e.allows(KindDesktop) || e.spec.DesktopApproval {
			t.Fatalf("%s: %+v", typ, e)
		}
	}
}

// Housekeeping sends a held answer once due (and not before), to the
// connection only; the pending cap sums the other features' asks
// (AskSource), never asking the source itself.
func TestAskHeldAnswerSent(t *testing.T) {
	d := newDevFixture(t)
	rec := &actSink{}
	d.m.addFeature(rec)
	td := d.addDevice(t, "c9", KindApp, 0x70)
	d.m.mu.Lock()
	p := d.m.st.Devices["c9"]
	delete(d.m.st.Devices, "c9")
	p.Kind = KindConnection
	d.m.st.Connections["c9"] = p
	src := &askSrc{n: 5}
	d.m.features = append(d.m.features, src, &askSrc{name: "grants", n: 100})
	now := time.Now()
	a := grantAsk("01JB2Z6V9K3M4N5P6Q7R8S9T0V", "x")
	a.Pending = 2
	d.m.opt.AskRand = func(int64) int64 { return 0 } // 1 minute
	v := managerHost{d.m}.Ask("c9", a, now)
	if v.Reason != "" {
		t.Fatalf("2 + 5 pending: %+v", v)
	}
	a.Pending = 3
	a.Ref = "01JB2Z6V9K3M4N5P6Q7R8S9T0W"
	a.Answer = json.RawMessage(`{"request_id":"` + a.Ref + `","approved":false}`)
	if v := (managerHost{d.m}).Ask("c9", a, now); v.Reason != AskPending {
		t.Fatalf("3 + 5 pending: %+v", v)
	}
	d.m.housekeeping(now.Add(59 * time.Second))
	d.m.drainOutbox(context.Background())
	d.m.mu.Unlock()
	decided := func() []*envelope.Inner {
		var out []*envelope.Inner
		for _, e := range d.inbox(td)["c9"] {
			if e.Type == "data.decided" {
				out = append(out, e)
			}
		}
		return out
	}
	if in := decided(); len(in) != 0 {
		t.Fatalf("answered before the delay: %v", in)
	}
	d.m.mu.Lock()
	d.m.housekeeping(now.Add(time.Minute))
	d.m.drainOutbox(context.Background())
	d.m.mu.Unlock()
	in := decided()
	if len(in) != 1 || in[0].Type != "data.decided" || string(in[0].Body) != string(a.Answer) {
		t.Fatalf("held answer: %+v", in)
	}
	if !rec.has("drop.ask_pending") {
		t.Fatal("not audited")
	}
}

type askSrc struct {
	name string
	n    int
}

func (a *askSrc) Name() string {
	if a.name == "" {
		return "other"
	}
	return a.name
}
func (a *askSrc) Types() []TypeSpec { return nil }
func (a *askSrc) Handle(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) {
	return nil, nil
}
func (a *askSrc) Load(json.RawMessage) error        { return nil }
func (a *askSrc) Save() (json.RawMessage, error)    { return json.RawMessage(`{}`), nil }
func (a *askSrc) PendingAsks(string, time.Time) int { return a.n }

// actSink records the activities' kinds.
type actSink struct{ kinds []string }

func (a *actSink) Name() string      { return "actsink" }
func (a *actSink) Types() []TypeSpec { return nil }
func (a *actSink) Handle(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) {
	return nil, nil
}
func (a *actSink) Load(json.RawMessage) error            { return nil }
func (a *actSink) Save() (json.RawMessage, error)        { return json.RawMessage(`{}`), nil }
func (a *actSink) RecordActivity(_ *Session, x Activity) { a.kinds = append(a.kinds, x.Kind) }

func (a *actSink) has(kind string) bool {
	for _, k := range a.kinds {
		if k == kind {
			return true
		}
	}
	return false
}
