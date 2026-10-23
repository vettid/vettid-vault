package vault

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// idleFixture is an owner-check fixture on a stepped clock: the vault
// opened at t0 with its deadline a day ahead.
type idleFixture struct {
	*ocFixture
	clk time.Time
}

func newIdleFixture(t *testing.T) *idleFixture {
	f := &idleFixture{ocFixture: newOCFixture(t), clk: time.Now().UTC().Truncate(time.Millisecond)}
	f.m.opt.OwnerCheckClock = func() time.Time { return f.clk }
	f.m.mu.Lock()
	rec := f.m.st.OwnerCheck
	rec.LastAt, rec.Deadline = f.clk, f.clk.Add(24*time.Hour)
	f.m.idleLockAt(f.clk) // the opening's first look: not past its time
	f.m.mu.Unlock()
	return f
}

func (f *idleFixture) deadline() time.Time { return f.m.st.OwnerCheck.Deadline }

// poke runs one batch (a vault.status from the app) at the fixture's
// clock and returns whether the vault locked after it.
func (f *idleFixture) poke(t *testing.T) bool {
	t.Helper()
	f.sendAs(f.app, "vault.status", `{}`)
	return f.m.Locked()
}

func idleLockAtOf(t *testing.T, body []byte) time.Time {
	t.Helper()
	o, err := strictjson.ParseObject(body)
	if err != nil {
		t.Fatal(err)
	}
	if oc, err := o.Object("owner_check"); err == nil {
		o = oc
	}
	s, ok, _ := o.OptString("idle_lock_at")
	if !ok {
		return time.Time{}
	}
	at, err := envelope.ParseTS(s)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

// §3.6.8: past the deadline by idle_lock.after_seconds (7 days by
// default) the vault locks itself, with the hold on or off, sends
// vault.locking{reason: "idle"} and audits vault.locked with ref idle.
func TestIdleLockFires(t *testing.T) {
	for _, holdOff := range []bool{false, true} {
		f := newIdleFixture(t)
		f.m.st.Settings.HoldOff = holdOff
		at := f.deadline().Add(DefaultIdleLockAfter)
		f.clk = at.Add(-time.Second)
		if f.poke(t) {
			t.Fatalf("hold off %v: locked a second early", holdOff)
		}
		f.inbox(f.app, f.desk)
		f.clk = at.Add(time.Millisecond)
		if !f.poke(t) {
			t.Fatalf("hold off %v: not locked past its time", holdOff)
		}
		l := find(f.inbox(f.app)["dev1"], ofType("vault.locking"))
		if l == nil || !strings.Contains(string(l.Body), `"reason":"idle"`) {
			t.Fatalf("hold off %v: vault.locking %+v", holdOff, l)
		}
		found := false
		for _, a := range f.oc.got {
			found = found || a.Kind == "vault.locked" && a.Ref == LockIdle && a.DeviceID == "" && a.Audit
		}
		if !found {
			t.Fatalf("hold off %v: vault.locked{idle} not audited", holdOff)
		}
	}
}

// idle_lock_at in vault.status's owner_check (app and desktops, not
// agents) and in vault.held; absent for a vault without a credential.
func TestIdleLockAtReported(t *testing.T) {
	f := newIdleFixture(t)
	want := f.deadline().Add(DefaultIdleLockAfter)
	for _, td := range []*tdev{f.app, f.desk} {
		if got := idleLockAtOf(t, f.req(t, td, "vault.status", `{}`).Body); !got.Equal(want) {
			t.Fatalf("%s: idle_lock_at %v, want %v", td.peer.ID, got, want)
		}
	}
	if got := idleLockAtOf(t, f.req(t, f.agent, "vault.status", `{}`).Body); !got.IsZero() {
		t.Fatal("an agent got idle_lock_at")
	}
	f.clk = f.deadline().Add(time.Minute)
	f.poke(t)
	held := find(f.inbox(f.app)["dev1"], ofType("vault.held"))
	if held == nil || !idleLockAtOf(t, held.Body).Equal(want) {
		t.Fatalf("vault.held %+v", held)
	}

	n := newIdleFixture(t)
	n.oc.noCred = true
	n.m.mu.Lock()
	n.m.refreshOwnerCred()
	_, ok := n.m.idleLockAt(n.clk)
	n.m.mu.Unlock()
	if ok {
		t.Fatal("idle lock without a credential")
	}
	n.clk = n.deadline().Add(MaxIdleLockAfter + time.Hour)
	if n.poke(t) {
		t.Fatal("a vault without a credential locked itself")
	}
}

// After an unlock already past the time, the idle lock waits one hour
// from the unlock; a check in that hour moves it with the deadline.
func TestIdleLockAfterUnlock(t *testing.T) {
	for _, check := range []bool{false, true} {
		f := newIdleFixture(t)
		opened := f.deadline().Add(DefaultIdleLockAfter + 48*time.Hour)
		f.clk = opened
		f.m.mu.Lock()
		f.m.idleOpened, f.m.idleGrace = false, time.Time{} // a new opening (a new Manager)
		f.m.mu.Unlock()
		if f.poke(t) {
			t.Fatal("locked at the unlock")
		}
		if got := idleLockAtOf(t, f.req(t, f.app, "vault.status", `{}`).Body); !got.Equal(opened.Add(IdleLockAfterUnlock)) {
			t.Fatalf("idle_lock_at %v, want the unlock + 1 h", got)
		}
		if check {
			f.clk = opened.Add(30 * time.Minute)
			f.req(t, f.app, TypeOwnerCheck, `{"ok":true}`)
		}
		f.clk = opened.Add(IdleLockAfterUnlock - time.Second)
		if f.poke(t) {
			t.Fatal("locked inside the hour")
		}
		f.clk = opened.Add(IdleLockAfterUnlock + time.Millisecond)
		if f.poke(t) == check {
			t.Fatalf("check %v: locked %v at the hour's end", check, f.m.Locked())
		}
	}
}

// A call in progress delays the idle lock until it ends.
func TestIdleLockWaitsForCall(t *testing.T) {
	f := newIdleFixture(t)
	c := &fakeCall{on: true}
	f.m.addFeature(c)
	f.clk = f.deadline().Add(DefaultIdleLockAfter + time.Minute)
	if f.poke(t) {
		t.Fatal("a call was cut")
	}
	c.on = false
	if !f.poke(t) {
		t.Fatal("not locked once the call ended")
	}
}

type fakeCall struct{ on bool }

func (c *fakeCall) Name() string                   { return "fakecall" }
func (c *fakeCall) Types() []TypeSpec              { return nil }
func (c *fakeCall) Load(json.RawMessage) error     { return nil }
func (c *fakeCall) Save() (json.RawMessage, error) { return nil, nil }
func (c *fakeCall) CallInProgress(time.Time) bool  { return c.on }
func (c *fakeCall) Handle(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) {
	return nil, nil
}

// The setting: 3,600–2,592,000, no "never", the app only; a shorter value
// applies at once; a longer one from the next check (until then the value
// of the last one); a record from before release L counts as the default.
func TestIdleLockSetting(t *testing.T) {
	f := newIdleFixture(t)
	for _, v := range []string{"0", "3599", "2592001", "-1", `"never"`, "null"} {
		if r := f.req(t, f.app, "settings.set", `{"version":`+uitoa(f.m.st.Settings.Version)+`,"set":{"idle_lock.after_seconds":`+v+`}}`); errCode(r) != "bad_request" {
			t.Fatalf("%s: %q", v, errCode(r))
		}
	}
	if r := f.req(t, f.desk, "settings.set", `{"version":0,"set":{"idle_lock.after_seconds":3600}}`); errCode(r) != "forbidden" {
		t.Fatalf("desktop: %q", errCode(r))
	}
	set := func(secs string) {
		t.Helper()
		if r := f.req(t, f.app, "settings.set", `{"version":`+uitoa(f.m.st.Settings.Version)+`,"set":{"idle_lock.after_seconds":`+secs+`}}`); errCode(r) != "" {
			t.Fatalf("set %s: %q", secs, errCode(r))
		}
	}
	status := func() time.Time { return idleLockAtOf(t, f.req(t, f.app, "vault.status", `{}`).Body) }
	set("3600")
	if got := status(); !got.Equal(f.deadline().Add(time.Hour)) {
		t.Fatalf("shorter value not at once: %v", got)
	}
	if !strings.Contains(string(f.req(t, f.app, "settings.get", `{}`).Body), `"idle_lock.after_seconds":3600`) {
		t.Fatal("settings.get")
	}
	// A longer value waits for the next check: until then the vault uses
	// the value it had at the last one (7 days), never the new 30.
	set("2592000")
	if got := status(); !got.Equal(f.deadline().Add(DefaultIdleLockAfter)) {
		t.Fatalf("longer value before a check: %v", got)
	}
	f.req(t, f.app, TypeOwnerCheck, `{"ok":true}`)
	if got := status(); !got.Equal(f.deadline().Add(MaxIdleLockAfter)) {
		t.Fatalf("longer value after the check: %v", got)
	}
	// A record from before release L: the default stands in for its check.
	f.m.st.OwnerCheck.IdleAfter = 0
	if got := status(); !got.Equal(f.deadline().Add(DefaultIdleLockAfter)) {
		t.Fatalf("pre-L record: %v", got)
	}
	// Past the deadline the app may send only the check (§3.6.3), with
	// the hold on or off, so the setting cannot change there.
	g := newIdleFixture(t)
	g.m.st.Settings.HoldOff = true
	g.clk = g.deadline().Add(time.Minute)
	if r := g.req(t, g.app, "settings.set", `{"version":`+uitoa(g.m.st.Settings.Version)+`,"set":{"idle_lock.after_seconds":3600}}`); errCode(r) == "" {
		t.Fatal("the setting changed past the deadline")
	}
}

// STAGING-TIME-SCALE S3, S4: at time scale 24 the default is 7 h past the
// deadline and the hour after an unlock is 2.5 minutes; the setting keeps
// real units.
func TestTimeScaleIdleLock(t *testing.T) {
	f := newIdleFixture(t)
	f.m.opt.TimeScale = 24
	if got := idleLockAtOf(t, f.req(t, f.app, "vault.status", `{}`).Body); !got.Equal(f.deadline().Add(7 * time.Hour)) {
		t.Fatalf("scaled idle_lock_at %v", got)
	}
	if !strings.Contains(string(f.req(t, f.app, "settings.get", `{}`).Body), `"idle_lock.after_seconds":604800`) {
		t.Fatal("setting not in real units")
	}
	opened := f.deadline().Add(8 * time.Hour)
	f.clk = opened
	f.m.mu.Lock()
	f.m.idleOpened, f.m.idleGrace = false, time.Time{}
	at, _ := f.m.idleLockAt(opened)
	f.m.mu.Unlock()
	if !at.Equal(opened.Add(150 * time.Second)) {
		t.Fatalf("scaled hour after an unlock: %v", at.Sub(opened))
	}
}
