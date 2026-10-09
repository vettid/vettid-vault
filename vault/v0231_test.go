package vault

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// VAULT-MESSAGING 0.23.1: errata to 0.23.0 from its implementation
// (vettid-vault #52), §10.4.1.

// A held answer's due time is the drawn delay, at most until 1 minute
// before the ask's exp, and never earlier than now (an ask whose exp is
// less than a minute away, or past, is answered at the next send).
func TestHeldAnswerDueClamp(t *testing.T) {
	var r recorded
	for _, c := range []struct {
		name  string
		exp   time.Duration // from now; 0: none
		delay time.Duration
		want  time.Duration
	}{
		{"no exp", 0, 20 * time.Minute, 20 * time.Minute},
		{"delay first", 30 * time.Minute, 5 * time.Minute, 5 * time.Minute},
		{"exp - 1 min first", 6 * time.Minute, 19 * time.Minute, 5 * time.Minute},
		{"exp within a minute", 30 * time.Second, time.Minute, 0},
		{"exp past", -time.Minute, time.Minute, 0},
	} {
		st := &AskState{Muted: true}
		a := grantAsk("r1", "x")
		if c.exp != 0 {
			a.Exp = askT0.Add(c.exp)
		}
		CheckAsk(st, "c1", a, 0, askT0, c.delay, r.rec)
		if len(st.Held) != 1 || !st.Held[0].Due.Equal(askT0.Add(c.want)) {
			t.Fatalf("%s: held %+v, want due %v", c.name, st.Held, askT0.Add(c.want))
		}
	}
}

// A grant request whose entries are partly in cooldown: each removed
// entry is audited drop.ask_cooldown on its own, also when the reduced
// request is then suppressed by a later check (here the pending cap).
func TestCooledEntriesAuditedWhenSuppressed(t *testing.T) {
	st := &AskState{}
	DeclineAsk(st, []string{"grant:item:A"}, askT0)
	DeclineAsk(st, []string{"grant:item:B"}, askT0)
	var r recorded
	a := grantAsk("r1", "grant:item:A", "grant:item:B", "grant:item:C")
	v := CheckAsk(st, "c1", a, AskMaxPending, askT0.Add(time.Hour), time.Minute, r.rec)
	if v.Reason != AskPending {
		t.Fatalf("verdict %+v", v)
	}
	if k := r.kinds(); len(k) != 3 || k[0] != "drop.ask_cooldown" || k[1] != "drop.ask_cooldown" || k[2] != "drop.ask_pending" {
		t.Fatalf("audit %v", k)
	}
	for _, x := range r {
		if x.Ref != "r1" || x.ConnectionID != "c1" || !x.Audit {
			t.Fatalf("entry %+v", x)
		}
	}
}

// 0.23.1 (owner decision of 2026-10-09): connection.asks.resume always
// clears the decline history and cooldowns, also on a connection that is
// not paused, and is always audited connection.asks_resumed; ask-state
// changes send sync.event{kind: "connection.changed", connection_id,
// version} to every owner device.
func TestResumeAlwaysClears(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	desk := d.addDevice(t, "app2", KindApp, 0x60) // every owner device that receives fan-out
	rec := &actSink{}
	d.m.addFeature(rec)
	d.addConnection("c1", 0x80)
	d.m.mu.Lock()
	h := managerHost{d.m}
	now := time.Now()
	h.AskDeclined("c1", []string{"auth"}, now)
	h.AskDeclined("c1", []string{"intro:x"}, now)
	st := d.m.st.Connections["c1"].Asks
	if st.Paused() || len(st.Declines) != 2 || st.cooldownsInForce(now) != 2 {
		d.m.mu.Unlock()
		t.Fatalf("setup %+v", st)
	}
	d.m.mu.Unlock()
	d.inbox(app, desk)
	for i := 0; i < 2; i++ { // the second resume finds nothing to clear
		rec.kinds = nil
		id := d.sendAs(app, "connection.asks.resume", `{"connection_id":"c1"}`)
		in := d.inbox(app, desk)
		if r := find(in["dev1"], reply(id)); r == nil || r.Status != envelope.StatusOK || string(r.Body) != `{}` {
			t.Fatalf("resume %d: %+v", i, r)
		}
		if !rec.has("connection.asks_resumed") {
			t.Fatalf("resume %d not audited", i)
		}
		for _, dev := range []string{"dev1", "app2"} {
			ev := find(in[dev], func(e *envelope.Inner) bool {
				return e.Type == "sync.event" && strings.Contains(string(e.Body), `"kind":"connection.changed"`)
			})
			if ev == nil {
				t.Fatalf("resume %d: no connection.changed to %s", i, dev)
			}
			var b map[string]json.RawMessage
			if err := json.Unmarshal(ev.Body, &b); err != nil || string(b["connection_id"]) != `"c1"` || b["version"] == nil || len(b) != 3 {
				t.Fatalf("connection.changed %s", ev.Body)
			}
		}
		d.m.mu.Lock()
		st := d.m.st.Connections["c1"].Asks
		clear := !st.Paused() && st.Declines == nil && st.Cooldowns == nil
		d.m.mu.Unlock()
		if !clear {
			t.Fatalf("resume %d left %+v", i, st)
		}
	}
	// The cleared decline history: two more declines do not pause.
	d.m.mu.Lock()
	h.AskDeclined("c1", []string{"auth"}, now)
	h.AskDeclined("c1", []string{"auth"}, now)
	paused := d.m.st.Connections["c1"].Asks.Paused()
	d.m.mu.Unlock()
	if paused {
		t.Fatal("declines before the resume still counted")
	}
}

// Held answers are kept in DEK state with the connection: one due while
// the vault is locked is sent after unlock, at the first send after it.
func TestHeldAnswerAfterUnlock(t *testing.T) {
	d := newDevFixture(t)
	d.addConnection("c9", 0x90)
	d.m.mu.Lock()
	d.m.opt.AskRand = func(int64) int64 { return 0 } // 1 minute
	d.m.st.Connections["c9"].Asks = &AskState{Muted: true}
	now := time.Now()
	a := grantAsk("01JB2Z6V9K3M4N5P6Q7R8S9T0V", "x")
	if v := (managerHost{d.m}).Ask("c9", a, now); v.Reason != AskMuted {
		d.m.mu.Unlock()
		t.Fatalf("verdict %+v", v)
	}
	d.m.mu.Unlock()
	if err := d.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	m, _, err := d.unlock(testPIN, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.st.Connections["c9"]
	if p == nil || p.Asks == nil || len(p.Asks.Held) != 1 || string(p.Asks.Held[0].Body) != string(a.Answer) ||
		!p.Asks.Held[0].Due.Equal(now.UTC().Add(time.Minute).Truncate(time.Millisecond)) {
		t.Fatalf("held answer not kept across the lock: %+v", p)
	}
	// Unlocked long after it was due: the first housekeeping sends it.
	later := now.Add(3 * time.Hour)
	if due := DueAnswers(&AskState{Held: append([]HeldAnswer(nil), p.Asks.Held...)}, later); len(due) != 1 {
		t.Fatalf("not due after unlock: %+v", due)
	}
	m.housekeeping(later)
	if len(p.Asks.Held) != 0 {
		t.Fatalf("still held after the first housekeeping: %+v", p.Asks.Held)
	}
}
