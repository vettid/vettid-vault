package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/peerwire"
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
	h.AskDeclined("c1", AskBucketGeneral, []string{"auth"}, now)
	h.AskDeclined("c1", AskBucketGeneral, []string{"intro:x"}, now)
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
	h.AskDeclined("c1", AskBucketGeneral, []string{"auth"}, now)
	h.AskDeclined("c1", AskBucketGeneral, []string{"auth"}, now)
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

// 0.80.0 (§10.4.1): a held answer that fell due while the vault was
// locked is not sent by the first batch's housekeeping, before the batch's
// messages, but after the first drain (a batch of less than MaxBatch), so
// that a withdraw collected in that drain still drops it.
func TestHeldAnswersAfterFirstDrain(t *testing.T) {
	d := newDevFixture(t)
	d.addConnection("c9", 0x90)
	d.m.mu.Lock()
	d.m.opt.AskRand = func(int64) int64 { return 0 }
	d.m.st.Connections["c9"].Asks = &AskState{Muted: true}
	now := time.Now()
	for _, ref := range []string{"01JB2Z6V9K3M4N5P6Q7R8S9T0V", "01JB2Z6V9K3M4N5P6Q7R8S9T0W"} {
		(managerHost{d.m}).Ask("c9", grantAsk(ref, "x"), now.Add(-3*time.Hour))
	}
	d.m.mu.Unlock()
	if err := d.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	m, _, err := d.unlock(testPIN, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	held := func() int {
		m.mu.Lock()
		defer m.mu.Unlock()
		return len(m.st.Connections["c9"].Asks.Held)
	}
	if held() != 2 {
		t.Fatalf("%d held after the unlock", held())
	}
	// A full batch is not a drain: the answers stay held, whatever is due.
	full := make([]Message, MaxBatch)
	for i := range full {
		full[i] = Message{MsgID: "full" + string(rune('A'+i)), Sender: "!"}
	}
	_ = m.ProcessBatch(context.Background(), &fakeCollector{}, full)
	if held() != 2 {
		t.Fatalf("%d held after a full batch", held())
	}
	// A withdraw handled in the batch drops one before the rest go out.
	m.mu.Lock()
	DropHeldAnswer(m.st.Connections["c9"].Asks, "data.decided", "01JB2Z6V9K3M4N5P6Q7R8S9T0V")
	m.mu.Unlock()
	_ = m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	if held() != 0 {
		t.Fatalf("%d held after the first drain", held())
	}
	// After that, housekeeping sends what is due as before.
	m.mu.Lock()
	m.st.Connections["c9"].Asks.Held = []HeldAnswer{{Due: now, Type: "data.decided", Ref: "x"}}
	m.mu.Unlock()
	_ = m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	if held() != 0 {
		t.Fatal("a later answer was held back")
	}
}

// withdrawStub stands for features/connauth in this package (which cannot
// import it): it registers connection.authenticate.withdraw for
// connections and does what connauth does with a held answer.
type withdrawStub struct{}

func (withdrawStub) Name() string { return "connauth" }
func (withdrawStub) Types() []TypeSpec {
	return []TypeSpec{{Type: peerwire.TypeConnAuthWithdraw, From: []string{KindConnection}}}
}
func (withdrawStub) Load(json.RawMessage) error     { return nil }
func (withdrawStub) Save() (json.RawMessage, error) { return json.RawMessage(`{}`), nil }
func (withdrawStub) Handle(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	if id, ok := peerwire.ParseConnAuthWithdraw(in.Body); ok {
		s.DropHeld(s.From().ID, peerwire.TypeConnAuthResponse, id)
	}
	return nil, nil
}

// connMsg seals a message from the connection td, as it is collected.
func (d *devFixture) connMsg(t testing.TB, td *tdev, typ, body string) Message {
	t.Helper()
	d.seq++
	id, _ := envelope.NewULID(time.Now())
	raw, err := td.ep.Seal(&envelope.Inner{ID: id, Type: typ, TS: time.Now(), Body: []byte(body)})
	if err != nil {
		t.Fatal(err)
	}
	return Message{MsgID: fmt.Sprintf("w%d", d.seq), Sender: relayauth.EncodeKey(td.peer.Relay.PK), JTI: "standing-" + td.peer.ID, Payload: raw}
}

// heldFixture is a vault just "unlocked" (its first drain still to come)
// with a connection that has held neutral answers for the given refs, all
// long due.
func heldFixture(t *testing.T, refs ...string) (*devFixture, *tdev) {
	t.Helper()
	d := newDevFixture(t)
	td := d.asConnection(t, "c1", 0x70)
	d.m.mu.Lock()
	d.m.addFeature(withdrawStub{})
	d.m.drainedOnce = false
	d.m.openedAt = time.Now()
	st := &AskState{}
	for _, r := range refs {
		st.Held = append(st.Held, HeldAnswer{Due: time.Now().Add(-time.Hour), Type: peerwire.TypeConnAuthResponse, Ref: r,
			Body: peerwire.DeniedConnAuth(r).Marshal()})
	}
	d.m.st.Connections["c1"].Asks = st
	d.m.mu.Unlock()
	d.inbox(td)
	return d, td
}

func sentRefs(ins []*envelope.Inner) []string {
	var out []string
	for _, in := range ins {
		if in.Type == peerwire.TypeConnAuthResponse {
			o, _ := strictjson.ParseObject(in.Body)
			r, _ := o.String("request_id")
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

const (
	refA = "01JB2Z6V9K3M4N5P6Q7R8S9T0A"
	refB = "01JB2Z6V9K3M4N5P6Q7R8S9T0B"
	refC = "01JB2Z6V9K3M4N5P6Q7R8S9T0C"
	refX = "01JB2Z6V9K3M4N5P6Q7R8S9T0X"
)

// 0.80.0: a withdraw collected in the first drain after an unlock drops
// the due held answer of its challenge before anything goes to the peer
// (the peer gets nothing at all); with several held, only the named one is
// dropped and an unknown id drops nothing. Fails if DropHeld does nothing,
// matches without the ref, or if the answers are sent before the batch's
// messages are handled.
func TestWithdrawInFirstDrainDropsHeldAnswer(t *testing.T) {
	d, td := heldFixture(t, refB)
	msg := d.connMsg(t, td, peerwire.TypeConnAuthWithdraw, string(peerwire.ConnAuthWithdrawBody(refB)))
	if err := d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg}); err != nil {
		t.Fatal(err)
	}
	// (relay.token.issued and other upkeep may go out; no answer may.)
	if got := sentRefs(d.inbox(td)["c1"]); len(got) != 0 {
		t.Fatalf("the peer got an answer after a withdraw of its only held challenge: %v", got)
	}
	d.m.mu.Lock()
	if n := len(d.m.st.Connections["c1"].Asks.Held); n != 0 {
		t.Fatalf("%d still held", n)
	}
	d.m.mu.Unlock()

	d, td = heldFixture(t, refA, refB, refC)
	batch := []Message{
		d.connMsg(t, td, peerwire.TypeConnAuthWithdraw, string(peerwire.ConnAuthWithdrawBody(refB))), // the second, not the first
		d.connMsg(t, td, peerwire.TypeConnAuthWithdraw, string(peerwire.ConnAuthWithdrawBody(refX))), // unknown: nothing
	}
	if err := d.m.ProcessBatch(context.Background(), &fakeCollector{}, batch); err != nil {
		t.Fatal(err)
	}
	if got := sentRefs(d.inbox(td)["c1"]); len(got) != 2 || got[0] != refA || got[1] != refC {
		t.Fatalf("answers sent %v, want [%s %s]", got, refA, refC)
	}
}

// A mailbox that stays full cannot hold the answers forever: the hold
// ends HeldAnswerHoldBound after the unlock even without a drain.
func TestHeldAnswersHoldBound(t *testing.T) {
	full := func(d *devFixture) []Message {
		b := make([]Message, MaxBatch)
		for i := range b {
			b[i] = Message{MsgID: fmt.Sprintf("full%d", i), Sender: "!"}
		}
		return b
	}
	d, td := heldFixture(t, refA)
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, full(d))
	if got := sentRefs(d.inbox(td)["c1"]); len(got) != 0 {
		t.Fatalf("sent within the bound: %v", got)
	}
	d.m.mu.Lock()
	d.m.openedAt = time.Now().Add(-HeldAnswerHoldBound - time.Second)
	d.m.mu.Unlock()
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, full(d))
	if got := sentRefs(d.inbox(td)["c1"]); len(got) != 1 || got[0] != refA {
		t.Fatalf("not sent after the bound: %v", got)
	}
}
