package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// callHeldFeature stands in for the calls feature (0.97.0 §10.10): test.callstart answers with a TURN credential
// held in memory for the call, cached as a copy without it; test.callring sends every device an offer held for
// the call, then a memory-only (ephemeral) message and a durable one. With ahead, a durable message goes first.
// held decides CallHeld: call id -> "lasts" or "rings" (missing: gone).
type callHeldFeature struct {
	calls int
	ahead bool
	held  map[string]string
}

func (f *callHeldFeature) Name() string { return "callheldstub" }
func (f *callHeldFeature) Types() []TypeSpec {
	return []TypeSpec{{Type: "test.callstart", Request: true, From: []string{KindApp}},
		{Type: "test.callring", Request: true, From: []string{KindApp}}}
}
func (f *callHeldFeature) Load(json.RawMessage) error     { return nil }
func (f *callHeldFeature) Save() (json.RawMessage, error) { return nil, nil }
func (f *callHeldFeature) Handle(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	f.calls++
	if f.ahead {
		s.NotifyAllDevices("sync.event", json.RawMessage(`{"kind":"ahead"}`))
	}
	switch in.Type {
	case "test.callstart":
		f.held["c1"] = "lasts"
		s.CacheResponseAsHeldForCall(json.RawMessage(`{"withheld":true}`), "c1")
		return json.RawMessage(`{"turn":"SECRET-TURN-ANSWER"}`), nil
	default:
		f.held["c2"] = "rings"
		s.NotifyDevicesWith("call.offer", json.RawMessage(`{"turn":"SECRET-TURN-OFFER"}`), "",
			SendOptions{Exp: s.Now().Add(45 * time.Second), Call: "c2"})
		s.NotifyDevicesWith("call.ice", json.RawMessage(`{"after":"ephemeral"}`), "",
			SendOptions{Exp: s.Now().Add(time.Minute), MemoryOnly: true})
		s.NotifyAllDevices("sync.event", json.RawMessage(`{"kind":"after"}`))
		return json.RawMessage(`{}`), nil
	}
}
func (f *callHeldFeature) CallHeld(id string, offer bool, _ time.Time) bool {
	h := f.held[id]
	return h == "rings" || h == "lasts" && !offer
}

func newCallHeld(t *testing.T) (*devFixture, *callHeldFeature) {
	d := newDevFixture(t)
	f := &callHeldFeature{held: map[string]string{}}
	d.m.addFeature(f)
	return d, f
}

// noSecretStored checks that no stored deposit and nothing in the state holds a held call message, while the
// durable message ahead of it to the same mailbox is stored (the positive control), and that its marker is.
func noSecretStored(t *testing.T, d *devFixture, id string) {
	t.Helper()
	control := false
	for _, in := range storedDeposits(t, d.m, d.devPeer) {
		if bytes.Contains(in.Body, []byte("SECRET")) || id != "" && in.Re == id {
			t.Fatalf("a stored deposit holds a held call message: %s", in.Body)
		}
		control = control || bytes.Contains(in.Body, []byte(`"ahead"`))
	}
	if !control {
		t.Fatal("the durable message ahead is not stored: the check proves nothing")
	}
	d.m.mu.Lock()
	st, _ := json.Marshal(d.m.st)
	markers := 0
	for _, e := range d.m.st.Outbox {
		if e.CallHeld && !e.Done {
			markers++
			if len(e.Payload) != 0 || e.Held != nil {
				t.Fatal("a marker carries a payload")
			}
		}
	}
	d.m.mu.Unlock()
	if strings.Contains(string(st), "SECRET") {
		t.Fatal("the state holds the credential")
	}
	if markers == 0 {
		t.Fatal("no marker holds the held message's place")
	}
}

// 0.97.0 §10.10: a call.start answer with a TURN credential is in no stored deposit and not in the state; it is
// deposited again from memory once the relay is back, after the durable message queued ahead of it; and a
// retransmission while the call lasts gets the live answer again, with the same inner id, without running the
// handler.
func TestCallHeldAnswerRetriedFromMemory(t *testing.T) {
	d, f := newCallHeld(t)
	f.ahead = true
	app := d.self()
	d.relay.failMailbox = map[string]error{d.devPeer.Relay.Mailbox: errors.New("relay down")}
	id := d.sendAs(app, "test.callstart", `{}`)
	noSecretStored(t, d, id)
	d.sendID(app, id, "test.callstart", `{}`) // a retransmission while the answer still waits: nothing more is queued
	noSecretStored(t, d, id)
	d.relay.failMailbox = nil
	d.inbox(app)
	retryNow(d.m)
	got := d.inbox(app)["dev1"]
	ahead, answer := -1, -1
	var liveID string
	for i, in := range got {
		switch {
		case bytes.Contains(in.Body, []byte(`"ahead"`)):
			ahead = i
		case in.Re == id:
			if answer >= 0 || string(in.Body) != `{"turn":"SECRET-TURN-ANSWER"}` {
				t.Fatalf("answer %d: %s", answer, in.Body)
			}
			answer, liveID = i, in.ID
		}
	}
	if ahead < 0 || answer < ahead {
		t.Fatalf("order: ahead at %d, answer at %d", ahead, answer)
	}
	retryNow(d.m)
	if n := len(d.inbox(app)["dev1"]); n != 0 {
		t.Fatalf("delivered again with nothing asked: %d", n)
	}
	d.sendID(app, id, "test.callstart", `{}`)
	again := find(d.inbox(app)["dev1"], reply(id))
	if again == nil || string(again.Body) != `{"turn":"SECRET-TURN-ANSWER"}` || again.ID != liveID || f.calls != 1 {
		t.Fatalf("retransmission: %+v (calls %d)", again, f.calls)
	}
	// The call ends: the next drain wipes the answer held for it, with nothing asked.
	delete(f.held, "c1")
	d.m.drainOutbox(context.Background())
	d.m.mu.Lock()
	n := len(d.m.callMsgs)
	d.m.mu.Unlock()
	if n != 0 {
		t.Fatal("the answer is still held after its call ended")
	}
}

// Once the vault no longer holds the call (it ended), a retransmission gets the cached copy, withheld; after a
// stop (the messages in memory gone), too, and the marker left in the stored outbox holds nothing back.
func TestCallHeldAnswerCopyOnceTheCallIsGone(t *testing.T) {
	for _, gone := range []string{"ended", "stopped"} {
		t.Run(gone, func(t *testing.T) {
			d, f := newCallHeld(t)
			app := d.self()
			d.relay.failMailbox = map[string]error{d.devPeer.Relay.Mailbox: errors.New("relay down")}
			id := d.sendAs(app, "test.callstart", `{}`)
			d.m.mu.Lock()
			for _, e := range d.m.st.Outbox {
				if e.CallHeld && (e.Attempts == 0 || e.Payload != nil) {
					t.Fatalf("the marker was not tried, or keeps the sealed bytes after its failed attempt (%d)", e.Attempts)
				}
			}
			d.m.mu.Unlock()
			d.relay.failMailbox = nil
			if gone == "ended" {
				delete(f.held, "c1")
			} else {
				d.m.mu.Lock()
				d.m.dropCallMsgs() // what a restart leaves: the marker, stored, and nothing in memory
				d.m.mu.Unlock()
			}
			d.inbox(app)
			d.sendID(app, id, "test.callstart", `{}`)
			retryNow(d.m)
			var answers []string
			for _, in := range d.inbox(app)["dev1"] {
				if in.Re == id {
					answers = append(answers, string(in.Body))
				}
			}
			if len(answers) != 1 || answers[0] != `{"withheld":true}` || f.calls != 1 {
				t.Fatalf("answers %v (calls %d)", answers, f.calls)
			}
			d.m.mu.Lock()
			defer d.m.mu.Unlock()
			for _, e := range d.m.st.Outbox {
				if e.CallHeld && !e.Done {
					t.Fatal("a marker without its message is still pending")
				}
			}
			if len(d.m.callMsgs) != 0 {
				t.Fatalf("%d messages still held", len(d.m.callMsgs))
			}
		})
	}
}

// A V→D offer with a TURN credential: not stored; its failed deposit is tried again from memory with the same
// inner id; the memory-only message and the durable one queued after it wait behind it (neither is lost or goes
// first); once delivered, it is gone from memory.
func TestCallHeldOfferRetriedAndAheadOfLaterDeposits(t *testing.T) {
	d, f := newCallHeld(t)
	f.ahead = true
	app := d.self()
	d.relay.failMailbox = map[string]error{d.devPeer.Relay.Mailbox: errors.New("relay down")}
	d.sendAs(app, "test.callring", `{}`)
	noSecretStored(t, d, "")
	d.m.mu.Lock()
	kept := len(d.m.volatile)
	d.m.mu.Unlock()
	if kept == 0 {
		t.Fatal("the memory-only message behind the offer was lost")
	}
	d.relay.failMailbox = nil
	d.inbox(app)
	retryNow(d.m)
	d.m.drainOutbox(context.Background()) // the memory-only one goes after the offer's own drain
	var order []string
	for _, in := range d.inbox(app)["dev1"] {
		switch {
		case in.Type == "call.offer":
			order = append(order, "offer")
			if string(in.Body) != `{"turn":"SECRET-TURN-OFFER"}` {
				t.Fatalf("offer %s", in.Body)
			}
		case in.Type == "call.ice":
			order = append(order, "ephemeral")
		case bytes.Contains(in.Body, []byte(`"after"`)):
			order = append(order, "after")
		case bytes.Contains(in.Body, []byte(`"ahead"`)):
			order = append(order, "ahead")
		}
	}
	if strings.Join(order, ",") != "ahead,offer,after,ephemeral" {
		t.Fatalf("order %v", order)
	}
	d.m.mu.Lock()
	n := len(d.m.callMsgs)
	d.m.mu.Unlock()
	if n != 0 {
		t.Fatal("a delivered offer is still held")
	}
}

// An offer whose call no longer rings is not deposited: its marker ends, and what waits behind it goes.
func TestCallHeldOfferNotSentOnceTheCallNoLongerRings(t *testing.T) {
	d, f := newCallHeld(t)
	app := d.self()
	d.relay.failMailbox = map[string]error{d.devPeer.Relay.Mailbox: errors.New("relay down")}
	d.sendAs(app, "test.callring", `{}`)
	d.relay.failMailbox = nil
	delete(f.held, "c2")
	d.inbox(app)
	retryNow(d.m)
	d.m.drainOutbox(context.Background())
	got := d.inbox(app)["dev1"]
	if find(got, ofType("call.offer")) != nil {
		t.Fatal("an offer went for a call that no longer rings")
	}
	if find(got, ofType("call.ice")) == nil || find(got, ofType("sync.event")) == nil {
		t.Fatal("what waited behind the offer was not delivered")
	}
}

// At a lock the held call messages are dropped first: vault.locking does not wait behind an offer whose deposit
// failed, and the offer is never sent.
func TestCallHeldDroppedAtLock(t *testing.T) {
	d, _ := newCallHeld(t)
	app := d.self()
	d.relay.failMailbox = map[string]error{d.devPeer.Relay.Mailbox: errors.New("relay down")}
	d.sendAs(app, "test.callring", `{}`)
	d.relay.failMailbox = nil
	d.inbox(app)
	if err := d.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := d.inbox(app)["dev1"]
	if find(got, ofType("vault.locking")) == nil {
		t.Fatalf("vault.locking waited behind the held offer: %d deposits", len(got))
	}
	if find(got, ofType("call.offer")) != nil {
		t.Fatal("the held offer was sent at the lock")
	}
}
