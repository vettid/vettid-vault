package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayclient"
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
	last  []byte // the last answer test.callstart returned
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
		f.last = []byte(`{"turn":"SECRET-TURN-ANSWER"}`)
		return f.last, nil
	default:
		f.held["c2"] = "rings"
		s.NotifyDevicesWith("call.offer", json.RawMessage(`{"call_id":"c2","turn":"SECRET-TURN-OFFER"}`), "",
			SendOptions{Exp: s.Now().Add(45 * time.Second), Call: "c2"})
		s.NotifyDevicesWith("call.ice", json.RawMessage(`{"after":"ephemeral","n":`+strconv.Itoa(f.calls)+`}`), "",
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
	retryNow(d.m) // one drain: the offer, then the durable and the memory-only messages behind it
	var order []string
	for _, in := range d.inbox(app)["dev1"] {
		switch {
		case in.Type == "call.offer":
			order = append(order, "offer")
			if string(in.Body) != `{"call_id":"c2","turn":"SECRET-TURN-OFFER"}` {
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

// A call.start answer the vault cannot hold (the device suspended on fork evidence) is lost, never queued durably:
// no stored deposit and nothing in the state holds it, and a retransmission once the device is back gets the copy.
func TestCallHeldAnswerNotHeldNeverStored(t *testing.T) {
	d, f := newCallHeld(t)
	app := d.self()
	d.m.mu.Lock()
	d.devPeer.Fork = &ForkSuspension{}
	d.m.mu.Unlock()
	id := d.sendAs(app, "test.callstart", `{}`)
	if f.calls != 1 {
		t.Fatalf("calls %d: the check proves nothing", f.calls)
	}
	d.m.mu.Lock()
	held := len(d.m.callMsgs)
	st, _ := json.Marshal(d.m.st)
	for _, e := range d.m.st.Outbox {
		if e.PeerID == d.devPeer.ID && !e.Done && e.Op == OpDeposit {
			t.Fatalf("an entry was queued for the suspended device: %+v", e)
		}
	}
	d.devPeer.Fork = nil
	d.m.mu.Unlock()
	if held != 0 || strings.Contains(string(st), "SECRET") {
		t.Fatalf("held %d, or the state holds the credential", held)
	}
	d.inbox(app)
	d.sendID(app, id, "test.callstart", `{}`)
	retryNow(d.m)
	again := find(d.inbox(app)["dev1"], reply(id))
	if again == nil || string(again.Body) != `{"withheld":true}` || f.calls != 1 {
		t.Fatalf("retransmission: %+v (calls %d)", again, f.calls)
	}
}

// A terminal answer for the device's mailbox ends a held message's marker at once (no retry), and an offer is
// wiped with it.
func TestCallHeldTerminalAnswerEndsIt(t *testing.T) {
	for _, code := range []string{CodeMailboxUnknown, CodeTokenRevoked} {
		for _, typ := range []string{"test.callstart", "test.callring"} {
			t.Run(code+"/"+typ, func(t *testing.T) {
				d, _ := newCallHeld(t)
				app := d.self()
				tries := 0
				d.relay.check = func(mailbox, _ string) error {
					if mailbox != d.devPeer.Relay.Mailbox {
						return nil
					}
					tries++
					return &relayclient.Error{Status: 404, Code: code}
				}
				d.sendAs(app, typ, `{}`)
				retryNow(d.m)
				if tries == 0 {
					t.Fatal("never tried: the check proves nothing")
				}
				first := tries
				retryNow(d.m)
				d.m.mu.Lock()
				defer d.m.mu.Unlock()
				for _, e := range d.m.st.Outbox {
					if e.CallHeld && !e.Done {
						t.Fatalf("the marker still waits after %s: %+v", code, e)
					}
				}
				if tries != first {
					t.Fatalf("tried again after %s: %d, then %d", code, first, tries)
				}
				if typ == "test.callring" && len(d.m.callMsgs) != 0 {
					t.Fatal("the offer is still held after a terminal answer")
				}
			})
		}
	}
}

// The handler's bytes with the credential are wiped once copied into memory; a dropped message's body is wiped;
// zeroize drops them all.
func TestCallHeldWiped(t *testing.T) {
	d, f := newCallHeld(t)
	app := d.self()
	d.relay.failMailbox = map[string]error{d.devPeer.Relay.Mailbox: errors.New("relay down")}
	d.sendAs(app, "test.callstart", `{}`)
	d.m.mu.Lock()
	var body []byte
	for _, cm := range d.m.callMsgs {
		body = cm.inner.Body
	}
	d.m.mu.Unlock()
	if !bytes.Contains(body, []byte("SECRET")) {
		t.Fatal("nothing held: the check proves nothing")
	}
	if !bytes.Equal(f.last, make([]byte, len(f.last))) || len(f.last) == 0 {
		t.Fatalf("the handler's answer was not wiped: %q", f.last)
	}
	delete(f.held, "c1")
	d.m.drainOutbox(context.Background())
	if !bytes.Equal(body, make([]byte, len(body))) {
		t.Fatal("the dropped message's body was not wiped")
	}
	f.held["c1"] = "lasts"
	d.sendAs(app, "test.callring", `{}`)
	d.m.mu.Lock()
	n := len(d.m.callMsgs)
	d.m.zeroize()
	left := d.m.callMsgs
	d.m.mu.Unlock()
	if n == 0 || left != nil {
		t.Fatalf("held %d before zeroize, %d after", n, len(left))
	}
}

// An offer whose marker another path ended (the device removed or suspended) is wiped at the next drain, while
// its call still rings.
func TestCallHeldOfferWipedWhenItsMarkerEnds(t *testing.T) {
	d, _ := newCallHeld(t)
	app := d.self()
	d.relay.failMailbox = map[string]error{d.devPeer.Relay.Mailbox: errors.New("relay down")}
	d.sendAs(app, "test.callring", `{}`)
	d.m.mu.Lock()
	ended := 0
	for _, e := range d.m.st.Outbox {
		if e.CallHeld && !e.Done {
			e.Done = true
			ended++
		}
	}
	held := len(d.m.callMsgs)
	d.m.mu.Unlock()
	if ended != 1 || held != 1 {
		t.Fatalf("markers %d, held %d: the check proves nothing", ended, held)
	}
	d.m.drainOutbox(context.Background())
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	if len(d.m.callMsgs) != 0 {
		t.Fatal("the offer is still held after its marker ended")
	}
}

// A deletion drops the held call messages first: step 2's drain sends no offer, and the deletion's notice goes.
func TestCallHeldDroppedAtDeletion(t *testing.T) {
	d, _ := newCallHeld(t)
	app := d.self()
	d.relay.failMailbox = map[string]error{d.devPeer.Relay.Mailbox: errors.New("relay down")}
	d.sendAs(app, "test.callring", `{}`)
	d.relay.failMailbox = nil
	d.inbox(app)
	if err := d.m.Delete(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := d.inbox(app)["dev1"]
	if find(got, ofType("call.offer")) != nil {
		t.Fatal("the held offer was sent at the deletion")
	}
	if find(got, ofType("device.unlinked")) == nil {
		t.Fatalf("the deletion's notice waited behind the held offer: %d deposits", len(got))
	}
}

// A held message that can't be sealed (no current epoch for the device) ends at once, dropped and not sent, and
// holds nothing behind it.
func TestCallHeldUnsealableEnds(t *testing.T) {
	d, _ := newCallHeld(t)
	app := d.self()
	d.relay.failMailbox = map[string]error{d.devPeer.Relay.Mailbox: errors.New("relay down")}
	d.sendAs(app, "test.callring", `{}`)
	d.relay.failMailbox = nil
	d.m.mu.Lock()
	kr := d.m.sessions[d.devPeer.ID]
	delete(d.m.sessions, d.devPeer.ID)
	d.m.mu.Unlock()
	d.inbox(app)
	retryNow(d.m)
	got := d.inbox(app)["dev1"]
	d.m.mu.Lock()
	d.m.sessions[d.devPeer.ID] = kr
	for _, e := range d.m.st.Outbox {
		if e.CallHeld && !e.Done {
			t.Fatal("an unsealable marker still waits")
		}
	}
	n := len(d.m.callMsgs)
	d.m.mu.Unlock()
	if n != 0 || find(got, ofType("call.offer")) != nil {
		t.Fatalf("held %d after a failed seal", n)
	}
	if find(got, ofType("sync.event")) == nil {
		t.Fatal("the durable message behind it did not go")
	}
}

// While the last state write failed, a marker is not deposited (it waits, in order); after a write, it goes.
func TestCallHeldWaitsWhileTheStateIsBehind(t *testing.T) {
	d, _ := newCallHeld(t)
	app := d.self()
	d.relay.failMailbox = map[string]error{d.devPeer.Relay.Mailbox: errors.New("relay down")}
	d.sendAs(app, "test.callring", `{}`)
	d.relay.failMailbox = nil
	d.m.mu.Lock()
	d.m.stateBehind = true
	d.m.mu.Unlock()
	d.inbox(app)
	retryNow(d.m)
	if got := d.inbox(app)["dev1"]; find(got, ofType("call.offer")) != nil || find(got, ofType("sync.event")) != nil {
		t.Fatal("deposited while the state is behind")
	}
	d.m.mu.Lock()
	d.m.stateBehind = false
	d.m.mu.Unlock()
	retryNow(d.m)
	if find(d.inbox(app)["dev1"], ofType("call.offer")) == nil {
		t.Fatal("not deposited once the state caught up")
	}
}

// The sealed bytes of a held message are wiped once deposited (the relay is handed the very slice).
func TestCallHeldSealedBytesWiped(t *testing.T) {
	d, _ := newCallHeld(t)
	app := d.self()
	var seen [][]byte
	d.relay.checkPayload = func(mailbox, _ string, payload []byte) error {
		if mailbox == d.devPeer.Relay.Mailbox {
			seen = append(seen, payload)
		}
		return nil
	}
	d.sendAs(app, "test.callring", `{}`)
	if find(d.inbox(app)["dev1"], ofType("call.offer")) == nil {
		t.Fatal("no offer: the check proves nothing")
	}
	zero := 0
	for _, p := range seen {
		if len(p) > 0 && bytes.Equal(p, make([]byte, len(p))) {
			zero++
		}
	}
	if zero != 2 {
		t.Fatalf("%d of %d deposits wiped, want the held offer's and the memory-only message's", zero, len(seen))
	}
}

// Memory-only messages kept behind a held message go in the order they were made, older batches first; those
// kept past a minute, or past the count, are lost as before.
func TestCallHeldKeptInOrderAndBounded(t *testing.T) {
	d, _ := newCallHeld(t)
	app := d.self()
	d.relay.failMailbox = map[string]error{d.devPeer.Relay.Mailbox: errors.New("relay down")}
	d.sendAs(app, "test.callring", `{}`)
	d.sendAs(app, "test.callring", `{}`)
	d.relay.failMailbox = nil
	d.inbox(app)
	retryNow(d.m)
	var ns []string
	for _, in := range d.inbox(app)["dev1"] {
		if in.Type == "call.ice" {
			ns = append(ns, string(in.Body))
		}
	}
	if len(ns) != 2 || !strings.Contains(ns[0], `"n":1`) || !strings.Contains(ns[1], `"n":2`) {
		t.Fatalf("kept messages %v", ns)
	}

	d.relay.failMailbox = map[string]error{d.devPeer.Relay.Mailbox: errors.New("relay down")}
	d.sendAs(app, "test.callring", `{}`)
	d.m.mu.Lock()
	for _, e := range d.m.volatile {
		e.Created = e.Created.Add(-2 * keptMaxAge)
	}
	for range keptMax + 10 {
		d.m.volatile = append(d.m.volatile, &OutboxEntry{ID: "x", Op: OpDeposit, PeerID: d.devPeer.ID, RelayURL: d.devPeer.Relay.URL,
			Mailbox: d.devPeer.Relay.Mailbox, Payload: []byte("p"), BestEffort: true, Created: d.m.now()})
	}
	d.m.mu.Unlock()
	d.m.drainOutbox(context.Background())
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	if len(d.m.volatile) != keptMax {
		t.Fatalf("%d kept, want %d (the old one and those past the count lost)", len(d.m.volatile), keptMax)
	}
	for _, e := range d.m.volatile {
		if e.ID != "x" {
			t.Fatal("a message kept past a minute")
		}
	}
}

// The offer's marker carries the offer's wake class (§14.2 trigger 5); an offer held for a call goes to apps and
// desktops only.
func TestCallHeldOfferWakeAndKinds(t *testing.T) {
	d, _ := newCallHeld(t)
	app := d.self()
	d.m.mu.Lock()
	d.m.st.Push = &PushRegistration{DeviceID: d.devPeer.ID}
	d.m.mu.Unlock()
	d.relay.failMailbox = map[string]error{d.devPeer.Relay.Mailbox: errors.New("relay down")}
	d.sendAs(app, "test.callring", `{}`)
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	wake := ""
	for _, e := range d.m.st.Outbox {
		if e.CallHeld {
			wake = e.Wake
		}
	}
	if wake != wakeCall+":c2" {
		t.Fatalf("the marker's wake %q", wake)
	}
	agent := *d.devPeer
	agent.ID, agent.Kind = "agent1", KindAgent
	d.m.sessions["agent1"] = d.m.sessions[d.devPeer.ID]
	defer delete(d.m.sessions, "agent1")
	before := len(d.m.callMsgs)
	if id := d.m.sendWith(&agent, "call.offer", json.RawMessage(`{"call_id":"c2"}`), SendOptions{Call: "c2"}, d.m.now()); id != "" ||
		len(d.m.callMsgs) != before {
		t.Fatal("an offer held for an agent")
	}
}
