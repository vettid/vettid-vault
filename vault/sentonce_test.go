package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// sentOnceFeature stands in for a LEASH value answer (0.97.0 §8.2 "Sent once
// from memory"): it answers with a secret, caches a copy without it and marks
// the answer sent once. With notify, it first queues a durable event to every
// device, so the answer has a stored deposit to the same mailbox ahead of it.
type sentOnceFeature struct {
	calls  int
	notify bool
}

func (f *sentOnceFeature) Name() string { return "sentoncestub" }
func (f *sentOnceFeature) Types() []TypeSpec {
	return []TypeSpec{{Type: "test.sentonce", Request: true, From: []string{KindApp}},
		{Type: "test.sentonceheld", Request: true, From: []string{KindApp, KindDesktop}, DesktopApproval: true}}
}
func (f *sentOnceFeature) Load(json.RawMessage) error     { return nil }
func (f *sentOnceFeature) Save() (json.RawMessage, error) { return nil, nil }
func (f *sentOnceFeature) Handle(_ context.Context, s *Session, _ *envelope.Inner) (json.RawMessage, error) {
	f.calls++
	if f.notify {
		s.NotifyAllDevices("sync.event", json.RawMessage(`{"kind":"ahead"}`))
	}
	s.CacheResponseAsSentOnce(json.RawMessage(`{"withheld":true}`))
	return json.RawMessage(`{"value":"SECRET-LEASH-VALUE"}`), nil
}

// storedDeposits opens every deposit in the state as a flush writes it, with
// the keys of that stored state (not the keyring in memory), for device p.
func storedDeposits(t *testing.T, m *Manager, p *Peer) []*envelope.Inner {
	t.Helper()
	m.mu.Lock()
	err := m.persist(context.Background(), false)
	raw, merr := json.Marshal(m.st)
	m.mu.Unlock()
	if err != nil || merr != nil {
		t.Fatal(err, merr)
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	kr, err := handshake.ImportKeyring(st.Devices[p.ID].Sessions)
	if err != nil || kr.Current() == nil {
		t.Fatalf("the stored keyring: %v", err)
	}
	var out []*envelope.Inner
	for _, e := range st.Outbox {
		if e.Op != OpDeposit || e.PeerID != p.ID || len(e.Payload) == 0 {
			continue
		}
		env, err := envelope.Parse(e.Payload)
		if err != nil {
			continue
		}
		if in, err := kr.Current().OpenSent(env); err == nil {
			out = append(out, in)
		}
	}
	return out
}

// retryNow ends the backoff of the entries a failed mailbox held, and delivers them.
func retryNow(m *Manager) {
	m.mu.Lock()
	for _, e := range m.st.Outbox {
		e.NotBefore = time.Time{}
	}
	m.mu.Unlock()
	m.drainOutbox(context.Background())
}

// 0.97.0 §8.2: an answer marked sent once is in no stored deposit, while the
// durable message queued ahead of it to the same, failing, mailbox is (the
// positive control); the answer is deposited once from memory and lost with
// the failed deposit; once the relay is back, a retransmission gets the
// cached copy without the value, and the handler does not run again.
func TestSentOnceAnswerNotInTheStoredOutbox(t *testing.T) {
	d := newDevFixture(t)
	f := &sentOnceFeature{notify: true}
	d.m.addFeature(f)
	app := d.self()
	d.relay.failMailbox = map[string]error{d.devPeer.Relay.Mailbox: errors.New("relay down")}
	id := d.sendAs(app, "test.sentonce", `{}`)
	if f.calls != 1 {
		t.Fatalf("%d calls", f.calls)
	}
	control := false
	for _, in := range storedDeposits(t, d.m, d.devPeer) {
		if bytes.Contains(in.Body, []byte("SECRET")) || in.Re == id {
			t.Fatalf("a stored deposit holds the sent-once answer: %s", in.Body)
		}
		control = control || bytes.Contains(in.Body, []byte(`"ahead"`))
	}
	if !control {
		t.Fatal("the durable message ahead of it is not stored: the check proves nothing")
	}
	if st, _ := json.Marshal(d.m.st); strings.Contains(string(st), "SECRET") {
		t.Fatal("the state holds the value")
	}
	d.relay.failMailbox = nil
	d.inbox(app) // drop what came before
	d.sendID(app, id, "test.sentonce", `{}`)
	retryNow(d.m)
	again := find(d.inbox(app)["dev1"], reply(id))
	if again == nil || again.Status != envelope.StatusOK || string(again.Body) != `{"withheld":true}` || f.calls != 1 {
		t.Fatalf("retransmission: %+v (calls %d)", again, f.calls)
	}
}

// Delivered once, from memory, behind the durable deposit to the same mailbox
// queued in the same batch; the answer carries the value, and nothing else
// does.
func TestSentOnceAnswerBehindTheDurableDeposits(t *testing.T) {
	d := newDevFixture(t)
	f := &sentOnceFeature{notify: true}
	d.m.addFeature(f)
	app := d.self()
	id := d.sendAs(app, "test.sentonce", `{}`)
	got := d.inbox(app)["dev1"]
	ahead, answer, answers := -1, -1, 0
	for i, in := range got {
		switch {
		case in.Type == "sync.event" && bytes.Contains(in.Body, []byte(`"ahead"`)):
			ahead = i
		case in.Re == id:
			answer = i
			answers++
			if string(in.Body) != `{"value":"SECRET-LEASH-VALUE"}` {
				t.Fatalf("answer: %s", in.Body)
			}
		}
	}
	if ahead < 0 || answers != 1 || answer < ahead {
		t.Fatalf("order: durable at %d, answer at %d (%d answers)", ahead, answer, answers)
	}
}

// The held path (a desktop's request approved on the phone, access.go's
// run of a held request) sends the answer once from memory too.
func TestSentOnceHeldAnswerNotInTheStoredOutbox(t *testing.T) {
	f := newOCFixture(t)
	st := &sentOnceFeature{notify: true}
	f.m.addFeature(st)
	f.relay.failMailbox = map[string]error{f.desk.peer.Relay.Mailbox: errors.New("relay down")}
	id := f.sendAs(f.desk, "test.sentonceheld", `{}`)
	ap := find(f.inbox(f.app, f.desk)["dev1"], ofType("approval.pending"))
	if ap == nil || st.calls != 0 {
		t.Fatal("not held")
	}
	f.sendAs(f.app, "approval.decide", `{"approval_id":"`+bodyStr(t, ap, "approval_id")+`","approve":true}`)
	if st.calls != 1 {
		t.Fatalf("%d calls", st.calls)
	}
	control := false
	for _, in := range storedDeposits(t, f.m, f.desk.peer) {
		if bytes.Contains(in.Body, []byte("SECRET")) || in.Re == id {
			t.Fatalf("a stored deposit holds the held sent-once answer: %s", in.Body)
		}
		control = control || bytes.Contains(in.Body, []byte(`"ahead"`))
	}
	if !control {
		t.Fatal("the durable message ahead of it is not stored: the check proves nothing")
	}
	if s, _ := json.Marshal(f.m.st); strings.Contains(string(s), "SECRET") {
		t.Fatal("the state holds the value")
	}
	if !f.cached(id) {
		t.Fatal("held answer not cached")
	}
	f.relay.failMailbox = nil
	f.inbox(f.desk)
	f.sendID(f.desk, id, "test.sentonceheld", `{}`)
	retryNow(f.m)
	again := find(f.inbox(f.desk)["desk1"], reply(id))
	if again == nil || string(again.Body) != `{"withheld":true}` || st.calls != 1 {
		t.Fatalf("retransmission: %+v (calls %d)", again, st.calls)
	}
}

// 0.97.0 §8.2: a retransmission handled while the live answer still waits in
// memory is answered behind it, from memory too: in one batch the live answer
// comes first and the copy second; with the relay down, neither is in a
// stored deposit.
func TestSentOnceDuplicateInOneBatch(t *testing.T) {
	d := newDevFixture(t)
	f := &sentOnceFeature{}
	d.m.addFeature(f)
	app := d.self()
	pair := func(tag string) (string, []Message) {
		id, _ := envelope.NewULID(testNow())
		var msgs []Message
		for n := range 2 {
			raw, err := app.ep.Seal(&envelope.Inner{ID: id, Type: "test.sentonce", TS: testNow(), Body: []byte(`{}`),
				Features: []string{handshake.CapConfirm}})
			if err != nil {
				t.Fatal(err)
			}
			msgs = append(msgs, Message{MsgID: fmt.Sprintf("%s%d", tag, n), Sender: relayauth.EncodeKey(d.devPeer.Relay.PK), Payload: raw})
		}
		return id, msgs
	}
	id, msgs := pair("up")
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, msgs)
	var bodies []string
	for _, x := range d.inbox(app)["dev1"] {
		if x.Re == id {
			bodies = append(bodies, string(x.Body))
		}
	}
	if len(bodies) != 2 || bodies[0] != `{"value":"SECRET-LEASH-VALUE"}` || bodies[1] != `{"withheld":true}` || f.calls != 1 {
		t.Fatalf("answers %v (calls %d)", bodies, f.calls)
	}
	d.relay.failMailbox = map[string]error{d.devPeer.Relay.Mailbox: errors.New("relay down")}
	f.notify = true // the durable message ahead: the positive control
	id, msgs = pair("down")
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, msgs)
	if f.calls != 2 {
		t.Fatalf("calls %d", f.calls)
	}
	control := false
	for _, in := range storedDeposits(t, d.m, d.devPeer) {
		if in.Re == id {
			t.Fatalf("a stored deposit holds an answer: %s", in.Body)
		}
		control = control || bytes.Contains(in.Body, []byte(`"ahead"`))
	}
	if !control {
		t.Fatal("the durable message ahead is not stored: the check proves nothing")
	}
}

// A sent-once answer too large to seal is replaced by response_too_large
// (§8.1), and the body with the value it replaces is wiped too.
func TestSentOnceTooLargeWipesTheValue(t *testing.T) {
	d := newDevFixture(t)
	big := []byte(`{"value":"` + strings.Repeat("S", 300*1024) + `"}`)
	req := &envelope.Inner{ID: "01JB2Z6V9K3M4N5P6Q7R8S9TB7", Type: "agent.request"}
	out := &envelope.Inner{Type: req.Type, Re: req.ID, Status: envelope.StatusOK, Body: big}
	d.m.mu.Lock()
	d.m.sendResponseCached(d.devPeer, req, "k7", out, json.RawMessage(`{"withheld":true}`), true, d.m.now())
	replaced := false
	for _, e := range d.m.st.Outbox {
		replaced = replaced || e.InnerID == out.ID // response_too_large is sent durably, under the same id
	}
	d.m.mu.Unlock()
	if !replaced {
		t.Fatal("not replaced by response_too_large: the check proves nothing")
	}
	if !bytes.Equal(big, make([]byte, len(big))) {
		t.Fatal("the replaced sent-once body was not wiped")
	}
}

// 0.97.0 §8.2: never ahead of a blocked durable deposit. The durable message
// queued ahead of the answer to the same mailbox fails once (the relay is
// otherwise up): the sent-once answer is not delivered ahead of it (it is
// lost), the durable one goes on its retry, and a retransmission gets the
// copy without running the handler again.
func TestSentOnceNeverAheadOfABlockedDeposit(t *testing.T) {
	d := newDevFixture(t)
	f := &sentOnceFeature{notify: true}
	d.m.addFeature(f)
	app := d.self()
	failed := 0
	d.relay.check = func(mailbox, _ string) error {
		if mailbox == d.devPeer.Relay.Mailbox && failed == 0 {
			failed++
			return errors.New("relay blip")
		}
		return nil
	}
	id := d.sendAs(app, "test.sentonce", `{}`)
	if failed != 1 || f.calls != 1 {
		t.Fatalf("failed %d, calls %d", failed, f.calls)
	}
	for _, in := range d.inbox(app)["dev1"] {
		if in.Re == id || bytes.Contains(in.Body, []byte("SECRET")) {
			t.Fatalf("the sent-once answer went ahead of the blocked deposit: %s", in.Body)
		}
	}
	retryNow(d.m)
	ahead := false
	for _, in := range d.inbox(app)["dev1"] {
		if in.Re == id || bytes.Contains(in.Body, []byte("SECRET")) {
			t.Fatalf("the sent-once answer was kept for the retry: %s", in.Body)
		}
		ahead = ahead || bytes.Contains(in.Body, []byte(`"ahead"`))
	}
	if !ahead {
		t.Fatal("the durable message was not delivered on its retry")
	}
	d.sendID(app, id, "test.sentonce", `{}`)
	retryNow(d.m)
	again := find(d.inbox(app)["dev1"], reply(id))
	if again == nil || string(again.Body) != `{"withheld":true}` || f.calls != 1 {
		t.Fatalf("retransmission: %+v (calls %d)", again, f.calls)
	}
}
