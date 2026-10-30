package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// timeStub records the relay time a handler sees and the unlock callbacks.
type timeStub struct {
	mu       sync.Mutex
	relay    []time.Time
	now      []time.Time
	unlocked int
}

func (g *timeStub) Name() string { return "timestub" }
func (g *timeStub) Types() []TypeSpec {
	return []TypeSpec{{Type: "vote.proposal", Request: true, From: conns, Connections: PeersService}}
}
func (g *timeStub) Load(json.RawMessage) error     { return nil }
func (g *timeStub) Save() (json.RawMessage, error) { return nil, nil }
func (g *timeStub) Handle(_ context.Context, s *Session, _ *envelope.Inner) (json.RawMessage, error) {
	g.mu.Lock()
	g.relay = append(g.relay, s.RelayTime())
	g.now = append(g.now, s.Now())
	g.mu.Unlock()
	return json.RawMessage(`{}`), nil
}
func (g *timeStub) Unlocked(*Session) { g.mu.Lock(); g.unlocked++; g.mu.Unlock() }

// A handler sees the relay's time of the message (its deposited_at), and
// UnlockObserver features are told once per opening.
func TestRelayTimeAndUnlockObserver(t *testing.T) {
	d := newDevFixture(t)
	st := &timeStub{}
	d.m.addFeature(st)
	sinkOf(d)
	svc := d.asConnection(t, "svc", 0x70)
	d.m.st.Connections["svc"].PeerKind = "service"
	deposited := time.Date(2026, 10, 30, 9, 8, 7, 654000000, time.UTC)
	send := func(depositedAt string) {
		d.seq++
		id, _ := envelope.NewULID(time.Now())
		raw, err := svc.ep.Seal(&envelope.Inner{ID: id, Type: "vote.proposal", TS: time.Now(), Body: []byte(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		msg := Message{MsgID: fmt.Sprintf("r%d", d.seq), Sender: relayauth.EncodeKey(svc.peer.Relay.PK), JTI: "standing-svc",
			DepositedAt: depositedAt, Payload: raw}
		_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg})
	}
	send(deposited.Format(time.RFC3339Nano))
	send("not a time")
	send("")
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.relay) != 3 {
		t.Fatalf("handled %d", len(st.relay))
	}
	if !st.relay[0].Equal(deposited) {
		t.Errorf("relay time %v, want %v", st.relay[0], deposited)
	}
	// Unknown or unparseable: the processing time.
	for i := 1; i < 3; i++ {
		if !st.relay[i].Equal(st.now[i]) {
			t.Errorf("message %d: relay time %v, processing time %v", i, st.relay[i], st.now[i])
		}
	}
	if st.unlocked != 1 {
		t.Errorf("unlock observer called %d times", st.unlocked)
	}
}
