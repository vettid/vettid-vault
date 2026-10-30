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

// reqStub sends a request from Tick and takes its answer.
type reqStub struct {
	mu      sync.Mutex
	ticks   int
	sentID  string
	sendErr error
	got     []*envelope.Inner
	peers   []string
	own     int
}

func (g *reqStub) Name() string                   { return "reqstub" }
func (g *reqStub) Types() []TypeSpec              { return nil }
func (g *reqStub) Load(json.RawMessage) error     { return nil }
func (g *reqStub) Save() (json.RawMessage, error) { return nil, nil }
func (g *reqStub) Handle(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) {
	return nil, nil
}
func (g *reqStub) Tick(s *Session) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.ticks++
	if g.ticks == 1 {
		g.sentID, g.sendErr = s.SendRequest("svc", "vote.status", json.RawMessage(`{"proposal_id":"x"}`))
		g.own = len(s.OwnIdentityKeys())
	}
}
func (g *reqStub) Response(s *Session, in *envelope.Inner) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.got = append(g.got, in)
	g.peers = append(g.peers, s.From().ID)
	return true
}

// A request a feature sends (Session.SendRequest) is registered; its
// answer reaches the feature's ResponseObserver with the answering
// connection as the sender; an answer to nothing the vault asked is
// dropped; Tick runs with every batch.
func TestFeatureRequestsAndTick(t *testing.T) {
	d := newDevFixture(t)
	st := &reqStub{}
	d.m.addFeature(st)
	sinkOf(d)
	svc := d.asConnection(t, "svc", 0x70)
	d.m.st.Connections["svc"].PeerKind = "service"
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil) // a batch with no message ticks
	st.mu.Lock()
	id, err, own := st.sentID, st.sendErr, st.own
	st.mu.Unlock()
	if err != nil || id == "" || own < 1 {
		t.Fatalf("send: %q %v %d", id, err, own)
	}
	// The request left for the connection under that id.
	found := false
	for _, in := range d.inbox(svc)[svc.peer.ID] {
		found = found || in.ID == id && in.Type == "vote.status"
	}
	if !found {
		t.Fatal("the request was not sent")
	}
	send := func(re string) {
		d.seq++
		rid, _ := envelope.NewULID(time.Now())
		raw, err := svc.ep.Seal(&envelope.Inner{ID: rid, Type: "vote.status", Re: re, Status: envelope.StatusOK, TS: time.Now(), Body: []byte(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		msg := Message{MsgID: fmt.Sprintf("q%d", d.seq), Sender: relayauth.EncodeKey(svc.peer.Relay.PK), JTI: "standing-svc", Payload: raw}
		_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg})
	}
	send("01JBQZ0000000000000000ZZZZ") // matches no request
	st.mu.Lock()
	n := len(st.got)
	st.mu.Unlock()
	if n != 0 {
		t.Fatal("an answer to nothing reached the feature")
	}
	send(id)
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.got) != 1 || st.got[0].Re != id || st.peers[0] != "svc" {
		t.Fatalf("%+v %v", st.got, st.peers)
	}
	if st.ticks < 3 {
		t.Errorf("%d ticks", st.ticks)
	}
	// The answer is taken once.
}
