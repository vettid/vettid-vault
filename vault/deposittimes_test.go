package vault

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// idRelay records the msg_ids the relay returned, or answers with id
// instead when set.
type idRelay struct {
	Relay
	ids []string
	id  string
}

func (r *idRelay) Deposit(ctx context.Context, url, mailbox, token string, payload []byte) (string, error) {
	id, err := r.Relay.Deposit(ctx, url, mailbox, token, payload)
	if err == nil && r.id != "" {
		id = r.id
	}
	if err == nil {
		r.ids = append(r.ids, id)
	}
	return id, err
}

// (BALLOT-PROTOCOL 0.15.0 §4.2) A timed request's deposit records the time
// of the msg_id the relay returned, under the request's inner id; other
// types record nothing.
func TestDepositTimesRecordTheRelaysMsgID(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	relayID, err := envelope.NewULID(f.clk.Add(-time.Minute)) // the relay's clock, not the vault's
	if err != nil {
		t.Fatal(err)
	}
	ir := &idRelay{Relay: f.m(0).relay, id: relayID}
	f.m(0).relay = ir
	var cast, note string
	f.do(0, func(m *Manager, p *Peer) {
		cast = m.sendTo(p, "vote.cast", []byte(`{"n":1}`), f.clk)
		note = m.sendTo(p, "test.note", []byte(`{"n":2}`), f.clk)
	})
	if len(ir.ids) != 2 {
		t.Fatalf("%d deposits", len(ir.ids))
	}
	want, ok := envelope.ULIDTime(ir.ids[0])
	if !ok {
		t.Fatalf("the relay's msg_id %q is no ULID", ir.ids[0])
	}
	m := f.m(0)
	if got := m.depositTimes(cast); len(got) != 1 || got[0] != want {
		t.Errorf("vote.cast: %v, want [%d]", got, want)
	}
	if got := m.depositTimes(note); got != nil {
		t.Errorf("test.note recorded %v", got)
	}
	if h := (managerHost{m}).DepositTimes(cast); len(h) != 1 || h[0] != want {
		t.Errorf("the host's DepositTimes: %v", h)
	}
}

// A deposit whose answer was lost, or whose msg_id is not a ULID, records
// nothing: an answer timed at it is then no answer.
func TestDepositTimesNoneWithoutTheRelaysAnswer(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	lr := &lostAnswerRelay{Relay: f.m(0).relay, mailbox: f.m(1).st.Relay.Mailbox, lose: true}
	f.m(0).relay = lr
	var lost string
	f.do(0, func(m *Manager, p *Peer) { lost = m.sendTo(p, "vote.status", []byte(`{"n":1}`), f.clk) })
	if got := f.m(0).depositTimes(lost); got != nil {
		t.Errorf("a lost answer recorded %v", got)
	}
	f = newR29Fx(t)
	f.longTokens()
	ir := &idRelay{Relay: f.m(0).relay, id: "not-a-ulid"}
	f.m(0).relay = ir
	var bad string
	f.do(0, func(m *Manager, p *Peer) { bad = m.sendTo(p, "vote.status", []byte(`{"n":2}`), f.clk) })
	if len(ir.ids) == 0 {
		t.Fatal("setup: nothing deposited")
	}
	if got := f.m(0).depositTimes(bad); got != nil {
		t.Errorf("a msg_id that is no ULID recorded %v", got)
	}
}

// Times are kept per request across retries (each distinct one once, at
// most maxDepositTimes) and pruned 16 days after the first.
func TestDepositTimesKeptAcrossRetriesAndPruned(t *testing.T) {
	f := newR29Fx(t)
	m := f.m(0)
	e := &OutboxEntry{InnerID: "req", Type: "vote.cast"}
	id := func(ms int64) string {
		s, err := envelope.NewULID(time.UnixMilli(ms))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recordDepositTime(e, id(1000), f.clk)
	m.recordDepositTime(e, id(1000), f.clk) // the same time again
	m.recordDepositTime(e, id(2000), f.clk.Add(time.Hour))
	if got := m.depositTimes("req"); len(got) != 2 || got[0] != 1000 || got[1] != 2000 {
		t.Fatalf("%v", got)
	}
	for i := int64(0); i < 2*maxDepositTimes; i++ {
		m.recordDepositTime(e, id(3000+i), f.clk)
	}
	if n := len(m.depositTimes("req")); n != maxDepositTimes {
		t.Errorf("%d times kept, want at most %d", n, maxDepositTimes)
	}
	m.recordDepositTime(&OutboxEntry{Type: "vote.cast"}, id(1), f.clk) // no inner id
	if len(m.st.DepositTimes) != 1 {
		t.Errorf("an entry without an inner id was recorded: %d", len(m.st.DepositTimes))
	}
	f.advance(DedupeRetention)
	m.prune()
	if m.depositTimes("req") == nil {
		t.Error("pruned at 16 days, not after")
	}
	f.advance(time.Second)
	m.prune()
	if m.depositTimes("req") != nil {
		t.Error("kept past 16 days")
	}
}

// At most maxDepositRequests requests are kept: the one whose first deposit
// is the oldest goes first.
func TestDepositTimesBoundedByRequests(t *testing.T) {
	f := newR29Fx(t)
	m := f.m(0)
	m.mu.Lock()
	defer m.mu.Unlock()
	id, err := envelope.NewULID(f.clk)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxDepositRequests; i++ {
		m.recordDepositTime(&OutboxEntry{InnerID: fmt.Sprintf("req-%05d", i), Type: "vote.status"}, id, f.clk.Add(time.Duration(i)*time.Second))
	}
	m.recordDepositTime(&OutboxEntry{InnerID: "req-new", Type: "vote.status"}, id, f.clk.Add(time.Hour*2))
	if n := len(m.st.DepositTimes); n != maxDepositRequests {
		t.Fatalf("%d requests kept, want %d", n, maxDepositRequests)
	}
	if m.depositTimes("req-00000") != nil || m.depositTimes("req-00001") == nil || m.depositTimes("req-new") == nil {
		t.Error("not the oldest dropped")
	}
	// A further time for a request already kept drops nothing.
	m.recordDepositTime(&OutboxEntry{InnerID: "req-00001", Type: "vote.status"}, id, f.clk)
	if m.depositTimes("req-00002") == nil {
		t.Error("a request dropped for a retry's time")
	}
}
