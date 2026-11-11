package vault

import (
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
)

// staleAnswer brings R (side 1) to §3.4.1's residual "A stale reconnect
// answer after a rekey's confirmation": I (0) confirmed its rekey K and
// ended its reconnect naming the epoch before; that reconnect's hs.init
// reaches R late and R answers it. It returns the delayed hs.init's
// answer's id at R.
func (f *r29Fx) staleAnswer() string {
	f.t.Helper()
	f.longTokens()
	f.rekey(0)
	if f.deliver(0, 1, kHSInit) != 1 {
		f.t.Fatal("setup: rekey hs.init not delivered")
	}
	f.advance(time.Minute)
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	rc := f.takeKind(0, 1, kHSInit)
	if len(rc) != 1 {
		f.t.Fatalf("setup: expected the reconnect hs.init, got %d", len(rc))
	}
	f.advance(time.Minute)
	if f.deliver(1, 0, kHSResp) != 1 || f.deliver(0, 1, kHSFin) != 1 || f.deliver(1, 0, kConfirm) < 1 {
		f.dump()
		f.t.Fatal("setup: the rekey did not complete")
	}
	if f.openReconnect(0) != nil {
		f.t.Fatal("setup: I kept its reconnect open past its rekey's confirmation")
	}
	f.advance(time.Minute)
	f.process(1, rc[0]) // the delayed reconnect hs.init: R answers it
	id := f.reconnectAnswer(1)
	if id == "" {
		f.dump()
		f.t.Fatal("setup: R did not answer the delayed reconnect")
	}
	return id
}

// reconnectAnswer is side s's open answer to a reconnect of its peer, or "".
func (f *r29Fx) reconnectAnswer(s int) string {
	for id, aw := range f.m(s).st.Awaiting {
		if aw.New == nil && aw.PeerID == f.id[s] && aw.Purpose == handshake.PurposeReconnect {
			return id
		}
	}
	return ""
}

// GC #6647: a message from I under a newer epoch, with a later ts than the
// answered hs.init, ends R's stale answer at once, so R's rekeys are not
// held back until L (16 days).
func TestR30StaleReconnectAnswerDroppedByALaterMessage(t *testing.T) {
	f := newR29Fx(t)
	f.staleAnswer()
	f.advance(time.Minute)
	f.note(0, "under-K")
	f.settle()
	if f.reconnectAnswer(1) != "" {
		f.dump()
		t.Fatal("R's stale reconnect answer is still open after a later message under a newer epoch")
	}
	if !f.audited(1, "answer_ended_stale") {
		t.Fatal("the drop was not recorded")
	}
	// R's own rekey is no longer held back by it.
	f.rekey(1)
	if f.deliver(1, 0, kHSInit) != 1 {
		f.dump()
		t.Fatal("R's rekey was held back after the drop")
	}
	f.settle()
	if f.p(1).suspended() || f.p(0).suspended() || !f.sameEpoch() {
		f.dump()
		t.Fatal("the pair did not end on one epoch")
	}
	f.talks()
}

// The drop needs both conditions: a message under the very epoch the
// hs.init named (not newer) keeps the answer.
func TestR30StaleAnswerKeptForAMessageUnderTheNamedEpoch(t *testing.T) {
	f := newR29Fx(t)
	id := f.staleAnswer()
	f.do(1, func(m *Manager, p *Peer) {
		aw := m.st.Awaiting[id]
		m.dropStaleReconnectAnswers(p, aw.Reconnect.Named, f.clk.Add(time.Hour), f.clk)
		if m.st.Awaiting[id] == nil {
			t.Fatal("an answer was dropped for a message under the epoch its hs.init named")
		}
		m.dropStaleReconnectAnswers(p, p.LastEpochID, aw.Reconnect.TS, f.clk)
		if m.st.Awaiting[id] == nil {
			t.Fatal("an answer was dropped for a message whose ts is not later than its hs.init's")
		}
		aw.Reconnect.Older = true
		m.dropStaleReconnectAnswers(p, p.LastEpochID, f.clk.Add(time.Hour), f.clk)
		if m.st.Awaiting[id] == nil {
			t.Fatal("a restore's answer was dropped")
		}
		aw.Reconnect.Older = false
		m.dropStaleReconnectAnswers(p, p.LastEpochID, f.clk.Add(time.Hour), f.clk)
		if m.st.Awaiting[id] != nil {
			t.Fatal("setup check: the answer was not dropped when both conditions hold")
		}
	})
}
