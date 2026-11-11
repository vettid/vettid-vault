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
		aw.Reconnect.Fork = true
		m.dropStaleReconnectAnswers(p, p.LastEpochID, f.clk.Add(time.Hour), f.clk)
		if m.st.Awaiting[id] == nil {
			t.Fatal("a fork sign's answer was dropped")
		}
		aw.Reconnect.Fork = false
		named := aw.Reconnect.Named
		aw.Reconnect.Named = []byte("an epoch not among the peer's")
		m.dropStaleReconnectAnswers(p, p.LastEpochID, f.clk.Add(time.Hour), f.clk)
		if m.st.Awaiting[id] == nil {
			t.Fatal("an answer naming an epoch not among the peer's was dropped")
		}
		aw.Reconnect.Named = named
		m.dropStaleReconnectAnswers(p, p.LastEpochID, f.clk.Add(time.Hour), f.clk)
		if m.st.Awaiting[id] != nil {
			t.Fatal("setup check: the answer was not dropped when both conditions hold")
		}
	})
}

// (Opus review of a09a3ff, Medium) A copy of P reconnects naming E0, older
// than Q's confirmed E1 (§3.4.1 "Fork by ctx"): Q's answer is fork evidence
// judged at its hs.fin. The honest P's later message under E1 must not end
// that answer as stale: the copy's hs.fin still suspends.
func TestR30StaleAnswerKeepsAForkByCtxAnswer(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	snap := f.snapshot(0) // P's copy line: E0
	f.rekey(1)            // Q begins E1 with P
	f.settle()
	f.note(0, "under-E1")
	f.settle()
	f.startCopy(0, snap)
	f.rotate(2) // the copy line rotates a→b
	f.lose(2, 1, kAny)
	f.do(2, func(m *Manager, p *Peer) {
		for id, og := range m.st.Outgoing {
			if og.PeerID == p.ID {
				m.abandonOutgoing(id, f.clk)
			}
		}
		m.startReconnect(p, f.clk)
	})
	f.deliver(2, 1, kHSInit)
	if f.reconnectAnswer(1) == "" {
		f.dump()
		t.Fatal("setup: Q did not answer the copy's reconnect")
	}
	f.advance(time.Minute)
	f.note(0, "honest-under-E1") // newer than E0, a later ts
	f.deliver(0, 1, kNote)
	if f.reconnectAnswer(1) == "" {
		t.Fatal("a fork-by-ctx answer was ended as stale")
	}
	f.deliver(1, 2, kHSResp)
	f.deliver(2, 1, kHSFin)
	if !f.suspendedRef(1, "epoch") {
		f.dump()
		t.Fatal("Q did not suspend at the copy's hs.fin")
	}
}

// (Opus review of a09a3ff, Low: hs.fin excluded) I's rekey K and reconnect
// X are both open and R answers both; I takes K's hs.resp, then X's. R gets
// K's hs.fin (made under K, newer, a later ts), a copy of it, then X's
// hs.fin: neither K's hs.fin nor its copy may end X's answer.
func TestR30StaleAnswerNotEndedByAnHsFin(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	f.advance(time.Minute)
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	if f.deliver(0, 1, kHSInit) != 2 {
		f.dump()
		t.Fatal("setup: expected both hs.init")
	}
	resps := f.takeKind(1, 0, kHSResp)
	if len(resps) != 2 {
		t.Fatalf("setup: expected two hs.resp, got %d", len(resps))
	}
	f.advance(time.Minute)
	f.process(0, resps[0])
	f.advance(time.Minute)
	f.process(0, resps[1])
	fins := f.takeKind(0, 1, kHSFin)
	if len(fins) != 2 {
		f.dump()
		t.Fatalf("setup: expected two hs.fin, got %d", len(fins))
	}
	f.process(1, fins[0])
	f.advance(time.Second)
	f.process(1, f.pos(fins[0], "redeposited-fin-k")) // deposited again (a crash before the answer): a new msg_id
	if f.reconnectAnswer(1) == "" {
		t.Fatal("an hs.fin ended the reconnect answer")
	}
	f.process(1, fins[1])
	f.settle()
	if f.p(0).Pending != nil || !f.sameEpoch() || f.p(1).suspended() {
		f.dump()
		t.Fatal("the pair did not end on one epoch")
	}
	f.talks()
}

// (Opus review of a09a3ff, Low: after confirmPending) I's reconnect X and
// R's rekey Pr cross; R answers X late while Pr is pending at R; I
// activates Pr at its hs.fin ("A verified hs.fin comes first": X ends) and
// confirms it. That hs.confirm, under R's then pending Pr, confirms Pr and
// then ends X's answer.
func TestR30StaleAnswerEndedByAConfirmOfTheOwnPendingEpoch(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	x := f.takeKind(0, 1, kHSInit)
	if len(x) != 1 {
		t.Fatal("setup: no reconnect hs.init")
	}
	f.advance(time.Minute)
	f.rekey(1)
	if f.deliver(1, 0, kHSInit) != 1 || f.deliver(0, 1, kHSResp) != 1 || f.p(1).Pending == nil {
		f.dump()
		t.Fatal("setup: R's rekey is not pending")
	}
	f.advance(time.Minute)
	f.process(1, x[0]) // X reaches R late; Pr pending at R
	if f.reconnectAnswer(1) == "" {
		f.dump()
		t.Fatal("setup: R did not answer X")
	}
	f.advance(time.Minute)
	if f.deliver(1, 0, kHSFin) != 1 {
		f.dump()
		t.Fatal("setup: Pr's hs.fin did not reach I")
	}
	f.advance(time.Minute)
	f.deliver(0, 1, kConfirm)
	if f.p(1).Pending != nil {
		t.Fatal("setup: Pr not confirmed at R")
	}
	if f.reconnectAnswer(1) != "" {
		f.dump()
		t.Fatal("the hs.confirm under R's pending epoch did not end X's answer")
	}
	f.settle()
	if !f.sameEpoch() || f.p(0).suspended() || f.p(1).suspended() {
		f.dump()
		t.Fatal("the pair did not end on one epoch")
	}
}
