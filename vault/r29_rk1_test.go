package vault

import (
	"bytes"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
)

// VAULT-MESSAGING 0.90.0 §3.4.2 RK1, the reconnect after a demotion as
// release 29 builds it: the parts the §6.3.2 RK1 row lists without a test.

// RK1-b: while side 0's reconnect after a strict-F1 demotion is open and
// names an epoch other than its current one, side 1's rekey hs.init is
// acked, discarded and audited rekey_replaced_by_reconnect: no answer, and
// the reconnect stays open.
func TestR29RK1RekeyReplacedByReconnect(t *testing.T) {
	f, e0, _ := strictF1(t, false)
	og := f.openReconnect(0)
	if og == nil || !bytes.Equal(og.Named, e0) || bytes.Equal(og.Named, f.cur(0)) {
		t.Fatal("setup: side 0 has no open reconnect naming an epoch other than its current one")
	}
	if f.deliver(1, 0, kHSInit) == 0 { // side 1's rekey, restarted at its rotation (S5)
		t.Fatal("setup: no rekey hs.init from side 1")
	}
	if !f.audited(0, "rekey_replaced_by_reconnect") {
		f.dump()
		t.Fatal("side 1's rekey was not audited rekey_replaced_by_reconnect")
	}
	for _, aw := range f.m(0).st.Awaiting {
		if aw.PeerID == f.id[0] && aw.Purpose == handshake.PurposeRekey {
			t.Fatal("side 0 answered the rekey its reconnect replaces")
		}
	}
	if f.lose(0, 1, kHSResp) != 0 {
		t.Fatal("side 0 sent an hs.resp to the replaced rekey")
	}
	if og := f.openReconnect(0); og == nil || !bytes.Equal(og.Named, e0) {
		t.Fatal("side 0's reconnect did not stay open")
	}
}

// RK1-d: between two persons only an answer to the peer's reconnect holds a
// side's own reconnect. With an answer to side 1's rekey awaiting hs.fin,
// side 0 can reconnect and its reconnect starts; with an answer to side 1's
// reconnect awaiting hs.fin, it can not.
func TestR29RK1RekeyAnswerHoldsNoReconnect(t *testing.T) {
	t.Run("rekey answer", func(t *testing.T) {
		f := newR29Fx(t)
		f.longTokens()
		f.rekey(1)
		f.deliver(1, 0, kHSInit) // side 0 answers; the answer awaits hs.fin
		if !awaits(f, 0, handshake.PurposeRekey) {
			t.Fatal("setup: no rekey answer awaiting hs.fin")
		}
		if !f.m(0).canReconnect(f.p(0), f.clk) {
			t.Fatal("canReconnect: a rekey answer held the reconnect")
		}
		f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
		if f.openReconnect(0) == nil {
			t.Fatal("startReconnect: a rekey answer held the reconnect")
		}
	})
	t.Run("reconnect answer", func(t *testing.T) {
		f := newR29Fx(t)
		f.longTokens()
		f.do(1, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
		f.deliver(1, 0, kHSInit)
		if !awaits(f, 0, handshake.PurposeReconnect) {
			t.Fatal("setup: no reconnect answer awaiting hs.fin")
		}
		if f.m(0).canReconnect(f.p(0), f.clk) {
			t.Fatal("canReconnect: an answer to the peer's reconnect did not hold the reconnect")
		}
		f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
		if f.openReconnect(0) != nil {
			t.Fatal("startReconnect: an answer to the peer's reconnect did not hold the reconnect")
		}
	})
}

func awaits(f *r29Fx, s int, purpose handshake.Purpose) bool {
	for _, aw := range f.m(s).st.Awaiting {
		if aw.PeerID == f.id[s] && aw.Purpose == purpose && aw.New == nil {
			return true
		}
	}
	return false
}

// RK1-c: a pending epoch, and B with it, starts in the write that queues
// its hs.fin, whether or not the hs.fin was deposited. Side 0's deposits
// are refused from before its hs.fin is queued: FinAt is that write's time,
// and B ends the pending epoch PendingLife later though the hs.fin never
// left.
func TestR29RK1BFromTheQueuedFin(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.advance(time.Hour)
	f.holdDeposits(0, true)
	queued := f.clk
	f.deliver(1, 0, kHSResp) // the write that queues hs.fin
	pe := f.p(0).Pending
	if pe == nil {
		t.Fatal("setup: no pending epoch")
	}
	if !pe.FinAt.Equal(queued) {
		t.Fatalf("FinAt %v, want the time of the write that queued hs.fin %v", pe.FinAt, queued)
	}
	if f.lose(0, 1, kHSFin) != 0 {
		t.Fatal("setup: the hs.fin was deposited")
	}
	id := append([]byte(nil), pe.ID...)
	f.advance(PendingLife - time.Minute)
	f.tick(0)
	if f.p(0).Pending == nil || !bytes.Equal(f.p(0).Pending.ID, id) {
		t.Fatal("the pending epoch ended before B")
	}
	f.advance(2 * time.Minute)
	f.tick(0)
	if f.p(0).Pending != nil && bytes.Equal(f.p(0).Pending.ID, id) {
		t.Fatal("B did not end the pending epoch whose hs.fin was queued but never deposited")
	}
	if !f.audited(0, "pending_abandoned_b_passed") {
		f.dump()
		t.Fatal("not audited as B passed")
	}
}
