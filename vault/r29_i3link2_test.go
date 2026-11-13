package vault

import (
	"bytes"
	"testing"
	"time"
)

// More of §3.4.1 "Strict F1" for links applied at hs.fin (owner decision
// 2026-11-12). Side 0 is P, side 1 is Q, side 2 an old copy of P.

// Strict F1 suspends at a reconnect's hs.fin. The copy establishes E1 with
// Q and makes a note under it before P's reconnect hs.init (an earlier
// inner ts); the note reaches Q only after Q answered P's reconnect naming
// E0 (then the confirmed epoch, not current), so it sets E1's flag without
// ending that answer as stale. At P's hs.fin the link runs strict F1 with
// E = E0, finds E1's flag set and suspends: the reconnect's epoch is not
// established and its carried record goes with it.
func TestR29I3StrictF1SuspendsAtReconnectFin(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	for s := 0; s < 2; s++ {
		f.do(s, func(m *Manager, _ *Peer) { m.dirty = true })
	}
	snap := f.snapshot(0)
	f.rotate(0)
	f.startCopy(0, snap)
	f.lose(0, 1, kHSInit) // P's own rekey at its rotation: lost

	f.rekey(2)
	if f.deliver(2, 1, kHSInit) != 1 || f.deliver(1, 2, kHSResp) != 1 || f.p(2).Pending == nil {
		t.Fatal("setup: the copy is not pending")
	}
	e1 := append([]byte(nil), f.p(2).Pending.ID...)
	if f.deliver(2, 1, kHSFin) != 1 || !bytes.Equal(f.cur(1), e1) {
		t.Fatal("setup: Q did not establish the copy's E1")
	}
	f.deliver(1, 2, kAny)
	if !bytes.Equal(f.cur(2), e1) {
		t.Fatal("setup: the copy did not confirm E1")
	}
	f.note(2, "copy-under-e1-before-the-link") // made now, delivered later

	f.advance(time.Second)
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	if f.deliver(0, 1, kHSInit) != 1 || f.deliver(1, 0, kHSResp) != 1 || f.p(0).Pending == nil {
		t.Fatalf("setup: Q did not answer P's reconnect naming E0; Q's audits %v", auditEvents(f.m(1)))
	}
	e2 := append([]byte(nil), f.p(0).Pending.ID...)

	n := len(f.got[1])
	if f.deliver(2, 1, kNote) != 1 || len(f.got[1]) != n+1 || !f.flag(1, e1) {
		t.Fatal("setup: Q did not take the copy's note under E1 before the link")
	}
	if f.audited(1, "answer_ended_stale") || f.p(1).suspended() {
		t.Fatal("setup: the note ended Q's answer to P's reconnect, or suspended")
	}

	if f.deliver(0, 1, kHSFin) != 1 {
		t.Fatal("setup: no hs.fin from P")
	}
	if !f.suspendedRef(1, "epoch") || !f.forkFeed(1) {
		f.dump()
		t.Fatal("strict F1 did not suspend (ref epoch) at P's reconnect hs.fin")
	}
	if f.p(1).epochMeta(e2) != nil || !bytes.Equal(f.cur(1), e1) {
		t.Fatal("the reconnect's epoch was established on a suspended connection")
	}
	for _, c := range f.p(1).Carried {
		if bytes.Equal(c.Epoch, e2) {
			t.Fatal("the carried record of an epoch never established was kept")
		}
	}
}
