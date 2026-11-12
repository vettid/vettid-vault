package vault

import (
	"bytes"
	"testing"
	"time"
)

// §6.3.1 Rule E's scope (VAULT-MESSAGING 0.89.2): at the verified hs.fin
// of a rekey or reconnect, R destroys the epochs later than its confirmed
// one only when the handshake named the confirmed epoch while it was not
// current. Side 0 is I, side 1 is R.

// ruleEUnconfirmedCurrent: I rekeys to E1; R activates E1 (current, not
// yet confirmed: I has sent nothing under it); I confirms E1 and then
// reconnects naming E1, R's current epoch. R establishes E2 at the hs.fin;
// R's hs.confirm for E2 is lost. It returns E1 and E2.
func ruleEUnconfirmedCurrent(t *testing.T, f *r29Fx) (e1, e2 []byte) {
	t.Helper()
	e0 := append([]byte(nil), f.cur(1)...)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	if f.p(0).Pending == nil {
		t.Fatal("setup: I is not pending")
	}
	e1 = append([]byte(nil), f.p(0).Pending.ID...)
	f.deliver(0, 1, kHSFin)
	if !bytes.Equal(f.cur(1), e1) || !bytes.Equal(f.p(1).confirmedID(), e0) {
		t.Fatal("setup: R's E1 is not current and unconfirmed")
	}
	f.deliver(1, 0, kConfirm)
	if !bytes.Equal(f.cur(0), e1) || f.p(0).Pending != nil {
		t.Fatal("setup: I did not confirm E1")
	}
	f.advance(time.Minute)
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	if og := f.openReconnect(0); og == nil || !bytes.Equal(og.Named, e1) {
		t.Fatal("setup: I's reconnect does not name E1")
	}
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	if f.p(0).Pending == nil {
		t.Fatal("setup: I's reconnect epoch is not pending")
	}
	e2 = append([]byte(nil), f.p(0).Pending.ID...)
	f.deliver(0, 1, kHSFin)
	if !bytes.Equal(f.cur(1), e2) {
		t.Fatal("setup: R did not establish E2")
	}
	f.lose(1, 0, kConfirm)
	return e1, e2
}

// A reconnect that named R's current, unconfirmed epoch E1 destroys
// nothing at R: E1 is kept as superseded. I abandons its pending epoch E2
// (its own ik rotation, S5) and goes on under E1: R takes I's messages
// under E1, nothing suspends, and the pair converges.
func TestR29RuleENotAtReconnectNamingUnconfirmedCurrent(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e1, _ := ruleEUnconfirmedCurrent(t, f)
	if e := f.p(1).epochMeta(e1); e == nil || e.Destroyed {
		t.Fatal("rule E destroyed E1, which the reconnect named while it was R's current epoch")
	}
	f.advance(time.Minute)
	f.rotate(0) // S5: I abandons its pending E2
	if f.p(0).Pending != nil || !bytes.Equal(f.cur(0), e1) {
		t.Fatal("setup: I did not abandon E2 and stay on E1")
	}
	f.note(0, "under-e1")
	for i := 0; i < 3; i++ {
		f.settle()
		f.advance(time.Hour)
		f.tick(0)
		f.tick(1)
	}
	f.settle()
	if f.p(0).suspended() || f.p(1).suspended() || f.forkFeed(0) || f.forkFeed(1) {
		f.dump()
		t.Fatal("a false fork: I's message under the epoch its reconnect named suspended the pair")
	}
	if f.p(0).State != PeerActive || f.p(1).State != PeerActive {
		t.Fatal("the pair did not stay active")
	}
	if !f.sameEpoch() {
		f.dump()
		t.Fatal("the pair did not converge on one epoch")
	}
	f.talks()
}

// A reconnect that named R's confirmed epoch E0 while E1 was current makes
// R's rule E destroy E1 at the hs.fin. An old copy of I that holds E1 (and
// confirms it with R's earlier hs.confirm) then sends under it with a later
// ts: R suspends (fork evidence, ref epoch, with a feed item).
func TestR29RuleEAtReconnectNamingConfirmedNotCurrent(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	for s := 0; s < 2; s++ {
		f.do(s, func(m *Manager, _ *Peer) { m.dirty = true }) // the long tokens are stored
	}
	e0 := append([]byte(nil), f.cur(1)...)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	if f.p(0).Pending == nil {
		t.Fatal("setup: I is not pending")
	}
	e1 := append([]byte(nil), f.p(0).Pending.ID...)
	f.deliver(0, 1, kHSFin)
	if !bytes.Equal(f.cur(1), e1) || !bytes.Equal(f.p(1).confirmedID(), e0) {
		t.Fatal("setup: R's E1 is not current and unconfirmed")
	}
	snap := f.snapshot(0) // I with E1 pending
	f.startCopy(0, snap)
	if f.deliver(1, 2, kAny) == 0 { // R's hs.confirm for E1 reaches only the copy
		t.Fatal("setup: no hs.confirm for the copy")
	}
	if !bytes.Equal(f.cur(2), e1) {
		t.Fatal("setup: the copy did not confirm E1")
	}
	f.advance(time.Minute)
	// I reconnects naming its current E0 (its pending E1 is abandoned):
	// R's confirmed epoch, not its current one.
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	if og := f.openReconnect(0); og == nil || !bytes.Equal(og.Named, e0) {
		t.Fatal("setup: I's reconnect does not name E0")
	}
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	f.deliver(0, 1, kHSFin)
	e := f.p(1).epochMeta(e1)
	if e == nil || !e.Destroyed {
		f.dump()
		t.Fatal("rule E did not destroy E1, later than the confirmed epoch the reconnect named")
	}
	if bytes.Equal(f.cur(1), e1) {
		t.Fatal("E1 is still R's current epoch")
	}
	f.settle()
	if f.p(1).suspended() || !f.sameEpoch() {
		t.Fatal("setup: the honest pair did not converge")
	}
	f.advance(time.Minute)
	f.note(2, "copy-under-e1") // a later ts than the hs.init's
	if f.deliver(2, 1, kAny) == 0 {
		t.Fatal("setup: the copy sent nothing")
	}
	if !f.suspendedRef(1, "epoch") || !f.forkFeed(1) {
		f.dump()
		t.Fatal("the copy's later message under the destroyed E1 did not suspend R")
	}
}
