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

// A rekey under Q's confirmed epoch while it is not current (rule E at
// hs.fin), carrying P's link. P's own earlier rekey made Cur at Q, signed
// by the old ik; Q's hs.confirm for it went to an old copy taken while Cur
// was pending at P, and P abandoned Cur at its rotation. Strict F1 (E =
// E0) first demotes Cur, audited connection.fork_suspected (ref epoch)
// with no feed item and no suspension; rule E then destroys it. A
// destroyed epoch is judged before a demoted one, so the copy's later note
// under Cur is rule E's fork evidence (a later ts): Q suspends. Before
// that, P and Q converge on the rekey's epoch and talk.
func TestR29I3StrictF1ThenRuleE(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	for s := 0; s < 2; s++ {
		f.do(s, func(m *Manager, _ *Peer) { m.dirty = true })
	}
	e0 := append([]byte(nil), f.cur(1)...)
	oldIK := append([]byte(nil), f.p(1).IK...)
	f.rekey(0)
	if f.deliver(0, 1, kHSInit) != 1 || f.deliver(1, 0, kHSResp) != 1 || f.deliver(0, 1, kHSFin) != 1 {
		t.Fatal("setup: P's first rekey did not reach Q's hs.fin")
	}
	cur := append([]byte(nil), f.cur(1)...)
	if bytes.Equal(cur, e0) || f.p(0).Pending == nil || !bytes.Equal(f.p(0).Pending.ID, cur) {
		t.Fatal("setup: Cur is not current at Q and pending at P")
	}
	snap := f.snapshot(0)

	f.rotate(0) // P abandons its pending Cur; identity.rotate and a rekey under E0
	f.startCopy(0, snap)
	if f.deliver(1, 2, kConfirm) != 1 || !bytes.Equal(f.cur(2), cur) {
		t.Fatal("setup: the copy did not confirm Cur")
	}

	if f.deliver(0, 1, kHSInit) != 1 {
		t.Fatal("setup: no rekey hs.init from P")
	}
	named := false
	for _, aw := range f.m(1).st.Awaiting {
		named = named || aw.NamedConfirmed && bytes.Equal(aw.InitEpoch, e0) && len(aw.Links) > 0
	}
	if !named {
		t.Fatalf("setup: P's rekey was not answered as one naming the confirmed epoch; Q's audits %v", auditEvents(f.m(1)))
	}
	if f.deliver(1, 0, kHSResp) != 1 || f.p(0).Pending == nil {
		t.Fatal("setup: P is not pending")
	}
	e2 := append([]byte(nil), f.p(0).Pending.ID...)
	if f.deliver(0, 1, kHSFin) != 1 || !bytes.Equal(f.cur(1), e2) || bytes.Equal(f.p(1).IK, oldIK) {
		t.Fatalf("Q did not follow the link and establish E2; Q's audits %v", auditEvents(f.m(1)))
	}
	e := f.p(1).epochMeta(cur)
	if e == nil || !e.Demoted || !e.Destroyed {
		f.dump()
		t.Fatal("Cur was not demoted by strict F1 and then destroyed by rule E")
	}
	if !f.audited(1, "epoch_demoted_f1") || !f.activity(1, "connection.fork_suspected", "epoch") || f.forkFeed(1) || f.p(1).suspended() {
		t.Fatal("the demotion was not audit-only")
	}

	f.deliver(1, 0, kAny)
	f.deliver(0, 1, kAny) // P's identity.rotate: links already followed
	f.settle()
	if f.p(1).suspended() || !f.sameEpoch() || !bytes.Equal(f.cur(1), e2) {
		t.Fatalf("P and Q did not converge on E2; Q's audits %v", auditEvents(f.m(1)))
	}
	f.talks()

	f.advance(time.Second)
	f.note(2, "copy-under-cur")
	if f.deliver(2, 1, kNote) != 1 {
		t.Fatal("setup: the copy sent nothing under Cur")
	}
	if !f.suspendedRef(1, "epoch") || f.activity(1, "drop.peer_key", "ancestor_ik") {
		t.Fatal("a message under Cur, demoted and destroyed, was not judged as rule E's fork evidence")
	}
}
