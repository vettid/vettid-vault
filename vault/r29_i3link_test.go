package vault

import (
	"bytes"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
)

// §3.4.1 invariant I3, last clause (owner decision 2026-11-12): once Q has
// followed P's ik link, Q accepts no message under an epoch an old copy of
// P set up that was deposited after that link, here when the link reaches
// Q in a handshake. Side 0 is P, side 1 is Q, side 2 an old copy of P taken
// before P's rotation. r29_i3copyinit_test.go has the rekey hs.fin.

// i3Reconnect: the link comes in P's reconnect, answered by Q while E0 was
// current; between Q's hs.resp and P's hs.fin the copy's rekey establishes
// E1 at Q, signed by the old ik (so not after the link's position x, the
// hs.fin, and not demoted by position). P's identity.rotate is held back.
// Strict F1 at hs.fin takes E as the epoch the reconnect named.
func i3Reconnect(t *testing.T) (f *r29Fx, e0, e1, e2, oldIK []byte) {
	t.Helper()
	f = newR29Fx(t)
	f.longTokens()
	for s := 0; s < 2; s++ {
		f.do(s, func(m *Manager, _ *Peer) { m.dirty = true })
	}
	e0 = append([]byte(nil), f.cur(1)...)
	oldIK = append([]byte(nil), f.p(1).IK...)
	snap := f.snapshot(0)

	f.rotate(0)
	f.startCopy(0, snap)
	f.lose(0, 1, kHSInit) // P's own rekey at its rotation: lost

	// The copy rekeys with Q: answered.
	f.rekey(2)
	if f.deliver(2, 1, kHSInit) != 1 || f.deliver(1, 2, kHSResp) != 1 || f.p(2).Pending == nil {
		t.Fatal("setup: the copy is not pending")
	}
	e1 = append([]byte(nil), f.p(2).Pending.ID...)

	// P reconnects naming E0 (its current): Q answers it, E0 current.
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	if f.deliver(0, 1, kHSInit) != 1 {
		t.Fatal("setup: no reconnect hs.init from P")
	}
	named := 0
	for _, aw := range f.m(1).st.Awaiting {
		if aw.Reconnect != nil && bytes.Equal(aw.Reconnect.Named, e0) && len(aw.Reconnect.Rotations) > 0 {
			named++
		}
	}
	if named != 1 {
		t.Fatalf("setup: Q holds %d answers to P's reconnect naming E0; Q's audits %v", named, auditEvents(f.m(1)))
	}
	if f.deliver(1, 0, kHSResp) != 1 || f.p(0).Pending == nil || f.p(0).Pending.Purpose != handshake.PurposeReconnect {
		t.Fatalf("setup: P's reconnect is not pending; P's audits %v", auditEvents(f.m(0)))
	}
	e2 = append([]byte(nil), f.p(0).Pending.ID...)

	// The copy's hs.fin: Q establishes E1 (signed by the old ik).
	if f.deliver(2, 1, kHSFin) != 1 || !bytes.Equal(f.cur(1), e1) {
		t.Fatal("setup: Q did not establish the copy's E1")
	}
	if e := f.p(1).epochMeta(e1); e == nil || !bytes.Equal(e.Signer, oldIK) {
		t.Fatal("setup: E1 is not signed by P's old ik at Q")
	}
	f.deliver(1, 2, kAny)
	if !bytes.Equal(f.cur(2), e1) {
		t.Fatal("setup: the copy did not confirm E1")
	}
	return f, e0, e1, e2, oldIK
}

// The reconnect's links applied at hs.fin run strict F1 with E the named
// epoch E0: E1 is demoted (by position, x = the hs.fin), audited
// connection.fork_suspected (ref epoch), nothing suspends, Q establishes
// E2, the copy's note under E1 deposited after the link is refused, and P
// and Q talk under E2.
func TestR29I3CopyEpochBesideReconnect(t *testing.T) {
	f, e0, e1, e2, oldIK := i3Reconnect(t)
	if f.deliver(0, 1, kHSFin) != 1 {
		t.Fatal("setup: no hs.fin from P")
	}
	if bytes.Equal(f.p(1).IK, oldIK) || !bytes.Equal(f.cur(1), e2) {
		t.Fatalf("Q did not follow P's link and establish E2 at P's hs.fin; Q's audits %v", auditEvents(f.m(1)))
	}
	if e := f.p(1).epochMeta(e1); e == nil || !e.Demoted {
		f.dump()
		t.Fatal("E1 was not demoted by strict F1 at P's reconnect hs.fin")
	}
	if !f.audited(1, "epoch_demoted_f1") || !f.activity(1, "connection.fork_suspected", "epoch") {
		t.Fatal("the demotion was not audited connection.fork_suspected (ref epoch)")
	}
	if f.p(1).suspended() || f.forkFeed(1) {
		t.Fatal("suspended, or a feed item, with E1's flag clear")
	}
	for _, id := range [][]byte{e0, e2} {
		if e := f.p(1).epochMeta(id); e == nil || e.Demoted || e.Destroyed {
			t.Fatal("P's own epoch E0 or E2 was judged")
		}
	}
	if f.openReconnect(1) != nil {
		t.Fatal("strict F1 started a reconnect beside the one just established")
	}

	n := len(f.got[1])
	f.note(2, "copy-under-e1-after-the-link")
	if f.deliver(2, 1, kNote) != 1 {
		t.Fatal("setup: the copy sent nothing under E1")
	}
	if len(f.got[1]) != n || !f.activity(1, "drop.peer_key", "ancestor_ik") || f.p(1).suspended() {
		t.Fatal("Q took the copy's note under E1 deposited after the link")
	}

	f.deliver(0, 1, kAny) // P's identity.rotate at last: its links are followed
	f.settle()
	if f.p(1).suspended() || f.p(0).suspended() || !f.sameEpoch() || !bytes.Equal(f.cur(1), e2) {
		t.Fatalf("P and Q did not settle on E2; Q's audits %v", auditEvents(f.m(1)))
	}
	f.talks()
	if f.p(1).suspended() || f.forkFeed(1) {
		t.Fatal("P's own messages under E2 were taken as fork evidence")
	}
}

// The copy sent under E1 before P's hs.fin (E1's flag set, its inner ts
// later than the reconnect hs.init's): Q takes it as P having moved on and
// ends its answer to P's reconnect (§6.3.1 "A stale reconnect answer ends
// at a later message"), so P's hs.fin establishes nothing and applies no
// link. The link then reaches Q in P's identity.rotate under E0, and strict
// F1 finds E1's flag set: Q suspends (ref epoch).
func TestR29I3CopyEpochBesideReconnectFlagSuspends(t *testing.T) {
	f, _, e1, e2, _ := i3Reconnect(t)
	f.advance(time.Second)
	f.note(2, "copy-under-e1-before-the-link")
	f.deliver(2, 1, kNote)
	if !f.flag(1, e1) || !f.audited(1, "answer_ended_stale") {
		t.Fatal("setup: E1's flag is not set at Q, or Q's answer to P's reconnect did not end")
	}
	f.deliver(0, 1, kHSFin)
	if f.p(1).epochMeta(e2) != nil {
		t.Fatal("setup: Q established E2 after the copy used E1")
	}
	f.deliver(0, 1, kRotate)
	if !f.suspendedRef(1, "epoch") || !f.forkFeed(1) {
		f.dump()
		t.Fatal("Q did not suspend (ref epoch) with E1's flag set")
	}
}

// A reconnect answer recorded without the named epoch (Named nil, a record
// from before it was kept) runs no strict F1 at hs.fin, as before.
func TestR29I3CopyEpochBesideReconnectNoNamed(t *testing.T) {
	f, _, e1, e2, _ := i3Reconnect(t)
	f.do(1, func(m *Manager, p *Peer) {
		for _, aw := range m.st.Awaiting {
			if aw.PeerID == p.ID && aw.Reconnect != nil {
				aw.Reconnect.Named = nil
				m.dirty = true
			}
		}
	})
	if f.deliver(0, 1, kHSFin) != 1 || !bytes.Equal(f.cur(1), e2) {
		t.Fatal("setup: Q did not establish E2 at P's hs.fin")
	}
	if e := f.p(1).epochMeta(e1); e == nil || e.Demoted || f.audited(1, "epoch_demoted_f1") {
		t.Fatal("a reconnect answer without a named epoch ran strict F1")
	}
}

// At the initiator's hs.resp. Q's own handshake is open (here a
// reconnect naming E0, its current epoch) when P, rotated, answers it with
// its links. While a handshake of Q's is open, Q establishes no other epoch
// with P except one that ends it ("A verified hs.fin comes first", §6.5,
// §6.6), and Q's rekeys wait for no pending epoch (§6.5) while its
// reconnect abandons one at its start; so no copy's epoch can be
// established at Q between Q's hs.init and P's hs.resp, and the epoch Q
// named is still current when the hs.resp's links are followed (strict F1
// with that epoch would do nothing). The copy's rekey crossing Q's
// reconnect is answered only if Q's th1 is the lower; then, either order:
//   - P's hs.resp first: Q's own handshake completed first, so its answer
//     to the copy's crossing rekey is dropped (§6.5; it is also pinned to
//     the old ik, H5), and the copy's hs.fin establishes nothing;
//   - the copy's hs.fin first: E1 is established and Q's reconnect is
//     abandoned, so P's hs.resp is dropped (no link followed there); the
//     link reaches Q in P's identity.rotate under E0, and strict F1 demotes
//     E1, so the copy's later note is refused.
func i3QReconnect(t *testing.T) (f *r29Fx, e0, oldIK []byte) {
	t.Helper()
	for try := 0; try < 64; try++ {
		f = newR29Fx(t)
		f.longTokens()
		for s := 0; s < 2; s++ {
			f.do(s, func(m *Manager, _ *Peer) { m.dirty = true })
		}
		e0 = append([]byte(nil), f.cur(1)...)
		oldIK = append([]byte(nil), f.p(1).IK...)
		snap := f.snapshot(0)
		f.rotate(0)
		f.startCopy(0, snap)
		f.lose(0, 1, kHSInit) // P's own rekey at its rotation: lost

		f.do(1, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
		og := f.openReconnect(1)
		if og == nil || !bytes.Equal(og.Named, e0) {
			t.Fatal("setup: Q's reconnect does not name E0")
		}
		f.rekey(2)
		var theirs [32]byte
		for _, c := range f.m(2).st.Outgoing {
			copy(theirs[:], c.Th1)
		}
		var ours [32]byte
		copy(ours[:], og.Th1)
		if !handshake.SimultaneousRekeyWinner(ours, theirs) {
			continue // Q's reconnect would be abandoned for the copy's rekey: not this case
		}
		if f.deliver(2, 1, kHSInit) != 1 || f.deliver(1, 2, kHSResp) != 1 || f.p(2).Pending == nil {
			t.Fatalf("setup: the copy's rekey was not answered beside Q's reconnect; Q's audits %v", auditEvents(f.m(1)))
		}
		if f.openReconnect(1) == nil {
			t.Fatal("setup: Q's reconnect was abandoned")
		}
		if f.deliver(1, 0, kHSInit) != 1 {
			t.Fatal("setup: Q's reconnect hs.init did not reach P")
		}
		return f, e0, oldIK
	}
	t.Fatal("setup: Q's th1 was never the lower")
	return nil, nil, nil
}

func TestR29I3QHandshakeRespFirst(t *testing.T) {
	f, e0, oldIK := i3QReconnect(t)
	if f.deliver(0, 1, kHSResp) != 1 {
		t.Fatal("setup: P did not answer Q's reconnect")
	}
	if bytes.Equal(f.p(1).IK, oldIK) {
		t.Fatal("Q did not follow P's link at the hs.resp")
	}
	if !bytes.Equal(f.cur(1), e0) {
		t.Fatal("Q's current epoch moved before P's hs.resp")
	}
	for _, aw := range f.m(1).st.Awaiting {
		if aw.PeerID == f.id[1] && aw.Purpose == handshake.PurposeRekey {
			t.Fatal("Q's answer to the copy's crossing rekey outlived P's hs.resp")
		}
	}
	e1 := append([]byte(nil), f.p(2).Pending.ID...)
	f.deliver(2, 1, kHSFin)
	if e := f.p(1).epochMeta(e1); e != nil {
		t.Fatalf("the copy's hs.fin after the link made an epoch at Q; Q's audits %v", auditEvents(f.m(1)))
	}
	if f.p(1).suspended() {
		t.Fatal("suspended")
	}
	f.deliver(0, 1, kAny)
	f.settle()
	if f.p(1).suspended() || !f.sameEpoch() {
		t.Fatalf("P and Q did not settle; Q's audits %v", auditEvents(f.m(1)))
	}
	f.talks()
}

func TestR29I3QHandshakeCopyFinFirst(t *testing.T) {
	f, _, oldIK := i3QReconnect(t)
	e1 := append([]byte(nil), f.p(2).Pending.ID...)
	if f.deliver(2, 1, kHSFin) != 1 || !bytes.Equal(f.cur(1), e1) {
		t.Fatal("setup: Q did not establish the copy's E1")
	}
	if f.openReconnect(1) != nil {
		t.Fatal("Q's reconnect was not abandoned at the copy's verified hs.fin")
	}
	f.deliver(1, 2, kAny)
	f.deliver(0, 1, kHSResp) // P's answer to the abandoned reconnect: dropped
	if !bytes.Equal(f.p(1).IK, oldIK) {
		t.Fatal("Q followed a link from an hs.resp to an abandoned handshake")
	}
	f.deliver(0, 1, kRotate) // the link, under E0: strict F1
	if e := f.p(1).epochMeta(e1); e == nil || !e.Demoted {
		f.dump()
		t.Fatal("E1 was not demoted by strict F1 at P's identity.rotate")
	}
	n := len(f.got[1])
	f.note(2, "copy-under-e1-after-the-link")
	f.deliver(2, 1, kNote)
	if len(f.got[1]) != n || !f.activity(1, "drop.peer_key", "ancestor_ik") {
		t.Fatal("Q took the copy's note under E1 deposited after the link")
	}
}
