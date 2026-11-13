package vault

import (
	"bytes"
	"testing"
)

// An old copy of P as initiator, against P's identity link carried by P's
// own rekey (trust model run seed 7497118903681018023, rotation off).
// Side 0 is P, side 1 is Q, side 2 an old copy of P taken before P's
// identity rotation.
//
//  1. P rotates its ik: identity.rotate under E0 and a rekey hs.init under
//     E0 carrying the link old->new go to Q's mailbox. The identity.rotate
//     is delayed (the relay may deliver in any order); the rekey is not.
//  2. The copy, still on the old ik, rekeys with Q: Q answers it.
//  3. Q answers P's rekey (ctx E0, Q's current epoch: an ordinary rekey,
//     no rule E); P goes pending.
//  4. The copy's hs.fin reaches Q: Q establishes E1, signed by the old ik.
//     The copy takes Q's hs.confirm and confirms E1.
//  5. P's hs.fin reaches Q: Q follows the link there and establishes E2.
//  6. The copy sends a note under E1, deposited after the link.
//  7. P's identity.rotate finally arrives.
//
// As built (release 29), the gap reproduces: the link is followed at P's
// hs.fin with no epoch (no strict F1), E1 was established before that
// position (no demotion by position), and when P's identity.rotate comes
// its link is already followed (ignored; R29-K9 judges only epochs Q began
// as initiator). Q takes the copy's note under E1 and nothing is ever
// visible. The test pins that behaviour; it fails once the gap is closed
// (for example by strict F1 on a rekey's links at hs.fin, with E the
// epoch the hs.init traveled under), and must then be inverted.
func TestR29CopyInitiatorAfterLinkViaRekey(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	for s := 0; s < 2; s++ {
		f.do(s, func(m *Manager, _ *Peer) { m.dirty = true })
	}
	e0 := append([]byte(nil), f.cur(1)...)
	oldIK := append([]byte(nil), f.p(1).IK...)
	snap := f.snapshot(0)

	// 1.
	f.rotate(0)
	f.startCopy(0, snap)

	// 2.
	f.rekey(2)
	if f.deliver(2, 1, kHSInit) != 1 {
		t.Fatal("setup: no rekey hs.init from the copy")
	}
	if f.deliver(1, 2, kHSResp) != 1 || f.p(2).Pending == nil {
		t.Fatal("setup: the copy is not pending")
	}
	e1 := append([]byte(nil), f.p(2).Pending.ID...)

	// 3.
	if f.deliver(0, 1, kHSInit) != 1 {
		t.Fatal("setup: no rekey hs.init from P")
	}
	if f.deliver(1, 0, kHSResp) != 1 || f.p(0).Pending == nil {
		t.Fatalf("setup: P is not pending; Q's audits %v", auditEvents(f.m(1)))
	}
	e2 := append([]byte(nil), f.p(0).Pending.ID...)

	// 4.
	if f.deliver(2, 1, kHSFin) != 1 || !bytes.Equal(f.cur(1), e1) {
		t.Fatal("setup: Q did not establish the copy's E1")
	}
	if e := f.p(1).epochMeta(e1); e == nil || !bytes.Equal(e.Signer, oldIK) {
		t.Fatal("setup: E1 is not signed by P's old ik at Q")
	}
	f.deliver(1, 2, kAny) // Q's hs.confirm for E1 reaches the copy
	if !bytes.Equal(f.cur(2), e1) {
		t.Fatal("setup: the copy did not confirm E1")
	}

	// 5.
	if f.deliver(0, 1, kHSFin) != 1 {
		t.Fatal("setup: no hs.fin from P")
	}
	if bytes.Equal(f.p(1).IK, oldIK) || !bytes.Equal(f.cur(1), e2) {
		t.Fatalf("setup: Q did not follow P's link and establish E2 at P's hs.fin; Q's audits %v", auditEvents(f.m(1)))
	}
	if e := f.p(1).epochMeta(e1); e != nil {
		t.Logf("after the link: E1 at Q demoted %v, destroyed %v, flag %v", e.Demoted, e.Destroyed, e.GotFromPeer)
	}

	// 6.
	n := len(f.got[1])
	f.note(2, "copy-under-e1-after-the-link")
	f.deliver(2, 1, kNote)
	accepted := len(f.got[1]) == n+1
	t.Logf("Q handled the copy's note under E1 deposited after the link: %v; Q suspended %v; Q's fork feed %v; Q's current is E2 %v, confirmed is E1 %v, E2 %v",
		accepted, f.p(1).suspended(), f.forkFeed(1), bytes.Equal(f.cur(1), e2), bytes.Equal(f.p(1).confirmedID(), e1), bytes.Equal(f.p(1).confirmedID(), e2))

	// 7.
	f.deliver(0, 1, kAny)
	t.Logf("after P's identity.rotate: Q suspended %v, fork feed %v, Q's audits %v", f.p(1).suspended(), f.forkFeed(1), auditEvents(f.m(1)))
	_ = e0
	if !accepted || f.p(1).suspended() || f.forkFeed(1) {
		t.Fatal("the gap no longer reproduces: invert this test (the copy's message must be refused, or Q suspend)")
	}
	if e := f.p(1).epochMeta(e1); e == nil || e.Demoted || e.Destroyed {
		t.Fatal("E1 is no longer kept at Q")
	}
}
