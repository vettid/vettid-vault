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
//     (flagged: the copy then sends a note under E1, before the link.)
//  5. P's hs.fin reaches Q: Q follows the link there.
//
// Until the owner decision of 2026-11-12 the link was followed at P's hs.fin
// with no strict F1, E1 was established before that position (no demotion
// by position), and P's later identity.rotate found its link already
// followed: Q took the copy's messages under E1 and nothing was visible.
// Now the link applied at hs.fin runs strict F1 with E the epoch the
// hs.init traveled under (§3.4.1 invariant I3).
type i3Rekey struct {
	f              *r29Fx
	e0, e1, e2     []byte
	oldIK          []byte
	beforeFinNotes int // notes Q handled before P's hs.fin
}

// i3CopyBesideRekey runs steps 1 to 4; with flagged the copy sends a note
// under E1 before P's hs.fin (its received flag set at Q). With oldRecord
// Q's answer to P's rekey is made a record written before InitEpoch. Step 5
// is the caller's.
func i3CopyBesideRekey(t *testing.T, flagged, oldRecord bool) *i3Rekey {
	t.Helper()
	f := newR29Fx(t)
	f.longTokens()
	for s := 0; s < 2; s++ {
		f.do(s, func(m *Manager, _ *Peer) { m.dirty = true })
	}
	x := &i3Rekey{f: f, e0: append([]byte(nil), f.cur(1)...), oldIK: append([]byte(nil), f.p(1).IK...)}
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
	x.e1 = append([]byte(nil), f.p(2).Pending.ID...)

	// 3.
	if f.deliver(0, 1, kHSInit) != 1 {
		t.Fatal("setup: no rekey hs.init from P")
	}
	if f.deliver(1, 0, kHSResp) != 1 || f.p(0).Pending == nil {
		t.Fatalf("setup: P is not pending; Q's audits %v", auditEvents(f.m(1)))
	}
	x.e2 = append([]byte(nil), f.p(0).Pending.ID...)
	recorded := 0
	f.do(1, func(m *Manager, p *Peer) {
		for _, aw := range m.st.Awaiting {
			if aw.PeerID != p.ID || aw.Purpose != "rekey" || len(aw.Links) == 0 {
				continue
			}
			recorded++
			if !bytes.Equal(aw.InitEpoch, x.e0) {
				t.Fatal("the answer to P's rekey does not record E0 as the epoch its hs.init traveled under")
			}
			if oldRecord {
				aw.InitEpoch = nil
				m.dirty = true
			}
		}
	})
	if recorded != 1 {
		t.Fatalf("setup: %d answers to P's link-carrying rekey at Q", recorded)
	}

	// 4.
	if f.deliver(2, 1, kHSFin) != 1 || !bytes.Equal(f.cur(1), x.e1) {
		t.Fatal("setup: Q did not establish the copy's E1")
	}
	if e := f.p(1).epochMeta(x.e1); e == nil || !bytes.Equal(e.Signer, x.oldIK) {
		t.Fatal("setup: E1 is not signed by P's old ik at Q")
	}
	f.deliver(1, 2, kAny) // Q's hs.confirm for E1 reaches the copy
	if !bytes.Equal(f.cur(2), x.e1) {
		t.Fatal("setup: the copy did not confirm E1")
	}
	if flagged {
		n := len(f.got[1])
		f.note(2, "copy-under-e1-before-the-link")
		f.deliver(2, 1, kNote)
		if len(f.got[1]) != n+1 || !f.flag(1, x.e1) {
			t.Fatal("setup: Q did not take the copy's note under E1 before the link")
		}
	}
	x.beforeFinNotes = len(f.got[1])
	return x
}

// The flag clear: strict F1 at P's hs.fin, E = E0, demotes E1 by position
// (x = the hs.fin), audited connection.fork_suspected (ref epoch) with no
// feed item and no suspension; Q establishes E2, and the copy's note under
// E1 deposited after the link is refused (ancestor_ik).
func TestR29CopyInitiatorAfterLinkViaRekey(t *testing.T) {
	x := i3CopyBesideRekey(t, false, false)
	f := x.f

	// 5.
	if f.deliver(0, 1, kHSFin) != 1 {
		t.Fatal("setup: no hs.fin from P")
	}
	if bytes.Equal(f.p(1).IK, x.oldIK) || !bytes.Equal(f.cur(1), x.e2) {
		t.Fatalf("Q did not follow P's link and establish E2 at P's hs.fin; Q's audits %v", auditEvents(f.m(1)))
	}
	e := f.p(1).epochMeta(x.e1)
	if e == nil || !e.Demoted || e.Destroyed {
		f.dump()
		t.Fatal("E1 was not demoted by strict F1 at P's hs.fin")
	}
	if !f.audited(1, "epoch_demoted_f1") || !f.activity(1, "connection.fork_suspected", "epoch") {
		t.Fatal("the demotion was not audited connection.fork_suspected (ref epoch)")
	}
	if f.p(1).suspended() || f.forkFeed(1) {
		t.Fatal("suspended, or a feed item, with E1's flag clear")
	}
	for _, id := range [][]byte{x.e0, x.e2} {
		if e := f.p(1).epochMeta(id); e == nil || e.Demoted || e.Destroyed {
			t.Fatal("P's own epoch E0, or the hs.fin's own epoch E2, was judged")
		}
	}

	// The copy's note under E1, deposited after the link: refused.
	n := len(f.got[1])
	f.note(2, "copy-under-e1-after-the-link")
	if f.deliver(2, 1, kNote) != 1 {
		t.Fatal("setup: the copy sent nothing under E1")
	}
	if len(f.got[1]) != n || !f.activity(1, "drop.peer_key", "ancestor_ik") {
		t.Fatal("Q took the copy's note under E1 deposited after the link")
	}
	if f.p(1).suspended() {
		t.Fatal("a message under E1 deposited after the link suspended")
	}

	// P's identity.rotate arrives at last (links already followed:
	// ignored), and P and Q talk under E2.
	f.deliver(0, 1, kAny)
	f.settle()
	if f.p(1).suspended() || f.p(0).suspended() || !f.sameEpoch() || !bytes.Equal(f.cur(1), x.e2) {
		t.Fatalf("P and Q did not settle on E2; Q's audits %v", auditEvents(f.m(1)))
	}
	f.talks()
	if f.p(1).suspended() || f.forkFeed(1) {
		t.Fatal("P's own messages under E2 were taken as fork evidence")
	}
}

// The flag set (the copy sent under E1 before the link): strict F1 at P's
// hs.fin suspends (ref epoch, the neutral feed item) and E2 is not
// established.
func TestR29CopyInitiatorAfterLinkViaRekeyFlagSuspends(t *testing.T) {
	x := i3CopyBesideRekey(t, true, false)
	f := x.f
	f.deliver(0, 1, kHSFin)
	if !f.suspendedRef(1, "epoch") || !f.forkFeed(1) {
		f.dump()
		t.Fatal("Q did not suspend (ref epoch) at P's hs.fin with E1's flag set")
	}
	if bytes.Equal(f.cur(1), x.e2) || f.p(1).epochMeta(x.e2) != nil {
		t.Fatal("E2 was established on a suspended connection")
	}
}

// An answer recorded before InitEpoch (an old record) is finished as
// before: no strict F1 at hs.fin, E1 kept, the copy's note taken.
func TestR29CopyInitiatorAfterLinkViaRekeyOldRecord(t *testing.T) {
	x := i3CopyBesideRekey(t, false, true)
	f := x.f
	if f.deliver(0, 1, kHSFin) != 1 || !bytes.Equal(f.cur(1), x.e2) {
		t.Fatal("setup: Q did not establish E2 at P's hs.fin")
	}
	if e := f.p(1).epochMeta(x.e1); e == nil || e.Demoted || e.Destroyed || f.audited(1, "epoch_demoted_f1") {
		t.Fatal("an old record ran strict F1")
	}
	n := len(f.got[1])
	f.note(2, "copy-under-e1-after-the-link")
	f.deliver(2, 1, kNote)
	if len(f.got[1]) != n+1 || f.p(1).suspended() {
		t.Fatal("an old record's behaviour changed")
	}
}

// The epoch a rekey's hs.init traveled under is kept with Q's answer
// across a restart: Q locks and unlocks between its answer and P's hs.fin,
// and strict F1 at the hs.fin still demotes E1.
func TestR29CopyInitiatorAfterLinkViaRekeyRestart(t *testing.T) {
	x := i3CopyBesideRekey(t, false, false)
	f := x.f
	f.restart(1)
	if f.deliver(0, 1, kHSFin) != 1 || !bytes.Equal(f.cur(1), x.e2) {
		t.Fatalf("Q did not establish E2 at P's hs.fin after its restart; Q's audits %v", auditEvents(f.m(1)))
	}
	if e := f.p(1).epochMeta(x.e1); e == nil || !e.Demoted || !f.audited(1, "epoch_demoted_f1") {
		f.dump()
		t.Fatal("E1 was not demoted by strict F1 after Q's restart")
	}
	n := len(f.got[1])
	f.note(2, "copy-under-e1-after-the-link")
	f.deliver(2, 1, kNote)
	if len(f.got[1]) != n || f.p(1).suspended() {
		t.Fatal("Q took the copy's note under E1 deposited after the link")
	}
}
