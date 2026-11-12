package vault

import (
	"bytes"
	"testing"
	"time"
)

// An old copy of Q that collects Q's live mailbox (§3.4.1 Residuals) runs
// a reconnect after a strict-F1 demotion, which replaces P's rekey
// (rekey_replaced_by_reconnect), and gets an epoch with P. Side 0 is P,
// side 1 is Q, side 2 the copy of Q.
//
//  1. P rekeys; Q activates E1 at hs.fin; Q's hs.confirm is lost. The
//     copy is taken now (E1 current at Q).
//  2. P rotates its ik: its pending E1 is abandoned (S5); identity.rotate
//     under E0 and a rekey naming E0 go to Q's mailbox. The copy collects
//     them: strict F1 demotes E1, the copy reconnects naming E0
//     (reconnectNaming), and P's rekey is discarded.
//  3. P answers the copy's reconnect; the copy goes pending (E2) and sends
//     hs.fin; P activates E2.
//  4. Q rotates its ik; its identity.rotate under E1 and its rekey never
//     reach P (P away past the relay's message lifetime).
//  5. The copy collects P's hs.confirm, confirms E2 and sends a note under
//     it: P handles it as Q's, and E2 becomes P's confirmed epoch.
//  6. A month later (P's records of E1 are kept 64 days after it was
//     superseded) Q reconnects naming E1, carrying its link. E1 is no longer kept as
//     abandoned while pending at P (a newer epoch, E2, is confirmed), and
//     E2, between E1 and P's confirmed epoch, is signed by the link's old
//     ik: "Fork by ctx". P suspends at the reconnect's hs.fin (ref epoch,
//     with a feed item).
func TestR29CopyReconnectAfterReplacedRekey(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	for s := 0; s < 2; s++ {
		f.do(s, func(m *Manager, _ *Peer) { m.dirty = true }) // the long tokens are stored
	}
	e0 := append([]byte(nil), f.cur(0)...)

	// 1.
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	if f.p(0).Pending == nil {
		t.Fatal("setup: P is not pending")
	}
	e1 := append([]byte(nil), f.p(0).Pending.ID...)
	f.deliver(0, 1, kHSFin)
	if !bytes.Equal(f.cur(1), e1) {
		t.Fatal("setup: Q did not activate E1")
	}
	f.lose(1, 0, kConfirm)
	snap := f.snapshot(1)

	// 2.
	f.advance(time.Hour)
	f.rotate(0)
	if f.p(0).Pending != nil {
		t.Fatal("setup: P's pending E1 was not abandoned at its rotation")
	}
	f.startCopy(1, snap)
	if f.deliver(0, 2, kAny) == 0 {
		t.Fatal("setup: nothing from P in Q's mailbox")
	}
	if !f.audited(2, "rekey_replaced_by_reconnect") {
		t.Fatalf("the copy did not discard P's rekey; its audits %v", auditEvents(f.m(2)))
	}
	if og := f.openReconnect(2); og == nil || !bytes.Equal(og.Named, e0) {
		t.Fatal("the copy has no reconnect naming E0 open")
	}

	// 3.
	if f.deliver(2, 0, kHSInit) != 1 {
		t.Fatal("setup: no reconnect hs.init from the copy")
	}
	f.deliver(0, 2, kHSResp)
	if f.p(2).Pending == nil {
		t.Fatalf("the copy is not pending after P's hs.resp; P's audits %v", auditEvents(f.m(0)))
	}
	e2 := append([]byte(nil), f.p(2).Pending.ID...)
	f.deliver(2, 0, kHSFin)
	if !bytes.Equal(f.cur(0), e2) {
		t.Fatalf("P did not activate the copy's epoch E2; P's audits %v", auditEvents(f.m(0)))
	}

	// 4.
	f.advance(time.Hour)
	f.rotate(1)
	f.lose(1, 0, kAny)

	// 5.
	if f.deliver(0, 2, kConfirm) != 1 || !bytes.Equal(f.cur(2), e2) {
		t.Fatal("setup: the copy did not confirm E2")
	}
	f.note(2, "from-the-copy")
	n0 := len(f.got[0])
	f.deliver(2, 0, kNote)
	if len(f.got[0]) != n0+1 || !f.flag(0, e2) || !bytes.Equal(f.p(0).confirmedID(), e2) {
		t.Fatal("setup: P did not handle the copy's note under E2")
	}
	for _, a := range f.p(0).Abandoned {
		if bytes.Equal(a, e1) {
			t.Fatal("E1 is still kept as abandoned while pending at P after E2 was confirmed")
		}
	}
	if f.p(0).suspended() || f.forkFeed(0) || f.forkFeed(1) {
		t.Fatal("setup: something is already visible")
	}
	t.Logf("P activated and confirmed E2, made with the copy, and handled its note as Q's")

	// 6.
	f.advance(31 * 24 * time.Hour)
	f.tick(0)
	f.tick(1)
	if f.p(0).epochMeta(e1) == nil {
		t.Fatal("setup: P no longer knows E1")
	}
	f.lose(0, 1, kAny) // P's messages under E2: Q cannot open them
	f.do(1, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	if og := f.openReconnect(1); og == nil || !bytes.Equal(og.Named, e1) {
		t.Fatal("setup: Q has no reconnect naming E1")
	}
	f.deliver(1, 0, kHSInit)
	if f.p(0).suspended() {
		t.Fatal("P suspended before Q's hs.fin")
	}
	f.deliver(0, 1, kHSResp)
	f.deliver(1, 0, kHSFin)
	if !f.p(0).suspended() || !f.suspendedRef(0, "epoch") || !f.forkFeed(0) {
		t.Fatalf("P did not suspend (fork by ctx, with a feed item) at Q's reconnect; P's activity %v", activityKinds(f.sink[0]))
	}
	t.Logf("P suspended at Q's reconnect hs.fin (ref epoch, feed item); Q suspended %v, Q feed %v", f.p(1).suspended(), f.forkFeed(1))
}

func auditEvents(m *Manager) []string {
	var out []string
	for _, a := range m.st.Audit {
		out = append(out, a.Event)
	}
	return out
}

func activityKinds(s *recSink) []string {
	var out []string
	for _, a := range s.got {
		k := a.Kind
		if a.Feed {
			k += "(feed)"
		}
		out = append(out, k+":"+a.Ref)
	}
	return out
}
