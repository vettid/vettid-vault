package vault

import (
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
)

func (f *r29Fx) countOutgoingReconnects(s int) int {
	n := 0
	for _, og := range f.m(s).st.Outgoing {
		if og.PeerID == f.id[s] && og.Purpose == handshake.PurposeReconnect {
			n++
		}
	}
	return n
}

func (f *r29Fx) auditCount(s int, ev string) int {
	n := 0
	for _, a := range f.m(s).st.Audit {
		if a.Event == ev {
			n++
		}
	}
	return n
}

// The delta review's probes of 1c9f209, kept as regression tests.

// RR2-1: Q's E1 was confirmed by R's old copy (its hs.confirm sets E1's
// received flag); R's link under E0 then meets strict F1 with the flag
// set: Q suspends (ref epoch) at once, so nothing is left wedged
// (0.87.1: this test "flips to suspended").
func TestR29RR2OwnCopyNoRKLostReconnectWedges(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	snap := f.snapshot(1)
	f.rotate(1)
	f.deliver(0, 1, kAny)
	f.deliver(1, 0, kHSResp)
	f.startCopy(1, snap)
	if f.deliver(0, 2, kHSFin) != 1 {
		t.Fatal("setup: no hs.fin for the copy")
	}
	f.deliver(2, 0, kConfirm) // sets E1's received flag
	f.deliver(1, 0, kRotate)  // strict F1: E1's flag is set
	if !f.suspendedRef(0, "epoch") {
		f.dump()
		t.Fatal("strict F1 over an epoch with its flag set did not suspend")
	}
}

// RR2-2: tickDemoted, with the current epoch demoted and every reconnect
// lost: how many reconnects over 6 handshake lifetimes (no bound besides
// the reconnect token)?
func TestR29RR2TickDemotedBound(t *testing.T) {
	f := demoted(t, nil)
	starts := 0
	for i := 0; i < 6; i++ {
		starts += f.lose(0, 1, kHSInit)
		f.advance(HandshakeTTL + time.Hour)
		f.tick(0)
	}
	t.Logf("reconnect hs.inits deposited over 6 lifetimes while demoted: %d; issued registry %d", starts, len(f.m(0).st.Issued))
	if starts > ReconnectTries || f.p(0).State != PeerStale {
		t.Errorf("%d tries while demoted (bound %d), state %v", starts, ReconnectTries, f.p(0).State)
	}
}

// RR2-3: tickDemoted when no reconnect can start (the reconnect token
// expired): every batch calls reconnectNaming, which abandons rekeys and
// notes reconnect_not_started.
func TestR29RR2TickDemotedNoTokenSpam(t *testing.T) {
	f := demoted(t, nil)
	f.lose(0, 1, kAny)
	f.advance(HandshakeTTL + time.Hour)
	f.p(0).Reconnect.Token = ""
	before := f.auditCount(0, "reconnect_not_started")
	for i := 0; i < 50; i++ {
		f.tick(0)
	}
	after := f.auditCount(0, "reconnect_not_started")
	t.Logf("reconnect_not_started notes from 50 empty batches: %d", after-before)
	if after-before != 0 {
		t.Errorf("batches audit reconnect_not_started (%d in 50): the 1000-entry audit ring is flushed by it", after-before)
	}
	if f.p(0).State != PeerStale {
		t.Error("no reconnect token left, yet not stale")
	}
}

// RR2-1b: Q's current epoch demoted by strict F1 (flag clear, the
// demoted fixture) and its reconnect naming E0 lost, with the standing
// tokens expiring 30 days on (as without longTokens): the pair recovers.
func TestR29RR2OwnCopyNoRKLostReconnectTokenExpiry(t *testing.T) {
	f := demoted(t, nil)
	f.lose(0, 1, kHSInit)
	for i := 0; i < 4; i++ {
		f.deliver(1, 0, kAny)
		f.lose(0, 1, kHSInit)
		f.deliver(0, 1, kAny)
	}
	f.note(0, "after-wedge")
	f.p(0).Standing.Exp = f.clk.Add(30 * 24 * time.Hour)
	f.p(1).Standing.Exp = f.clk.Add(30 * 24 * time.Hour)
	day := 0
	for ; day < 120; day++ {
		f.advance(24 * time.Hour)
		f.tick(0)
		f.tick(1)
		f.settle()
		ok := false
		for _, b := range f.got[1] {
			if strings.Contains(b, "after-wedge") {
				ok = true
			}
		}
		if ok {
			break
		}
	}
	t.Logf("held note arrived after %d days", day+1)
	if day == 120 {
		f.dump()
		t.Error("never recovered")
	}
}

// RR2-4: handleResp's new rule-C return (and the suspended return after
// followLinks) come after the outgoing handshake was deleted: the tokens
// its hs.init carried are neither revoked nor in the issued registry, so
// removing the connection leaves them redeemable.
func TestR29RR2HandleRespConflictReturnLeaksTokens(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	snap := f.snapshot(1)
	f.startCopy(1, snap)
	f.rotate(2) // the copy: ik0 -> ik1'
	f.lose(2, 0, kRotate)
	f.deliver(2, 0, kHSInit) // Seen: ik0 -> ik1'
	if len(f.p(0).Seen) == 0 {
		t.Fatal("setup: no seen link")
	}
	f.rotate(1) // the original: ik0 -> ik1
	f.lose(1, 0, kAny)
	var jtis []string
	f.do(0, func(m *Manager, p *Peer) {
		og := m.startReconnectCtx(p, p.LastEpochID, f.clk)
		if og == nil {
			t.Fatal("setup: no reconnect")
		}
		for _, it := range og.Issued {
			jtis = append(jtis, it.JTI)
		}
	})
	n := f.deliver(0, 1, kHSInit)
	if f.p(0).Conflict != nil {
		t.Fatal("setup: conflict before the hs.resp")
	}
	r := f.deliver(1, 0, kHSResp)
	t.Logf("reconnect hs.init delivered %d, hs.resp delivered %d, conflict %v, outgoing reconnects left %d",
		n, r, f.p(0).Conflict != nil, f.countOutgoingReconnects(0))
	if f.p(0).Conflict == nil {
		f.dump()
		t.Skip("setup: hs.resp did not hit rule C")
	}
	f.do(0, func(m *Manager, p *Peer) { m.removePeer(p, "", f.clk) })
	unrevoked := 0
	for _, j := range jtis {
		revoked := false
		for _, e := range f.m(0).st.Outbox {
			if e.Op == OpRevoke && e.Value == j {
				revoked = true
			}
		}
		for _, it := range f.m(0).st.Issued {
			if it.JTI == j && it.Denied {
				revoked = true
			}
		}
		if !revoked {
			unrevoked++
		}
	}
	t.Logf("reconnect tokens %d, unrevoked after removal %d", len(jtis), unrevoked)
	if unrevoked > 0 {
		t.Errorf("%d tokens of the reconnect whose hs.resp hit rule C are left redeemable", unrevoked)
	}
}

// RR2-5: followLinks' deferred restart (L2) inside handleResp: the
// completing reconnect's outgoing entry is already deleted, so the
// restarted rekey starts beside the reconnect's pending epoch (what
// 1c9f209 forbids for an open reconnect).
func TestR29RR2HandleRespRestartBesidePending(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	// Q's reconnect while its rekey is open (startReconnectCtx does not
	// abandon an outgoing rekey).
	f.do(0, func(m *Manager, p *Peer) {
		if m.startReconnectCtx(p, p.LastEpochID, f.clk) == nil {
			t.Fatal("setup: no reconnect")
		}
	})
	held := f.lose(0, 1, kHSInit) // the reconnect hs.init, delivered later
	f.deliver(1, 0, kHSResp)      // the rekey's answer: pending E1, signer ik0
	if f.p(0).Pending == nil {
		t.Fatal("setup: no pending")
	}
	t.Logf("held reconnect hs.init %d; pending purpose %s", held, f.p(0).Pending.Purpose)
	// Re-queue Q's reconnect hs.init: abandon & restart is simplest.
	f.lose(0, 1, kAny)
	f.rotate(1)
	f.lose(1, 0, kRotate)
	var rekeysBefore int
	f.do(0, func(m *Manager, p *Peer) {
		for id, og := range m.st.Outgoing {
			if og.PeerID == p.ID && og.Purpose == handshake.PurposeReconnect {
				// deposit its hs.init again
				_ = id
				m.queueDeposit(&OutboxEntry{Op: OpDeposit, PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox,
					Token: p.Reconnect.Token, Payload: m.outgoing[id].Envelope(), Handshake: true}, f.clk)
			}
			if og.PeerID == p.ID && og.Purpose == handshake.PurposeRekey {
				rekeysBefore++
			}
		}
	})
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	rek := 0
	for _, og := range f.m(0).st.Outgoing {
		if og.PeerID == f.id[0] && og.Purpose == handshake.PurposeRekey {
			rek++
		}
	}
	pp := ""
	if f.p(0).Pending != nil {
		pp = string(f.p(0).Pending.Purpose)
	}
	t.Logf("after the reconnect's hs.resp with links: pending %q, outgoing rekeys %d (before %d)", pp, rek, rekeysBefore)
	f.settle()
	for i := 0; i < 4; i++ {
		f.advance(time.Hour)
		f.tick(0)
		f.tick(1)
		f.settle()
	}
	t.Logf("same epoch %v", f.sameEpoch())
	if pp == "reconnect" && rek > 0 {
		t.Error("a rekey runs beside the reconnect's pending epoch")
	}
	if !f.sameEpoch() {
		f.dump()
		t.Error("split")
	}
	f.talks()
}
