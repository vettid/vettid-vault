package vault

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

// The independent review's probes of PR #206 (at 7c87776), kept as
// regression tests: each failed there and passes with its fix.

// Probe A: a message under an abandoned pending epoch must not move the
// confirmed epoch ("nothing under it confirms any more", §6.3.1; the
// model's newer() excludes Abandoned epochs).
func TestR29ReviewAbandonedPendingDoesNotConfirm(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e0 := append([]byte(nil), f.cur(0)...)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	if f.p(0).Pending == nil {
		t.Fatal("setup: no pending epoch")
	}
	e1 := append([]byte(nil), f.p(0).Pending.ID...)
	f.deliver(0, 1, kHSFin)
	if f.lose(1, 0, kConfirm) != 1 {
		t.Fatal("setup: no hs.confirm")
	}
	f.advance(PendingLife + time.Hour)
	f.tick(0)
	f.tick(0)
	if f.p(0).Pending != nil {
		t.Fatal("setup: B did not abandon the pending epoch")
	}
	if !bytes.Equal(f.p(0).confirmedID(), e0) {
		t.Fatalf("setup: confirmed moved already")
	}
	confBefore := 0
	for _, e := range f.m(0).st.Outbox {
		if e.Confirm {
			confBefore++
		}
	}
	f.note(1, "late-under-abandoned")
	f.deliver(1, 0, kNote)
	confAfter := 0
	for _, e := range f.m(0).st.Outbox {
		if e.Confirm {
			confAfter++
		}
	}
	t.Logf("confirmed=e1? %v; current=e0? %v; hs.confirm entries queued by the INITIATOR: %d -> %d",
		bytes.Equal(f.p(0).confirmedID(), e1), bytes.Equal(f.cur(0), e0), confBefore, confAfter)
	if bytes.Equal(f.p(0).confirmedID(), e1) {
		t.Error("a message under an abandoned pending epoch moved the confirmed epoch to it")
	}
}

// Probe B: messages held while the current epoch was demoted are sealed
// later with their original ts; held past MaxDurableAge they are dropped
// by the receiver (stale_or_future), although §3.4.1 says none is dropped.
func TestR29ReviewHeldMessagesNewTS(t *testing.T) {
	f := demoted(t, nil)
	f.note(0, "held-while-demoted")
	// Drive the repair handshake, but delay the hs.confirm 17 days (the
	// vault locked meanwhile), within B.
	advanced := false
	for i := 0; i < 20; i++ {
		n := f.deliver(0, 1, kAny)
		if !advanced && f.p(0).Pending != nil && n > 0 {
			// hs.fin delivered; the responder's hs.confirm waits.
			f.advance(17 * 24 * time.Hour)
			advanced = true
		}
		n += f.deliver(1, 0, kAny)
		f.d[0].appInbox()
		f.d[1].appInbox()
		if n == 0 {
			f.advance(time.Hour)
			f.tick(0)
			f.tick(1)
		}
	}
	got := 0
	for _, b := range f.got[1] {
		if strings.Contains(b, "held-while-demoted") {
			got++
		}
	}
	t.Logf("advanced=%v same epoch=%v held arrived %d times; side 1 stale_or_future audited: %v",
		advanced, f.sameEpoch(), got, f.audited(1, "stale_or_future"))
	if advanced && got == 0 {
		t.Error("a held message was lost: sealed with its original ts after more than MaxDurableAge")
	}
}

// Probe C: an f1 or demoted reconnect (reconnectNaming) that
// expires is retried with no bound; and
// an expired reconnect's tokens are not revoked (housekeeping uses
// dropOutgoing, not abandonOutgoing).
func TestR29ReviewOtherReconnectsBoundedTokensRevoked(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.do(0, func(m *Manager, p *Peer) {
		if !m.reconnectNaming(p, p.LastEpochID, "f1", f.clk) {
			t.Fatal("setup: no reconnect")
		}
	})
	tries := 0
	unrevoked := 0
	for i := 0; i < 6; i++ {
		var jtis []string
		for _, og := range f.m(0).st.Outgoing {
			if og.PeerID == f.id[0] && og.Named != nil {
				tries++
				for _, it := range og.Issued {
					jtis = append(jtis, it.JTI)
				}
			}
		}
		f.lose(0, 1, kAny)
		f.advance(HandshakeTTL + time.Hour)
		f.tick(0)
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
	}
	t.Logf("f1 reconnect attempts seen over 6 lifetimes: %d; state %v; tokens of expired reconnects not revoked: %d",
		tries, f.p(0).State, unrevoked)
	if tries > ReconnectTries {
		t.Errorf("an f1 reconnect was tried %d times (no bound; the bound is %d)", tries, ReconnectTries)
	}
	if unrevoked > 0 {
		t.Errorf("%d tokens of expired reconnect hs.inits were left redeemable", unrevoked)
	}
}

// Probe D: the tokens a pending reconnect's hs.init carried live only in
// Peer.Pending.Issued until confirmation; removing the connection while
// the reconnect is pending leaves them unrevoked (denyPeerTokens does not
// look there).
func TestR29ReviewPendingReconnectTokensOnRemove(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	pe := f.p(0).Pending
	if pe == nil || pe.Purpose != "reconnect" || len(pe.Issued) == 0 {
		t.Fatalf("setup: no pending reconnect with tokens: %+v", pe)
	}
	var jtis []string
	for _, it := range pe.Issued {
		jtis = append(jtis, it.JTI)
	}
	inRegistry := 0
	for _, j := range jtis {
		for _, it := range f.m(0).st.Issued {
			if it.JTI == j {
				inRegistry++
			}
		}
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
	t.Logf("pending reconnect tokens %d, in the issued registry %d, unrevoked after removal %d", len(jtis), inRegistry, unrevoked)
	if unrevoked > 0 {
		t.Errorf("%d tokens of a pending reconnect left redeemable after the connection was removed", unrevoked)
	}
}

// Probe E: rule C's "seen" links (0.86.0: every valid link that passes
// step 3 is kept as seen, followed or not, e.g. one in an unfinished
// handshake's rotations). An old copy's second successor carried only in
// a rekey hs.init that is answered but not finished, followed by the real
// link, must suspend (I4). The code compares only against followed links.
func TestR29ReviewRuleCSeenLinkInUnfinishedRekey(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	snap := f.snapshot(1)
	f.startCopy(1, snap)
	f.rotate(2) // the old copy: ik0 -> ik1'
	lostRot := f.lose(2, 0, kRotate)
	nInit := f.deliver(2, 0, kHSInit) // its rekey carries ik0 -> ik1' (S8): answered
	for _, a := range f.m(0).st.Audit {
		t.Logf("Q audit after copy hs.init: %s", a.Event)
	}
	answered := 0
	for _, aw := range f.m(0).st.Awaiting {
		if aw.PeerID == f.id[0] && len(aw.Links) > 0 {
			answered++
		}
	}
	f.rotate(1) // the original: ik0 -> ik1
	nRot := f.deliver(1, 0, kRotate)
	t.Logf("copy identity.rotate lost %d, copy rekey hs.init delivered %d, answered with links %d, real identity.rotate delivered %d; Q conflict=%v fork=%v",
		lostRot, nInit, answered, nRot, f.p(0).Conflict != nil, f.p(0).Fork != nil)
	if answered > 0 && nRot > 0 && f.p(0).Conflict == nil && f.p(0).Fork == nil {
		t.Error("two successors of ik0 reached Q (one seen in an answered rekey, one followed) and Q is not suspended")
	}
}

// Probe F: S8 rekeys between two release-29 vaults. ParseInit (and
// ParseResp) still refuse `rotations` for any purpose but reconnect
// ("present && purpose != reconnect"), so the rekey a vault starts after
// its own ik rotation, which carries its link (S8) to a peer with
// features, is refused by every release-29 peer (rekey_rejected). The
// pair stays on the epoch signed by the old ik.
func TestR29ReviewS8RekeyAfterRotation(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e0 := append([]byte(nil), f.cur(0)...)
	f.rotate(0)
	f.settle()
	f.advance(time.Hour)
	f.tick(0)
	f.tick(1)
	f.settle()
	t.Logf("side 1 rekey_rejected=%v; same epoch=%v; still on the pre-rotation epoch=%v; side 0 epoch signed by own chain %d of %d",
		f.audited(1, "rekey_rejected"), f.sameEpoch(), bytes.Equal(f.cur(0), e0), f.p(0).OwnChainAtEpoch, len(f.m(0).st.Rotations))
	if f.audited(1, "rekey_rejected") {
		t.Error("a release-29 peer refused the S8 rekey (rotations in a rekey hs.init) at parse")
	}
	if bytes.Equal(f.cur(0), e0) || f.p(0).OwnChainAtEpoch != len(f.m(0).st.Rotations) || !f.sameEpoch() {
		t.Error("no epoch under the new ik was established after the rotation")
	}
	if e := f.p(1).epochMeta(f.cur(1)); e == nil || !bytes.Equal(e.Signer, f.m(0).keys.ik.Public().(ed25519.PublicKey)) {
		t.Error("the peer's current epoch is not signed by the new ik")
	}
}
