package vault

import (
	"bytes"
	"testing"
	"time"
)

// §3.4.1 "The reconnect bound" (R29-K6): every reconnect Q starts with P is
// bounded the same way, not only the reconnect after a demotion.

// A plain reconnect (the standing token expired, §7.2) that expires
// unanswered is tried again; the third failed try for the same named epoch
// makes the connection stale, and no fourth starts.
func TestR29PlainReconnectBoundedThenStale(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.p(0).Standing.Exp = f.clk // expired: §7.2 reconnects
	f.tick(0)
	for i := 1; i <= 3; i++ {
		og := f.openReconnect(0)
		if og == nil {
			f.dump()
			t.Fatalf("try %d: no reconnect open", i)
		}
		if f.m(0).currentDemoted(f.p(0)) {
			t.Fatal("setup: demoted")
		}
		f.lose(0, 1, kAny)
		f.advance(HandshakeTTL + time.Hour)
		f.tick(0)
		if i < 3 && f.p(0).State == PeerStale {
			t.Fatalf("stale after %d failed tries", i)
		}
	}
	if f.p(0).State != PeerStale || !f.sink[0].has("connection.stale") {
		f.dump()
		t.Fatal("the third failed try of a plain reconnect did not make the connection stale")
	}
	f.tick(0)
	if f.openReconnect(0) != nil {
		t.Fatal("a fourth try started")
	}
}

// A plain reconnect whose pending epoch reaches B makes the connection
// stale at once (§6.3.1), with no new try.
func TestR29PlainPendingReconnectAtBStale(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	if f.p(0).Pending == nil {
		t.Fatal("setup: no pending reconnect")
	}
	f.lose(0, 1, kAny)
	f.advance(PendingLife + time.Hour)
	f.tick(0)
	f.tick(0)
	if f.p(0).State != PeerStale || !f.sink[0].has("connection.stale") || f.openReconnect(0) != nil {
		f.dump()
		t.Fatal("a pending reconnect at B did not make the connection stale at once")
	}
}

// Q cannot start a reconnect it needs (its standing token expired) because
// it holds no reconnect token for P: the connection is stale.
func TestR29NoReconnectTokenStale(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.p(0).Reconnect.Token = ""
	f.p(0).Standing.Exp = f.clk
	f.tick(0)
	if f.p(0).State != PeerStale || !f.sink[0].has("connection.stale") {
		f.dump()
		t.Fatal("no reconnect token, a reconnect needed, yet not stale")
	}
}

// §6.3.1 "Initiator" (R29-I6): a pending rekey is abandoned when the vault
// finds it holds no valid standing token for the peer (judged at the
// tick, without a refused deposit); the connection then reconnects naming
// its current epoch.
func TestR29I6NoTokenAbandonsPendingRekey(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e0, _ := f.lostConfirm()
	f.p(0).Standing.Exp = f.clk.Add(-time.Second)
	f.tick(0)
	if f.p(0).Pending != nil || !f.audited(0, "pending_abandoned_no_token") {
		f.dump()
		t.Fatal("a pending rekey without a valid standing token was not abandoned")
	}
	og := f.openReconnect(0)
	if og == nil || !bytes.Equal(og.Named, e0) {
		f.dump()
		t.Fatal("no reconnect naming the current epoch")
	}
}
