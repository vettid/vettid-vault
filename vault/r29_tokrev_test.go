package vault

import (
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"
)

// 0.88.2 §8.6 token_revoked between two vaults (owner decision a, GC
// 01M6SRQ1B7NM0Q00G0CEGHFES8): for a deposit to a connection with a
// standing token, the answer ends that token only, not the connection.

// revocations makes side s's relay judge each deposit to the other side
// by the other side's revocations (jti, sub), as a relay does.
func (f *r29Fx) revocations(s int) {
	o := 1 - s
	r := f.d[s].relay
	r.mu.Lock()
	r.check = func(mailbox, token string) error {
		if mailbox != f.m(o).st.Relay.Mailbox {
			return nil
		}
		c, err := relayauth.ParseToken(token, f.pk(o))
		if err != nil {
			return nil
		}
		or := f.d[o].relay
		for _, x := range or.revoked {
			if x == "jti:"+c.Jti || x == "sub:"+c.Sub {
				return &relayclient.Error{Status: 403, Code: CodeTokenRevoked}
			}
		}
		return nil
	}
	r.mu.Unlock()
}

// The shape of the random search's seed 15373789217866551976: P (side 1)
// reconnects; its hs.init carries a standing token, which Q (side 0)
// holds from the reconnect's hs.fin; P rotates before any hs.confirm, and
// S5 abandons its pending epoch, revoking the tokens its hs.init carried.
// Q's next deposit is answered token_revoked: Q drops that token and,
// holding no other, tries to reconnect (its reconnect token, from the same
// hs.init, is revoked too: a failed try). P's own restarted reconnect
// brings fresh tokens; the pair converges, not stale, and the waiting
// message arrives.
func TestR29TokenRevokedEndsTheTokenOnly(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.revocations(0)
	f.revocations(1)
	before := f.p(0).Standing.Token
	f.do(1, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	f.deliver(1, 0, kHSInit)
	f.deliver(0, 1, kHSResp)
	f.deliver(1, 0, kHSFin)
	f.lose(0, 1, kConfirm)
	tok := f.p(0).Standing.Token
	if tok == before {
		t.Fatal("setup: Q does not hold the reconnect's standing token")
	}
	f.rotate(1) // S5: P abandons its pending epoch, revoking its tokens; its identity.rotate and new reconnect wait in the relay
	f.note(0, "after-revoke")
	if f.p(0).State == PeerStale {
		f.dump()
		t.Fatal("token_revoked on a standing token made the connection stale")
	}
	if f.p(0).Standing.Token == tok || !f.audited(0, "standing_token_revoked") {
		t.Fatal("the revoked token was not dropped")
	}
	if f.openReconnect(0) == nil && !f.audited(0, "reconnect_token_revoked") {
		f.dump()
		t.Fatal("holding no other standing token, Q did not try to reconnect")
	}
	f.settle()
	f.advance(time.Minute)
	f.tick(0)
	f.tick(1)
	f.settle()
	if !f.sameEpoch() || f.p(0).State != PeerActive || f.p(1).State != PeerActive || f.arrived(1, "after-revoke") != 1 {
		f.dump()
		t.Fatal("the pair did not converge, or the waiting message was lost")
	}
	// The revoked token is refused if offered again.
	f.do(0, func(m *Manager, p *Peer) {
		if _, err := m.heldToken(tok, p); err == nil {
			t.Fatal("a revoked standing token was accepted again")
		}
	})
}

// A reconnect's own hs.init answered token_revoked is a failed try
// (§3.4.1 "The reconnect bound"): three make the connection stale.
func TestR29ReconnectTokenRevokedCountsAsTry(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.revocations(0)
	rt := f.p(0).Reconnect.Token
	c, err := relayauth.ParseToken(rt, f.pk(1))
	if err != nil {
		t.Fatal(err)
	}
	r := f.d[1].relay
	r.mu.Lock()
	r.revoked = append(r.revoked, "jti:"+c.Jti) // P revoked Q's reconnect token
	r.mu.Unlock()
	for i := 1; i <= ReconnectTries; i++ {
		f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
		if i < ReconnectTries && f.p(0).State == PeerStale {
			t.Fatalf("stale after %d refused tries", i)
		}
	}
	if f.p(0).State != PeerStale || !f.audited(0, "reconnect_token_revoked") {
		f.dump()
		t.Fatal("three reconnect hs.inits answered token_revoked did not make it stale")
	}
}
