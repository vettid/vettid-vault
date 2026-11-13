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
// reconnects; its hs.init carries a standing token; P rotates before any
// hs.confirm, and S5 abandons its pending epoch, revoking the tokens its
// hs.init carried. Before 0.88.2 Q (side 0) held them from the reconnect's
// hs.fin and its next deposits were refused. (0.88.2, R29-T1) Q keeps them
// apart as carried tokens and goes on with its held ones, so it never
// holds a token P revoked; P's own restarted reconnect brings fresh tokens;
// the pair converges, not stale, and the waiting message arrives.
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
	if f.p(0).Standing.Token != before {
		t.Fatal("Q adopted the reconnect's standing token at hs.fin (R29-T1)")
	}
	c := f.p(0).carriedFor(f.p(0).LastEpochID)
	if c == nil || c.Standing.Token == "" {
		t.Fatal("setup: Q does not keep the reconnect's carried tokens")
	}
	tok := c.Standing.Token
	f.rotate(1) // S5: P abandons its pending epoch, revoking its tokens; its identity.rotate and new reconnect wait in the relay
	f.note(0, "after-revoke")
	if f.p(0).State == PeerStale {
		f.dump()
		t.Fatal("the revocation of a carried token made the connection stale")
	}
	if f.p(0).Standing.Token == tok {
		t.Fatal("Q holds a token P revoked")
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
	// (0.88.2) Q never deposited with the revoked carried token, so it has
	// not learnt the revocation from the relay; what counts is that it
	// never adopted it.
	if f.p(0).Standing.Token == tok {
		t.Fatal("Q adopted a token P revoked")
	}
}

// A reconnect's own hs.init answered token_revoked is a failed try
// (§3.4.1 "The reconnect bound"), and the reconnect token is dropped (its
// jti recorded, so it is never adopted again): the next reconnect finds no
// reconnect token, and the connection is stale.
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
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	p := f.p(0)
	if p.State == PeerStale || !f.audited(0, "reconnect_token_revoked") || p.RC == nil || p.RC.Tries != 1 {
		f.dump()
		t.Fatal("a reconnect hs.init answered token_revoked is not one failed try")
	}
	if p.Reconnect.Token != "" {
		t.Fatal("the revoked reconnect token is still held")
	}
	if _, err := f.m(0).heldToken(rt, p, TokReconnect); err != errRevokedHeld {
		t.Fatalf("the revoked reconnect token offered again: %v, want errRevokedHeld", err)
	}
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	if f.p(0).State != PeerStale {
		f.dump()
		t.Fatal("a reconnect with no reconnect token left did not make it stale")
	}
}
