package vault

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/handshake"
)

// More of the identity-link gate (idLinksAllowed; §3.4.1 Table A,
// "Earlier, after its cut-off") and RK8 (§3.4.2): the fork answer's
// exemption, the suspension guard after an hs.resp's links, and honest
// reconnects carrying identity links.

// An answer kept as fork evidence whose hs.init (before the cut-off)
// carried identity links not followed: its hs.fin, from the earlier key
// after the cut-off, is not refused by the gate; it suspends, and no link
// moves the ik.
func TestIDLinksGateForkAnswerStillSuspends(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	fin, aw := f.rk7ReconnectFin()
	link, _ := f.copyLink()
	aw.Reconnect.Fork = true
	aw.Reconnect.Rotations = []json.RawMessage{link.Marshal()}
	ik := append([]byte(nil), f.p(0).IK...)
	f.process(0, fin)
	if f.p(0).Fork == nil || f.superseded() != 0 {
		t.Fatalf("fork %v, refused %d: the gate refused the fork answer", f.p(0).Fork != nil, f.superseded())
	}
	if !bytes.Equal(f.p(0).IK, ik) {
		t.Fatal("the ik moved")
	}
}

// After an hs.resp's identity links are applied, a suspension stops it
// (R29-K4: an epoch signed by the old ik, established after the hs.resp's
// position, with its received flag set): no relay link is followed, no
// token kept, and the reconnect does not complete.
func TestRK8RespSuspendedByItsLinksFollowsNothing(t *testing.T) {
	f := rkPair(t)
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	f.rotate(1)
	f.lose(1, 0, kRotate)
	f.lose(1, 0, kHSInit)
	k, k1 := f.m(1).keys.relay, rkKey(rkK1)
	rots := f.m(1).ownRotationsSince(0)
	resp := f.rk8RespWith(k1, []*handshake.RelayLink{rkLink(t, k, k1)}, k1, "rk-2000", func(c *handshake.ResponderConfig) {
		c.Rotations = rots
	})
	f.do(0, func(m *Manager, p *Peer) {
		e := p.epochMeta(p.LastEpochID)
		e.EstAt, e.GotFromPeer = f.clk.Add(time.Hour), true // after the hs.resp's position, used by P's side
	})
	standing := f.p(0).Standing.Token
	f.process(0, resp)
	if !f.p(0).suspended() {
		t.Fatal("setup: the links did not suspend")
	}
	if !f.relayIs(k) || len(f.p(0).EarlierRelays) != 0 {
		t.Fatal("a relay link was followed after the suspension")
	}
	if f.p(0).Standing.Token != standing || f.p(0).Pending != nil {
		t.Fatal("a token was kept, or the reconnect completed")
	}
}

// Honest reconnects carrying identity links (side 1 rotated its ik, its
// identity.rotate lost) with relay links K -> K1: from the current key,
// and from the earlier key K before its cut-off. Each is accepted, and
// both the ik and the relay key are followed.
func TestRK8HonestReconnectsWithIdentityLinks(t *testing.T) {
	for _, c := range []struct {
		name    string
		earlier bool
		resp    bool
	}{
		{"hs.init from the current key", false, false},
		{"hs.init from an earlier key before its cut-off", true, false},
		{"hs.resp from the current key", false, true},
		{"hs.resp from an earlier key before its cut-off", true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := rkPair(t)
			if c.resp {
				f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
			}
			f.rotate(1)
			f.lose(1, 0, kRotate)
			f.lose(1, 0, kHSInit)
			newIK := pubOf(f.m(1).keys.ik)
			k, k1 := f.m(1).keys.relay, rkKey(rkK1)
			links := []*handshake.RelayLink{rkLink(t, k, k1)}
			rots := f.m(1).ownRotationsSince(0)
			ids := []string{"rk-1000", "rk-1100"}
			if c.earlier {
				f.rkFollowTo(k1) // cut-off at rkCut; these come before it
				ids = []string{"rk-0400", "rk-0450"}
			}
			if c.resp {
				f.process(0, f.rk8RespWith(k1, links, k1, ids[0], func(rc *handshake.ResponderConfig) { rc.Rotations = rots }))
			} else {
				ini, init := f.rk8InitWith(k1, links, k1, ids[0], func(ic *handshake.InitiatorConfig) { ic.Rotations = rots })
				f.process(0, init)
				f.process(0, f.rk8Fin(ini, relayauth.MailboxID(rkPub(k1)), ids[1]))
			}
			if f.refusedFor("superseded_relay")+f.refusedFor("unknown_ik")+f.refusedFor("relay_unlinked") != 0 {
				t.Fatal("refused")
			}
			if !bytes.Equal(f.p(0).IK, newIK) || !f.relayIs(k1) {
				t.Fatalf("ik followed %v, relay followed %v", bytes.Equal(f.p(0).IK, newIK), f.relayIs(k1))
			}
		})
	}
}
