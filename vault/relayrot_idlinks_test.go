package vault

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// The identity-link gate (idLinksAllowed; VAULT-MESSAGING 0.90.4 §3.4.1
// Table A, "Earlier, after its cut-off"): from an earlier relay key of the
// peer's after its cut-off, identity links that are not all already
// followed are never applied, whatever message carries them.

// rkFollowTo makes side 0 follow side 1's relay key K to k with the cut-off
// at rkCut (no RK6: side 0's own handshakes stay as they are).
func (f *r29Fx) rkFollowTo(k ed25519.PrivateKey) {
	f.t.Helper()
	f.m(0).opt.RelayKeyRotation = true
	f.do(0, func(m *Manager, p *Peer) {
		m.relayAt, m.msgID = f.clk, rkCut
		if err := m.followRelayLinks(p, []*handshake.RelayLink{rkLink(f.t, f.m(1).keys.relay, k)}, rkAddr(k)); err != nil {
			f.t.Fatal(err)
		}
	})
}

// copyLink is a link from side 1's current ik to a new ik, as an old copy
// replaying it, or a peer that moved on, would carry; its private key.
func (f *r29Fx) copyLink() (*handshake.Rotation, ed25519.PrivateKey) {
	f.t.Helper()
	nk := rkKey(0xc0)
	r, err := handshake.NewRotation(f.m(1).keys.ik, nk, f.m(1).keys.kem.Public())
	if err != nil {
		f.t.Fatal(err)
	}
	return r, nk
}

// A's regression: an RK8 reconnect hs.init from an earlier key after its
// cut-off, while side 0's own reconnect is pending (so §6.6 "The links of
// a refused reconnect" would apply its links), carrying [ik -> copy]: the
// ik does not move, and it is refused superseded_relay.
func TestReviewA_RK8RefusedReconnectLinksMoveIK(t *testing.T) {
	f := rkPair(t)
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	if f.deliver(0, 1, kHSInit) != 1 || f.deliver(1, 0, kHSResp) != 1 || f.p(0).Pending == nil {
		t.Fatal("setup: side 0's reconnect not pending")
	}
	k1 := rkKey(rkK1)
	f.rkFollowTo(k1)
	ik := append([]byte(nil), f.p(0).IK...)
	link, nk := f.copyLink()
	_, init := f.rk8InitWith(k1, []*handshake.RelayLink{rkLink(t, f.m(1).keys.relay, k1)}, k1, "rk-1000", func(c *handshake.InitiatorConfig) {
		c.Identity, c.Rotations = nk, []*handshake.Rotation{link}
	})
	f.process(0, init)
	if !bytes.Equal(f.p(0).IK, ik) {
		t.Fatal("the ik moved")
	}
	if f.refusedFor("superseded_relay") != 1 {
		t.Fatal("not refused superseded_relay")
	}
}

// Every message kind that carries identity links, from an earlier key
// after its cut-off, with a link not yet followed: the ik never moves.
func TestIdentityLinksFromEarlierAfterNeverMoveIK(t *testing.T) {
	k1 := rkKey(rkK1)
	for _, c := range []struct {
		name string
		run  func(t *testing.T, f *r29Fx)
	}{
		{"identity.rotate", func(t *testing.T, f *r29Fx) {
			f.rotate(1)
			f.lose(1, 0, kHSInit)
			rot := f.rkTake(kRotate, rkAfter)
			f.rkFollowTo(k1)
			f.process(0, rot)
		}},
		{"relay.address.update", func(t *testing.T, f *r29Fx) {
			f.rkFollowTo(k1)
			f.rotate(1)
			f.lose(1, 0, kRotate)
			f.lose(1, 0, kHSInit)
			u := &peerwire.AddressUpdate{Relay: rkAddr(k1), Token: f.rk8Tok(k1, "u-st", 25*24*time.Hour),
				Links: []*handshake.RelayLink{rkLink(t, f.m(1).keys.relay, k1)}}
			f.do(1, func(m *Manager, p *Peer) {
				u.Rotations = m.ownRotationsSince(0)
				b, err := u.Marshal()
				if err != nil {
					t.Fatal(err)
				}
				m.sendTo(p, peerwire.TypeRelayAddressUpdate, b, f.clk)
			})
			f.process(0, f.rkTake(kOther, rkAfter))
		}},
		{"reconnect hs.init, own reconnect pending (refused-reconnect links)", func(t *testing.T, f *r29Fx) {
			f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
			f.deliver(0, 1, kHSInit)
			f.deliver(1, 0, kHSResp)
			f.rkFollowTo(k1)
			link, nk := f.copyLink()
			_, init := f.rk8InitWith(k1, []*handshake.RelayLink{rkLink(t, f.m(1).keys.relay, k1)}, k1, "rk-1000", func(c *handshake.InitiatorConfig) {
				c.Identity, c.Rotations = nk, []*handshake.Rotation{link}
			})
			f.process(0, init)
		}},
		{"reconnect hs.init, then its hs.fin", func(t *testing.T, f *r29Fx) {
			f.rkFollowTo(k1)
			link, nk := f.copyLink()
			ini, init := f.rk8InitWith(k1, []*handshake.RelayLink{rkLink(t, f.m(1).keys.relay, k1)}, k1, "rk-1000", func(c *handshake.InitiatorConfig) {
				c.Identity, c.Rotations = nk, []*handshake.Rotation{link}
			})
			f.process(0, init)
			if len(f.m(0).st.Awaiting) == 1 {
				f.process(0, f.rk8Fin(ini, rkAddr(k1).Mailbox, "rk-1100"))
			}
		}},
		{"hs.resp to the own reconnect", func(t *testing.T, f *r29Fx) {
			f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
			f.rkFollowTo(k1)
			link, nk := f.copyLink()
			f.process(0, f.rk8RespWith(k1, []*handshake.RelayLink{rkLink(t, f.m(1).keys.relay, k1)}, k1, "rk-2000", func(c *handshake.ResponderConfig) {
				c.Identity, c.Rotations = nk, []*handshake.Rotation{link}
			}))
		}},
		{"rekey hs.fin", func(t *testing.T, f *r29Fx) {
			f.rotate(1) // its rekey carries the link
			f.lose(1, 0, kRotate)
			f.deliver(1, 0, kHSInit)
			f.deliver(0, 1, kHSResp)
			fin := f.rkTake(kHSFin, rkAfter)
			f.rkFollowTo(k1)
			f.process(0, fin)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := rkPair(t)
			ik := append([]byte(nil), f.p(0).IK...)
			c.run(t, f)
			if !bytes.Equal(f.p(0).IK, ik) {
				t.Fatal("identity links from an earlier key after its cut-off moved the ik")
			}
			if f.refusedFor("superseded_relay") == 0 {
				t.Fatal("not refused superseded_relay")
			}
		})
	}
}
