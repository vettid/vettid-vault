package vault

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// Relay-key rotation, receiving side III (VAULT-MESSAGING 0.90.4 §3.4.2
// RK5, RK7, RK8 and RK10; §3.4.1 rule U, rule C and Table A).

// rkSendRots has side 1 send side 0 an update to K1 carrying rots as its
// identity links.
func (f *r29Fx) rkSendRots(rots func(m *Manager, p *Peer) []*handshake.Rotation) {
	f.t.Helper()
	k1 := rkKey(rkK1)
	tok, err := relayauth.MintToken(k1, relayauth.Claims{Iss: relayauth.MailboxID(rkPub(k1)), Sub: relayauth.EncodeKey(f.pk(0)),
		Aud: "https://relay.example.org", Iat: f.clk.Add(-time.Minute), Exp: f.clk.Add(25 * 24 * time.Hour), Jti: "p-st-rots"})
	if err != nil {
		f.t.Fatal(err)
	}
	u := &peerwire.AddressUpdate{Relay: rkAddr(k1), Token: tok, Links: []*handshake.RelayLink{rkLink(f.t, f.m(1).keys.relay, k1)}}
	f.do(1, func(m *Manager, p *Peer) {
		u.Rotations = rots(m, p)
		b, err := u.Marshal()
		if err != nil {
			f.t.Fatal(err)
		}
		m.sendTo(p, peerwire.TypeRelayAddressUpdate, b, f.clk)
	})
}

// RK5 with RK10: an update whose identity links are valid but whose ik
// fails the requirement (the epoch it travels under was signed by an ik
// the links do not start at) is refused, and none of its identity links
// is followed: the vault's ik for the peer is unchanged.
func TestRK10UpdateIKRequirementFailsNoIdentityLinkFollowed(t *testing.T) {
	f := rkPair(t)
	f.rotate(1)
	f.lose(1, 0, kHSInit)
	f.deliver(1, 0, kRotate)
	ik1 := append([]byte(nil), f.m(1).keys.ik.Public().(ed25519.PublicKey)...)
	if !bytes.Equal(f.p(0).IK, ik1) {
		t.Fatal("setup: the first identity.rotate was not followed")
	}
	f.rotate(1)
	f.lose(1, 0, kRotate)
	f.lose(1, 0, kHSInit)
	// Only the second link (ik1 -> ik2): valid, but the epoch's signer is
	// ik0, which it does not start at.
	f.rkSendRots(func(m *Manager, _ *Peer) []*handshake.Rotation { return m.ownRotationsSince(1) })
	f.deliver(1, 0, kOther)
	if !bytes.Equal(f.p(0).IK, ik1) {
		t.Fatal("a refused update moved the peer's ik")
	}
	if f.followedK1() || f.activityCount(0, "drop.peer_key", "ancestor_ik") != 1 {
		t.Fatal("the update was followed, or not refused ancestor_ik")
	}
}

// Rule U with Table A's identity.rotate row: an update from an earlier
// relay key after its cut-off whose identity links are only partly
// followed (an already-followed link, then ik -> a new ik) is refused
// superseded_relay, and the ik is unchanged: a relay link is the same for
// every recipient, so such an update may come from an old copy.
func TestRuleUEarlierAfterCutoffPartlyFollowedRotationsRefused(t *testing.T) {
	f := rkPair(t)
	f.rotate(1)
	f.lose(1, 0, kHSInit)
	f.deliver(1, 0, kRotate)
	ik1 := append([]byte(nil), f.m(1).keys.ik.Public().(ed25519.PublicKey)...)
	f.rkSend(true, true)
	f.deliver(1, 0, kOther)
	if !f.followedK1() || !bytes.Equal(f.p(0).IK, ik1) {
		t.Fatal("setup: the update was not followed")
	}
	f.rotate(1)
	f.lose(1, 0, kRotate)
	f.lose(1, 0, kHSInit)
	n := f.activityCount(0, "drop.peer_key", "superseded_relay")
	// From K (earlier, after its cut-off): [ik0 -> ik1 (followed), ik1 -> ik2].
	f.rkSendRots(func(m *Manager, _ *Peer) []*handshake.Rotation { return m.ownRotationsSince(0) })
	f.deliver(1, 0, kOther)
	if !bytes.Equal(f.p(0).IK, ik1) {
		t.Fatal("an update from an earlier key after its cut-off moved the ik")
	}
	if f.activityCount(0, "drop.peer_key", "superseded_relay") != n+1 {
		t.Fatal("the update was not refused superseded_relay")
	}
}
