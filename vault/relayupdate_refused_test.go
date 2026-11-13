package vault

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
)

// relay.address.update is refused from every peer (release 29 rotates no
// relay key and builds no receiving side for it, §3.4.1 A5, rule U): it
// is audited drop.peer_key with ref relay_unlinked, and the peer's relay
// address, tokens and the vault's denylist stay as they were.

// updateBody is a well-formed legacy update moving the sender to a relay
// key seeded with seed, with standing and reconnect tokens minted by that
// mailbox for own (the receiving vault's relay key), as the old handler
// would have taken it.
func updateBody(t testing.TB, own ed25519.PublicKey, seed byte, now time.Time) []byte {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	pk := priv.Public().(ed25519.PublicKey)
	url, mb := "https://relay.example.org", relayauth.MailboxID(pk)
	mint := func(jti string) string {
		tok, err := relayauth.MintToken(priv, relayauth.Claims{Iss: mb, Sub: relayauth.EncodeKey(own), Aud: url,
			Iat: now.Add(-time.Minute), Exp: now.Add(20 * 24 * time.Hour), Jti: jti})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	b, err := json.Marshal(map[string]any{
		"relay":           map[string]string{"url": url, "mailbox": mb, "pk": base64.StdEncoding.EncodeToString(pk)},
		"token":           mint("upd-standing"),
		"reconnect_token": mint("upd-reconnect"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// peerSnap is what a refused update must leave alone.
type peerSnap struct {
	relay               PeerRelay
	standing, reconnect HeldToken
	deniedSubs, denied  int
}

func snapPeer(m *Manager, p *Peer) peerSnap {
	s := peerSnap{relay: p.Relay, standing: p.Standing, reconnect: p.Reconnect,
		deniedSubs: len(m.st.DeniedSubs)}
	s.relay.PK = append([]byte(nil), p.Relay.PK...)
	for _, it := range m.st.Issued {
		if it.Denied {
			s.denied++
		}
	}
	return s
}

func (a peerSnap) same(b peerSnap) bool {
	return a.relay.URL == b.relay.URL && a.relay.Mailbox == b.relay.Mailbox && bytes.Equal(a.relay.PK, b.relay.PK) &&
		a.standing == b.standing && a.reconnect == b.reconnect &&
		a.deniedSubs == b.deniedSubs && a.denied == b.denied
}

// From a connection, a service and the member's device: refused, audited,
// nothing changed.
func TestRelayAddressUpdateRefusedFromEveryPeer(t *testing.T) {
	cases := []struct {
		name string
		send func(t *testing.T, d *devFixture) *Peer
	}{
		{"connection", func(t *testing.T, d *devFixture) *Peer {
			td := d.asConnection(t, "per", 0x74)
			p := d.m.st.Connections["per"]
			before := snapPeer(d.m, p)
			sendC(d, td, "relay.address.update", string(updateBody(t, d.m.keys.relay.Public().(ed25519.PublicKey), 0x91, time.Now())))
			checkUnchanged(t, d, p, before)
			return p
		}},
		{"service", func(t *testing.T, d *devFixture) *Peer {
			td := d.asConnection(t, "svc", 0x70)
			p := d.m.st.Connections["svc"]
			p.PeerKind = "service"
			before := snapPeer(d.m, p)
			sendC(d, td, "relay.address.update", string(updateBody(t, d.m.keys.relay.Public().(ed25519.PublicKey), 0x92, time.Now())))
			checkUnchanged(t, d, p, before)
			return p
		}},
		{"device", func(t *testing.T, d *devFixture) *Peer {
			p := d.devPeer
			before := snapPeer(d.m, p)
			if err := d.send("relay.address.update", updateBody(t, d.m.keys.relay.Public().(ed25519.PublicKey), 0x93, time.Now())); err != nil {
				t.Fatal(err)
			}
			checkUnchanged(t, d, p, before)
			return p
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newDevFixture(t)
			sinkOf(d)
			c.send(t, d)
		})
	}
}

func checkUnchanged(t *testing.T, d *devFixture, p *Peer, before peerSnap) {
	t.Helper()
	if !snapPeer(d.m, p).same(before) {
		t.Fatalf("the update changed the peer's relay, tokens or the denylist:\n before %+v\n after  %+v", before, snapPeer(d.m, p))
	}
	got := d.audits("drop.peer_key")
	if len(got) != 1 || got[0].Ref != "relay_unlinked" || !got[0].Audit {
		t.Fatalf("not audited drop.peer_key relay_unlinked: %+v", got)
	}
	if p.Kind == KindConnection && got[0].ConnectionID != p.ID || p.Kind != KindConnection && got[0].DeviceID != p.ID {
		t.Fatalf("audited for another peer: %+v", got[0])
	}
}

// An old copy of side 1 holding the current epoch's keys sends side 0 an
// update that names a relay key and mailbox of its choosing: side 0 keeps
// side 1's address and tokens, so nothing it sends is redirected.
func TestRelayAddressUpdateFromOldCopyRedirectsNothing(t *testing.T) {
	f := newR29Fx(t)
	snap := f.snapshot(1)
	f.startCopy(1, snap)
	m0, p := f.m(0), f.p(0)
	before := snapPeer(m0, p)
	body := updateBody(t, m0.keys.relay.Public().(ed25519.PublicKey), 0x94, f.clk)
	f.do(2, func(m *Manager, q *Peer) { m.sendTo(q, "relay.address.update", json.RawMessage(body), f.clk) })
	if f.deliver(2, 0, kAny) == 0 {
		t.Fatal("setup: the copy's update did not reach side 0")
	}
	if !snapPeer(m0, p).same(before) {
		t.Fatalf("the copy's update redirected side 1's address or tokens:\n before %+v\n after  %+v", before, snapPeer(m0, p))
	}
	if !f.activity(0, "drop.peer_key", "relay_unlinked") {
		t.Fatal("the copy's update was not audited drop.peer_key relay_unlinked")
	}
	f.talks() // the real side 1 is still reached at its own address
}
