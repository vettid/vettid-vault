package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/envelope"
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

// peerSnap is what a refused update must leave alone: the peer's relay and
// tokens, the denylist, the tokens issued (none is issued in answer: no
// relay.token.issued), and, with a devFixture, the deposits to the peer's
// mailbox (deposits; -1 when not counted).
type peerSnap struct {
	relay               PeerRelay
	standing, reconnect HeldToken
	deniedSubs, denied  int
	issued, deposits    int
}

func snapPeer(m *Manager, p *Peer) peerSnap {
	s := peerSnap{relay: p.Relay, standing: p.Standing, reconnect: p.Reconnect,
		deniedSubs: len(m.st.DeniedSubs), issued: len(m.st.Issued)}
	s.relay.PK = append([]byte(nil), p.Relay.PK...)
	for _, it := range m.st.Issued {
		if it.Denied {
			s.denied++
		}
	}
	s.deposits = -1
	return s
}

// snapDev settles housekeeping (a batch with nothing in it: a fixture's
// connection is given the tokens it lacks) and snapshots p, its deposits
// counted too.
func snapDev(t testing.TB, d *devFixture, p *Peer) peerSnap {
	t.Helper()
	if err := d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	s := snapPeer(d.m, p)
	s.deposits = d.depositsTo(p.Relay.Mailbox)
	return s
}

func (a peerSnap) same(b peerSnap) bool {
	return a.relay.URL == b.relay.URL && a.relay.Mailbox == b.relay.Mailbox && bytes.Equal(a.relay.PK, b.relay.PK) &&
		a.standing == b.standing && a.reconnect == b.reconnect &&
		a.deniedSubs == b.deniedSubs && a.denied == b.denied &&
		a.issued == b.issued && a.deposits == b.deposits
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
			before := snapDev(t, d, p)
			sendC(d, td, "relay.address.update", string(updateBody(t, d.m.keys.relay.Public().(ed25519.PublicKey), 0x91, time.Now())))
			checkUnchanged(t, d, p, before)
			return p
		}},
		{"service", func(t *testing.T, d *devFixture) *Peer {
			td := d.asConnection(t, "svc", 0x70)
			p := d.m.st.Connections["svc"]
			p.PeerKind = "service"
			before := snapDev(t, d, p)
			sendC(d, td, "relay.address.update", string(updateBody(t, d.m.keys.relay.Public().(ed25519.PublicKey), 0x92, time.Now())))
			checkUnchanged(t, d, p, before)
			return p
		}},
		{"device", func(t *testing.T, d *devFixture) *Peer {
			p := d.devPeer
			before := snapDev(t, d, p)
			if err := d.send("relay.address.update", updateBody(t, d.m.keys.relay.Public().(ed25519.PublicKey), 0x93, time.Now())); err != nil {
				t.Fatal(err)
			}
			checkUnchanged(t, d, p, before)
			return p
		}},
	}
	cases = append(cases, []struct {
		name string
		send func(t *testing.T, d *devFixture) *Peer
	}{
		// A desktop and an agent with no access session: the type is
		// accessExempt (§6.8), so it reaches the refusal.
		{"desktop without an access session", func(t *testing.T, d *devFixture) *Peer {
			return refuseFromDevice(t, d, KindDesktop)
		}},
		{"agent without an access session", func(t *testing.T, d *devFixture) *Peer {
			return refuseFromDevice(t, d, KindAgent)
		}},
		// A malformed body is refused the same way (the refusal reads no
		// member of it).
		{"malformed body", func(t *testing.T, d *devFixture) *Peer {
			td := d.asConnection(t, "per", 0x74)
			p := d.m.st.Connections["per"]
			before := snapDev(t, d, p)
			sendC(d, td, "relay.address.update", `{"relay":"nowhere","token":7}`)
			checkUnchanged(t, d, p, before)
			return p
		}},
	}...)
	for _, on := range []bool{false, true} {
		for _, c := range cases {
			name := c.name
			if on {
				// Rule U (0.90.3): the legacy body has no relay_links, so it
				// is a malformed body, refused as a whole: dropped with no
				// drop.peer_key entry and nothing changed.
				name += ", relay-key rotation on"
			}
			t.Run(name, func(t *testing.T) {
				d := newDevFixture(t)
				sinkOf(d)
				d.m.opt.RelayKeyRotation = on
				c.send(t, d)
			})
		}
	}
}

func refuseFromDevice(t *testing.T, d *devFixture, kind string) *Peer {
	t.Helper()
	td := d.addDevice(t, "d-"+kind, kind, 0x84)
	p := td.peer
	if p.Access != nil {
		t.Fatal("setup: the device has an access session")
	}
	before := snapDev(t, d, p)
	d.sendAs(td, "relay.address.update", string(updateBody(t, d.m.keys.relay.Public().(ed25519.PublicKey), 0x95, time.Now())))
	checkUnchanged(t, d, p, before)
	return p
}

// §8.2: a resend of the update with the same inner id is a duplicate: it
// is refused and audited once.
func TestRelayAddressUpdateResendAuditedOnce(t *testing.T) {
	d := newDevFixture(t)
	sinkOf(d)
	td := d.asConnection(t, "per", 0x74)
	p := d.m.st.Connections["per"]
	before := snapDev(t, d, p)
	body := string(updateBody(t, d.m.keys.relay.Public().(ed25519.PublicKey), 0x96, time.Now()))
	id, _ := envelope.NewULID(time.Now())
	for i := 0; i < 2; i++ {
		raw, err := td.ep.Seal(&envelope.Inner{ID: id, Type: "relay.address.update", TS: time.Now(), Body: []byte(body)})
		if err != nil {
			t.Fatal(err)
		}
		msg := Message{MsgID: fmt.Sprintf("dup%d", i), Sender: relayauth.EncodeKey(p.Relay.PK), JTI: "standing-per", Payload: raw}
		if err := d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg}); err != nil {
			t.Fatal(err)
		}
	}
	checkUnchanged(t, d, p, before) // audited exactly once
}

func checkUnchanged(t *testing.T, d *devFixture, p *Peer, before peerSnap) {
	t.Helper()
	after := snapPeer(d.m, p)
	if before.deposits >= 0 {
		after.deposits = d.depositsTo(p.Relay.Mailbox)
	}
	if !after.same(before) {
		t.Fatalf("the update changed the peer's relay, tokens or the denylist, or was answered:\n before %+v\n after  %+v", before, after)
	}
	got := d.audits("drop.peer_key")
	if d.m.opt.RelayKeyRotation {
		if len(got) != 0 {
			t.Fatalf("a malformed update was audited drop.peer_key: %+v", got)
		}
		return
	}
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
