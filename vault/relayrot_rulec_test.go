package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// VAULT-MESSAGING 0.90.3 §3.4.1 rule C for relay links (one successor per
// key; links kept as seen; at most 32 per peer; the relay fork; the vault
// and its own device) and §3.4.2 RK12 (relay links seen while suspended).
// The update itself is still refused (relay_unlinked): rule U is not built.

// rkUpdate is a relay.address.update body announcing to with links.
func rkUpdate(t testing.TB, to ed25519.PrivateKey, links ...*handshake.RelayLink) string {
	t.Helper()
	u := &peerwire.AddressUpdate{Relay: rkAddr(to), Token: "v4.public.VEVTVA", Links: links}
	b, err := u.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// rkConn is a devFixture with relay-key rotation on and a connection whose
// relay key is k (addDevice's seed+1).
func rkConn(t *testing.T) (*devFixture, *tdev, *Peer, ed25519.PrivateKey) {
	d := newDevFixture(t)
	sinkOf(d)
	d.m.opt.RelayKeyRotation = true
	td := d.asConnection(t, "per", 0x74)
	return d, td, d.m.st.Connections["per"], rkKey(0x75)
}

func seenLinks(p *Peer) [][2]ed25519.PublicKey {
	var out [][2]ed25519.PublicKey
	for _, raw := range p.RelaySeen {
		l, err := handshake.ParseRelayLink(raw)
		if err != nil {
			panic(err)
		}
		out = append(out, [2]ed25519.PublicKey{l.Old, l.New})
	}
	return out
}

// Rule U's two lists (0.90.3): no link of the chain is kept for its count,
// a link whose old equals its new, a repeated key or an end mismatch; the
// earlier valid links are still kept for a bad signature or a break.
func TestRuleCRelayLinksKeptLists(t *testing.T) {
	k0, k1, k2, k3, kx := rkKey(0x51), rkKey(0x52), rkKey(0x53), rkKey(0x54), rkKey(0x5f)
	l01, l12, l23 := rkLink(t, k0, k1), rkLink(t, k1, k2), rkLink(t, k2, k3)
	badSig := rkLink(t, k1, k2)
	badSig.SigOld = append([]byte(nil), l23.SigOld...)
	same := &handshake.RelayLink{Old: rkPub(k1), New: rkPub(k1), SigOld: l12.SigOld, SigNew: l12.SigNew}
	var long []*handshake.RelayLink
	prev := k0
	for i := 0; i < handshake.MaxRelayLinks+1; i++ {
		next := rkKey(byte(0x80 + i))
		long = append(long, rkLink(t, prev, next))
		prev = next
	}
	for _, c := range []struct {
		name     string
		links    []*handshake.RelayLink
		announce ed25519.PrivateKey
		kept     int
		ok       bool
	}{
		{"valid", []*handshake.RelayLink{l01, l12, l23}, k3, 3, true},
		{"no links", nil, k1, 0, false},
		{"33 links", long, prev, 0, false},
		{"old equals new", []*handshake.RelayLink{l01, same}, k1, 0, false},
		{"a repeated key", []*handshake.RelayLink{l01, rkLink(t, k1, k0)}, k0, 0, false},
		{"first old not the sender", []*handshake.RelayLink{l12}, k2, 0, false},
		{"last new not the announced key", []*handshake.RelayLink{l01, l12}, k3, 0, false},
		{"a bad signature", []*handshake.RelayLink{l01, badSig, l23}, k3, 1, false},
		{"a break", []*handshake.RelayLink{l01, rkLink(t, kx, k2), l23}, k3, 1, false},
		{"a bad signature first", []*handshake.RelayLink{badLink(rkLink(t, k0, k1)), l12}, k2, 0, false},
	} {
		kept, ok := relayLinksKept(rkPub(k0), rkPub(c.announce), c.links)
		if len(kept) != c.kept || ok != c.ok {
			t.Fatalf("%s: kept %d (ok %v), want %d (ok %v)", c.name, len(kept), ok, c.kept, c.ok)
		}
	}
}

func badLink(l *handshake.RelayLink) *handshake.RelayLink {
	l.SigNew = append([]byte(nil), l.SigOld...)
	return l
}

// Rule C: an update's valid links are kept as seen though the update is
// refused; the same link again changes nothing; a second successor of a
// seen key suspends the connection as a relay fork (fork_suspected, ref
// relay, a high feed item), and connection.rotation.resolve then answers
// not_found.
func TestRuleCRelayForkFromTwoUpdates(t *testing.T) {
	d, td, p, k := rkConn(t)
	ka, kb := rkKey(0x61), rkKey(0x62)
	sendC(d, td, "relay.address.update", rkUpdate(t, ka, rkLink(t, k, ka)))
	if s := seenLinks(p); len(s) != 1 || !suite.EqualPublic(s[0][0], rkPub(k)) || !suite.EqualPublic(s[0][1], rkPub(ka)) || p.suspended() {
		t.Fatalf("the update's link was not kept as seen: %v", s)
	}
	if got := d.audits("drop.peer_key"); len(got) != 1 || got[0].Ref != "relay_unlinked" {
		t.Fatalf("the update was not still refused relay_unlinked: %+v", got)
	}
	sendC(d, td, "relay.address.update", rkUpdate(t, ka, rkLink(t, k, ka)))
	if len(p.RelaySeen) != 1 || p.suspended() {
		t.Fatal("the same link again was recorded again, or suspended")
	}
	sendC(d, td, "relay.address.update", rkUpdate(t, kb, rkLink(t, k, kb)))
	if p.RelayFork == nil || p.Fork == nil || !p.suspended() {
		t.Fatal("a second successor of a seen relay key did not suspend the connection")
	}
	if got := d.audits("connection.fork_suspected"); len(got) != 1 || got[0].Ref != "relay" || !got[0].Feed || got[0].Priority != "high" || got[0].ConnectionID != p.ID {
		t.Fatalf("not audited as a relay fork with its feed item: %+v", got)
	}
	if len(p.RelaySeen) != 1 {
		t.Fatal("the second successor was kept as seen")
	}
	// Another successor once the fork is recorded: recorded once, one
	// audit entry and one feed item.
	sendC(d, td, "relay.address.update", rkUpdate(t, rkKey(0x63), rkLink(t, k, rkKey(0x63))))
	if got := d.audits("connection.fork_suspected"); len(got) != 1 {
		t.Fatalf("the relay fork was audited again: %d", len(got))
	}
	if id := d.m.sendTo(p, "test.note", []byte(`{}`), time.Now()); id != "" {
		t.Fatal("a connection suspended as a relay fork was sent to")
	}
}

// Rule C against a followed link: a second successor of a key the vault
// followed the peer away from is a relay fork too.
func TestRuleCRelaySecondSuccessorOfAFollowedLink(t *testing.T) {
	d, td, p, k := rkConn(t)
	ka, kb := rkKey(0x61), rkKey(0x62)
	d.m.mu.Lock()
	d.m.relayAt, d.m.msgID = time.Now(), "zz-cut"
	err := d.m.followRelayLinks(p, []*handshake.RelayLink{rkLink(t, k, ka)}, rkAddr(ka))
	d.m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// From the earlier key k, before its cut-off ("w..." < "zz-cut"): the
	// copy's link k->kb.
	msg := d.connMsg(t, td, "relay.address.update", rkUpdate(t, kb, rkLink(t, k, kb)))
	msg.Sender = relayauth.EncodeKey(rkPub(k))
	if err := d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg}); err != nil {
		t.Fatal(err)
	}
	if p.RelayFork == nil || !p.suspended() {
		t.Fatal("a second successor of a followed relay key did not suspend")
	}
}

// connection.rotation.resolve answers not_found while a relay fork is
// recorded, also with an identity conflict recorded too.
func TestRuleCRelayForkResolveNotFound(t *testing.T) {
	f := newFixture(t)
	m := f.m
	now := time.Now()
	old, a, b := rkKey(1), rkKey(2), rkKey(3)
	kem, _ := suite.GeneratePrivateKey()
	ra, _ := handshake.NewRotation(old, a, kem.Public())
	rb, _ := handshake.NewRotation(old, b, kem.Public())
	p := rkPeer(m, "c1", rkKey(0x41))
	p.IK, p.Chain = rkPub(a), []json.RawMessage{ra.Marshal()}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.rotationConflict(p, rb, now) || p.Conflict == nil {
		t.Fatal("setup: no identity conflict")
	}
	m.suspendRelayFork(p, now)
	if p.RelayFork == nil {
		t.Fatal("the relay fork was not recorded on a record already suspended")
	}
	s := m.session(now)
	s.from = PeerInfo{ID: "app1", Kind: KindApp}
	in := testInner(`{"connection_id":"c1","new_ik":"` + b64(rkPub(b)) + `"}`)
	if _, err := m.hRotationResolve(context.Background(), s, in); err != errNotFound || p.Conflict == nil {
		t.Fatalf("resolved while a relay fork is recorded: %v", err)
	}
}

// Rule C keeps at most 32 seen relay links per peer.
func TestRuleCRelaySeenCap(t *testing.T) {
	f := newFixture(t)
	m := f.m
	m.opt.RelayKeyRotation = true
	p := rkPeer(m, "c1", rkKey(0x41))
	for i := 0; i < MaxRelaySeen+5; i++ {
		m.relayRuleC(p, rkLink(t, rkKey(byte(0x80+i)), rkKey(byte(0x10+i))), time.Now())
	}
	if len(p.RelaySeen) != MaxRelaySeen {
		t.Fatalf("seen %d", len(p.RelaySeen))
	}
}

// The first list: an update whose chain is refused for an end mismatch (its
// first old is not the sender) keeps no link, so a later different
// successor is no fork. The second list: one refused for a bad signature
// keeps its earlier valid links.
func TestRuleCRelayRefusedChainsKeepWhatTheListsSay(t *testing.T) {
	d, td, p, k := rkConn(t)
	ka, kb, kc := rkKey(0x61), rkKey(0x62), rkKey(0x63)
	sendC(d, td, "relay.address.update", rkUpdate(t, kb, rkLink(t, ka, kb)))
	if len(p.RelaySeen) != 0 {
		t.Fatal("a link of a chain with an end mismatch was kept")
	}
	sendC(d, td, "relay.address.update", rkUpdate(t, kc, rkLink(t, k, ka), badLink(rkLink(t, ka, kc))))
	if s := seenLinks(p); len(s) != 1 || !suite.EqualPublic(s[0][1], rkPub(ka)) {
		t.Fatalf("the earlier valid link of a chain with a bad signature was not kept: %v", s)
	}
	if p.suspended() {
		t.Fatal("suspended")
	}
}

// §3.4.2 RK12: while the record is suspended (an epoch fork, or an identity
// conflict), the relay links of a refused message that pass rule C are kept
// as seen, and a second successor still records the relay fork, so that
// connection.rotation.resolve answers not_found.
func TestRK12RelayLinksSeenWhileSuspended(t *testing.T) {
	for _, how := range []string{"epoch fork", "identity conflict"} {
		t.Run(how, func(t *testing.T) {
			d, td, p, k := rkConn(t)
			d.m.mu.Lock()
			if how == "epoch fork" {
				d.m.suspendForkRef(p, "epoch", time.Now())
			} else {
				p.Conflict = &RotationConflict{OldIK: bytes.Repeat([]byte{1}, 32), At: time.Now()}
			}
			d.m.mu.Unlock()
			ka, kb := rkKey(0x61), rkKey(0x62)
			sendC(d, td, "relay.address.update", rkUpdate(t, ka, rkLink(t, k, ka)))
			if len(p.RelaySeen) != 1 || p.RelayFork != nil {
				t.Fatal("a relay link in a message refused at step 1 was not kept as seen")
			}
			sendC(d, td, "relay.address.update", rkUpdate(t, kb, rkLink(t, k, kb)))
			if p.RelayFork == nil {
				t.Fatal("a second successor while suspended did not record the relay fork")
			}
			if got := d.audits("connection.fork_suspected"); len(got) == 0 || got[len(got)-1].Ref != "relay" || !got[len(got)-1].Feed {
				t.Fatalf("the relay fork was not audited with its feed item: %+v", got)
			}
		})
	}
}

// Between the vault and its own device (nothing suspends): the first
// successor stays, the message with the other is refused (conflict), the
// vault sends that device nothing more, and tells the member (high).
func TestRuleCRelayOwnDeviceConflict(t *testing.T) {
	d := newDevFixture(t)
	sinkOf(d)
	d.m.opt.RelayKeyRotation = true
	p, k := d.devPeer, d.devKey
	ka, kb := rkKey(0x61), rkKey(0x62)
	if err := d.send("relay.address.update", []byte(rkUpdate(t, ka, rkLink(t, k, ka)))); err != nil {
		t.Fatal(err)
	}
	if len(p.RelaySeen) != 1 || p.RelayConflict != nil {
		t.Fatal("setup: the first successor was not seen")
	}
	// A deposit to the device queued before the conflict, not yet out.
	d.m.mu.Lock()
	d.m.queueDeposit(&OutboxEntry{PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Payload: []byte("queued")}, time.Now())
	d.m.mu.Unlock()
	deposits := d.depositsTo(p.Relay.Mailbox)
	conflictID, _ := envelope.NewULID(time.Now())
	d.sendID(d.self(), conflictID, "relay.address.update", rkUpdate(t, kb, rkLink(t, k, kb)))
	if got := d.depositsTo(p.Relay.Mailbox); got != deposits {
		t.Fatalf("a deposit queued before the conflict went out (%d -> %d)", deposits, got)
	}
	c := p.RelayConflict
	if c == nil || !suite.EqualPublic(c.Kept, rkPub(ka)) || !suite.EqualPublic(c.Refused, rkPub(kb)) || p.suspended() {
		t.Fatalf("not recorded as the device's conflict with the first successor kept: %+v", c)
	}
	if got := d.audits("drop.peer_key"); len(got) != 2 || got[1].Ref != "conflict" || got[1].DeviceID != p.ID {
		t.Fatalf("the second successor's message was not refused conflict: %+v", got)
	}
	if got := d.audits("connection.fork_suspected"); len(got) != 1 || !got[0].Feed || got[0].Priority != "high" || got[0].DeviceID != p.ID || got[0].Ref != "relay" {
		t.Fatalf("no high feed item for the device: %+v", got)
	}
	n := len(d.m.st.Outbox)
	d.m.mu.Lock()
	id := d.m.sendTo(p, "vault.held", []byte(`{}`), time.Now())
	d.m.queueDeposit(&OutboxEntry{PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Payload: []byte("x")}, time.Now())
	d.m.mu.Unlock()
	if id != "" || len(d.m.st.Outbox) != n {
		t.Fatal("something more was queued for the device")
	}
	// A resend of the conflicting update (the same inner id) is refused
	// again but audited once.
	d.sendID(d.self(), conflictID, "relay.address.update", rkUpdate(t, kb, rkLink(t, k, kb)))
	if got := d.audits("drop.peer_key"); len(got) != 2 {
		t.Fatalf("the resend was audited again: %+v", got)
	}
	// A volatile request's answer (pending.list) is not sent either.
	deposits = d.depositsTo(p.Relay.Mailbox)
	if err := d.send("pending.list", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if got := d.depositsTo(p.Relay.Mailbox); got != deposits {
		t.Fatal("a volatile answer was sent to the device")
	}
	// Its other messages are still taken (nothing suspends).
	if err := d.send("vault.status", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if len(d.audits("drop.peer_key")) != 2 || len(d.m.st.Outbox) != n {
		t.Fatal("a later message from the device was refused")
	}
}

// The switch off: an update's relay links are not checked (the update is
// refused as before, and nothing is seen or suspended).
func TestRuleCRelayNeedsTheSwitch(t *testing.T) {
	d, td, p, k := rkConn(t)
	d.m.opt.RelayKeyRotation = false
	ka, kb := rkKey(0x61), rkKey(0x62)
	sendC(d, td, "relay.address.update", rkUpdate(t, ka, rkLink(t, k, ka)))
	sendC(d, td, "relay.address.update", rkUpdate(t, kb, rkLink(t, k, kb)))
	if len(p.RelaySeen) != 0 || p.RelayFork != nil || p.suspended() || len(d.audits("drop.peer_key")) != 2 {
		t.Fatal("relay links judged with the switch off")
	}
}
