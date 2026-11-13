package vault

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Relay-key rotation, receiving side (VAULT-MESSAGING 0.90.3 §3.4.1
// "Terms"): a peer's earlier relay keys, kept with their followed relay
// link and cut-off until no token the vault issued to them can still
// deposit; only with Options.RelayKeyRotation.

func rkKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
}

func rkPub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func rkAddr(k ed25519.PrivateKey) handshake.RelayAddr {
	return handshake.RelayAddr{URL: "https://relay.example.org", Mailbox: relayauth.MailboxID(rkPub(k)), PK: rkPub(k)}
}

func rkLink(t testing.TB, from, to ed25519.PrivateKey) *handshake.RelayLink {
	t.Helper()
	l, err := handshake.NewRelayLink(from, to)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// rkPeer is a connection whose relay key on record is k.
func rkPeer(m *Manager, id string, k ed25519.PrivateKey) *Peer {
	a := rkAddr(k)
	p := &Peer{ID: id, Kind: KindConnection, State: PeerActive, Relay: PeerRelay{URL: a.URL, Mailbox: a.Mailbox, PK: a.PK}}
	m.st.Connections[id] = p
	return p
}

// §3.4.1 "Relay-key states" and "Cut-off": following a chain of two links
// makes both passed keys earlier, each with its link and the position of
// the message that followed as its cut-off, and the last key current.
func TestRelayFollowRecordsEarlierKeysAndCutoffs(t *testing.T) {
	f := newFixture(t)
	m := f.m
	m.opt.RelayKeyRotation = true
	k0, k1, k2 := rkKey(0x41), rkKey(0x42), rkKey(0x43)
	p := rkPeer(m, "c1", k0)
	at := testNow().UTC()
	m.relayAt, m.msgID = at, "m-0100"
	l1, l2 := rkLink(t, k0, k1), rkLink(t, k1, k2)
	if err := m.followRelayLinks(p, []*handshake.RelayLink{l1, l2}, rkAddr(k2)); err != nil {
		t.Fatal(err)
	}
	if !suite.EqualPublic(p.Relay.PK, rkPub(k2)) || p.Relay.Mailbox != relayauth.MailboxID(rkPub(k2)) {
		t.Fatal("the announced key is not current")
	}
	if len(p.EarlierRelays) != 2 {
		t.Fatalf("earlier keys: %d", len(p.EarlierRelays))
	}
	for i, l := range []*handshake.RelayLink{l1, l2} {
		e := p.EarlierRelays[i]
		if !suite.EqualPublic(e.Relay.PK, l.Old) || !bytes.Equal(e.Link, l.Marshal()) {
			t.Fatalf("earlier key %d: not the passed key with its link", i)
		}
		if !e.CutAt.Equal(at) || e.CutMsg != "m-0100" || e.CutMailbox != m.st.Relay.Mailbox {
			t.Fatalf("earlier key %d: cut-off %+v", i, e)
		}
	}
	for _, c := range []struct {
		key  ed25519.PrivateKey
		id   string
		want relayKeyState
	}{
		{k2, "m-0200", relayCurrent},
		{k0, "m-0099", relayEarlierBefore},
		{k1, "m-0050", relayEarlierBefore},
		{k0, "m-0101", relayEarlierAfter},
		{k1, "m-0100", relayEarlierAfter}, // the cut-off itself is not before it
		{rkKey(0x44), "m-0001", relayForeign},
	} {
		m.msgID = c.id
		if got := m.relayStateOf(p, rkPub(c.key)); got != c.want {
			t.Fatalf("%s: state %d, want %d", c.id, got, c.want)
		}
	}
	if m.peerByRelayKey(rkPub(k0)) != p || m.peerByRelayKey(rkPub(k1)) != p {
		t.Fatal("an earlier key does not name its peer")
	}
}

// The follow fails closed: a chain that does not start at the relay key on
// record, does not end at the announced key or does not verify, and a new
// key the vault keeps for the peer (rule U relay_rollback; I3: never a key
// it followed away from), change nothing.
func TestRelayFollowRefusesChainsNotFromTheKeyOnRecord(t *testing.T) {
	f := newFixture(t)
	m := f.m
	m.opt.RelayKeyRotation = true
	k0, k1, k2, kx := rkKey(0x41), rkKey(0x42), rkKey(0x43), rkKey(0x49)
	p := rkPeer(m, "c1", k0)
	m.relayAt, m.msgID = testNow(), "m-1"
	bad := rkLink(t, k1, k2)
	bad.SigNew = append([]byte(nil), bad.SigOld...)
	for name, c := range map[string]struct {
		links []*handshake.RelayLink
		to    ed25519.PrivateKey
	}{
		"not from the key on record": {[]*handshake.RelayLink{rkLink(t, kx, k1)}, k1},
		"end not the announced key":  {[]*handshake.RelayLink{rkLink(t, k0, k1)}, k2},
		"a bad signature":            {[]*handshake.RelayLink{rkLink(t, k0, k1), bad}, k2},
		"no links":                   {nil, k1},
	} {
		if err := m.followRelayLinks(p, c.links, rkAddr(c.to)); err == nil || len(p.EarlierRelays) != 0 || !suite.EqualPublic(p.Relay.PK, rkPub(k0)) {
			t.Fatalf("%s: followed", name)
		}
	}
	if err := m.followRelayLinks(p, []*handshake.RelayLink{rkLink(t, k0, k1)}, rkAddr(k1)); err != nil {
		t.Fatal(err)
	}
	// Back to k0, which the vault followed the peer away from.
	if err := m.followRelayLinks(p, []*handshake.RelayLink{rkLink(t, k1, k0)}, rkAddr(k0)); err == nil || !suite.EqualPublic(p.Relay.PK, rkPub(k1)) {
		t.Fatal("followed back to an earlier key")
	}
}

// §3.4.1 "Cut-off": in the mailbox the cut-off was collected from, a
// smaller msg_id is before it; in another mailbox, a deposited_at not later
// than the cut-off's (the same counts as before, Residuals). An unknown
// position is after (fail closed).
func TestRelayCutoffBeforeAndAfter(t *testing.T) {
	at := testNow().UTC()
	e := &EarlierRelay{CutAt: at, CutMsg: "01JB000000000000000000000M", CutMailbox: "own"}
	for _, c := range []struct {
		name    string
		at      time.Time
		id, box string
		before  bool
	}{
		{"same mailbox, smaller msg_id, later deposited_at", at.Add(time.Hour), "01JB000000000000000000000A", "own", true},
		{"same mailbox, same msg_id", at, "01JB000000000000000000000M", "own", false},
		{"same mailbox, larger msg_id, earlier deposited_at", at.Add(-time.Hour), "01JB000000000000000000000Z", "own", false},
		{"same mailbox, no msg_id", at.Add(-time.Hour), "", "own", false},
		{"other mailbox, earlier", at.Add(-time.Second), "01JB00000000000000000000ZZ", "old", true},
		{"other mailbox, the same deposited_at", at, "01JB00000000000000000000ZZ", "old", true},
		{"other mailbox, later", at.Add(time.Millisecond), "01JB0000000000000000000000", "old", false},
		{"other mailbox, no deposited_at", time.Time{}, "01JB0000000000000000000000", "old", false},
	} {
		if got := e.beforeCutoff(c.at, c.id, c.box); got != c.before {
			t.Fatalf("%s: before %v", c.name, got)
		}
	}
}

// §3.4.1 "Relay-key states": an earlier key is kept until no token the
// vault issued to it can still deposit, then dropped; seen relay links
// from it go with it.
func TestRelayEarlierKeyKeptWhileATokenCanDeposit(t *testing.T) {
	f := newFixture(t)
	m := f.m
	m.opt.RelayKeyRotation = true
	k0, k1, kz := rkKey(0x41), rkKey(0x42), rkKey(0x4a)
	p := rkPeer(m, "c1", k0)
	now := testNow()
	m.st.Issued = append(m.st.Issued, IssuedToken{JTI: "t0", Kind: TokStanding, Sub: relayauth.EncodeKey(rkPub(k0)), PeerID: p.ID,
		Exp: now.Add(10 * 24 * time.Hour), Denied: true})
	m.relayAt, m.msgID = now, "m-1"
	if err := m.followRelayLinks(p, []*handshake.RelayLink{rkLink(t, k0, k1)}, rkAddr(k1)); err != nil {
		t.Fatal(err)
	}
	p.RelaySeen = []json.RawMessage{rkLink(t, k0, kz).Marshal()} // as if seen before the follow
	m.pruneEarlierRelays(now.Add(9 * 24 * time.Hour))
	if p.earlierRelay(rkPub(k0)) == nil || len(p.RelaySeen) != 1 {
		t.Fatal("dropped while a token issued to it can still deposit (a revoked one counts until its exp)")
	}
	m.pruneEarlierRelays(now.Add(10 * 24 * time.Hour))
	if p.EarlierRelays != nil || len(p.RelaySeen) != 0 {
		t.Fatal("kept after its last token expired")
	}
	if m.relayStateOf(p, rkPub(k0)) != relayForeign {
		t.Fatal("a dropped key is not foreign")
	}
}

// The switch: off (the default), no sender is earlier, even with earlier
// keys in the state, and nothing is pruned.
func TestRelayEarlierKeysNeedTheSwitch(t *testing.T) {
	f := newFixture(t)
	m := f.m
	k0, k1 := rkKey(0x41), rkKey(0x42)
	p := rkPeer(m, "c1", k1)
	p.EarlierRelays = []EarlierRelay{{Relay: PeerRelay{PK: rkPub(k0)}, Link: rkLink(t, k0, k1).Marshal(), CutMsg: "m-9", CutMailbox: m.st.Relay.Mailbox}}
	m.msgID = "m-1"
	if m.relayStateOf(p, rkPub(k0)) != relayForeign || m.peerByRelayKey(rkPub(k0)) != nil {
		t.Fatal("an earlier key counted with the switch off")
	}
	m.pruneEarlierRelays(testNow().Add(365 * 24 * time.Hour))
	if len(p.EarlierRelays) != 1 {
		t.Fatal("pruned with the switch off")
	}
}

// The state: a peer without earlier keys writes none of the new members,
// and a stored peer without them reads as one with no earlier key, no seen
// relay link and no relay fork; one with them round-trips.
func TestRelayEarlierStateBackwardCompatible(t *testing.T) {
	plain, err := json.Marshal(&Peer{ID: "c1", Kind: KindConnection})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"earlier_relays", "relay_seen", "relay_fork", "relay_conflict"} {
		if strings.Contains(string(plain), `"`+k+`"`) {
			t.Fatalf("%s written for a peer without it", k)
		}
	}
	var old Peer
	if err := json.Unmarshal(plain, &old); err != nil || old.EarlierRelays != nil || old.RelaySeen != nil || old.RelayFork != nil || old.RelayConflict != nil {
		t.Fatal("an old peer does not read as no earlier keys")
	}
	k0, k1 := rkKey(0x41), rkKey(0x42)
	at := testNow().UTC()
	p := Peer{ID: "c1", Kind: KindConnection,
		EarlierRelays: []EarlierRelay{{Relay: PeerRelay{URL: "https://r", Mailbox: "mb", PK: rkPub(k0)}, Link: rkLink(t, k0, k1).Marshal(), CutAt: at, CutMsg: "m-1", CutMailbox: "own"}},
		RelaySeen:     []json.RawMessage{rkLink(t, k1, k0).Marshal()}, RelayFork: &ForkSuspension{At: at},
		RelayConflict: &RelayConflict{At: at, Old: rkPub(k0), Kept: rkPub(k1), Refused: rkPub(k0)}}
	b, err := json.Marshal(&p)
	if err != nil {
		t.Fatal(err)
	}
	var q Peer
	if err := json.Unmarshal(b, &q); err != nil {
		t.Fatal(err)
	}
	if b2, _ := json.Marshal(&q); !bytes.Equal(b, b2) {
		t.Fatalf("does not round-trip:\n%s\n%s", b, b2)
	}
}

// A link the vault follows is no longer only seen: the follow takes it out
// of the seen links (rule C keeps it as followed instead).
func TestRelayFollowedLinkLeavesTheSeenLinks(t *testing.T) {
	f := newFixture(t)
	m := f.m
	m.opt.RelayKeyRotation = true
	k0, k1, k2 := rkKey(0x41), rkKey(0x42), rkKey(0x43)
	p := rkPeer(m, "c1", k0)
	l01 := rkLink(t, k0, k1)
	if m.relayRuleC(p, l01, testNow()) != relayEvNone || len(p.RelaySeen) != 1 {
		t.Fatal("setup: not seen")
	}
	m.relayAt, m.msgID = testNow(), "m-1"
	if err := m.followRelayLinks(p, []*handshake.RelayLink{l01}, rkAddr(k1)); err != nil {
		t.Fatal(err)
	}
	if len(p.RelaySeen) != 0 {
		t.Fatal("the followed link is still kept as seen")
	}
	// And a later different successor of k0 is still a second successor
	// (against the followed link).
	if m.relayRuleC(p, rkLink(t, k0, k2), testNow()) != relayEvFork {
		t.Fatal("no fork against the followed link")
	}
}
