package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// VAULT-MESSAGING 0.90.3 §3.4.1 rule U (a relay.address.update) and rule T
// (its tokens), with §3.4.2 RK5 (the update's identity links and the ik
// requirement); only with Options.RelayKeyRotation.

// rkTok mints a deposit token as relay key iss's mailbox would, for own.
func rkTok(t testing.TB, iss ed25519.PrivateKey, own ed25519.PublicKey, exp time.Time, jti string) string {
	t.Helper()
	tok, err := relayauth.MintToken(iss, relayauth.Claims{Iss: relayauth.MailboxID(rkPub(iss)), Sub: relayauth.EncodeKey(own),
		Aud: "https://relay.example.org", Iat: testNow().Add(-time.Minute), Exp: exp, Jti: jti})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// rkOwn is the receiving vault's relay key.
func rkOwn(d *devFixture) ed25519.PublicKey { return d.m.keys.relay.Public().(ed25519.PublicKey) }

// rkBody is an update to `to` with links, a standing token and a reconnect
// token minted by to's mailbox for d's vault.
func rkBody(t testing.TB, d *devFixture, to ed25519.PrivateKey, links ...*handshake.RelayLink) *peerwire.AddressUpdate {
	exp := testNow().Add(20 * 24 * time.Hour)
	return &peerwire.AddressUpdate{Relay: rkAddr(to), Token: rkTok(t, to, rkOwn(d), exp, "st-"+fmt.Sprint(to[0])),
		ReconnectToken: rkTok(t, to, rkOwn(d), exp, "rc-"+fmt.Sprint(to[0])), Links: links}
}

func rkMarshal(t testing.TB, u *peerwire.AddressUpdate) string {
	t.Helper()
	b, err := u.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// rkSigned records the epoch td sends under, signed by the peer's ik on
// record, as an activation would (RK5's "the update's ik").
func rkSigned(d *devFixture, td *tdev) {
	id := td.ep.ID()
	td.peer.Epochs = append(td.peer.Epochs, EpochMeta{ID: id[:], Signer: append([]byte(nil), td.peer.IK...)})
	td.peer.LastEpochID = id[:]
}

// sendCFrom is sendC deposited with relay key sender.
func sendCFrom(d *devFixture, td *tdev, sender ed25519.PublicKey, typ, body string) (string, *fakeCollector) {
	d.seq++
	id, _ := envelope.NewULID(time.Now())
	raw, err := td.ep.Seal(&envelope.Inner{ID: id, Type: typ, TS: time.Now(), Body: []byte(body)})
	if err != nil {
		panic(err)
	}
	c := &fakeCollector{}
	msg := Message{MsgID: fmt.Sprintf("g%03d", d.seq), Sender: relayauth.EncodeKey(sender), JTI: "standing-" + td.peer.ID, Payload: raw}
	_ = d.m.ProcessBatch(context.Background(), c, []Message{msg})
	return msg.MsgID, c
}

// rkConnU is rkConn with the epoch's signer recorded: a connection rule U
// can follow.
func rkConnU(t *testing.T) (*devFixture, *tdev, *Peer, ed25519.PrivateKey) {
	d, td, p, k := rkConn(t)
	rkSigned(d, td)
	return d, td, p, k
}

func peerKeyRefs(d *devFixture) []string {
	var out []string
	for _, a := range d.audits("drop.peer_key") {
		out = append(out, a.Ref)
	}
	return out
}

// tokensIssued are the relay.token.issued d's vault sent td (cleared), as
// kind and sub.
func tokensIssued(t testing.TB, d *devFixture, td *tdev) [][2]string {
	t.Helper()
	var out [][2]string
	for _, in := range d.inbox(td)[td.peer.ID] {
		if in.Type != tokenIssuedType {
			continue
		}
		kind, tok, err := peerwire.ParseTokenIssued(in.Body)
		if err != nil {
			t.Fatal(err)
		}
		c, err := relayauth.ParseToken(tok, rkOwn(d))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, [2]string{kind, c.Sub})
	}
	return out
}

// Rule U: an update whose links lead from the sender (the key on record)
// to relay.pk is followed in one write: the passed key becomes earlier with
// this update's position as its cut-off, relay.pk current, the update's
// tokens kept; then relay.token.issued for the new key (standing and
// reconnect, sub the new key, to its mailbox), the reconnect tokens issued
// to the passed key revoked and the standing ones left to expire.
func TestRuleUFollowsAnUpdate(t *testing.T) {
	d, td, p, k := rkConnU(t)
	k1 := rkKey(0x61)
	d.m.st.Issued = append(d.m.st.Issued, IssuedToken{JTI: "rc-old", Kind: TokReconnect, Sub: relayauth.EncodeKey(rkPub(k)),
		PeerID: p.ID, Exp: time.Now().Add(100 * 24 * time.Hour)})
	u := rkBody(t, d, k1, rkLink(t, k, k1))
	d.inbox(td)
	id, _ := sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, u))
	if refs := peerKeyRefs(d); len(refs) != 0 {
		t.Fatalf("the update was refused: %v", refs)
	}
	if !suite.EqualPublic(p.Relay.PK, rkPub(k1)) || p.Relay.Mailbox != relayauth.MailboxID(rkPub(k1)) {
		t.Fatal("relay.pk is not current")
	}
	if len(p.EarlierRelays) != 1 || !suite.EqualPublic(p.EarlierRelays[0].Relay.PK, rkPub(k)) || p.EarlierRelays[0].CutMsg != id {
		t.Fatalf("the passed key is not earlier with this update as its cut-off: %+v", p.EarlierRelays)
	}
	if p.Standing.Token != u.Token || p.Reconnect.Token != u.ReconnectToken {
		t.Fatal("the update's tokens are not kept")
	}
	got := tokensIssued(t, d, td)
	sub1 := relayauth.EncodeKey(rkPub(k1))
	if len(got) != 2 || got[0] != [2]string{TokStanding, sub1} || got[1] != [2]string{TokReconnect, sub1} {
		t.Fatalf("not answered with standing and reconnect tokens for the new key at its mailbox: %v", got)
	}
	for _, it := range d.m.st.Issued {
		switch {
		case it.JTI == "rc-old" && !it.Denied:
			t.Fatal("the reconnect token issued to the passed key is not revoked")
		case it.JTI == "standing-per" && it.Denied:
			t.Fatal("the standing token issued to the passed key was revoked, not left to expire")
		}
	}
	d.m.mu.Lock()
	_ = d.m.flushThenDrain(context.Background())
	d.m.mu.Unlock()
	revoked := strings.Join(d.relay.revoked, " ")
	if !strings.Contains(revoked, "jti:rc-old") || strings.Contains(revoked, "jti:standing-per") {
		t.Fatalf("revocations at the relay: %s", revoked)
	}
}

// Rule U's chain checks (relay_unlinked), rollback (relay_rollback) and
// rule T on the update's token (token_unusable): each refused update has
// none of its links followed and none of its tokens kept. A link's form
// and the count are refused at parse time and keep no link as seen; so
// does an end mismatch; a bad signature keeps the earlier valid links.
func TestRuleURefusals(t *testing.T) {
	exp := testNow().Add(20 * 24 * time.Hour)
	for _, c := range []struct {
		name string
		body func(d *devFixture, k ed25519.PrivateKey) string
		ref  string // "" : no drop.peer_key (a malformed body)
		seen int
	}{
		{"a link's form", func(d *devFixture, k ed25519.PrivateKey) string {
			k1 := rkKey(0x61)
			s := rkMarshal(t, rkBody(t, d, k1, rkLink(t, k, k1)))
			var o map[string]any
			_ = json.Unmarshal([]byte(s), &o)
			o["relay_links"].([]any)[0].(map[string]any)["sig_old"] = base64.StdEncoding.EncodeToString([]byte("short"))
			b, _ := json.Marshal(o)
			return string(b)
		}, "relay_unlinked", 0},
		{"no links", func(d *devFixture, k ed25519.PrivateKey) string {
			k1 := rkKey(0x61)
			s := rkMarshal(t, rkBody(t, d, k1, rkLink(t, k, k1)))
			var o map[string]any
			_ = json.Unmarshal([]byte(s), &o)
			o["relay_links"] = []any{}
			b, _ := json.Marshal(o)
			return string(b)
		}, "relay_unlinked", 0},
		{"relay_links missing: malformed", func(d *devFixture, k ed25519.PrivateKey) string {
			k1 := rkKey(0x61)
			s := rkMarshal(t, rkBody(t, d, k1, rkLink(t, k, k1)))
			var o map[string]any
			_ = json.Unmarshal([]byte(s), &o)
			delete(o, "relay_links")
			b, _ := json.Marshal(o)
			return string(b)
		}, "", 0},
		{"a bad signature", func(d *devFixture, k ed25519.PrivateKey) string {
			k1, k2 := rkKey(0x61), rkKey(0x62)
			return rkMarshal(t, rkBody(t, d, k2, rkLink(t, k, k1), badLink(rkLink(t, k1, k2))))
		}, "relay_unlinked", 1},
		{"the first old is not the sender", func(d *devFixture, k ed25519.PrivateKey) string {
			k0, k1 := rkKey(0x60), rkKey(0x61)
			return rkMarshal(t, rkBody(t, d, k1, rkLink(t, k0, k1)))
		}, "relay_unlinked", 0},
		{"the last new is not relay.pk", func(d *devFixture, k ed25519.PrivateKey) string {
			k1, k2 := rkKey(0x61), rkKey(0x62)
			return rkMarshal(t, rkBody(t, d, k2, rkLink(t, k, k1)))
		}, "relay_unlinked", 0},
		{"a token not minted by relay.pk's mailbox", func(d *devFixture, k ed25519.PrivateKey) string {
			k1 := rkKey(0x61)
			u := rkBody(t, d, k1, rkLink(t, k, k1))
			u.Token = rkTok(t, rkKey(0x6f), rkOwn(d), exp, "x")
			return rkMarshal(t, u)
		}, "token_unusable", 1},
		{"an expired token", func(d *devFixture, k ed25519.PrivateKey) string {
			k1 := rkKey(0x61)
			u := rkBody(t, d, k1, rkLink(t, k, k1))
			u.Token = rkTok(t, k1, rkOwn(d), testNow().Add(-time.Second), "x")
			return rkMarshal(t, u)
		}, "token_unusable", 1},
		{"a token for another sub", func(d *devFixture, k ed25519.PrivateKey) string {
			k1 := rkKey(0x61)
			u := rkBody(t, d, k1, rkLink(t, k, k1))
			u.Token = rkTok(t, k1, rkPub(rkKey(0x6e)), exp, "x")
			return rkMarshal(t, u)
		}, "token_unusable", 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			d, td, p, k := rkConnU(t)
			before := snapDev(t, d, p)
			before.deposits = -1
			sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, c.body(d, k))
			refs := peerKeyRefs(d)
			if c.ref == "" && len(refs) != 0 || c.ref != "" && (len(refs) != 1 || refs[0] != c.ref) {
				t.Fatalf("refused %v, want %q", refs, c.ref)
			}
			after := snapPeer(d.m, p)
			if !after.same(before) || len(p.EarlierRelays) != 0 {
				t.Fatalf("a refused update changed the peer:\n before %+v\n after  %+v", before, after)
			}
			if len(p.RelaySeen) != c.seen {
				t.Fatalf("seen links: %d, want %d", len(p.RelaySeen), c.seen)
			}
		})
	}
}

// A reconnect_token that fails rule T is ignored, no reason to refuse:
// the update is followed and the reconnect token held stays.
func TestRuleTUpdateReconnectTokenIgnored(t *testing.T) {
	d, td, p, k := rkConnU(t)
	k1 := rkKey(0x61)
	u := rkBody(t, d, k1, rkLink(t, k, k1))
	u.ReconnectToken = rkTok(t, rkKey(0x6f), rkOwn(d), testNow().Add(time.Hour), "x")
	held := p.Reconnect
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, u))
	if refs := peerKeyRefs(d); len(refs) != 0 || !suite.EqualPublic(p.Relay.PK, rkPub(k1)) {
		t.Fatalf("refused (%v) or not followed", refs)
	}
	if p.Reconnect != held {
		t.Fatal("a reconnect token that fails rule T was kept")
	}
}

// relay_rollback: a link to a key the vault keeps for the peer (here the
// earlier key it followed it away from) is refused.
func TestRuleURollback(t *testing.T) {
	d, td, p, k := rkConnU(t)
	k1 := rkKey(0x61)
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, rkBody(t, d, k1, rkLink(t, k, k1))))
	if !suite.EqualPublic(p.Relay.PK, rkPub(k1)) {
		t.Fatal("setup: not followed")
	}
	sendCFrom(d, td, rkPub(k1), peerwire.TypeRelayAddressUpdate, rkMarshal(t, rkBody(t, d, k, rkLink(t, k1, k))))
	if refs := peerKeyRefs(d); len(refs) != 1 || refs[0] != "relay_rollback" || !suite.EqualPublic(p.Relay.PK, rkPub(k1)) {
		t.Fatalf("a rollback was not refused relay_rollback: %v", refs)
	}
}

// Rule U: leading links already followed are skipped; the rest is followed
// from the key on record, from whichever of the peer's keys the update
// came. If all are followed the update is a duplicate: ignored, and
// answered with fresh tokens for the current key, at most one an hour.
func TestRuleUSkipsFollowedLinksAndDuplicates(t *testing.T) {
	d, td, p, k := rkConnU(t)
	k1, k2 := rkKey(0x61), rkKey(0x62)
	l01, l12 := rkLink(t, k, k1), rkLink(t, k1, k2)
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, rkBody(t, d, k1, l01)))
	d.inbox(td)
	// From the earlier key, after its cut-off (Table A: rule U): the same
	// link again is a duplicate.
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, rkBody(t, d, k1, l01)))
	if refs := peerKeyRefs(d); len(refs) != 0 || len(p.EarlierRelays) != 1 {
		t.Fatalf("a duplicate was refused (%v) or followed again", refs)
	}
	if got := tokensIssued(t, d, td); len(got) != 2 {
		t.Fatalf("a duplicate was not answered with fresh tokens: %v", got)
	}
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, rkBody(t, d, k1, l01)))
	if got := tokensIssued(t, d, td); len(got) != 0 {
		t.Fatalf("a second duplicate within the hour was answered: %v", got)
	}
	// The whole chain from the earlier key: the followed link is skipped.
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, rkBody(t, d, k2, l01, l12)))
	if refs := peerKeyRefs(d); len(refs) != 0 || !suite.EqualPublic(p.Relay.PK, rkPub(k2)) || len(p.EarlierRelays) != 2 {
		t.Fatalf("the chain past a followed link was not followed (%v)", refs)
	}
}

// The per-peer cap on earlier relay keys fails closed: a follow past it is
// refused (unexpected) and changes nothing.
func TestRuleUEarlierRelaysCap(t *testing.T) {
	d, td, p, k := rkConnU(t)
	for i := 0; i < MaxEarlierRelays; i++ {
		x := rkKey(byte(0x90 + i))
		p.EarlierRelays = append(p.EarlierRelays, EarlierRelay{Relay: PeerRelay{PK: rkPub(x), Mailbox: relayauth.MailboxID(rkPub(x))}})
		d.m.st.Issued = append(d.m.st.Issued, IssuedToken{JTI: fmt.Sprint("cap", i), Kind: TokStanding, Sub: relayauth.EncodeKey(rkPub(x)),
			PeerID: p.ID, Exp: time.Now().Add(24 * time.Hour)})
	}
	k1 := rkKey(0x61)
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, rkBody(t, d, k1, rkLink(t, k, k1))))
	if refs := peerKeyRefs(d); len(refs) != 1 || refs[0] != "unexpected" || !suite.EqualPublic(p.Relay.PK, rkPub(k)) {
		t.Fatalf("a follow past the cap was not refused: %v", refs)
	}
}

// RK5's ik requirement fails closed: an update under an epoch whose signer
// the vault does not know is refused (unknown_ik), nothing followed.
func TestRK5UnknownSignerRefused(t *testing.T) {
	d, td, p, k := rkConn(t)
	k1 := rkKey(0x61)
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, rkBody(t, d, k1, rkLink(t, k, k1))))
	if refs := peerKeyRefs(d); len(refs) != 1 || refs[0] != "unknown_ik" || !suite.EqualPublic(p.Relay.PK, rkPub(k)) {
		t.Fatalf("not refused unknown_ik: %v", refs)
	}
}

// A device's update: rule U without RK5 (a device rotates no ik): followed,
// answered with a standing token only; one carrying identity links cannot
// occur and is refused (unexpected).
func TestRuleUFromADevice(t *testing.T) {
	for _, withRots := range []bool{false, true} {
		d := newDevFixture(t)
		sinkOf(d)
		d.m.opt.RelayKeyRotation = true
		td := d.addDevice(t, "dsk", KindDesktop, 0x84)
		p := td.peer
		k := append(ed25519.PublicKey(nil), p.Relay.PK...)
		k1 := rkKey(0x61)
		// The device's relay key is seed+1's (addDevice).
		u := rkBody(t, d, k1, rkLink(t, rkKey(0x85), k1))
		if !suite.EqualPublic(rkPub(rkKey(0x85)), k) {
			t.Fatal("setup: the device's relay key")
		}
		if withRots {
			r, err := handshake.NewRotation(rkKey(0x11), rkKey(0x12), d.m.keys.kem.Public())
			if err != nil {
				t.Fatal(err)
			}
			u.Rotations = []*handshake.Rotation{r}
		}
		d.inbox(td)
		d.sendAs(td, peerwire.TypeRelayAddressUpdate, rkMarshal(t, u))
		refs := peerKeyRefs(d)
		if withRots {
			if len(refs) != 1 || refs[0] != "unexpected" || !suite.EqualPublic(p.Relay.PK, k) {
				t.Fatalf("a device's update with identity links: %v", refs)
			}
			continue
		}
		if len(refs) != 0 || !suite.EqualPublic(p.Relay.PK, rkPub(k1)) {
			t.Fatalf("a device's update was not followed: %v", refs)
		}
		if got := tokensIssued(t, d, td); len(got) != 1 || got[0][0] != TokStanding {
			t.Fatalf("a device is answered with a standing token only: %v", got)
		}
	}
}

// Rule T: a relay.token.issued whose iss is a mailbox the vault does not
// know for the peer is deferred (left unacked, unprocessed) for at most two
// visibility timeouts after it was first seen, then processed (its token
// ignored); a known mailbox's is processed at once; at most 8 at once per
// peer.
func TestRuleTDefersUnknownMailbox(t *testing.T) {
	d, td, p, _ := rkConnU(t)
	clk := testNow()
	d.m.now = func() time.Time { return clk }
	k9 := rkKey(0x69)
	body := string(peerwire.TokenIssuedBody(TokStanding, rkTok(t, k9, rkOwn(d), clk.Add(20*24*time.Hour), "nx")))
	id, _ := envelope.NewULID(clk)
	raw, err := td.ep.Seal(&envelope.Inner{ID: id, Type: tokenIssuedType, TS: clk, Body: []byte(body)})
	if err != nil {
		t.Fatal(err)
	}
	msg := Message{MsgID: "defer-1", Sender: relayauth.EncodeKey(p.Relay.PK), JTI: "standing-per", Payload: raw}
	run := func() *fakeCollector {
		c := &fakeCollector{}
		if err := d.m.ProcessBatch(context.Background(), c, []Message{msg}); err != nil {
			t.Fatal(err)
		}
		return c
	}
	if c := run(); len(c.acked) != 0 || stAudited(d.m, "bad_issued_token") {
		t.Fatal("not deferred")
	}
	clk = clk.Add(RuleTVisibility)
	if c := run(); len(c.acked) != 0 {
		t.Fatal("not deferred again within two visibility timeouts")
	}
	clk = clk.Add(RuleTVisibility)
	if c := run(); len(c.acked) != 1 || !stAudited(d.m, "bad_issued_token") {
		t.Fatal("still deferred after two visibility timeouts, or its token kept")
	}
	if len(d.m.st.Deferred) != 0 {
		t.Fatal("the deferral is kept after the message was processed")
	}
	// At most 8 at once per peer.
	n := 0
	for i := 0; i < RuleTDeferMax+1; i++ {
		msg.MsgID = fmt.Sprintf("defer-x%d", i)
		if c := run(); len(c.acked) == 0 {
			n++
		}
	}
	if n != RuleTDeferMax {
		t.Fatalf("deferred %d at once, want %d", n, RuleTDeferMax)
	}
}

// Rule T: a relay.token.issued with an expired token is not kept.
func TestRuleTTokenIssuedExpiredIgnored(t *testing.T) {
	d, td, p, k := rkConnU(t)
	held := p.Reconnect
	body := string(peerwire.TokenIssuedBody(TokReconnect, rkTok(t, k, rkOwn(d), testNow().Add(-time.Minute), "old")))
	sendCFrom(d, td, rkPub(k), tokenIssuedType, body)
	if p.Reconnect != held || !stAudited(d.m, "bad_issued_token") {
		t.Fatal("an expired reconnect token was kept, or not audited bad_issued_token")
	}
}

func stAudited(m *Manager, ev string) bool {
	for _, a := range m.st.Audit {
		if a.Event == ev {
			return true
		}
	}
	return false
}

// With relay-key rotation off a valid update is refused relay_unlinked as
// before, and nothing changes.
func TestRuleUOffRefusesAValidUpdate(t *testing.T) {
	d, td, p, k := rkConnU(t)
	d.m.opt.RelayKeyRotation = false
	k1 := rkKey(0x61)
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, rkBody(t, d, k1, rkLink(t, k, k1))))
	if refs := peerKeyRefs(d); len(refs) != 1 || refs[0] != "relay_unlinked" || !suite.EqualPublic(p.Relay.PK, rkPub(k)) || len(p.RelaySeen) != 0 {
		t.Fatalf("with the switch off: %v", refs)
	}
}

// Rule U: the first old must be the key the update was deposited with. An
// update from the earlier key whose chain starts at the key on record is
// refused (relay_unlinked), though the chain itself would verify from it.
func TestRuleUFirstOldIsTheSender(t *testing.T) {
	d, td, p, k := rkConnU(t)
	k1, k2 := rkKey(0x61), rkKey(0x62)
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, rkBody(t, d, k1, rkLink(t, k, k1))))
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, rkBody(t, d, k2, rkLink(t, k1, k2))))
	if refs := peerKeyRefs(d); len(refs) != 1 || refs[0] != "relay_unlinked" || !suite.EqualPublic(p.Relay.PK, rkPub(k1)) {
		t.Fatalf("an update whose first old is not its sender: %v", refs)
	}
}

// Rule U makes relay.pk current: deposits queued on the held standing
// token go to the new mailbox with the new token; a queued
// relay.token.issued is dropped (its tokens name the passed key, RK2) and
// replaced by the answer's.
func TestRuleUQueuedDepositsFollow(t *testing.T) {
	d, td, p, k := rkConnU(t)
	old := p.Relay.Mailbox
	d.relay.mu.Lock()
	d.relay.failMailbox = map[string]error{old: errors.New("relay down")}
	d.relay.mu.Unlock()
	d.m.mu.Lock()
	d.m.sendTo(p, "test.queued", json.RawMessage(`{}`), time.Now())
	d.m.issueTo(p, TokStanding, time.Now())
	_ = d.m.flushThenDrain(context.Background())
	d.m.mu.Unlock()
	if d.depositsTo(old) != 0 {
		t.Fatal("setup: deposited")
	}
	k1 := rkKey(0x61)
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, rkBody(t, d, k1, rkLink(t, k, k1))))
	in := d.inbox(td)[p.ID]
	queued, issued := 0, 0
	for _, x := range in {
		switch x.Type {
		case "test.queued":
			queued++
		case tokenIssuedType:
			issued++
		}
	}
	if queued != 1 || issued != 2 {
		t.Fatalf("at the new mailbox: %d queued messages (want 1), %d relay.token.issued (want the answer's 2)", queued, issued)
	}
}

// RK5 "Links first" (this release's reading): the update's identity links are
// applied before rule U's checks, so they are followed even when rule U
// then refuses the update (here for its token); its relay links are not.
func TestRK5IdentityLinksFollowedWhenUpdateRefused(t *testing.T) {
	f := rkPair(t)
	f.rotate(1)
	f.lose(1, 0, kRotate)
	u := f.rkSend(true, true)
	f.lose(1, 0, kOther)
	f.do(1, func(m *Manager, p *Peer) {
		u.Token = u.ReconnectToken[:len(u.ReconnectToken)-4] + "AAAA"
		b, err := u.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		m.sendTo(p, peerwire.TypeRelayAddressUpdate, b, f.clk)
	})
	f.deliver(1, 0, kOther)
	if f.followedK1() || f.activityCount(0, "drop.peer_key", "token_unusable") != 1 {
		t.Fatal("setup: the update was not refused token_unusable")
	}
	if !bytes.Equal(f.p(0).IK, f.m(1).keys.ik.Public().(ed25519.PublicKey)) {
		t.Fatal("the refused update's identity links were not followed first")
	}
}

// rkIKLink is an identity link from the rkConn connection's ik (the
// device seed 0x74's) to a key seeded with seed.
func rkIKLink(t testing.TB, d *devFixture, seed byte) *handshake.Rotation {
	t.Helper()
	r, err := handshake.NewRotation(rkKey(0x74), rkKey(seed), d.m.keys.kem.Public())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// acceptFrom step 3, evidence first: an update's identity links are checked
// by rule C, and kept as seen, even when the message is then refused
// before rule U (here under an epoch rule E destroyed).
func TestRuleUIdentityLinksEvidenceFirst(t *testing.T) {
	d, td, p, k := rkConnU(t)
	if !suite.EqualPublic(p.IK, rkPub(rkKey(0x74))) {
		t.Fatal("setup: the connection's ik")
	}
	p.Epochs[len(p.Epochs)-1].Destroyed = true
	p.Epochs[len(p.Epochs)-1].DestroyTS = time.Now().Add(time.Hour)
	k1 := rkKey(0x61)
	u := rkBody(t, d, k1, rkLink(t, k, k1))
	u.Rotations = []*handshake.Rotation{rkIKLink(t, d, 0x20)}
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, u))
	if suite.EqualPublic(p.Relay.PK, rkPub(k1)) || !suite.EqualPublic(p.IK, rkPub(rkKey(0x74))) {
		t.Fatal("setup: the update under a destroyed epoch was followed")
	}
	if len(p.Seen) != 1 {
		t.Fatalf("the update's identity link was not kept as seen at step 3: %d", len(p.Seen))
	}
}

// RK5: when applying the update's identity links makes the record suspend
// (here R29-K9: an epoch the vault abandoned while pending, signed by the
// link's old ik, has its received flag set), no relay link is followed.
func TestRK5SuspendedByTheLinksFollowsNothing(t *testing.T) {
	d, td, p, k := rkConnU(t)
	p.Epochs = append(p.Epochs, EpochMeta{ID: bytes.Repeat([]byte{7}, len(p.LastEpochID)), Signer: append([]byte(nil), p.IK...),
		Mine: true, Abandoned: true, GotFromPeer: true})
	k1 := rkKey(0x61)
	u := rkBody(t, d, k1, rkLink(t, k, k1))
	u.Rotations = []*handshake.Rotation{rkIKLink(t, d, 0x20)}
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, u))
	if !p.suspended() {
		t.Fatal("setup: the links did not make the record suspend")
	}
	if suite.EqualPublic(p.Relay.PK, rkPub(k1)) {
		t.Fatal("a relay link was followed though the identity links suspended the record")
	}
}

// Rule T's deferral: a relay.token.issued minted by an earlier mailbox of
// the peer's is from a known mailbox: not deferred, processed at once and
// its token ignored.
func TestRuleTEarlierMailboxNotDeferred(t *testing.T) {
	d, td, p, k := rkConnU(t)
	k1 := rkKey(0x61)
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, rkBody(t, d, k1, rkLink(t, k, k1))))
	held := p.Standing
	body := string(peerwire.TokenIssuedBody(TokStanding, rkTok(t, k, rkOwn(d), testNow().Add(25*24*time.Hour), "from-k")))
	_, c := sendCFrom(d, td, rkPub(k1), tokenIssuedType, body)
	if len(c.acked) != 1 || p.Standing != held || len(d.m.st.Deferred) != 0 {
		t.Fatal("a token of an earlier mailbox was deferred, or kept")
	}
}

// Rule T's deferral cap counts every deferral of the peer's still recorded,
// whatever its age: the same relay.token.issued replayed under fresh
// msg_ids is deferred at most RuleTDeferMax times, then processed at once.
func TestRuleTDeferralsBounded(t *testing.T) {
	d, td, p, _ := rkConnU(t)
	clk := testNow()
	d.m.now = func() time.Time { return clk }
	body := string(peerwire.TokenIssuedBody(TokStanding, rkTok(t, rkKey(0x69), rkOwn(d), clk.Add(20*24*time.Hour), "nx")))
	id, _ := envelope.NewULID(clk)
	raw, err := td.ep.Seal(&envelope.Inner{ID: id, Type: tokenIssuedType, TS: clk, Body: []byte(body)})
	if err != nil {
		t.Fatal(err)
	}
	deferred := 0
	for i := 0; i < 3*RuleTDeferMax; i++ {
		clk = clk.Add(3 * RuleTVisibility) // each earlier deferral's window has passed
		c := &fakeCollector{}
		msg := Message{MsgID: fmt.Sprintf("replay-%02d", i), Sender: relayauth.EncodeKey(p.Relay.PK), JTI: "standing-per", Payload: raw}
		if err := d.m.ProcessBatch(context.Background(), c, []Message{msg}); err != nil {
			t.Fatal(err)
		}
		if len(c.acked) == 0 {
			deferred++
		}
	}
	if deferred != RuleTDeferMax || len(d.m.st.Deferred) > RuleTDeferMax {
		t.Fatalf("deferred %d (state %d), want at most %d", deferred, len(d.m.st.Deferred), RuleTDeferMax)
	}
}
