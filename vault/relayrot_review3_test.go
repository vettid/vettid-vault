package vault

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Review round 3 (VAULT-MESSAGING 0.90.4 §3.4.1 rule U, Table A, §3.4.2
// RK6, §7.1).

// rkDupUpdate has side 1 send side 0 an update whose relay chain is the
// one side 0 followed (K -> 0xa7, rkFollow), carrying rots, taken at
// msg_id id.
func (f *r29Fx) rkDupUpdate(rots []*handshake.Rotation, id string) Message {
	f.t.Helper()
	k2 := rkKey(0xa7)
	u := &peerwire.AddressUpdate{Relay: rkAddr(k2), Token: "v4.public.VEVTVA",
		Links: []*handshake.RelayLink{rkLink(f.t, f.m(1).keys.relay, k2)}, Rotations: rots}
	b, err := u.Marshal()
	if err != nil {
		f.t.Fatal(err)
	}
	f.do(1, func(m *Manager, p *Peer) { m.sendTo(p, peerwire.TypeRelayAddressUpdate, b, f.clk) })
	return f.rkTake(kOther, id)
}

// A copy holding P's earlier key K and an epoch Q accepts replays the
// followed relay link from K after its cut-off with an identity link
// ik -> copy_ik: a duplicate. Its identity links are judged as an
// identity.rotate in that row of Table A: refused superseded_relay, none
// applied. Q's ik for P stays, and P's next handshake is answered.
func TestZZRevACopyDuplicateRotatesIK(t *testing.T) {
	f := rkPair(t)
	ik := append([]byte(nil), f.p(0).IK...)
	f.rkFollow()
	r, err := handshake.NewRotation(f.m(1).keys.ik, rkKey(0x5c), f.m(1).keys.kem.Public())
	if err != nil {
		t.Fatal(err)
	}
	f.process(0, f.rkDupUpdate([]*handshake.Rotation{r}, rkAfter))
	if f.activityCount(0, "drop.peer_key", "superseded_relay") != 1 || !suite.EqualPublic(f.p(0).IK, ik) {
		t.Fatal("a duplicate update from an earlier key after its cut-off moved the ik, or was not refused superseded_relay")
	}
	f.rekey(1)
	f.process(0, f.rkTake(kHSInit, rkBefore))
	if len(f.m(0).st.Awaiting) != 1 || f.activityCount(0, "drop.peer_key", "ancestor_ik") != 0 {
		t.Fatal("P's next handshake was not answered")
	}
}

// Control: such a duplicate whose identity links are all already followed
// changes nothing and still has R29-K9 judged (the abandoned pending epoch
// is ended), as the ignored identity.rotate of that row.
func TestZZRevADuplicateFollowedLinksJudgeK9(t *testing.T) {
	f, e1 := k9Setup(t, true)
	last, err := handshake.ParseRotation(f.m(1).st.Rotations[len(f.m(1).st.Rotations)-1])
	if err != nil {
		t.Fatal(err)
	}
	msg := f.rkDupUpdate([]*handshake.Rotation{last}, rkAfter)
	p := f.p(0)
	p.IK, p.KEM = append([]byte(nil), last.NewIK...), last.NewKEM.Bytes()
	p.Chain = append(p.Chain, last.Marshal())
	f.rkFollow()
	f.process(0, msg)
	if f.superseded() != 0 || !f.ended(0, e1) {
		f.dump()
		t.Fatal("the duplicate with followed identity links was refused, or R29-K9 not judged")
	}
}

// RelayAwaitRC ends when a reconnect token of the new mailbox is adopted:
// a reconnect after that token is dropped (as #244's token_invalid drops
// it) follows "The reconnect bound" (stale), not RK6's owed wait.
func TestRK6AwaitEndsWhenATokenIsAdopted(t *testing.T) {
	f := rkPair(t)
	f.rkSend(false, false)
	f.deliver(1, 0, kOther)
	if f.p(0).RelayAwaitRC.IsZero() {
		t.Fatal("setup: no wait")
	}
	tok := f.rkMintK1("p-rc5")
	f.do(1, func(m *Manager, p *Peer) {
		m.sendTo(p, tokenIssuedType, peerwire.TokenIssuedBody(TokReconnect, tok), f.clk)
	})
	f.deliver(1, 0, kOther)
	if f.p(0).Reconnect.Token != tok || !f.p(0).RelayAwaitRC.IsZero() {
		t.Fatal("the wait outlived the token it waited for")
	}
	f.do(0, func(m *Manager, p *Peer) {
		p.Reconnect = HeldToken{} // refused token_invalid: dropped
		m.startReconnect(p, f.clk)
	})
	if f.p(0).State != PeerStale {
		t.Fatal("a reconnect without a token went into the owed wait instead of the reconnect bound")
	}
}

// rkTokAt mints like rkTok with the given aud and iat.
func rkTokAt(t testing.TB, iss ed25519.PrivateKey, own ed25519.PublicKey, aud string, iat, exp time.Time) string {
	t.Helper()
	tok, err := relayauth.MintToken(iss, relayauth.Claims{Iss: relayauth.MailboxID(rkPub(iss)), Sub: relayauth.EncodeKey(own),
		Aud: aud, Iat: iat, Exp: exp, Jti: "at"})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// §7.1: the own relay's max_token_lifetime_seconds caps a token only when
// its issuer's relay is the vault's own (keyed on the issuer's relay URL).
func TestHeldTokenOwnRelayLimitKeyedOnIssuerURL(t *testing.T) {
	d, _, p, _ := rkConnU(t)
	k1 := rkKey(0x61)
	d.m.limits.MaxTokenLifetimeSeconds = int64((10 * 24 * time.Hour).Seconds())
	now := testNow()
	for _, c := range []struct {
		url  string
		pass bool
	}{{"https://other.example.org", true}, {d.m.st.Relay.URL, false}} {
		tok := rkTokAt(t, k1, rkOwn(d), c.url, now.Add(-time.Minute), now.Add(20*24*time.Hour))
		r := PeerRelay{URL: c.url, Mailbox: rkAddr(k1).Mailbox, PK: rkPub(k1)}
		if _, err := d.m.heldTokenFrom(tok, p, r, TokStanding); (err == nil) != c.pass {
			t.Fatalf("issuer relay %s: err %v, want pass %v", c.url, err, c.pass)
		}
	}
}

// With relay-key rotation off an expired held token passes heldToken as
// before (rule T's expiry applies only with the switch on).
func TestHeldTokenExpiredSwitchOff(t *testing.T) {
	d, _, p, k := rkConnU(t)
	now := testNow()
	tok := rkTokAt(t, k, rkOwn(d), p.Relay.URL, now.Add(-2*time.Hour), now.Add(-time.Minute))
	d.m.opt.RelayKeyRotation = false
	if _, err := d.m.heldToken(tok, p, TokStanding); err != nil {
		t.Fatalf("switch off: an expired token refused: %v", err)
	}
	d.m.opt.RelayKeyRotation = true
	if _, err := d.m.heldToken(tok, p, TokStanding); err == nil {
		t.Fatal("switch on: an expired token accepted")
	}
}

// RK2: a relay.token.issued queued for the passed mailbox is dropped at the
// follow: nothing reaches the old mailbox when it recovers.
func TestRuleUQueuedTokenIssuedNotDeposited(t *testing.T) {
	d, td, p, k := rkConnU(t)
	old := p.Relay.Mailbox
	d.relay.mu.Lock()
	d.relay.failMailbox = map[string]error{old: errors.New("relay down")}
	d.relay.mu.Unlock()
	d.m.mu.Lock()
	d.m.issueTo(p, TokStanding, time.Now())
	_ = d.m.flushThenDrain(context.Background())
	d.m.mu.Unlock()
	k1 := rkKey(0x61)
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, rkBody(t, d, k1, rkLink(t, k, k1))))
	d.relay.mu.Lock()
	d.relay.failMailbox = nil
	d.relay.mu.Unlock()
	d.m.mu.Lock()
	for _, e := range d.m.st.Outbox {
		e.NotBefore = time.Time{}
	}
	_ = d.m.flushThenDrain(context.Background())
	d.m.mu.Unlock()
	if n := d.depositsTo(old); n != 0 {
		t.Fatalf("%d deposits reached the passed mailbox", n)
	}
}

// RelayAwaitRC ends too when a carried reconnect token of the new mailbox
// is adopted at a confirmation.
func TestRK6AwaitEndsAtAnAdoption(t *testing.T) {
	d, td, p, k := rkConnU(t)
	k1 := rkKey(0x61)
	u := rkBody(t, d, k1, rkLink(t, k, k1))
	u.ReconnectToken = ""
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, u))
	if p.RelayAwaitRC.IsZero() {
		t.Fatal("setup: no wait")
	}
	exp := testNow().Add(200 * 24 * time.Hour)
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	d.m.adoptHeld(p, TokReconnect, &p.Reconnect, HeldToken{Token: rkTok(t, k1, rkOwn(d), exp, "carried"), Exp: exp})
	if p.Reconnect.Token == "" || !p.RelayAwaitRC.IsZero() {
		t.Fatal("not adopted, or the wait outlived the adopted token")
	}
}
