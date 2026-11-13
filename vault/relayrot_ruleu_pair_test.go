package vault

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Rule U, RK5, RK6 and rule T in a real pair: side 1 (P) announces a new
// relay key K1 to side 0 (Q), which has relay-key rotation on. P itself
// does not rotate (that side is not built): it keeps depositing with K,
// which after Q's follow is an earlier key, after its cut-off.

const rkK1 = 0xb1

// rkSend has side 1 send side 0 an update to K1 with links from its relay
// key; withRC adds a reconnect token, withRots side 1's identity links
// since the epoch's signer (RK5). It returns the update.
func (f *r29Fx) rkSend(withRC, withRots bool) *peerwire.AddressUpdate {
	f.t.Helper()
	k1 := rkKey(rkK1)
	own := f.pk(0)
	mint := func(jti string) string {
		exp := f.clk.Add(25 * 24 * time.Hour) // a standing token: within §7.1's 30 days
		if jti == "p-rc" {
			exp = f.clk.Add(300 * 24 * time.Hour)
		}
		tok, err := relayauth.MintToken(k1, relayauth.Claims{Iss: relayauth.MailboxID(rkPub(k1)), Sub: relayauth.EncodeKey(own),
			Aud: "https://relay.example.org", Iat: f.clk.Add(-time.Minute), Exp: exp, Jti: jti})
		if err != nil {
			f.t.Fatal(err)
		}
		return tok
	}
	u := &peerwire.AddressUpdate{Relay: rkAddr(k1), Token: mint("p-st"), Links: []*handshake.RelayLink{rkLink(f.t, f.m(1).keys.relay, k1)}}
	if withRC {
		u.ReconnectToken = mint("p-rc")
	}
	f.do(1, func(m *Manager, p *Peer) {
		if withRots {
			u.Rotations = m.ownRotationsSince(p.OwnChainAtEpoch)
		}
		b, err := u.Marshal()
		if err != nil {
			f.t.Fatal(err)
		}
		m.sendTo(p, peerwire.TypeRelayAddressUpdate, b, f.clk)
	})
	return u
}

// rkOn turns relay-key rotation on at side 0, with long tokens.
func rkPair(t *testing.T) *r29Fx {
	f := newR29Fx(t)
	f.longTokens()
	f.m(0).opt.RelayKeyRotation = true
	return f
}

func (f *r29Fx) followedK1() bool { return suite.EqualPublic(f.p(0).Relay.PK, rkPub(rkKey(rkK1))) }

// RK5: the update's identity links are applied first, so an update that
// carries side 1's new ik link (its identity.rotate lost) is followed: the
// chain from the update's ik (its epoch's signer) ends at the current ik.
func TestRK5UpdateLinksAppliedFirst(t *testing.T) {
	f := rkPair(t)
	f.rotate(1)
	f.lose(1, 0, kRotate)
	f.rkSend(true, true)
	f.deliver(1, 0, kOther)
	if !bytes.Equal(f.p(0).IK, f.m(1).keys.ik.Public().(ed25519.PublicKey)) {
		t.Fatal("the update's identity links were not followed")
	}
	if !f.followedK1() || f.activityCount(0, "drop.peer_key", "unknown_ik")+f.activityCount(0, "drop.peer_key", "ancestor_ik") != 0 {
		t.Fatal("the update was not followed after its identity links")
	}
}

// RK5's ik requirement: an update under an epoch signed by an ik the vault
// has since followed away from, carrying no identity links, is refused
// (Table B for its ik: ancestor_ik) and nothing is followed.
func TestRK5UpdateUnderAncestorIKRefused(t *testing.T) {
	f := rkPair(t)
	f.rotate(1)
	f.deliver(1, 0, kRotate)
	if !bytes.Equal(f.p(0).IK, f.m(1).keys.ik.Public().(ed25519.PublicKey)) {
		t.Fatal("setup: the identity.rotate was not followed")
	}
	f.rkSend(true, false)
	f.deliver(1, 0, kOther)
	if f.followedK1() || f.activityCount(0, "drop.peer_key", "ancestor_ik") != 1 {
		t.Fatal("an update from an ancestor ik without links was followed, or not refused ancestor_ik")
	}
}

// RK6: at the follow, side 0's own open reconnect whose hs.init carried
// tokens naming the passed key (no hs.fin sent) is abandoned, its tokens
// revoked, and started again with tokens naming the new key, deposited to
// the new mailbox on the update's reconnect token.
func TestRK6RestartsOwnReconnect(t *testing.T) {
	f := rkPair(t)
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	var oldJTIs []string
	for _, og := range f.m(0).st.Outgoing {
		for _, it := range og.Issued {
			oldJTIs = append(oldJTIs, it.JTI)
		}
	}
	if len(oldJTIs) == 0 {
		t.Fatal("setup: no reconnect")
	}
	u := f.rkSend(true, false)
	f.deliver(1, 0, kOther)
	if !f.followedK1() {
		t.Fatal("setup: not followed")
	}
	sub1 := relayauth.EncodeKey(rkPub(rkKey(rkK1)))
	n := 0
	for _, og := range f.m(0).st.Outgoing {
		if og.Purpose != handshake.PurposeReconnect {
			continue
		}
		n++
		for _, it := range og.Issued {
			if it.Sub != sub1 {
				t.Fatal("the restarted reconnect carries a token naming the passed key")
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d own reconnects after the follow, want the restarted one", n)
	}
	for _, j := range oldJTIs {
		denied := false
		for _, it := range f.m(0).st.Issued {
			denied = denied || it.JTI == j && it.Denied
		}
		if !denied {
			t.Fatal("the abandoned reconnect's tokens are not revoked")
		}
	}
	f.m(0).mu.Lock()
	_ = f.m(0).flushThenDrain(t.Context())
	f.m(0).mu.Unlock()
	found := false
	f.d[0].relay.mu.Lock()
	for _, dep := range f.d[0].relay.deposits {
		found = found || dep.mailbox == relayauth.MailboxID(rkPub(rkKey(rkK1))) && dep.token == u.ReconnectToken
	}
	f.d[0].relay.mu.Unlock()
	if !found {
		t.Fatal("the restart was not deposited to the new mailbox on the update's reconnect token")
	}
}

// RK6 (0.90.2): without a held reconnect token for the new mailbox the
// restart waits (never on the token held for the earlier mailbox), and
// starts once one arrives (a relay.token.issued after the cut-off: its
// tokens only, by rule T).
func TestRK6RestartWaitsForAToken(t *testing.T) {
	f := rkPair(t)
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	f.rkSend(false, false)
	f.deliver(1, 0, kOther)
	if !f.followedK1() || f.p(0).RelayRestart == nil || len(f.m(0).st.Outgoing) != 0 {
		t.Fatal("the restart did not wait for a reconnect token for the new mailbox")
	}
	k1 := rkKey(rkK1)
	tok, err := relayauth.MintToken(k1, relayauth.Claims{Iss: relayauth.MailboxID(rkPub(k1)), Sub: relayauth.EncodeKey(f.pk(0)),
		Aud: "https://relay.example.org", Iat: f.clk.Add(-time.Minute), Exp: f.clk.Add(300 * 24 * time.Hour), Jti: "p-rc2"})
	if err != nil {
		t.Fatal(err)
	}
	f.do(1, func(m *Manager, p *Peer) {
		m.sendTo(p, tokenIssuedType, peerwire.TokenIssuedBody(TokReconnect, tok), f.clk)
	})
	f.deliver(1, 0, kOther)
	if f.p(0).RelayRestart != nil || len(f.m(0).st.Outgoing) != 1 {
		t.Fatal("the owed restart did not start on the new reconnect token")
	}
}

// RK6: an owed restart is given up 60 days after the follow without a
// token: the vault holds no reconnect token for the peer's mailbox, and
// the connection becomes stale ("The reconnect bound").
func TestRK6RestartGivenUp(t *testing.T) {
	f := rkPair(t)
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	f.rkSend(false, false)
	f.deliver(1, 0, kOther)
	f.advance(RelayRestartWait - time.Minute)
	f.tick(0)
	if f.p(0).State != PeerActive || f.p(0).RelayRestart == nil {
		t.Fatal("given up before 60 days")
	}
	f.advance(time.Minute)
	f.tick(0)
	if f.p(0).State != PeerStale || f.p(0).RelayRestart != nil {
		t.Fatal("not stale 60 days after the follow without a token")
	}
}

// Rule T at a confirmation: a carried token that is not the current
// mailbox's (here one minted by the earlier key's) is not adopted.
func TestRuleTCarriedTokenOfEarlierMailboxNotAdopted(t *testing.T) {
	d, td, p, k := rkConnU(t)
	k1 := rkKey(0x61)
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, rkBody(t, d, k1, rkLink(t, k, k1))))
	held := p.Standing
	c := HeldToken{Token: rkTok(t, k, rkOwn(d), testNow().Add(29*24*time.Hour), "c-old"), Exp: testNow().Add(29 * 24 * time.Hour)}
	d.m.adoptHeld(p, TokStanding, &p.Standing, c)
	if p.Standing != held {
		t.Fatal("a carried token of the earlier mailbox was adopted")
	}
}

// Gap 1 (rule U: "A handshake does not pin P's relay key"): side 0's rekey
// began while side 1's key on record was K; after the follow, side 1's
// hs.resp re-deposited with the new key (S2) completes it.
func TestRuleUHandshakeRespNotPinned(t *testing.T) {
	f := rkPair(t)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	resp := f.takeKind(1, 0, kHSResp)
	if len(resp) != 1 {
		t.Fatal("setup: no hs.resp")
	}
	f.rkFollow()
	msg := f.pos(resp[0], rkAfter)
	msg.Sender = relayauth.EncodeKey(rkPub(rkKey(0xa7)))
	f.process(0, msg)
	if f.p(0).Pending == nil {
		t.Fatal("the hs.resp from the current key was refused for the key the handshake began with")
	}
}

// Gap 1, the responder's side: side 1's rekey answered by side 0 while K
// was on record; its hs.fin re-deposited with the new key establishes it.
func TestRuleUHandshakeFinNotPinned(t *testing.T) {
	f := rkPair(t)
	f.rekey(1)
	f.deliver(1, 0, kHSInit)
	f.deliver(0, 1, kHSResp)
	fin := f.takeKind(1, 0, kHSFin)
	if len(fin) != 1 || len(f.m(0).st.Awaiting) != 1 {
		t.Fatal("setup: no hs.fin")
	}
	f.rkFollow()
	msg := f.pos(fin[0], rkAfter)
	msg.Sender = relayauth.EncodeKey(rkPub(rkKey(0xa7)))
	f.process(0, msg)
	if len(f.m(0).st.Awaiting) != 0 {
		t.Fatal("the hs.fin from the current key was refused for the key the hs.init came from")
	}
}

// Gap 2 (rule T): a reconnect hs.init from an earlier key before its
// cut-off carries tokens minted by that key's mailbox (its from.relay);
// they pass rule T for depositing the answer there.
func TestRuleTReconnectInitFromEarlierKeyBeforeCutoff(t *testing.T) {
	f := rkPair(t)
	f.do(1, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	init := f.rkTake(kHSInit, rkBefore)
	f.rkFollow()
	mb := f.m(1).st.Relay.Mailbox
	before := f.d[0].depositsTo(mb)
	f.process(0, init)
	if f.audited(0, "reconnect_bad_token") || len(f.m(0).st.Awaiting) != 1 {
		t.Fatal("the reconnect from the earlier key before its cut-off was not answered")
	}
	f.m(0).mu.Lock()
	_ = f.m(0).flushThenDrain(t.Context())
	f.m(0).mu.Unlock()
	if f.d[0].depositsTo(mb) != before+1 {
		t.Fatal("the answer was not deposited to the mailbox the hs.init's from.relay names")
	}
}

// Gap 1 does not open the sender check: an hs.resp from a key that is not
// the peer's is still refused, and the handshake kept.
func TestRuleUHandshakeForeignSenderRefused(t *testing.T) {
	f := rkPair(t)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	resp := f.takeKind(1, 0, kHSResp)
	if len(resp) != 1 {
		t.Fatal("setup: no hs.resp")
	}
	f.rkFollow()
	msg := f.pos(resp[0], rkAfter)
	msg.Sender = relayauth.EncodeKey(rkPub(rkKey(0x3c)))
	f.process(0, msg)
	if f.p(0).Pending != nil || len(f.m(0).st.Outgoing) != 1 {
		t.Fatal("an hs.resp from a foreign key completed the handshake, or ended it")
	}
}

// rkMintK1 mints a reconnect token of K1's mailbox for side 0.
func (f *r29Fx) rkMintK1(jti string) string {
	f.t.Helper()
	k1 := rkKey(rkK1)
	tok, err := relayauth.MintToken(k1, relayauth.Claims{Iss: relayauth.MailboxID(rkPub(k1)), Sub: relayauth.EncodeKey(f.pk(0)),
		Aud: "https://relay.example.org", Iat: f.clk.Add(-time.Minute), Exp: f.clk.Add(300 * 24 * time.Hour), Jti: jti})
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

// RK6: an owed restart ends when another epoch is established after the
// follow ("dropped once P's reconnect is established"): a reconnect token
// arriving later starts nothing, and the working connection is not made
// stale 60 days on.
func TestRK6OwedRestartEndsAtAnEstablishment(t *testing.T) {
	f := rkPair(t)
	f.rekey(1)
	f.deliver(1, 0, kHSInit) // side 0 answers side 1's rekey (pinned to K)
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	f.deliver(0, 1, kHSResp)
	f.lose(0, 1, kHSInit)
	fin := f.takeKind(1, 0, kHSFin)
	if len(fin) != 1 {
		t.Fatal("setup: no hs.fin")
	}
	f.rkSend(false, false)
	f.deliver(1, 0, kOther)
	if !f.followedK1() || f.p(0).RelayRestart == nil {
		t.Fatal("setup: no owed restart")
	}
	before := append([]byte(nil), f.cur(0)...)
	msg := fin[0]
	msg.MsgID = "take-zz-fin"
	msg.Sender = relayauth.EncodeKey(rkPub(rkKey(rkK1))) // S2: deposited again with the new key
	f.process(0, msg)
	if bytes.Equal(f.cur(0), before) || f.p(0).RelayRestart != nil {
		t.Fatal("the epoch was not established, or the owed restart outlived it")
	}
	f.do(1, func(m *Manager, p *Peer) {
		m.sendTo(p, tokenIssuedType, peerwire.TokenIssuedBody(TokReconnect, f.rkMintK1("p-rc3")), f.clk)
	})
	f.deliver(1, 0, kOther)
	if len(f.m(0).st.Outgoing) != 0 {
		t.Fatal("a reconnect was started from the epoch before the established one")
	}
	f.advance(RelayRestartWait + time.Minute)
	f.tick(0)
	if f.p(0).State != PeerActive {
		t.Fatal("a working connection was made stale")
	}
}

// RK6: an owed restart whose epoch is no longer the current one (and the
// current one is not demoted) is dropped when a token arrives, not
// started.
func TestRK6OwedRestartDroppedForANewerEpoch(t *testing.T) {
	d, _, p, _ := rkConnU(t)
	p.Reconnect = HeldToken{Token: rkTok(t, rkKey(0x75), rkOwn(d), time.Now().Add(100*24*time.Hour), "rc"), Exp: time.Now().Add(100 * 24 * time.Hour)}
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	if !d.m.heldReconnectForCurrent(p, time.Now()) {
		t.Fatal("setup: no reconnect token for the current mailbox")
	}
	p.RelayRestart = &RelayRestart{Named: []byte("an-older-epoch-id-000000000000"), Since: time.Now()}
	d.m.rk6Tick(p, time.Now())
	if p.RelayRestart != nil || len(d.m.st.Outgoing) != 0 {
		t.Fatal("a restart naming an epoch no longer current was started or kept")
	}
}

// RK6's give-up after 60 days is "The reconnect bound"'s "no reconnect
// token", which is not judged while carried tokens wait (§6.3.1).
func TestRK6GiveUpNotWhileCarriedTokensWait(t *testing.T) {
	d, _, p, _ := rkConnU(t)
	now := time.Now()
	p.Epochs[len(p.Epochs)-1].Mine = false
	p.Confirmed = nil
	p.Carried = []CarriedTokens{{Epoch: append([]byte(nil), p.LastEpochID...), Standing: HeldToken{Token: "v4.public.VEVTVA", Exp: now.Add(20 * 24 * time.Hour)}, Since: now}}
	p.RelayRestart = &RelayRestart{Named: append([]byte(nil), p.LastEpochID...), Since: now.Add(-RelayRestartWait - time.Hour)}
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	if !d.m.carriedWait(p, now) {
		t.Fatal("setup: carried tokens do not wait")
	}
	d.m.rk6Tick(p, now)
	if p.State == PeerStale {
		t.Fatal("made stale while carried tokens wait")
	}
}

// Rule U revokes the reconnect tokens of handshakes not yet activated that
// name the passed key: an answer's (its epoch then established keeps it
// revoked, recorded once) and a pending epoch's.
func TestRuleURevokesInFlightReconnectTokens(t *testing.T) {
	t.Run("an answer's, kept revoked at its activation", func(t *testing.T) {
		f := rkPair(t)
		f.do(1, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
		f.deliver(1, 0, kHSInit)
		var jti string
		for _, aw := range f.m(0).st.Awaiting {
			for _, it := range aw.Issued {
				if it.Kind == TokReconnect {
					jti = it.JTI
				}
			}
		}
		if jti == "" {
			t.Fatal("setup: no answer with a reconnect token")
		}
		f.rkSend(true, false)
		f.deliver(1, 0, kOther)
		if !f.followedK1() || !rkDenied(f.m(0), jti) {
			t.Fatal("the answer's reconnect token naming the passed key was not revoked")
		}
		f.deliver(0, 1, kHSResp)
		fin := f.takeKind(1, 0, kHSFin)
		if len(fin) != 1 {
			t.Fatal("setup: no hs.fin")
		}
		msg := fin[0]
		msg.MsgID = "take-zz-fin"
		msg.Sender = relayauth.EncodeKey(rkPub(rkKey(rkK1)))
		f.process(0, msg)
		if len(f.m(0).st.Awaiting) != 0 {
			t.Fatal("setup: the reconnect was not established")
		}
		n := 0
		for _, it := range f.m(0).st.Issued {
			if it.JTI == jti {
				n++
				if !it.Denied {
					t.Fatal("the revoked token was recorded again as live at the activation")
				}
			}
		}
		if n != 1 {
			t.Fatalf("the token is recorded %d times", n)
		}
	})
	t.Run("a pending epoch's", func(t *testing.T) {
		f := rkPair(t)
		f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
		f.deliver(0, 1, kHSInit)
		f.deliver(1, 0, kHSResp)
		pe := f.p(0).Pending
		if pe == nil {
			t.Fatal("setup: no pending epoch")
		}
		var jti string
		for _, it := range pe.Issued {
			if it.Kind == TokReconnect {
				jti = it.JTI
			}
		}
		f.rkSend(true, false)
		f.deliver(1, 0, kOther)
		if !f.followedK1() || jti == "" || !rkDenied(f.m(0), jti) {
			t.Fatal("the pending epoch's reconnect token naming the passed key was not revoked")
		}
	})
}

func rkDenied(m *Manager, jti string) bool {
	for _, it := range m.st.Issued {
		if it.JTI == jti && it.Denied {
			return true
		}
	}
	return false
}
