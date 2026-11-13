package vault

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Review findings on rule U, rule T and RK6 (VAULT-MESSAGING 0.90.4
// §3.4.1, §3.4.2 RK6 and RK10, §7.1).

// An old copy holding P's earlier relay key K and its ik sends, from K
// after K's cut-off, an update carrying an identity link ik -> copy_ik and
// a relay chain that fails only its end check (or one signature). The
// update is refused and none of its links is followed (RK10): Q's ik for
// P stays, and P's next handshake is accepted. Control: the same link in
// an identity.rotate from K after the cut-off is refused superseded_relay.
func TestReviewACopyAfterCutoffRotatesIK(t *testing.T) {
	for _, c := range []string{"end mismatch", "a bad signature", "control: identity.rotate"} {
		t.Run(c, func(t *testing.T) {
			f := rkPair(t)
			ik := append([]byte(nil), f.p(0).IK...)
			f.rkFollow()
			copyIK := rkKey(0x5c)
			r, err := handshake.NewRotation(f.m(1).keys.ik, copyIK, f.m(1).keys.kem.Public())
			if err != nil {
				t.Fatal(err)
			}
			k, kx, ky := f.m(1).keys.relay, rkKey(0x5d), rkKey(0x5e)
			typ, body, kind := peerwire.TypeRelayAddressUpdate, "", kOther
			switch c {
			case "end mismatch":
				u := &peerwire.AddressUpdate{Relay: rkAddr(ky), Token: "v4.public.VEVTVA", Links: []*handshake.RelayLink{rkLink(t, k, kx)},
					Rotations: []*handshake.Rotation{r}}
				b, _ := u.Marshal()
				body = string(b)
			case "a bad signature":
				u := &peerwire.AddressUpdate{Relay: rkAddr(kx), Token: "v4.public.VEVTVA", Links: []*handshake.RelayLink{badLink(rkLink(t, k, kx))},
					Rotations: []*handshake.Rotation{r}}
				b, _ := u.Marshal()
				body = string(b)
			default:
				typ, kind = "identity.rotate", kRotate
				body = `{"rotation":` + string(r.Marshal()) + `,"rotations":[` + string(r.Marshal()) + `]}`
			}
			f.do(1, func(m *Manager, p *Peer) { m.sendTo(p, typ, []byte(body), f.clk) })
			f.process(0, f.rkTake(kind, rkAfter))
			want, n := "relay_unlinked", 0
			if typ == "identity.rotate" {
				want = "superseded_relay"
			}
			n = f.activityCount(0, "drop.peer_key", want)
			if n != 1 || !suite.EqualPublic(f.p(0).IK, ik) {
				t.Fatalf("refused %s %d times; ik moved: %v", want, n, !suite.EqualPublic(f.p(0).IK, ik))
			}
			// P's next handshake (a rekey from K before the cut-off) is
			// answered: its ik is still the current one.
			f.rekey(1)
			f.process(0, f.rkTake(kHSInit, rkBefore))
			if len(f.m(0).st.Awaiting) != 1 || f.activityCount(0, "drop.peer_key", "ancestor_ik") != 0 {
				t.Fatal("P's next handshake was not answered")
			}
		})
	}
}

// After a follow with no reconnect token for the new mailbox, the one held
// for the passed mailbox counts as not held: a reconnect the vault then
// wants (a demotion's, a start) neither uses it nor makes the connection
// stale, but waits (RK6) and starts once a token of the new mailbox
// arrives, on that token.
func TestReviewAReconnectAfterFollowUsesOldMailboxToken(t *testing.T) {
	for _, how := range []string{"start", "demotion"} {
		t.Run(how, func(t *testing.T) {
			f := rkPair(t)
			oldRC := f.p(0).Reconnect.Token
			f.rkSend(false, false)
			f.deliver(1, 0, kOther)
			if !f.followedK1() || f.p(0).Reconnect.Token != "" {
				t.Fatal("setup: not followed, or the passed mailbox's reconnect token still held")
			}
			f.do(0, func(m *Manager, p *Peer) {
				if how == "start" {
					m.startReconnect(p, f.clk)
				} else {
					m.reconnectNaming(p, p.LastEpochID, "demoted", f.clk)
				}
			})
			if f.p(0).State != PeerActive || len(f.m(0).st.Outgoing) != 0 || f.p(0).RelayRestart == nil {
				t.Fatal("the reconnect did not wait for a token of the new mailbox")
			}
			for _, dep := range f.d[0].relay.deposits {
				if dep.token == oldRC {
					t.Fatal("the passed mailbox's reconnect token was used")
				}
			}
			tok := f.rkMintK1("p-rc4")
			f.do(1, func(m *Manager, p *Peer) {
				m.sendTo(p, tokenIssuedType, peerwire.TokenIssuedBody(TokReconnect, tok), f.clk)
			})
			f.deliver(1, 0, kOther)
			if len(f.m(0).st.Outgoing) != 1 || f.p(0).Reconnect.Token != tok {
				t.Fatal("the owed reconnect did not start on the new mailbox's token")
			}
		})
	}
}

// §7.1's holder's checks apply to rule U's tokens: a standing token over 30
// days is refused (token_unusable); a reconnect token over 365 days is
// ignored (not held), and the update followed.
func TestRuleTUpdateHolderChecks(t *testing.T) {
	t.Run("standing over 30 days", func(t *testing.T) {
		d, td, p, k := rkConnU(t)
		k1 := rkKey(0x61)
		u := rkBody(t, d, k1, rkLink(t, k, k1))
		u.Token = rkTok(t, k1, rkOwn(d), testNow().Add(31*24*time.Hour), "st31")
		sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, u))
		if refs := peerKeyRefs(d); len(refs) != 1 || refs[0] != "token_unusable" || !suite.EqualPublic(p.Relay.PK, rkPub(k)) {
			t.Fatalf("a 31-day standing token: %v", refs)
		}
	})
	t.Run("reconnect far in the future", func(t *testing.T) {
		d, td, p, k := rkConnU(t)
		k1 := rkKey(0x61)
		u := rkBody(t, d, k1, rkLink(t, k, k1))
		u.ReconnectToken = rkTok(t, k1, rkOwn(d), testNow().Add(400*24*time.Hour), "rc400")
		sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, u))
		if refs := peerKeyRefs(d); len(refs) != 0 || !suite.EqualPublic(p.Relay.PK, rkPub(k1)) {
			t.Fatalf("not followed: %v", refs)
		}
		if p.Reconnect.Token == u.ReconnectToken {
			t.Fatal("a reconnect token over 365 days was held")
		}
	})
}

// The cap is inclusive: a follow reaching exactly MaxEarlierRelays earlier
// keys is made.
func TestRuleUEarlierRelaysCapExact(t *testing.T) {
	d, td, p, k := rkConnU(t)
	for i := 0; i < MaxEarlierRelays-1; i++ {
		x := rkKey(byte(0x90 + i))
		p.EarlierRelays = append(p.EarlierRelays, EarlierRelay{Relay: PeerRelay{PK: rkPub(x), Mailbox: relayauth.MailboxID(rkPub(x))}})
		d.m.st.Issued = append(d.m.st.Issued, IssuedToken{JTI: fmt.Sprint("cap", i), Kind: TokStanding, Sub: relayauth.EncodeKey(rkPub(x)),
			PeerID: p.ID, Exp: time.Now().Add(24 * time.Hour)})
	}
	k1 := rkKey(0x61)
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, rkBody(t, d, k1, rkLink(t, k, k1))))
	if refs := peerKeyRefs(d); len(refs) != 0 || len(p.EarlierRelays) != MaxEarlierRelays {
		t.Fatalf("a follow to exactly the cap was refused: %v (%d)", refs, len(p.EarlierRelays))
	}
}

// RK6: an owed restart whose epoch is not the current one is kept while
// the current epoch is demoted, and starts as the reconnect after a
// demotion (naming the newest epoch not demoted).
func TestRK6OwedRestartWithADemotedEpoch(t *testing.T) {
	d, _, p, _ := rkConnU(t)
	older := []byte("an-older-epoch-id-00000000000000")[:len(p.LastEpochID)]
	p.Epochs = append([]EpochMeta{{ID: older, Signer: append([]byte(nil), p.IK...)}}, p.Epochs...)
	p.Epochs[len(p.Epochs)-1].Demoted = true
	p.Reconnect = HeldToken{Token: rkTok(t, rkKey(0x75), rkOwn(d), time.Now().Add(100*24*time.Hour), "rc"), Exp: time.Now().Add(100 * 24 * time.Hour)}
	p.RelayRestart = &RelayRestart{Named: older, Since: time.Now()}
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	if !d.m.currentDemoted(p) {
		t.Fatal("setup: the current epoch is not demoted")
	}
	d.m.rk6Tick(p, time.Now())
	if p.RelayRestart != nil || len(d.m.st.Outgoing) != 1 {
		t.Fatal("the owed restart with a demoted current epoch was not started")
	}
	for _, og := range d.m.st.Outgoing {
		if string(og.Named) != string(older) {
			t.Fatal("the reconnect does not name the newest epoch not demoted")
		}
	}
}

// RK6: an owed restart of a connection no longer active (here stale) is
// dropped and starts nothing.
func TestRK6OwedRestartNotWhenInactive(t *testing.T) {
	d, _, p, _ := rkConnU(t)
	p.Reconnect = HeldToken{Token: rkTok(t, rkKey(0x75), rkOwn(d), time.Now().Add(100*24*time.Hour), "rc"), Exp: time.Now().Add(100 * 24 * time.Hour)}
	p.RelayRestart = &RelayRestart{Named: append([]byte(nil), p.LastEpochID...), Since: time.Now()}
	p.State = PeerStale
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	d.m.rk6Tick(p, time.Now())
	if p.RelayRestart != nil || len(d.m.st.Outgoing) != 0 {
		t.Fatal("an owed restart of a stale connection was started or kept")
	}
}

// Rule U's duplicate from a device is answered too, at most once an hour.
func TestRuleUDeviceDuplicate(t *testing.T) {
	d := newDevFixture(t)
	sinkOf(d)
	d.m.opt.RelayKeyRotation = true
	td := d.addDevice(t, "dsk", KindDesktop, 0x84)
	k, k1 := rkKey(0x85), rkKey(0x61)
	l := rkLink(t, k, k1)
	d.sendAs(td, peerwire.TypeRelayAddressUpdate, rkMarshal(t, rkBody(t, d, k1, l)))
	if !suite.EqualPublic(td.peer.Relay.PK, rkPub(k1)) {
		t.Fatal("setup: not followed")
	}
	d.inbox(td)
	for i, want := range []int{1, 0} {
		raw, err := td.ep.Seal(&envelope.Inner{ID: fmt.Sprintf("01JB2Z6V9K3M4N5P6Q7R8S9T%02d", i), Type: peerwire.TypeRelayAddressUpdate, TS: testNow(),
			Body: []byte(rkMarshal(t, rkBody(t, d, k1, l))), Features: []string{handshake.CapConfirm}})
		if err != nil {
			t.Fatal(err)
		}
		msg := Message{MsgID: fmt.Sprintf("dup-z%d", i), Sender: relayauth.EncodeKey(rkPub(k)), Payload: raw}
		_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg})
		if got := tokensIssued(t, d, td); len(got) != want {
			t.Fatalf("duplicate %d: %d answers, want %d", i, len(got), want)
		}
	}
}

// Rule T's deferral: a relay.token.issued from the mailbox an update has
// not yet made known is deferred, and adopted when it comes again after
// the follow.
func TestRuleTDeferredTokenAdoptedAfterTheFollow(t *testing.T) {
	d, td, p, k := rkConnU(t)
	k1 := rkKey(0x61)
	tok := rkTok(t, k1, rkOwn(d), testNow().Add(25*24*time.Hour), "late")
	id, _ := envelope.NewULID(time.Now())
	raw, err := td.ep.Seal(&envelope.Inner{ID: id, Type: tokenIssuedType, TS: time.Now(), Body: peerwire.TokenIssuedBody(TokStanding, tok)})
	if err != nil {
		t.Fatal(err)
	}
	msg := Message{MsgID: "g999", Sender: relayauth.EncodeKey(rkPub(k)), JTI: "standing-per", Payload: raw}
	c := &fakeCollector{}
	_ = d.m.ProcessBatch(context.Background(), c, []Message{msg})
	if len(c.acked) != 0 {
		t.Fatal("setup: not deferred")
	}
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, rkBody(t, d, k1, rkLink(t, k, k1))))
	if !suite.EqualPublic(p.Relay.PK, rkPub(k1)) {
		t.Fatal("setup: not followed")
	}
	c = &fakeCollector{} // the relay delivers it again (after the cut-off: tokens only, by rule T)
	_ = d.m.ProcessBatch(context.Background(), c, []Message{msg})
	if len(c.acked) != 1 || p.Standing.Token != tok {
		t.Fatal("the deferred token was not adopted after the follow")
	}
}

// Rule U's duplicate keeps RK5's "links first": from a key Q has not
// passed the cut-off of (here the earlier key, deposited before it), its
// identity links are followed though no relay link is.
func TestRuleUDuplicateFollowsIdentityLinks(t *testing.T) {
	d, td, p, k := rkConnU(t)
	k1 := rkKey(0x61)
	l := rkLink(t, k, k1)
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, rkBody(t, d, k1, l)))
	if !suite.EqualPublic(p.Relay.PK, rkPub(k1)) {
		t.Fatal("setup: not followed")
	}
	u := rkBody(t, d, k1, l)
	u.Rotations = []*handshake.Rotation{rkIKLink(t, d, 0x20)}
	id, _ := envelope.NewULID(time.Now())
	raw, err := td.ep.Seal(&envelope.Inner{ID: id, Type: peerwire.TypeRelayAddressUpdate, TS: time.Now(), Body: []byte(rkMarshal(t, u))})
	if err != nil {
		t.Fatal(err)
	}
	msg := Message{MsgID: "g000", Sender: relayauth.EncodeKey(rkPub(k)), JTI: "standing-per", Payload: raw} // before the cut-off
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg})
	if refs := peerKeyRefs(d); len(refs) != 0 || !suite.EqualPublic(p.IK, rkPub(rkKey(0x20))) {
		t.Fatalf("a duplicate update's identity links were not followed: %v", refs)
	}
}

// The same rule on the follow path: an update from an earlier key after
// its cut-off whose relay chain leads on past the current key, carrying an
// identity link not followed, is refused superseded_relay as an
// identity.rotate of that row would be: nothing followed.
func TestRuleUEarlierAfterFollowRefusesNewIdentityLinks(t *testing.T) {
	d, td, p, k := rkConnU(t)
	k1, k3 := rkKey(0x61), rkKey(0x63)
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, rkBody(t, d, k1, rkLink(t, k, k1))))
	u := rkBody(t, d, k3, rkLink(t, k, k1), rkLink(t, k1, k3))
	u.Rotations = []*handshake.Rotation{rkIKLink(t, d, 0x20)}
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, u))
	if refs := peerKeyRefs(d); len(refs) != 1 || refs[0] != "superseded_relay" || !suite.EqualPublic(p.Relay.PK, rkPub(k1)) ||
		!suite.EqualPublic(p.IK, rkPub(rkKey(0x74))) {
		t.Fatalf("refused %v; followed relay %v; ik moved %v", refs, suite.EqualPublic(p.Relay.PK, rkPub(k3)), !suite.EqualPublic(p.IK, rkPub(rkKey(0x74))))
	}
}

// An earlier key is kept by a revoked reconnect token until the relay has
// taken the revocation (its revoke still in the outbox).
func TestRelayEarlierKeyKeptUntilTheRevokeIsTaken(t *testing.T) {
	f := newFixture(t)
	m := f.m
	m.opt.RelayKeyRotation = true
	k0, k1 := rkKey(0x41), rkKey(0x42)
	p := rkPeer(m, "c1", k0)
	now := testNow()
	m.st.Issued = append(m.st.Issued, IssuedToken{JTI: "t0", Kind: TokReconnect, Sub: relayauth.EncodeKey(rkPub(k0)), PeerID: p.ID,
		Exp: now.Add(300 * 24 * time.Hour), Denied: true})
	m.st.Outbox = append(m.st.Outbox, &OutboxEntry{ID: "rv", Op: OpRevoke, Kind: "jti", Value: "t0", Created: now})
	m.relayAt, m.msgID = now, "m-1"
	if err := m.followRelayLinks(p, []*handshake.RelayLink{rkLink(t, k0, k1)}, rkAddr(k1)); err != nil {
		t.Fatal(err)
	}
	m.pruneEarlierRelays(now.Add(time.Hour))
	if p.EarlierRelays == nil {
		t.Fatal("dropped while its revoke was not taken")
	}
	m.st.Outbox[len(m.st.Outbox)-1].Done = true
	m.pruneEarlierRelays(now.Add(time.Hour))
	if p.EarlierRelays != nil {
		t.Fatal("kept after its revoke was taken")
	}
}

// Rule T (Gap 2): a reconnect hs.init from an earlier key before its
// cut-off is answered only at the address the vault keeps for that key:
// one whose from.relay differs from it is refused (reconnect_bad_token).
func TestRuleTReconnectInitAnswerAddressIsTheKeptOne(t *testing.T) {
	f := rkPair(t)
	// Side 1 announces another relay URL in its hs.init (from.relay.url),
	// its tokens minted for it (aud): the vault keeps the one on record.
	const elsewhere = "https://elsewhere.example.org"
	f.d[1].relay.mu.Lock()
	f.d[1].relay.base = elsewhere
	f.d[1].relay.mu.Unlock()
	f.m(1).st.Relay.URL = elsewhere
	f.do(1, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	init := f.rkTake(kHSInit, rkBefore)
	f.rkFollow()
	if f.p(0).EarlierRelays[0].Relay.URL == elsewhere {
		t.Fatal("setup: the kept address is the announced one")
	}
	f.process(0, init)
	if !f.audited(0, "reconnect_bad_token") || len(f.m(0).st.Awaiting) != 0 {
		t.Fatal("answered at an address other than the one kept for the earlier key")
	}
}

// The owed wait after a follow covers the reconnect after a demotion that
// the demotion's tick wants, and lasts RelayRestartWait from the follow:
// after that "no reconnect token" makes the connection stale as before.
func TestReviewAOwedWaitAtTheDemotionTickAndItsBound(t *testing.T) {
	d, td, p, k := rkConnU(t)
	k1 := rkKey(0x61)
	u := rkBody(t, d, k1, rkLink(t, k, k1))
	u.ReconnectToken = ""
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, u))
	if !suite.EqualPublic(p.Relay.PK, rkPub(k1)) || p.RelayAwaitRC.IsZero() {
		t.Fatal("setup: not followed, or no wait")
	}
	p.Epochs[len(p.Epochs)-1].Demoted = true
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	now := time.Now()
	d.m.tickDemoted(p, now)
	if p.State != PeerActive || p.RelayRestart == nil {
		t.Fatal("the demotion's tick made the connection stale during the owed wait")
	}
	p.RelayRestart = nil
	later := now.Add(RelayRestartWait + time.Minute)
	d.m.tickDemoted(p, later)
	if p.State != PeerStale {
		t.Fatal("still waiting past the owed wait's bound")
	}
}
