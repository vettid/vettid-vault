package vault

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// VAULT-MESSAGING 0.90.4 §3.4.2 RK8 (links in reconnects), with §3.4.1
// rule U's checks, rule C's two lists, Table A, RK5, RK6 and RK12, in a
// real pair. Side 1 (P) does not rotate (that side is not built): the test
// plays its rotating side, building the reconnect message with side 1's
// keys, depositing it with K (side 1's relay key) and announcing K1.

const rkK2, rkK3 = 0xb2, 0xb3

// rk8Tok mints a token of side 1's mailbox for key k (sub: side 0's relay
// key), as the announced key's mailbox would.
func (f *r29Fx) rk8Tok(k ed25519.PrivateKey, jti string, life time.Duration) string {
	f.t.Helper()
	tok, err := relayauth.MintToken(k, relayauth.Claims{Iss: relayauth.MailboxID(rkPub(k)), Sub: relayauth.EncodeKey(f.pk(0)),
		Aud: "https://relay.example.org", Iat: f.clk.Add(-time.Minute), Exp: f.clk.Add(life), Jti: jti})
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

// rk8Init builds side 1's reconnect hs.init to side 0 announcing ann with
// links, its tokens minted by tokKey's mailbox, as a Message deposited
// with side 1's relay key K at msg_id id.
func (f *r29Fx) rk8Init(ann ed25519.PrivateKey, links []*handshake.RelayLink, tokKey ed25519.PrivateKey, id string) (*handshake.Initiator, Message) {
	f.t.Helper()
	return f.rk8InitWith(ann, links, tokKey, id, nil)
}

// rk8InitWith is rk8Init with mod applied to the initiator's config.
func (f *r29Fx) rk8InitWith(ann ed25519.PrivateKey, links []*handshake.RelayLink, tokKey ed25519.PrivateKey, id string, mod func(*handshake.InitiatorConfig)) (*handshake.Initiator, Message) {
	f.t.Helper()
	m1, p1 := f.m(1), f.p(1)
	cfg := handshake.InitiatorConfig{
		Purpose: handshake.PurposeReconnect, Ctx: handshake.EpochCtx(epochIDOf(p1.LastEpochID)),
		Identity: m1.keys.ik, StaticKEM: m1.keys.kem.Public(), Relay: rkAddr(ann), RelayLinks: links,
		ResponderIK: p1.IK, KnownResponderChain: parseRotations(p1.Chain), ResponderEK: f.m(0).keys.kem.Public(),
		ResponderRelayKey: f.pk(0), PinnedSuite: p1.Suite, Policy: policyFor(KindConnection), Now: f.clk,
		Token: f.rk8Tok(tokKey, "rk8-st-"+id, 25*24*time.Hour), ReconnectToken: f.rk8Tok(tokKey, "rk8-rc-"+id, 300*24*time.Hour),
	}
	if mod != nil {
		mod(&cfg)
	}
	ini, err := handshake.NewInitiator(cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	return ini, f.rk8Msg(ini.Envelope(), id)
}

// rk8Msg is payload deposited by side 1 with K at msg_id id.
func (f *r29Fx) rk8Msg(payload []byte, id string) Message {
	return Message{MsgID: id, DepositedAt: f.clk.UTC().Format(time.RFC3339Nano), Sender: relayauth.EncodeKey(f.pk(1)), Payload: payload}
}

// rk8Taken takes side 0's deposits to mailbox mb.
func (f *r29Fx) rk8Taken(mb string) []stubDeposit {
	f.t.Helper()
	m0 := f.m(0)
	m0.mu.Lock()
	_ = m0.flushThenDrain(context.Background())
	m0.mu.Unlock()
	r := f.d[0].relay
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []stubDeposit
	kept := r.deposits[:0]
	for _, d := range r.deposits {
		if d.mailbox == mb {
			out = append(out, d)
			continue
		}
		kept = append(kept, d)
	}
	r.deposits = kept
	return out
}

// rk8Fin completes ini with side 0's hs.resp found in mailbox mb, and
// returns the hs.fin as a Message deposited with K at msg_id id.
func (f *r29Fx) rk8Fin(ini *handshake.Initiator, mb, id string) Message {
	f.t.Helper()
	for _, d := range f.rk8Taken(mb) {
		res, err := ini.HandleResp(d.payload, f.pk(0), f.clk)
		if err != nil {
			continue
		}
		res.Epoch.Destroy()
		msg := f.rk8Msg(res.Fin, id)
		for _, aw := range f.m(0).st.Awaiting {
			for _, it := range aw.Issued {
				if it.Kind == TokStanding {
					msg.JTI = it.JTI // deposited on the answer's standing token
				}
			}
		}
		return msg
	}
	f.t.Fatal("setup: no hs.resp in the announced mailbox")
	return Message{}
}

func (f *r29Fx) relayIs(k ed25519.PrivateKey) bool {
	return suite.EqualPublic(f.p(0).Relay.PK, rkPub(k))
}

func (f *r29Fx) refusedFor(ref string) int { return f.activityCount(0, "drop.peer_key", ref) }

// RK8, hs.init: side 1's reconnect, deposited with K and announcing K1 with
// the link K -> K1, is answered at K1's mailbox; at its verified hs.fin
// side 0 follows to K1 in the write that establishes the reconnect, with
// the hs.fin as the cut-off (counting as before it), and sends
// relay.token.issued for K1. The hs.resp's tokens name K (RK2).
func TestRK8ReconnectInitFollowedAtHsFin(t *testing.T) {
	f := rkPair(t)
	k, k1 := f.m(1).keys.relay, rkKey(rkK1)
	ini, init := f.rk8Init(k1, []*handshake.RelayLink{rkLink(t, k, k1)}, k1, "rk-1000")
	f.process(0, init)
	if f.relayIs(k1) {
		t.Fatal("followed at the hs.init")
	}
	mb1 := relayauth.MailboxID(rkPub(k1))
	cur := append([]byte(nil), f.cur(0)...)
	fin := f.rk8Fin(ini, mb1, "rk-1100")
	f.holdDeposits(0, true)
	f.note(0, "queued on the held token")
	f.holdDeposits(0, false)
	f.process(0, fin)
	if !f.relayIs(k1) || len(f.p(0).EarlierRelays) != 1 {
		t.Fatal("not followed at the hs.fin")
	}
	if f.p(0).Reconnect.Token != "" || f.p(0).Standing.Token != "" || f.p(0).RelayAwaitRC.IsZero() {
		t.Fatal("a token held for the passed mailbox still counts")
	}
	moved := false
	for _, e := range f.m(0).st.Outbox {
		moved = moved || !e.Done && e.Type == "test.note" && e.Mailbox == mb1
	}
	if !moved {
		t.Fatal("the queued deposit did not move to the new mailbox")
	}
	e := f.p(0).EarlierRelays[0]
	f.m(0).msgID = "rk-1101"
	if e.CutMsg != "rk-1100" || f.m(0).relayStateOf(f.p(0), f.pk(1)) != relayEarlierAfter {
		t.Fatalf("cut-off %q", e.CutMsg)
	}
	if string(f.cur(0)) == string(cur) {
		t.Fatal("the reconnect was not established")
	}
	f.m(0).msgID = "rk-1100"
	if f.m(0).relayStateOf(f.p(0), f.pk(1)) != relayEarlierBefore {
		t.Fatal("the hs.fin itself does not count as before its cut-off")
	}
	if f.refusedFor("relay_unlinked")+f.refusedFor("superseded_relay")+f.refusedFor("token_unusable") != 0 {
		t.Fatal("refused")
	}
	issued := false
	for _, e := range f.m(0).st.Outbox {
		issued = issued || !e.Done && e.Type == tokenIssuedType && e.Mailbox == mb1
	}
	if !issued {
		t.Fatal("no relay.token.issued for K1 queued")
	}
	subK := relayauth.EncodeKey(f.pk(1))
	for _, it := range f.m(0).st.Issued {
		if it.Sub == subK && it.Kind == TokReconnect && !it.Denied {
			t.Fatal("a reconnect token issued to the passed key was not revoked")
		}
	}
}

// RK6 at an hs.init's RK8 follow: the vault's own open reconnect is dropped
// once the peer's is established, and is not restarted.
func TestRK6NotRestartedAtReconnectFollow(t *testing.T) {
	f := rkPair(t)
	k, k1 := f.m(1).keys.relay, rkKey(rkK1)
	ini, init := f.rk8Init(k1, []*handshake.RelayLink{rkLink(t, k, k1)}, k1, "rk-1000")
	f.process(0, init)
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	if len(f.m(0).st.Awaiting) != 1 {
		t.Skip("the crossing rule dropped the answer")
	}
	f.process(0, f.rk8Fin(ini, relayauth.MailboxID(rkPub(k1)), "rk-1100"))
	if !f.relayIs(k1) {
		t.Fatal("setup: not followed")
	}
	if len(f.m(0).st.Outgoing) != 0 || f.p(0).RelayRestart != nil {
		t.Fatal("the own reconnect was restarted or kept")
	}
}

// RK8: the hs.resp went to the announced key's mailbox on the hs.init's
// token, and the tokens in it name the key on record, K (RK2).
func TestRK8AnswerAtAnnouncedMailboxTokensNameRecord(t *testing.T) {
	f := rkPair(t)
	k, k1 := f.m(1).keys.relay, rkKey(rkK1)
	_, init := f.rk8Init(k1, []*handshake.RelayLink{rkLink(t, k, k1)}, k1, "rk-1000")
	f.process(0, init)
	deps := f.rk8Taken(relayauth.MailboxID(rkPub(k1)))
	if len(deps) != 1 {
		t.Fatalf("%d deposits at the announced mailbox", len(deps))
	}
	subK := relayauth.EncodeKey(f.pk(1))
	for _, aw := range f.m(0).st.Awaiting {
		for _, it := range aw.Issued {
			if it.Sub != subK {
				t.Fatal("a token in the answer names another key than the one on record")
			}
		}
	}
}

// RK8: without the switch, the same hs.init is from a sender that is not
// its from.relay.pk: refused as before, nothing answered or followed.
func TestRK8NeedsTheSwitch(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	k, k1 := f.m(1).keys.relay, rkKey(rkK1)
	_, init := f.rk8Init(k1, []*handshake.RelayLink{rkLink(t, k, k1)}, k1, "rk-1000")
	f.process(0, init)
	if !f.audited(0, "hs_init_sender_mismatch") || len(f.m(0).st.Awaiting) != 0 {
		t.Fatal("answered without the switch")
	}
}

// Rule U, "Precedence": in a reconnect, a first old that is not the
// deposit key is a parse-time refusal (relay_unlinked): no link is kept.
func TestRK8InitEndMismatchRelayUnlinked(t *testing.T) {
	f := rkPair(t)
	k1, k2 := rkKey(rkK1), rkKey(rkK2)
	_, init := f.rk8Init(k2, []*handshake.RelayLink{rkLink(t, k1, k2)}, k2, "rk-1000")
	f.process(0, init)
	if f.refusedFor("relay_unlinked") != 1 || len(f.p(0).RelaySeen) != 0 || len(f.m(0).st.Awaiting) != 0 {
		t.Fatal("not refused relay_unlinked with no link kept")
	}
}

// Rule C's second list: a chain refused only for a bad signature keeps its
// earlier valid links as seen, and is refused relay_unlinked.
func TestRK8InitBadSignatureKeepsEarlierLinks(t *testing.T) {
	f := rkPair(t)
	k, k1, k2 := f.m(1).keys.relay, rkKey(rkK1), rkKey(rkK2)
	bad := rkLink(t, k1, k2)
	bad.SigNew = append([]byte(nil), bad.SigNew...)
	bad.SigNew[0] ^= 1
	_, init := f.rk8Init(k2, []*handshake.RelayLink{rkLink(t, k, k1), bad}, k2, "rk-1000")
	f.process(0, init)
	if f.refusedFor("relay_unlinked") != 1 || len(f.p(0).RelaySeen) != 1 || len(f.m(0).st.Awaiting) != 0 {
		t.Fatalf("refused %d, seen %d", f.refusedFor("relay_unlinked"), len(f.p(0).RelaySeen))
	}
}

// Rule C between vaults: a reconnect whose relay link is a second
// successor of a key already seen suspends the connection (a relay fork).
func TestRK8InitSecondSuccessorSuspends(t *testing.T) {
	f := rkPair(t)
	k, k1, k3 := f.m(1).keys.relay, rkKey(rkK1), rkKey(rkK3)
	_, a := f.rk8Init(k1, []*handshake.RelayLink{rkLink(t, k, k1)}, k1, "rk-1000")
	f.process(0, a)
	_, b := f.rk8Init(k3, []*handshake.RelayLink{rkLink(t, k, k3)}, k3, "rk-1001")
	f.process(0, b)
	if f.p(0).RelayFork == nil || !f.p(0).suspended() || len(f.m(0).st.Awaiting) != 0 {
		t.Fatal("a second successor in a reconnect did not suspend, or was answered")
	}
}

// RK12: while the record is suspended, a reconnect's relay links that
// pass rule C are kept as seen; the reconnect is refused.
func TestRK12ReconnectLinksSeenWhileSuspended(t *testing.T) {
	f := rkPair(t)
	f.p(0).Fork = &ForkSuspension{At: f.clk}
	k, k1 := f.m(1).keys.relay, rkKey(rkK1)
	_, init := f.rk8Init(k1, []*handshake.RelayLink{rkLink(t, k, k1)}, k1, "rk-1000")
	f.process(0, init)
	if len(f.p(0).RelaySeen) != 1 || len(f.m(0).st.Awaiting) != 0 {
		t.Fatal("the links were not kept as seen, or the reconnect was answered")
	}
}

// Rule T (RK8): the hs.init's tokens must be minted by the announced key's
// mailbox; otherwise refused token_unusable, nothing answered.
func TestRK8InitTokensOfAnotherMailboxRefused(t *testing.T) {
	f := rkPair(t)
	k, k1 := f.m(1).keys.relay, rkKey(rkK1)
	_, init := f.rk8Init(k1, []*handshake.RelayLink{rkLink(t, k, k1)}, k, "rk-1000")
	f.process(0, init)
	if f.refusedFor("token_unusable") != 1 || len(f.m(0).st.Awaiting) != 0 {
		t.Fatal("not refused token_unusable")
	}
}

// RK8 "If Q has already followed P away from the announced key":
// superseded_relay.
func TestRK8InitAnnouncedKeyAlreadyPassedRefused(t *testing.T) {
	f := rkPair(t)
	k, k1, k2 := f.m(1).keys.relay, rkKey(rkK1), rkKey(rkK2)
	f.do(0, func(m *Manager, p *Peer) {
		m.relayAt, m.msgID = f.clk, "rk-0500"
		if err := m.followRelayLinks(p, []*handshake.RelayLink{rkLink(t, k, k1), rkLink(t, k1, k2)}, rkAddr(k2)); err != nil {
			t.Fatal(err)
		}
	})
	_, init := f.rk8Init(k1, []*handshake.RelayLink{rkLink(t, k, k1)}, k1, "rk-1000")
	f.process(0, init)
	if f.refusedFor("superseded_relay") != 1 || len(f.m(0).st.Awaiting) != 0 {
		t.Fatal("not refused superseded_relay")
	}
}

// RK8 "When Q accepts it": from an earlier key after its cut-off, with links
// already followed (the announced key current), the reconnect is answered
// and the follow changes nothing; without links it stays refused.
func TestRK8InitFromEarlierKeyAfterCutoffAccepted(t *testing.T) {
	f := rkPair(t)
	k, k1 := f.m(1).keys.relay, rkKey(rkK1)
	f.do(0, func(m *Manager, p *Peer) {
		m.relayAt, m.msgID = f.clk, "rk-0500"
		if err := m.followRelayLinks(p, []*handshake.RelayLink{rkLink(t, k, k1)}, rkAddr(k1)); err != nil {
			t.Fatal(err)
		}
	})
	ini, init := f.rk8Init(k1, []*handshake.RelayLink{rkLink(t, k, k1)}, k1, "rk-1000")
	f.process(0, init)
	if f.refusedFor("superseded_relay") != 0 || len(f.m(0).st.Awaiting) != 1 {
		t.Fatal("not answered")
	}
	cur := append([]byte(nil), f.cur(0)...)
	f.process(0, f.rk8Fin(ini, relayauth.MailboxID(rkPub(k1)), "rk-1100"))
	if string(f.cur(0)) == string(cur) || !f.relayIs(k1) || len(f.p(0).EarlierRelays) != 1 {
		t.Fatal("not established, or the follow changed something")
	}
}

// RK8 at the hs.fin: rule U's checks run again before anything is applied.
// The vault followed P elsewhere since the hs.init: relay_rollback, the
// reconnect does not complete and nothing is followed.
func TestRK8RollbackAtHsFinNothingFollowed(t *testing.T) {
	f := rkPair(t)
	k, k1, k3 := f.m(1).keys.relay, rkKey(rkK1), rkKey(rkK3)
	ini, init := f.rk8Init(k1, []*handshake.RelayLink{rkLink(t, k, k1)}, k1, "rk-1000")
	f.process(0, init)
	fin := f.rk8Fin(ini, relayauth.MailboxID(rkPub(k1)), "rk-1100")
	f.do(0, func(m *Manager, p *Peer) {
		m.relayAt, m.msgID = f.clk, "rk-1050"
		if err := m.followRelayLinks(p, []*handshake.RelayLink{rkLink(t, k, k3)}, rkAddr(k3)); err != nil {
			t.Fatal(err)
		}
	})
	cur := append([]byte(nil), f.cur(0)...)
	f.process(0, fin)
	if string(f.cur(0)) != string(cur) || !f.relayIs(k3) {
		t.Fatal("established, or followed")
	}
	if f.refusedFor("superseded_relay")+f.refusedFor("relay_rollback") == 0 {
		t.Fatal("not refused")
	}
}

// rk8Resp answers side 0's reconnect hs.init (taken from side 1's mailbox)
// as side 1, announcing ann with links, its tokens minted by tokKey's
// mailbox, deposited with K at msg_id id.
func (f *r29Fx) rk8Resp(ann ed25519.PrivateKey, links []*handshake.RelayLink, tokKey ed25519.PrivateKey, id string) Message {
	f.t.Helper()
	return f.rk8RespWith(ann, links, tokKey, id, nil)
}

// rk8RespWith is rk8Resp with mod applied to the responder's config.
func (f *r29Fx) rk8RespWith(ann ed25519.PrivateKey, links []*handshake.RelayLink, tokKey ed25519.PrivateKey, id string, mod func(*handshake.ResponderConfig)) Message {
	f.t.Helper()
	m1 := f.m(1)
	for _, d := range f.rk8Taken(m1.st.Relay.Mailbox) {
		pi, err := handshake.OpenInit(d.payload, m1.lookupKEM, f.clk)
		if err != nil {
			continue
		}
		body := pi.Init()
		a := rkAddr(ann)
		p1 := f.p(1)
		rcfg := handshake.ResponderConfig{
			Identity: m1.keys.ik, Policy: policyFor(KindConnection), PinnedSuite: p1.Suite,
			CollectSender: f.pk(0), RecordRelayKey: f.pk(0), KnownInitiatorIK: p1.IK, KnownInitiatorChain: parseRotations(p1.Chain),
			ExpectedCtx: body.Ctx, Now: f.clk, Relay: &a, RelayLinks: links,
			Token: f.rk8Tok(tokKey, "rk8r-st-"+id, 25*24*time.Hour), ReconnectToken: f.rk8Tok(tokKey, "rk8r-rc-"+id, 300*24*time.Hour),
		}
		if mod != nil {
			mod(&rcfg)
		}
		_, env, err := pi.Respond(rcfg)
		if err != nil {
			f.t.Fatal(err)
		}
		msg := f.rk8Msg(env, id)
		for _, og := range f.m(0).st.Outgoing {
			for _, it := range og.Issued {
				if it.Kind == TokStanding {
					msg.JTI = it.JTI // deposited on the hs.init's standing token
				}
			}
		}
		return msg
	}
	f.t.Fatal("setup: no reconnect hs.init")
	return Message{}
}

// RK8, hs.resp: the answer to side 0's reconnect, deposited with K and
// announcing K1, is followed in the write that processes it after sig_R
// verifies, with the hs.resp as the cut-off; the hs.fin goes to K1's
// mailbox on the answer's token; the epoch is pending; the reconnect that
// made the follow is not restarted (RK6).
func TestRK8ReconnectRespFollowed(t *testing.T) {
	f := rkPair(t)
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	k, k1 := f.m(1).keys.relay, rkKey(rkK1)
	resp := f.rk8Resp(k1, []*handshake.RelayLink{rkLink(t, k, k1)}, k1, "rk-2000")
	f.holdDeposits(0, true)
	f.note(0, "queued on the held token")
	f.holdDeposits(0, false)
	f.process(0, resp)
	if !f.relayIs(k1) || f.p(0).EarlierRelays[0].CutMsg != "rk-2000" || f.p(0).Pending == nil {
		t.Fatal("not followed at the hs.resp, or no pending epoch")
	}
	moved := false
	for _, e := range f.m(0).st.Outbox {
		moved = moved || !e.Done && e.Type == "test.note" && e.Mailbox == relayauth.MailboxID(rkPub(k1))
	}
	if !moved {
		t.Fatal("the queued deposit did not move to the new mailbox")
	}
	if len(f.m(0).st.Outgoing) != 0 || f.p(0).RelayRestart != nil {
		t.Fatal("the reconnect that made the follow was restarted")
	}
	deps := f.rk8Taken(relayauth.MailboxID(rkPub(k1)))
	fin := false
	for _, d := range deps {
		fin = fin || d.token != "" && d.token == f.p(0).Pending.Carried.Standing.Token
	}
	if !fin {
		t.Fatal("the hs.fin did not go to the announced mailbox on the answer's token")
	}
}

// RK8, hs.resp: a token not minted by the announced key's mailbox is
// refused token_unusable; nothing is followed and the reconnect does not
// complete.
func TestRK8RespTokenOfAnotherMailboxRefused(t *testing.T) {
	f := rkPair(t)
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	k, k1 := f.m(1).keys.relay, rkKey(rkK1)
	resp := f.rk8Resp(k1, []*handshake.RelayLink{rkLink(t, k, k1)}, k, "rk-2000")
	f.process(0, resp)
	if f.relayIs(k1) || f.p(0).Pending != nil || f.refusedFor("token_unusable") != 1 {
		t.Fatal("followed, or not refused token_unusable")
	}
}

// RK8, hs.resp: a first old that is not the deposit key: relay_unlinked,
// no link kept, nothing followed.
func TestRK8RespEndMismatchRelayUnlinked(t *testing.T) {
	f := rkPair(t)
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	k1, k2 := rkKey(rkK1), rkKey(rkK2)
	resp := f.rk8Resp(k2, []*handshake.RelayLink{rkLink(t, k1, k2)}, k2, "rk-2000")
	f.process(0, resp)
	if f.relayIs(k2) || f.p(0).Pending != nil || f.refusedFor("relay_unlinked") != 1 || len(f.p(0).RelaySeen) != 0 {
		t.Fatal("not refused relay_unlinked with no link kept")
	}
}

// Rule U, "When it is refused": a parse-time refusal of a reconnect's chain
// (here its first old not the deposit key) checks and keeps no link,
// identity links included.
func TestRK8InitEndMismatchKeepsNoIdentityLink(t *testing.T) {
	f := rkPair(t)
	f.rotate(1)
	f.lose(1, 0, kRotate)
	f.lose(1, 0, kHSInit)
	k1, k2 := rkKey(rkK1), rkKey(rkK2)
	_, init := f.rk8InitWith(k2, []*handshake.RelayLink{rkLink(t, k1, k2)}, k2, "rk-1000", func(c *handshake.InitiatorConfig) {
		c.Rotations = f.m(1).ownRotationsSince(0)
	})
	n := len(f.p(0).Seen)
	f.process(0, init)
	if f.refusedFor("relay_unlinked") != 1 || len(f.p(0).Seen) != n {
		t.Fatal("an identity link of a chain refused at parse time was kept as seen")
	}
}

// The same for an hs.resp to the vault's reconnect.
func TestRK8RespEndMismatchKeepsNoIdentityLink(t *testing.T) {
	f := rkPair(t)
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	f.rotate(1)
	f.lose(1, 0, kRotate)
	f.lose(1, 0, kHSInit)
	k1, k2 := rkKey(rkK1), rkKey(rkK2)
	resp := f.rk8RespWith(k2, []*handshake.RelayLink{rkLink(t, k1, k2)}, k2, "rk-2000", func(c *handshake.ResponderConfig) {
		c.Rotations = f.m(1).ownRotationsSince(0)
	})
	n := len(f.p(0).Seen)
	f.process(0, resp)
	if f.refusedFor("relay_unlinked") != 1 || len(f.p(0).Seen) != n {
		t.Fatal("an identity link of a chain refused at parse time was kept as seen")
	}
}

// RK8 at the hs.fin: rule T on the hs.init's token is checked again; one
// expired since is refused token_unusable, nothing followed.
func TestRK8TokenExpiredAtHsFinRefused(t *testing.T) {
	f := rkPair(t)
	k, k1 := f.m(1).keys.relay, rkKey(rkK1)
	ini, init := f.rk8InitWith(k1, []*handshake.RelayLink{rkLink(t, k, k1)}, k1, "rk-1000", func(c *handshake.InitiatorConfig) {
		c.Token = f.rk8Tok(k1, "short", 10*time.Minute)
	})
	f.process(0, init)
	fin := f.rk8Fin(ini, relayauth.MailboxID(rkPub(k1)), "rk-1100")
	f.advance(time.Hour)
	fin.DepositedAt = f.clk.UTC().Format(time.RFC3339Nano)
	f.process(0, fin)
	if f.relayIs(k1) || f.refusedFor("token_unusable") != 1 {
		t.Fatal("followed, or not refused token_unusable")
	}
}

// RK8 "before or after that key's cut-off": an answer to the vault's
// reconnect from an earlier key after its cut-off, whose links connect it
// to the announced (current) key, completes the handshake.
func TestRK8RespFromEarlierKeyAfterCutoffAccepted(t *testing.T) {
	f := rkPair(t)
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	k, k1 := f.m(1).keys.relay, rkKey(rkK1)
	f.do(0, func(m *Manager, p *Peer) {
		m.relayAt, m.msgID = f.clk, "rk-0500"
		if err := m.followRelayLinks(p, []*handshake.RelayLink{rkLink(t, k, k1)}, rkAddr(k1)); err != nil {
			t.Fatal(err)
		}
	})
	resp := f.rk8Resp(k1, []*handshake.RelayLink{rkLink(t, k, k1)}, k1, "rk-2000")
	f.process(0, resp)
	if f.p(0).Pending == nil || f.refusedFor("superseded_relay") != 0 {
		t.Fatal("the answer from the earlier key with links was not accepted")
	}
}

// Rule U's cap (MaxEarlierRelays) in RK8's checks.
func TestRK8ChecksCap(t *testing.T) {
	f := newFixture(t)
	m := f.m
	m.opt.RelayKeyRotation = true
	k0, k1 := rkKey(0x61), rkKey(0x62)
	p := rkPeer(m, "c8", k0)
	for i := 0; i < MaxEarlierRelays; i++ {
		p.EarlierRelays = append(p.EarlierRelays, EarlierRelay{Relay: PeerRelay{PK: rkPub(rkKey(byte(0x80 + i)))}})
	}
	if _, reason := m.rk8Checks(p, []*handshake.RelayLink{rkLink(t, k0, k1)}, rkPub(k1)); reason != "unexpected" {
		t.Fatalf("reason %q, want the cap's", reason)
	}
	p.EarlierRelays = p.EarlierRelays[:MaxEarlierRelays-1]
	// A later new key the vault keeps (rule U: relay_rollback).
	k5 := rkKey(0x65)
	kept := rkKey(0x80)
	if _, reason := m.rk8Checks(p, []*handshake.RelayLink{rkLink(t, k0, kept), rkLink(t, kept, k5)}, rkPub(k5)); reason != "relay_rollback" {
		t.Fatalf("reason %q, want relay_rollback", reason)
	}
	if _, reason := m.rk8Checks(p, []*handshake.RelayLink{rkLink(t, k0, k1)}, rkPub(k1)); reason != "" {
		t.Fatalf("reason %q under the cap", reason)
	}
}
