package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// VAULT-MESSAGING 0.90.4 §3.4.1 Table A, the rows "Earlier, before its
// cut-off" and "Earlier, after its cut-off", in a real pair: side 0 (Q)
// follows side 1 (P) from P's relay key K, the one P still deposits with,
// to a key K' (as rule U or RK8 will, through followRelayLinks), with the
// cut-off at msg_id rkCut. P's messages are then delivered with a msg_id
// before or after it.

const (
	rkCut    = "rk-0500"
	rkBefore = "rk-0400"
	rkAfter  = "rk-0600"
)

// rkFollow makes side 0 follow side 1 from its relay key to a new one,
// with the cut-off at rkCut, and turns relay-key rotation on at side 0.
func (f *r29Fx) rkFollow() {
	f.t.Helper()
	m0 := f.m(0)
	m0.opt.RelayKeyRotation = true
	k, k2 := f.m(1).keys.relay, rkKey(0xa7)
	f.do(0, func(m *Manager, p *Peer) {
		m.relayAt, m.msgID = f.clk, rkCut
		if err := m.followRelayLinks(p, []*handshake.RelayLink{rkLink(f.t, k, k2)}, rkAddr(k2)); err != nil {
			f.t.Fatal(err)
		}
	})
	if !suite.EqualPublic(f.p(0).Relay.PK, rkPub(k2)) || f.m(0).relayStateOf(f.p(0), f.pk(1)) == relayForeign {
		f.t.Fatal("setup: side 0 did not follow")
	}
}

// rkTake takes side 1's single deposit of kind k to side 0, with msg_id id.
func (f *r29Fx) rkTake(k int, id string) Message {
	f.t.Helper()
	ms := f.takeKind(1, 0, k)
	if len(ms) != 1 {
		f.t.Fatalf("setup: %d deposits of kind %d", len(ms), k)
	}
	return f.pos(ms[0], id)
}

func (f *r29Fx) superseded() int { return f.activityCount(0, "drop.peer_key", "superseded_relay") }

// activityCount counts side s's activity records of kind with ref.
func (f *r29Fx) activityCount(s int, kind, ref string) int {
	n := 0
	for _, a := range f.sink[s].got {
		if a.Kind == kind && a.Ref == ref {
			n++
		}
	}
	return n
}

// Session messages: accepted before the cut-off, refused
// (superseded_relay) after it.
func TestTableAEarlierSessionMessage(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.note(1, "early")
	early := f.rkTake(kNote, rkBefore)
	f.note(1, "late")
	late := f.rkTake(kNote, rkAfter)
	f.rkFollow()
	n := len(f.got[0])
	f.process(0, late)
	if len(f.got[0]) != n || f.superseded() != 1 {
		t.Fatalf("a message after the cut-off was not refused superseded_relay (handled %d, refused %d)", len(f.got[0])-n, f.superseded())
	}
	f.process(0, early)
	if len(f.got[0]) != n+1 || f.superseded() != 1 {
		t.Fatal("a message before the cut-off was not accepted")
	}
}

// relay.token.issued after the cut-off: "tokens by rule T only", not
// refused for its sender.
func TestTableAEarlierTokenIssuedAfterCutoff(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.do(1, func(m *Manager, p *Peer) { m.issueTo(p, TokStanding, f.clk) })
	msg := f.rkTake(kOther, rkAfter)
	f.rkFollow()
	f.process(0, msg)
	if f.superseded() != 0 {
		t.Fatal("relay.token.issued after the cut-off refused superseded_relay")
	}
}

// identity.rotate after the cut-off: every link already followed is
// ignored (R29-K9 still judged); a link not yet followed is refused
// (superseded_relay) and not followed.
func TestTableAEarlierIdentityRotateAfterCutoff(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rotate(1)
	first := f.rkTake(kRotate, rkBefore)
	f.rkFollow()
	f.process(0, first)
	if f.superseded() != 0 || !suite.EqualPublic(f.p(0).IK, []byte(f.m(1).keys.ik.Public().(ed25519.PublicKey))) {
		t.Fatal("setup: the identity.rotate before the cut-off was not followed")
	}
	again := first
	again.MsgID = rkAfter // the same message again, after the cut-off: every link followed
	f.p(0).PeerFeatures = nil
	f.process(0, again)
	if f.superseded() != 0 {
		t.Fatal("an identity.rotate whose links are all followed was refused after the cut-off")
	}
	if f.p(0).PeerFeatures != nil {
		t.Fatal("the ignored identity.rotate counted its features")
	}
	ik := append([]byte(nil), f.p(0).IK...)
	f.rotate(1)
	next := f.rkTake(kRotate, "rk-0700")
	f.process(0, next)
	if f.superseded() != 1 || !bytes.Equal(f.p(0).IK, ik) {
		t.Fatal("a new link after the cut-off was followed, or not refused superseded_relay")
	}
}

// A rekey hs.init (session mode): Table B before the cut-off (answered),
// refused after it (superseded_relay), unanswered.
func TestTableAEarlierRekeyInit(t *testing.T) {
	for _, c := range []struct {
		id       string
		answered bool
	}{{rkBefore, true}, {rkAfter, false}} {
		t.Run(c.id, func(t *testing.T) {
			f := newR29Fx(t)
			f.longTokens()
			f.rekey(1)
			msg := f.rkTake(kHSInit, c.id)
			f.rkFollow()
			n := f.answerCount(0)
			f.process(0, msg)
			if got := f.answerCount(0) > n; got != c.answered || (f.superseded() == 1) == c.answered {
				t.Fatalf("answered %v, refused superseded_relay %d", got, f.superseded())
			}
		})
	}
}

// A reconnect hs.init (sealed): after the cut-off refused
// (superseded_relay); before it, not refused for its sender (§3.4.2 RK8's
// links, which let a reconnect pass after the cut-off, are not built yet).
func TestTableAEarlierReconnectInit(t *testing.T) {
	for _, c := range []struct {
		id      string
		refused bool
	}{{rkBefore, false}, {rkAfter, true}} {
		t.Run(c.id, func(t *testing.T) {
			f := newR29Fx(t)
			f.longTokens()
			f.do(1, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
			msg := f.rkTake(kHSInit, c.id)
			f.rkFollow()
			refusedBefore := f.auditCount(0, "reconnect_refused")
			f.process(0, msg)
			if (f.superseded() == 1) != c.refused || f.auditCount(0, "reconnect_refused") != refusedBefore {
				t.Fatalf("superseded_relay %d, reconnect_refused %d", f.superseded(), f.auditCount(0, "reconnect_refused")-refusedBefore)
			}
		})
	}
}

// An hs.resp to side 0's rekey begun before the follow: after the cut-off
// refused (superseded_relay) with the handshake kept (S2); the same answer
// deposited before the cut-off then completes it.
func TestTableAEarlierHsRespKeepsTheHandshake(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	if f.deliver(0, 1, kHSInit) != 1 {
		t.Fatal("setup: no rekey hs.init")
	}
	resp := f.rkTake(kHSResp, rkAfter)
	f.rkFollow()
	og := len(f.m(0).st.Outgoing)
	f.process(0, resp)
	if f.superseded() != 1 || len(f.m(0).st.Outgoing) != og || og == 0 {
		t.Fatalf("not refused with the handshake kept: refused %d, outgoing %d -> %d", f.superseded(), og, len(f.m(0).st.Outgoing))
	}
	resp.MsgID = rkBefore
	f.process(0, resp)
	if len(f.m(0).st.Outgoing) != og-1 || f.p(0).Pending == nil {
		t.Fatal("the kept handshake did not complete on the answer before the cut-off (its epoch pending)")
	}
}

// An hs.fin to side 0's answer: after the cut-off refused
// (superseded_relay) with the answer kept; before it, established.
func TestTableAEarlierHsFinKeepsTheAnswer(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(1)
	if f.deliver(1, 0, kHSInit) != 1 || f.deliver(0, 1, kHSResp) != 1 {
		t.Fatal("setup: no rekey")
	}
	fin := f.rkTake(kHSFin, rkAfter)
	f.rkFollow()
	n := f.answerCount(0)
	f.process(0, fin)
	if f.superseded() != 1 || f.answerCount(0) != n || n == 0 {
		t.Fatalf("not refused with the answer kept: refused %d, answers %d -> %d", f.superseded(), n, f.answerCount(0))
	}
	cur := append([]byte(nil), f.cur(0)...)
	fin.MsgID = rkBefore
	f.process(0, fin)
	if f.answerCount(0) != n-1 || bytes.Equal(f.cur(0), cur) {
		t.Fatal("the kept answer was not established by the hs.fin before the cut-off")
	}
}

// The switch off: the same deposits from P's key, after side 0 recorded the
// follow, are from a foreign key: never judged by their cut-off.
func TestTableANeedsTheSwitch(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.note(1, "early")
	early := f.rkTake(kNote, rkBefore)
	f.rkFollow()
	f.m(0).opt.RelayKeyRotation = false
	n := len(f.got[0])
	f.process(0, early)
	if len(f.got[0]) != n || f.superseded() != 0 || !f.audited(0, "unknown_kid") {
		t.Fatal("an earlier key's message was judged with the switch off")
	}
}

// acceptFrom step 3 before Table A: an hs.resp refused after the cut-off
// (its handshake kept) still has its identity links checked by rule C and
// kept as seen. P rotated its ik (its identity.rotate lost), so its answer
// to Q's rekey carries the link (S8).
func TestTableAEarlierHsRespLinksCheckedFirst(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rotate(1)
	if f.lose(1, 0, kRotate) != 1 {
		t.Fatal("setup: no identity.rotate to lose")
	}
	// P's own rekey after its rotation, if it began one, would cross Q's
	// (§6.5, the lower th1 wins): P abandons it, so that it answers Q's.
	f.do(1, func(m *Manager, p *Peer) { m.abandonHandshakes(p, true, false, f.clk) })
	f.lose(1, 0, kAny)
	f.rekey(0)
	if f.deliver(0, 1, kHSInit) != 1 {
		t.Fatal("setup: no rekey hs.init")
	}
	resp := f.rkTake(kHSResp, rkAfter)
	f.rkFollow()
	seen := len(f.p(0).Seen)
	f.process(0, resp)
	if f.superseded() != 1 || len(f.m(0).st.Outgoing) == 0 {
		t.Fatal("setup: the answer was not refused with its handshake kept")
	}
	if len(f.p(0).Seen) != seen+1 {
		t.Fatalf("the refused answer's identity link was not kept as seen (%d -> %d)", seen, len(f.p(0).Seen))
	}
}

// relay.token.issued after the cut-off gives its tokens only (Table A,
// "Earlier, after its cut-off": "tokens by rule T only"): its token goes
// through heldToken and is kept, and nothing else of the message counts:
// an old copy's features change no PeerFeatures, it does not mark the
// device heard, and it raises no device.update_needed.
func TestTableAEarlierTokenIssuedTokensOnly(t *testing.T) {
	d, p, tok := rkTokenAfterCutoff(t, false)
	if p.Standing.Token != tok {
		t.Fatal("the token was not taken")
	}
	if p.Heard || p.PeerFeatures != nil || len(d.audits("device.update_needed")) != 0 || len(d.audits("drop.peer_key")) != 0 {
		t.Fatalf("more than its tokens counted: heard %v, features %v, update_needed %d", p.Heard, p.PeerFeatures, len(d.audits("device.update_needed")))
	}
}

// The epoch's checks come first: a relay.token.issued after the cut-off
// under an epoch rule E destroyed (with an earlier ts) is refused
// (superseded_epoch), and its token is not taken.
func TestTableAEarlierTokenIssuedEpochChecksFirst(t *testing.T) {
	d, p, tok := rkTokenAfterCutoff(t, true)
	if p.Standing.Token == tok {
		t.Fatal("a token was taken from a message under a destroyed epoch")
	}
	if got := d.audits("drop.peer_key"); len(got) != 1 || got[0].Ref != "superseded_epoch" {
		t.Fatalf("not refused by the epoch's checks: %+v", got)
	}
}

// rkTokenAfterCutoff: the vault follows its device from its relay key to a
// new one; the device then sends, from the earlier key after the cut-off,
// relay.token.issued with a valid token of the new key's mailbox and
// features lacking hs_confirm. With destroyed, the device's epoch is first
// marked destroyed by rule E, after the message's ts.
func rkTokenAfterCutoff(t *testing.T, destroyed bool) (*devFixture, *Peer, string) {
	t.Helper()
	d := newDevFixture(t)
	sinkOf(d)
	d.m.opt.RelayKeyRotation = true
	p, k, k2 := d.devPeer, d.devKey, rkKey(0xb1)
	now := time.Now()
	d.m.mu.Lock()
	d.m.relayAt, d.m.msgID = now, "m-cut"
	if err := d.m.followRelayLinks(p, []*handshake.RelayLink{rkLink(t, k, k2)}, rkAddr(k2)); err != nil {
		t.Fatal(err)
	}
	p.Heard, p.PeerFeatures = false, nil
	if destroyed {
		id := d.ep.ID()
		p.Epochs = append(p.Epochs, EpochMeta{ID: id[:], Destroyed: true, DestroyTS: now.Add(time.Hour)})
	}
	d.m.mu.Unlock()
	tok, err := relayauth.MintToken(k2, relayauth.Claims{Iss: p.Relay.Mailbox, Sub: relayauth.EncodeKey(d.m.keys.relay.Public().(ed25519.PublicKey)),
		Aud: p.Relay.URL, Iat: now.Add(-time.Minute), Exp: now.Add(25 * 24 * time.Hour), Jti: "after-cut"})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := envelope.NewULID(now)
	raw, err := d.ep.Seal(&envelope.Inner{ID: id, Type: tokenIssuedType, TS: now, Body: []byte(`{"token":"` + tok + `"}`),
		Features: []string{"x_copy_feature"}})
	if err != nil {
		t.Fatal(err)
	}
	msg := Message{MsgID: "m-zzz", Sender: relayauth.EncodeKey(rkPub(k)), Payload: raw}
	if err := d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg}); err != nil {
		t.Fatal(err)
	}
	return d, p, tok
}
