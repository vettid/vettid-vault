package vault

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// The trust model's F-scenarios (f_scenarios_test.go at 641ef63) that need
// no old copy, against the real code.

// lostConfirm: side 0 rekeys; side 1 activates E1 and its hs.confirm is
// lost; side 0 holds E1 pending. It returns E0 and E1.
func (f *r29Fx) lostConfirm() (e0, e1 []byte) {
	f.t.Helper()
	e0 = append([]byte(nil), f.cur(0)...)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	f.deliver(0, 1, kHSFin)
	if f.lose(1, 0, kConfirm) != 1 {
		f.t.Fatal("setup: no hs.confirm")
	}
	e1 = append([]byte(nil), f.cur(1)...)
	if f.p(0).Pending == nil || !bytes.Equal(f.p(0).Pending.ID, e1) {
		f.t.Fatal("setup: not pending")
	}
	return e0, e1
}

// F5 (handler): the responder's next message after a lost hs.confirm is
// its daily rekey from E1, an hs.init under the pending epoch: confirmed
// first, it is under the current epoch and answered.
func TestR29F5ConfirmBeforeHandler(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	_, e1 := f.lostConfirm()
	f.advance(25 * time.Hour)
	f.tick(1) // side 1's rekey interval: hs.init under E1
	if f.deliver(1, 0, kHSInit) != 1 {
		t.Fatal("setup: no rekey from E1")
	}
	if f.p(0).Pending != nil || !bytes.Equal(f.cur(0), e1) || f.answerCount(0) != 1 {
		f.dump()
		t.Fatal("the rekey under the pending epoch did not confirm it before it was handled")
	}
	f.settle()
	f.talks()
}

// F5 (link): side 1 activated E1 (hs.confirm lost) and rotates: its
// identity.rotate travels under E1. Confirmed first, H5 finds no pending
// epoch to abandon.
func TestR29F5LinkUnderPendingConfirms(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	_, e1 := f.lostConfirm()
	f.rotate(1)
	f.deliver(1, 0, kRotate)
	if f.p(0).Pending != nil || !bytes.Equal(f.cur(0), e1) {
		f.dump()
		t.Fatal("the link under the pending epoch did not confirm it")
	}
	if f.audited(0, "pending_abandoned_h5") || f.audited(0, "pending_abandoned_link") {
		t.Fatal("H5 abandoned an epoch the peer activated")
	}
	f.settle()
	f.advance(time.Hour)
	f.tick(0)
	f.tick(1)
	f.settle()
	f.talks()
}

// F5 (dedupe): a message under the pending epoch whose inner id was seen
// under the old one still confirms (the confirmation precedes dedupe).
func TestR29F5DuplicateUnderPendingConfirms(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e0 := append([]byte(nil), f.cur(0)...)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	id := f.m(1).newID(f.clk)
	in := &envelope.Inner{ID: id, Type: "test.note", TS: f.clk, Body: json.RawMessage(`{"n":"dup"}`)}
	f.do(1, func(m *Manager, p *Peer) { // under E0 (side 1 has not activated E1)
		raw, err := m.sealFor(p, m.sessions[p.ID].Current(), in)
		if err != nil {
			t.Fatal(err)
		}
		m.queueDeposit(&OutboxEntry{PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Payload: raw}, f.clk)
	})
	f.deliver(1, 0, kNote)
	f.deliver(0, 1, kHSFin)
	f.lose(1, 0, kConfirm)
	f.do(1, func(m *Manager, p *Peer) { // the same inner id under E1
		c := *in
		c.Seq = 0
		raw, err := m.sealFor(p, m.sessions[p.ID].Current(), &c)
		if err != nil {
			t.Fatal(err)
		}
		m.queueDeposit(&OutboxEntry{PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Payload: raw}, f.clk)
	})
	f.deliver(1, 0, kAny)
	if f.p(0).Pending != nil || bytes.Equal(f.cur(0), e0) {
		t.Fatal("a duplicate under the pending epoch did not confirm it")
	}
	if len(f.got[0]) != 1 {
		t.Fatal("the duplicate was handled twice")
	}
}

// F9 (token_expired): side 0 holds E1 pending (its hs.fin lost); its next
// deposit is refused token_expired: it abandons the pending epoch and
// reconnects naming its current epoch E0.
func TestR29F9TokenExpiredReconnects(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e0 := append([]byte(nil), f.cur(0)...)
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	f.lose(0, 1, kHSFin)
	mb := f.m(1).st.Relay.Mailbox
	r := f.d[0].relay
	r.mu.Lock()
	r.failMailbox = map[string]error{mb: &relayclient.Error{Status: 401, Code: CodeTokenExpired}}
	r.mu.Unlock()
	// 0.86.6 S5: while the token's exp has not passed on the vault's own
	// clock, token_expired keeps the pending epoch.
	f.note(0, "x")
	if f.p(0).Pending == nil {
		t.Fatal("token_expired abandoned the pending epoch before its exp on our clock")
	}
	f.do(0, func(_ *Manager, p *Peer) { p.Standing.Exp = f.clk.Add(-time.Second) })
	f.advance(2 * time.Hour) // the deposit's retry: refused again, now past exp
	f.do(0, func(*Manager, *Peer) {})
	r.mu.Lock()
	r.failMailbox = nil
	r.mu.Unlock()
	var named []byte
	for _, og := range f.m(0).st.Outgoing {
		if og.Purpose != handshake.PurposeReconnect {
			continue
		}
		if b, err := handshake.ParseInit(og.Init.Body); err == nil && b.Ctx == handshake.EpochCtx(epochIDOf(e0)) {
			named = append([]byte(nil), e0...)
		}
	}
	if f.p(0).Pending != nil || named == nil {
		f.dump()
		t.Fatal("token_expired: no reconnect naming the current epoch, or still pending")
	}
	f.settle()
	if !f.sameEpoch() {
		t.Fatal("did not converge")
	}
}

// F10: the responder's hs.confirm gets no definite answer (429) while the
// initiator keeps sending under E0 in three batches: exactly one hs.confirm
// stays in the responder's outbox.
func TestR29F10ConfirmResendCapped(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.rekey(0)
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	mb := f.m(0).st.Relay.Mailbox
	r := f.d[1].relay
	r.mu.Lock()
	r.failMailbox = map[string]error{mb: &relayclient.Error{Status: 429, Code: "rate_limited"}}
	r.mu.Unlock()
	f.deliver(0, 1, kHSFin)
	for i := 0; i < 3; i++ {
		f.note(0, "under-E0")
		f.advance(time.Minute)
		f.deliver(0, 1, kNote)
	}
	n := 0
	for _, e := range f.m(1).st.Outbox {
		if e.Confirm && !e.Done {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("hs.confirm entries in the responder's outbox: %d", n)
	}
	r.mu.Lock()
	r.failMailbox = nil
	r.mu.Unlock()
	f.advance(time.Hour)
	f.tick(1)
	f.settle()
	if f.p(0).Pending != nil || !f.sameEpoch() {
		t.Fatal("did not confirm once the relay took it")
	}
}

// F13 (lifetimes): B = L + T + 2 days and the confirmed epoch's keys
// B + T + 2 days; the responder still opens a message under its confirmed
// epoch late in that window.
func TestR29F13Lifetimes(t *testing.T) {
	if PendingLife != HandshakeTTL+14*24*time.Hour+2*24*time.Hour || ConfirmedKeysFor != PendingLife+16*24*time.Hour {
		t.Fatalf("B %v, keys %v", PendingLife, ConfirmedKeysFor)
	}
	f := newR29Fx(t)
	f.longTokens()
	f.lostConfirm()
	// side 0 is locked: nothing judges B. It sends under E0 late.
	f.advance(ConfirmedKeysFor - 2*24*time.Hour)
	f.note(0, "late")
	f.deliver(0, 1, kNote)
	if len(f.got[1]) != 1 {
		t.Fatal("a late message under the confirmed epoch was not accepted")
	}
}

// F13 (B after the first short collect): past B, the timers before the
// first collect after an unlock do not abandon the pending epoch; a
// confirmation collected then still confirms it.
func TestR29F13BAfterShortCollect(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	_, e1 := f.lostConfirm()
	f.do(1, func(m *Manager, p *Peer) { m.queueConfirm(p, f.clk) })
	f.advance(PendingLife + 24*time.Hour)
	m := f.m(0)
	m.mu.Lock()
	m.drainedOnce = false // a fresh unlock: no short collect yet
	m.housekeeping(f.clk)
	m.mu.Unlock()
	if f.p(0).Pending == nil {
		t.Fatal("B judged before the first short collect")
	}
	f.deliver(1, 0, kConfirm)
	if f.p(0).Pending != nil || !bytes.Equal(f.cur(0), e1) {
		t.Fatal("the waiting confirmation did not confirm")
	}
}

// F13 / §6.2 (rekey ctx = the confirmed epoch): the initiator, having
// abandoned its pending epoch, rekeys from E0, which the responder (on E1,
// its confirmed epoch E0) answers as if current; rule E destroys E1.
func TestR29F13RekeyNamingConfirmedEpoch(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	_, e1 := f.lostConfirm()
	f.do(0, func(m *Manager, p *Peer) {
		m.abandonPending(p, "test", false, f.clk)
		m.startRekey(p, f.clk)
	})
	f.deliver(0, 1, kHSInit)
	if f.answerCount(1) != 1 {
		f.dump()
		t.Fatal("a rekey naming the confirmed epoch was not answered")
	}
	f.settle()
	if e := f.p(1).epochMeta(e1); e == nil || !e.Destroyed || !f.sameEpoch() {
		f.dump()
		t.Fatal("rule E / convergence")
	}
}

// Question B (the lead's rule, "if redeemable, revoke"): an abandoned
// pending reconnect's tokens are revoked in the same write; the vault
// restarts a reconnect (not a rekey), and a peer that did activate the
// abandoned epoch converges through it.
func TestR29AbandonedReconnectTokensRevoked(t *testing.T) {
	for _, path := range []string{"B", "S5"} {
		f := newR29Fx(t)
		f.longTokens()
		f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
		f.deliver(0, 1, kHSInit)
		f.deliver(1, 0, kHSResp)
		pe := f.p(0).Pending
		if pe == nil || pe.Purpose != handshake.PurposeReconnect || len(pe.Issued) == 0 {
			t.Fatal("setup: no pending reconnect with tokens")
		}
		var jtis []string
		for _, tk := range pe.Issued {
			jtis = append(jtis, tk.JTI)
		}
		f.deliver(0, 1, kHSFin) // the peer activates it
		f.lose(1, 0, kConfirm)
		switch path {
		case "B":
			f.advance(PendingLife + time.Hour)
			f.tick(0)
		case "S5":
			f.rotate(0)
		}
		if f.p(0).Pending != nil {
			t.Fatalf("%s: not abandoned", path)
		}
		f.do(0, func(*Manager, *Peer) {}) // drain the revokes
		for _, j := range jtis {
			if !f.d[0].relayRevoked("jti", j) {
				t.Fatalf("%s: token %s not revoked", path, j)
			}
		}
		if !f.m(0).hasOutgoing(f.id[0], handshake.PurposeReconnect) {
			t.Fatalf("%s: no reconnect restarted", path)
		}
		f.settle()
		f.advance(time.Minute)
		f.tick(0)
		f.tick(1)
		f.settle()
		if !f.sameEpoch() {
			f.dump()
			t.Fatalf("%s: did not converge", path)
		}
		f.talks()
	}
}
