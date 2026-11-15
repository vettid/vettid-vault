package vault

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// §6.3.1: B on a pending epoch is judged after the batch's messages, so a
// confirmation in the batch that reaches B comes first. (Before, the batch's
// housekeeping abandoned the epoch at B and the hs.confirm behind it found
// nothing pending: toward a device the device exception, between vaults a
// reconnect.)
func TestR29PendingConfirmedInTheBatchThatReachesB(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e0, e1 := f.lostConfirm()
	f.advance(PendingLife + time.Hour)
	f.tick(1) // side 1's resend of hs.confirm (ConfirmResend has passed)
	if f.deliver(1, 0, kConfirm) != 1 {
		f.dump()
		t.Fatal("setup: no hs.confirm resent")
	}
	if f.p(0).Pending != nil || !bytes.Equal(f.cur(0), e1) || bytes.Equal(f.cur(0), e0) {
		f.dump()
		t.Fatal("the hs.confirm in the batch that reached B did not confirm the pending epoch")
	}
	if f.p(0).State != PeerActive || f.openReconnect(0) != nil {
		f.dump()
		t.Fatal("the confirmed epoch was followed by a reconnect")
	}
}

// B still ends a pending epoch whose confirmation does not come: the first
// batch past B with nothing for it (judged after its messages, the same
// batch) abandons it.
func TestR29PendingAbandonedAtBWithoutConfirm(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	_, e1 := f.lostConfirm()
	f.advance(PendingLife + time.Hour)
	f.tick(0)
	if f.p(0).Pending != nil || bytes.Equal(f.cur(0), e1) {
		f.dump()
		t.Fatal("B did not end a pending epoch nobody confirmed")
	}
}

// B is judged only from the batch after the first short collect since the
// unlock (drainedOnce as it was when the batch began): the unlock's first
// drain does not judge it, even after its messages.
func TestR29PendingNotJudgedInTheFirstDrain(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	_, e1 := f.lostConfirm()
	f.do(0, func(m *Manager, _ *Peer) { m.drainedOnce = false }) // as just after an unlock
	f.advance(PendingLife + time.Hour)
	f.tick(0)
	if f.p(0).Pending == nil || !bytes.Equal(f.p(0).Pending.ID, e1) {
		f.dump()
		t.Fatal("the unlock's first drain judged B")
	}
	f.tick(0)
	if f.p(0).Pending != nil {
		f.dump()
		t.Fatal("the batch after the first drain did not judge B")
	}
}

// Past B with no valid standing token either: B decides, as before it was
// judged after the batch's messages (the missing token does not abandon
// the epoch first in the batch's housekeeping).
func TestR29PendingPastBWithoutTokenIsB(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.lostConfirm()
	f.advance(PendingLife + time.Hour)
	f.p(0).Standing.Exp = f.clk.Add(-time.Second)
	f.tick(0)
	if f.p(0).Pending != nil || !f.audited(0, "pending_abandoned_b_passed") || f.audited(0, "pending_abandoned_no_token") {
		f.dump()
		t.Fatal("past B, the missing token decided instead of B")
	}
}

// Past B, a batch that carries no message under the pending epoch (here
// R's reconnect hs.init, sealed): B is judged before the batch's messages,
// as before 0.90.13, so B decides (b_passed), not the message.
func TestR29PendingPastBNoMessageUnderItIsBFirst(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.lostConfirm()
	f.advance(PendingLife + time.Hour)
	f.do(1, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	if f.deliver(1, 0, kHSInit) != 1 {
		f.dump()
		t.Fatal("setup: no reconnect hs.init")
	}
	if !f.audited(0, "pending_abandoned_b_passed") {
		f.dump()
		t.Fatal("past B, a message not under the pending epoch was handled before B")
	}
}

// Past B with the standing token expired too, and the batch carries the
// hs.confirm: B waits for it, and nothing in the batch's housekeeping (the
// missing token, the reconnect for an expired one) ends the epoch first.
func TestR29PendingConfirmedPastBWithoutToken(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	_, e1 := f.lostConfirm()
	f.advance(PendingLife + time.Hour)
	f.tick(1) // side 1's resend of hs.confirm
	f.p(0).Standing.Exp = f.clk.Add(-time.Second)
	if f.deliver(1, 0, kConfirm) != 1 {
		f.dump()
		t.Fatal("setup: no hs.confirm resent")
	}
	if f.p(0).Pending != nil || !bytes.Equal(f.cur(0), e1) {
		f.dump()
		t.Fatal("the epoch was ended before the hs.confirm in the batch")
	}
	for _, why := range []string{"b_passed", "no_token", "reconnect"} {
		if f.audited(0, "pending_abandoned_"+why) {
			f.dump()
			t.Fatalf("abandoned (%s) though confirmed in the batch", why)
		}
	}
}

// pendingUnderIn marks a peer past B only for a message addressed to its
// pending epoch (the hs.confirm), not for one addressed elsewhere (side
// 0's own note, addressed to side 1's receive kid), and not before B.
func TestR29PendingUnderInByRecipientKid(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.lostConfirm()
	f.advance(PendingLife + time.Hour)
	f.tick(1) // the hs.confirm resent
	f.note(0, "elsewhere")
	deposits := func(from, to, k int) []Message {
		fm := f.m(from)
		fm.mu.Lock()
		_ = fm.flushThenDrain(context.Background())
		fm.mu.Unlock()
		var out []Message
		f.d[from].relay.mu.Lock()
		defer f.d[from].relay.mu.Unlock()
		for _, dep := range f.d[from].relay.deposits {
			env, err := envelope.Parse(dep.payload)
			if err == nil && dep.mailbox == f.m(to).st.Relay.Mailbox && f.kindOf(from, to, env) == k {
				out = append(out, Message{Payload: dep.payload})
			}
		}
		return out
	}
	confirm, note := deposits(1, 0, kConfirm), deposits(0, 1, kNote)
	if len(confirm) == 0 || len(note) == 0 {
		t.Fatalf("setup: %d hs.confirm, %d notes", len(confirm), len(note))
	}
	id := f.id[0]
	f.do(0, func(m *Manager, _ *Peer) {
		if !m.pendingUnderIn(confirm, f.clk)[id] {
			t.Error("the hs.confirm under the pending epoch did not make B wait")
		}
		if m.pendingUnderIn(note, f.clk)[id] {
			t.Error("a message addressed elsewhere made B wait")
		}
		if m.pendingUnderIn(confirm, f.clk.Add(-2*time.Hour))[id] {
			t.Error("B waited before it had passed")
		}
	})
}
