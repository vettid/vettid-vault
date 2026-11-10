package vault

import (
	"bytes"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayclient"
)

// §6.3.1 "Responder" (vettid.org #554 at 9839e49): while R's current
// epoch is one it activated as responder and its confirmed epoch is
// neither that epoch nor a later one, R queues hs.confirm again 12 days
// after the last one it queued, unless one is still in its outbox; not
// while demoted or suspended; the time is kept in R's state.

// reconfirmSetup: I (side 0) reconnects; R (side 1) activates E1 at hs.fin
// and queues hs.confirm, which waits in the relay (I is locked).
func reconfirmSetup(t *testing.T) (*r29Fx, []byte) {
	t.Helper()
	f := newR29Fx(t)
	f.longTokens()
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp)
	f.deliver(0, 1, kHSFin)
	e1 := append([]byte(nil), f.cur(1)...)
	if f.p(0).Pending == nil || !bytes.Equal(f.p(0).Pending.ID, e1) {
		t.Fatal("setup: I's reconnect epoch not pending, or R not on it")
	}
	return f, e1
}

// confirmsTo returns (and removes) side from's hs.confirm deposits to to.
func (f *r29Fx) confirmsTo(from, to int) []Message { return f.takeKind(from, to, kConfirm) }

// I is locked past 14 days (the relay drops the first hs.confirm); R
// queues hs.confirm again at 12 days; I collects it and confirms before B.
func TestR29ReconfirmEvery12Days(t *testing.T) {
	f, e1 := reconfirmSetup(t)
	f.advance(ConfirmResend - time.Hour)
	f.tick(1)
	f.advance(2 * time.Hour)
	f.tick(1)
	f.advance(3 * 24 * time.Hour) // I unlocks at 15 days
	confirms := f.confirmsTo(1, 0)
	if len(confirms) != 2 {
		f.dump()
		t.Fatalf("hs.confirm deposits waiting for I: %d", len(confirms))
	}
	f.lose(1, 0, kAny)        // R's other traffic (its daily rekey) is not under test
	f.process(0, confirms[1]) // the first passed the relay's 14 days
	if f.p(0).Pending != nil || !bytes.Equal(f.cur(0), e1) || f.p(0).State != PeerActive {
		f.dump()
		t.Fatal("I did not confirm from the hs.confirm sent again")
	}
}

// None before 12 days after the last one, and none once the epoch is
// confirmed.
func TestR29ReconfirmStopsWhenConfirmed(t *testing.T) {
	f, _ := reconfirmSetup(t)
	f.confirmsTo(1, 0)
	f.advance(ConfirmResend - time.Hour)
	f.tick(1)
	if n := len(f.confirmsTo(1, 0)); n != 0 {
		t.Fatalf("%d hs.confirm before 12 days", n)
	}
	f.do(0, func(m *Manager, p *Peer) { m.confirmPending(p, f.clk) }) // as at I's collect of the hs.confirm
	f.note(0, "under-E1-confirmed")
	f.deliver(0, 1, kNote)
	f.lose(1, 0, kAny)
	if !bytes.Equal(f.p(1).confirmedID(), f.cur(1)) {
		t.Fatal("setup: R's epoch not confirmed")
	}
	f.advance(2 * ConfirmResend)
	f.tick(1)
	if n := len(f.confirmsTo(1, 0)); n != 0 {
		t.Fatalf("%d hs.confirm after the epoch was confirmed", n)
	}
}

// None while R's epoch is demoted, or while the connection is suspended.
func TestR29ReconfirmNotDemotedOrSuspended(t *testing.T) {
	for _, why := range []string{"demoted", "suspended"} {
		f, e1 := reconfirmSetup(t)
		f.confirmsTo(1, 0)
		f.do(1, func(m *Manager, p *Peer) {
			if why == "demoted" {
				p.epochMeta(e1).Demoted = true
			} else {
				m.suspendForkRef(p, "epoch", f.clk)
			}
		})
		f.advance(ConfirmResend + time.Hour)
		f.tick(1)
		if n := len(f.confirmsTo(1, 0)); n != 0 {
			t.Fatalf("%s: %d hs.confirm", why, n)
		}
	}
}

// The last-queued time is in R's state: a restart does not reset it.
func TestR29ReconfirmTimeSurvivesRestart(t *testing.T) {
	f, _ := reconfirmSetup(t)
	f.confirmsTo(1, 0)
	at := f.p(1).ConfirmAt
	if at.IsZero() {
		t.Fatal("setup: no time recorded")
	}
	f.advance(time.Hour)
	f.restart(1)
	if !f.p(1).ConfirmAt.Equal(at) {
		t.Fatal("the last-queued time did not survive the restart")
	}
	f.tick(1)
	if n := len(f.confirmsTo(1, 0)); n != 0 {
		t.Fatalf("%d hs.confirm right after the restart", n)
	}
	f.advance(ConfirmResend)
	f.tick(1)
	if n := len(f.confirmsTo(1, 0)); n != 1 {
		t.Fatalf("%d hs.confirm 12 days after the last", n)
	}
}

// None while one is still in R's outbox (here its deposit keeps failing).
func TestR29ReconfirmNotWhileQueued(t *testing.T) {
	f, _ := reconfirmSetup(t)
	f.confirmsTo(1, 0)
	r := f.d[1].relay
	r.mu.Lock()
	r.failMailbox = map[string]error{f.m(0).st.Relay.Mailbox: &relayclient.Error{Status: 503, Code: "unavailable"}}
	r.mu.Unlock()
	f.advance(ConfirmResend + time.Hour)
	f.tick(1) // queued again; its deposit fails and it stays queued
	f.advance(ConfirmResend + time.Hour)
	f.tick(1)
	n := 0
	for _, e := range f.m(1).st.Outbox {
		if e.Confirm && !e.Done {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d hs.confirm in R's outbox", n)
	}
}

// It stops once the epoch stops being current: R's own rekey from E1 is
// answered and confirmed, and R's current epoch is E2.
func TestR29ReconfirmStopsWhenNotCurrent(t *testing.T) {
	f, e1 := reconfirmSetup(t)
	f.confirmsTo(1, 0)
	f.rekey(1)
	f.deliver(1, 0, kHSInit) // under E1: it also confirms I's pending E1
	f.deliver(0, 1, kHSResp)
	f.deliver(1, 0, kHSFin)
	f.deliver(0, 1, kConfirm)
	if bytes.Equal(f.cur(1), e1) || f.p(1).Pending != nil {
		f.dump()
		t.Fatal("setup: R's current epoch is still E1")
	}
	f.lose(1, 0, kAny)
	f.advance(2 * ConfirmResend)
	f.tick(1)
	if n := len(f.confirmsTo(1, 0)); n != 0 {
		t.Fatalf("%d hs.confirm after E1 stopped being current", n)
	}
}
