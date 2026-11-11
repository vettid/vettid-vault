package vault

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Card GC #6875: a durable message that waited in the outbox past §8.4's 16
// days with no key change, and no attempt of which may have reached the
// relay, is sealed again with a fresh ts at deposit and arrives (before,
// the peer dropped it as too old, after the relay accepted it: lost
// silently).
func TestAgeRestampedAtDeposit(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e, in := f.waitingNote(0, "aged")
	f.advance(17 * 24 * time.Hour)
	f.release(0)
	f.settle()
	if n := f.arrived(1, "aged"); n != 1 {
		t.Fatalf("arrived %d times, want 1", n)
	}
	if e.InnerID != in.ID || f.audited(0, "undelivered_window") {
		t.Fatalf("inner id %q (was %q), audited not delivered %v", e.InnerID, in.ID, f.audited(0, "undelivered_window"))
	}
	f.talks()
}

// One an attempt of which may have reached the relay (Tried) is never
// stamped again: past the 16 days it is not delivered, and told.
func TestAgeTriedPastWindowAtDeposit(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e, _ := f.waitingNote(0, "tried-aged")
	f.do(0, func(m *Manager, p *Peer) { e.Tried = true })
	f.advance(17 * 24 * time.Hour)
	f.release(0)
	f.settle()
	if !e.Done || !f.audited(0, "undelivered_window") {
		t.Fatalf("done %v, audited %v: want not delivered (drop.undelivered_window)", e.Done, f.audited(0, "undelivered_window"))
	}
	if n := f.arrived(1, "tried-aged"); n != 0 {
		t.Fatalf("arrived %d times", n)
	}
	f.talks()
}

// Tried, but still within the 16 days: deposited as it is (its kept ts
// keeps the peer's dedupe in force).
func TestAgeTriedWithinWindowAsIs(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e, _ := f.waitingNote(0, "tried-young")
	f.do(0, func(m *Manager, p *Peer) { e.Tried = true })
	before := append([]byte(nil), e.Payload...)
	f.advance(10 * 24 * time.Hour)
	f.do(0, func(m *Manager, p *Peer) {
		if m.ageCheck(e, f.clk) || !bytes.Equal(e.Payload, before) {
			t.Fatal("a tried entry within the window was changed")
		}
	})
	f.release(0)
	f.settle()
	if n := f.arrived(1, "tried-young"); n != 1 {
		t.Fatalf("arrived %d times, want 1", n)
	}
	f.talks()
}

// Young entries are left as they are; past RestampAfter one is sealed
// again in place (unstored until a write stores it).
func TestAgeRestampAfter(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e, _ := f.waitingNote(0, "young")
	before := append([]byte(nil), e.Payload...)
	f.advance(RestampAfter - time.Hour)
	f.do(0, func(m *Manager, p *Peer) {
		if m.ageCheck(e, f.clk) || !bytes.Equal(e.Payload, before) {
			t.Fatal("a young entry was changed")
		}
	})
	f.advance(2 * time.Hour)
	f.do(0, func(m *Manager, p *Peer) {
		if !m.ageCheck(e, f.clk) || bytes.Equal(e.Payload, before) || !m.unstored[e.ID] || e.Done {
			t.Fatal("an entry past RestampAfter was not sealed again in place")
		}
	})
	f.release(0)
	f.settle()
	if n := f.arrived(1, "young"); n != 1 {
		t.Fatalf("arrived %d times, want 1", n)
	}
	f.talks()
}

// The member's notice (card GC #6875, owner decision a, GC #7711): an
// entry past the window that may have reached the peer is told as
// unconfirmed, batched by the hour; others not delivered; the vault's
// upkeep and quota refreshes are not told.
func TestNoticeKinds(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e, in := f.waitingNote(0, "tried-aged-notice")
	f.do(0, func(m *Manager, p *Peer) { e.Tried = true })
	f.advance(17 * 24 * time.Hour)
	f.release(0)
	f.settle()
	found := false
	for _, a := range f.sink[0].got {
		if a.Kind == NoticeUnconfirmed {
			found = a.Feed && a.Batch == NoticeWindow && a.Ref == in.ID && a.ConnectionID == f.p(0).ID
		}
	}
	if !found {
		t.Fatalf("no unconfirmed notice: %+v", f.sink[0].got)
	}
	f.do(0, func(m *Manager, p *Peer) {
		for _, c := range []struct {
			e    *OutboxEntry
			kind string
		}{
			{&OutboxEntry{PeerID: p.ID, Type: "test.note", InnerID: "n1"}, NoticeNotDelivered},
			{&OutboxEntry{PeerID: p.ID, Type: "profile.update", InnerID: "n2"}, ""},
			{&OutboxEntry{PeerID: p.ID, Type: "att.offer", InnerID: "n3"}, ""},
			{&OutboxEntry{PeerID: p.ID, Type: "relay.token.refresh", InnerID: "n6"}, ""},
			{&OutboxEntry{PeerID: p.ID, Type: "relay.token.issued", InnerID: "n7"}, ""},
			{&OutboxEntry{PeerID: p.ID, Type: "message.send", InnerID: "n8"}, NoticeNotDelivered},
			{&OutboxEntry{PeerID: p.ID, QuotaRefresh: true, InnerID: "n4"}, ""},
			{&OutboxEntry{PeerID: p.ID, InnerID: "n5"}, NoticeNotDelivered}, // type unreadable: told
		} {
			before := len(f.sink[0].got)
			m.notDelivered(c.e, "undelivered_removed", f.clk)
			got := ""
			for _, a := range f.sink[0].got[before:] {
				if a.Feed {
					got = a.Kind
				}
			}
			if got != c.kind || !c.e.Done {
				t.Fatalf("%+v: notice %q, want %q", c.e, got, c.kind)
			}
		}
	})
}

// Review H1: a crash after the relay accepted a deposit, before the write
// that stored its Tried, then a restart past RestampAfter and the peer's
// dedupe: the entry is taken as tried (no clean end), so it is never
// stamped again, and the peer runs it once.
func TestAgeCrashAfterDeposit(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.waitingNote(0, "crash")
	snap := f.snapshot(0) // stored: waiting, not tried, not a clean end
	f.release(0)
	f.settle()
	if n := f.arrived(1, "crash"); n != 1 {
		t.Fatalf("first copy arrived %d times", n)
	}
	f.advance(17 * 24 * time.Hour)
	f.do(1, func(m *Manager, p *Peer) { m.housekeeping(f.clk) })
	f.startCopy(0, snap) // the crash: the copy from before the write, as side 2
	f.release(2)
	f.do(2, func(m *Manager, p *Peer) { _ = m.flushThenDrain(context.Background()) })
	f.do(1, func(m *Manager, p *Peer) { m.housekeeping(f.clk) }) // the peer's dedupe forgets the first copy
	f.deliver(2, 1, kAny)
	if n := f.arrived(1, "crash"); n != 1 {
		t.Fatalf("arrived %d times after the crash, want 1", n)
	}
}

// A clean end keeps Tried as stored: an entry that waited through a lock
// with no attempt is still stamped again after the unlock.
func TestCleanEndKeepsUntried(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	w, _ := f.waitingNote(0, "clean")
	st := &State{CleanEnd: true, OutboxTried: true}
	e := &OutboxEntry{Op: OpDeposit, Payload: w.Payload} // a real session-mode payload
	st.Outbox = []*OutboxEntry{e}
	st.init()
	if e.Tried || st.CleanEnd {
		t.Fatalf("tried %v, clean end %v after init", e.Tried, st.CleanEnd)
	}
}

// Review L1 of the re-check: a lock whose first write stores entries a
// failed batch write left (unstored) deposits them in its second drain;
// the store must not say a clean end until the write after that drain.
func TestLockWaitingBranchCleanEnd(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	var seen []bool
	m, p := f.m(0), f.p(0)
	func() {
		// Directly, not through f.do, whose write would store the entry.
		m.mu.Lock()
		defer m.mu.Unlock()
		m.sendTo(p, "test.note", []byte(`{"n":"unstored-at-lock"}`), f.clk)
		e := m.st.Outbox[len(m.st.Outbox)-1]
		m.markUnstored(e) // as after a batch whose write failed
		m.opt.Hooks.DropDeposit = func(x *OutboxEntry) bool {
			if x == e {
				seen = append(seen, m.st.CleanEnd)
			}
			return false
		}
	}()
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] {
		t.Fatalf("clean end at the second drain's deposit: %v (want one deposit, not yet clean)", seen)
	}
}

// Review L1: a re-stamped entry is not overtaken by a later one to the
// same mailbox in the same drain.
func TestAgeRestampKeepsOrder(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.waitingNote(0, "first-old")
	f.advance(3 * 24 * time.Hour)
	f.waitingNote(0, "second-young")
	f.release(0)
	f.settle()
	got := f.got[1]
	i, j := -1, -1
	for k, b := range got {
		switch {
		case strings.Contains(b, "first-old"):
			i = k
		case strings.Contains(b, "second-young"):
			j = k
		}
	}
	if i < 0 || j < 0 || i > j {
		t.Fatalf("order %v: the re-stamped first must arrive first", got)
	}
}

// The notice carries the connection's name; the member's own removal is
// told or not by NoticeOwnRemoval (#7806), a removal by the peer always.
func TestNoticeNameAndOwnRemoval(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.do(0, func(m *Manager, p *Peer) {
		p.Name = "Alex"
		before := len(f.sink[0].got)
		m.removingOwn = true
		m.notDelivered(&OutboxEntry{PeerID: p.ID, Type: "test.note", InnerID: "own"}, "undelivered_removed", f.clk)
		m.removingOwn = false
		told := false
		for _, a := range f.sink[0].got[before:] {
			told = told || a.Feed && a.Kind == NoticeNotDelivered
		}
		if told != NoticeOwnRemoval {
			t.Fatalf("the member's own removal: told %v, want %v", told, NoticeOwnRemoval)
		}
		before = len(f.sink[0].got)
		m.notDelivered(&OutboxEntry{PeerID: p.ID, Type: "test.note", InnerID: "theirs"}, "undelivered_removed", f.clk)
		var got *Activity
		for i, a := range f.sink[0].got[before:] {
			if a.Feed {
				got = &f.sink[0].got[before+i]
			}
		}
		if got == nil || got.Name != "Alex" {
			t.Fatalf("a removal by the peer: %+v", got)
		}
	})
}

// Review M1 (#218): an entry waits, untried, through a clean lock; then
// every state write fails, from the unlock's Start through the next lock.
// Nothing may be deposited while the store still says clean with it
// untried: 17 days on it would be stamped again, and the peer, its dedupe
// past, would run it twice.
func TestAgeCleanLoadNoDepositBeforeWrite(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.waitingNote(0, "m1") // stored: waiting, not tried
	d := f.d[0]
	refuse := func(on bool) {
		d.relay.mu.Lock()
		defer d.relay.mu.Unlock()
		d.relay.failMailbox = nil
		if on {
			d.relay.failMailbox = map[string]error{f.m(1).st.Relay.Mailbox: &relayclient.Error{Status: 429, Code: "rate_limited"}}
		}
	}
	refuse(true) // the lock's drains are refused too: a clean end, untried
	if err := d.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	fail := &putFailStore{Store: d.store, key: store.StateKey(d.vid), n: 1 << 20}
	d.opts.Store = fail
	f.reopen(0) // loaded clean; Start's write fails; the relay accepts now
	refuse(false)
	func() {
		m := d.m
		m.mu.Lock()
		defer m.mu.Unlock()
		m.retryPeer(f.p(0).ID)
		_ = m.flushThenDrain(context.Background()) // fails: the outage
	}()
	_ = d.m.Lock(context.Background()) // its writes fail too
	fail.mu.Lock()
	fail.n = 0 // the outage ends
	fail.mu.Unlock()
	f.reopen(0)
	// Whatever the outage deposited reaches the peer, before any drain.
	pumpOnly(t, f.d[0], f.d[1], func(*envelope.Envelope) bool { return true })
	f.advance(17 * 24 * time.Hour)
	f.do(1, func(m *Manager, p *Peer) { m.housekeeping(f.clk) }) // the peer's dedupe forgets
	f.release(0)
	f.settle()
	if n := f.arrived(1, "m1"); n != 1 {
		t.Fatalf("arrived %d times, want 1", n)
	}
}

// Review L (#218): the own-removal switch through the removal itself: the
// member's own removal is not told, a removal by the peer is.
func TestNoticeOwnRemovalEndToEnd(t *testing.T) {
	for _, dir := range []string{"out", "in"} {
		f := newR29Fx(t)
		f.longTokens()
		f.waitingNote(0, "to-"+dir)
		before := len(f.sink[0].got)
		f.do(0, func(m *Manager, p *Peer) { m.removeConnection(p, dir, f.clk) })
		told := false
		for _, a := range f.sink[0].got[before:] {
			told = told || a.Feed && a.Kind == NoticeNotDelivered
		}
		if want := dir == "in" || NoticeOwnRemoval; told != want {
			t.Fatalf("removal %q: told %v, want %v", dir, told, want)
		}
		if !f.audited(0, "undelivered_removed") {
			t.Fatalf("removal %q: not audited", dir)
		}
	}
}

// Re-check #7846 (1): a lock right after a clean load, with no write since,
// takes the waiting branch: its first drain sends nothing (the guard), so
// the second, after its write, must. Without the branch the lock sends
// nothing and the message waits for the next unlock.
func TestAgeLockAfterCleanLoadDeposits(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.waitingNote(0, "m1") // stored: waiting, not tried
	d := f.d[0]
	mb := f.m(1).st.Relay.Mailbox
	d.relay.mu.Lock()
	d.relay.failMailbox = map[string]error{mb: &relayclient.Error{Status: 429, Code: "rate_limited"}}
	d.relay.mu.Unlock()
	if err := d.m.Lock(context.Background()); err != nil { // clean, untried
		t.Fatal(err)
	}
	f.reopenNoStart(0) // loaded clean, and no write since
	count := func() int {
		d.relay.mu.Lock()
		defer d.relay.mu.Unlock()
		n := 0
		for _, dep := range d.relay.deposits {
			if dep.mailbox == mb {
				n++
			}
		}
		return n
	}
	before := count()
	m := d.m
	func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.retryPeer(f.p(0).ID) // due now; nothing written
	}()
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := count() - before; n != 1 {
		t.Fatalf("the lock deposited %d, want 1", n)
	}
}

// Re-check #7846 (2): an entry waiting for a standing token is not sealed
// again (no seq burned) every drain; it is judged once a token is there.
func TestAgeNoRestampWithoutStandingToken(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e, _ := f.waitingNote(0, "m1")
	f.advance(RestampAfter + time.Hour)
	m, p := f.m(0), f.p(0)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.retryPeer(p.ID) // due
	p.Standing.Token = ""
	was := append([]byte(nil), e.Payload...)
	m.drainOutbox(context.Background())
	if !bytes.Equal(e.Payload, was) {
		t.Fatal("sealed again while waiting for a standing token")
	}
}
