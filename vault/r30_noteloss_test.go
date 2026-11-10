package vault

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// Release 30: durable messages between two vaults are never lost silently
// (owner: "we can't lose messages"; GC #7160, owner decision b #7213;
// VAULT-MESSAGING 0.88.7). Two causes:
//   1. markStale dropped the held entries, and stale is not final: the
//      peer's rekey or reconnect makes the connection active again, and
//      only the messages held at that moment were lost (§3.4.1 "The
//      reconnect bound", "Stale is not final").
//   2. An entry was sealed once, at queue time; after a long wait it was
//      deposited under an epoch the peer had dropped, or with a ts past
//      §8.4's 16 days, refused by the peer after the relay accepted it
//      (§8.3 "Re-sealed at a key change").

// r30NoteSeeds are the random-pair seeds that lost a test.note on main
// (49284d4) and converge with the fix: R29RP_BURST and R29RP_REFRESH, then
// two R29RP_BURST alone. Every one converges on main without #216's quota
// fix too.
var r30NoteSeeds = []struct {
	seed    uint64
	refresh bool
}{
	{9545559820980032774, true}, {8594494249170355390, true}, {8579791540454706926, true},
	{17172539816259494157, true}, {2741807807086018555, true}, {16785278149167989050, true},
	{15093282355162425551, true}, {6650889704533313486, true},
	{3269441301900938, false}, {16236571777707351782, false},
}

func TestR30NoteLossSeeds(t *testing.T) {
	saved := rpRunModes
	t.Cleanup(func() { rpRunModes = saved })
	for _, c := range r30NoteSeeds {
		t.Run(strconv.FormatUint(c.seed, 10), func(t *testing.T) {
			rpRunModes = rpModes{refresh: c.refresh}
			if v, _ := rpRun(t, c.seed, 40, true, false); v != "" {
				t.Fatalf("verdict %q, want converged (no note lost)", v)
			}
		})
	}
}

// sealedNote opens side s's waiting note entry to its peer under epoch ep
// (nil if it is not sealed under ep).
func (f *r29Fx) sealedNote(s int, e *OutboxEntry, ep *handshake.Epoch) *envelope.Inner {
	f.t.Helper()
	if e.Held != nil || len(e.Payload) == 0 {
		return nil
	}
	env, err := envelope.Parse(e.Payload)
	if err != nil {
		f.t.Fatal(err)
	}
	in, err := ep.OpenSent(env)
	if err != nil {
		return nil
	}
	return in
}

// waitingNote queues a test.note from side s and returns its entry, left
// waiting (as one waiting for a valid standing token: later deposits on a
// token of their own, the handshake's, pass it, §8.4).
func (f *r29Fx) waitingNote(s int, body string) (*OutboxEntry, *envelope.Inner) {
	f.t.Helper()
	var e *OutboxEntry
	f.do(s, func(m *Manager, p *Peer) {
		r := f.d[s].relay
		r.mu.Lock()
		r.failMailbox = map[string]error{f.m(1 - s).st.Relay.Mailbox: &relayclient.Error{Status: 503, Code: "unavailable"}}
		r.mu.Unlock()
		m.sendTo(p, "test.note", []byte(`{"n":"`+body+`"}`), f.clk)
		e = m.st.Outbox[len(m.st.Outbox)-1]
	})
	r := f.d[s].relay
	r.mu.Lock()
	r.failMailbox = nil
	r.mu.Unlock()
	f.do(s, func(m *Manager, p *Peer) { e.NotBefore, e.AwaitToken = f.clk.Add(365*24*time.Hour), true })
	in := f.sealedNote(s, e, f.m(s).sessions[f.p(s).ID].Current())
	if in == nil || e.Done {
		f.t.Fatal("setup: the note is not waiting under the current epoch")
	}
	return e, in
}

// peerReconnects starts side 1's reconnect: side 0 answers it on the
// token its hs.init carried, which passes side 0's entries waiting for a
// valid standing token (§8.4), and activates at its hs.fin.
func (f *r29Fx) peerReconnects() {
	f.t.Helper()
	f.do(1, func(m *Manager, p *Peer) {
		m.startReconnect(p, f.clk)
	})
	if !f.m(1).hasOutgoing(f.p(1).ID, handshake.PurposeReconnect) {
		f.t.Fatal("setup: side 1's reconnect did not start")
	}
}

// release makes side s's waiting entries due again.
func (f *r29Fx) release(s int) {
	f.do(s, func(m *Manager, p *Peer) { m.retryPeer(p.ID) })
}

// Cause 1: a stale connection with held messages that the peer's
// reconnect makes active again sends them, and the member is told it
// works again (connection.active_again).
func TestR30StaleHeldRevived(t *testing.T) {
	f := demoted(t, nil)
	f.note(0, "held-at-stale")
	f.lose(0, 1, kAny) // side 0's reconnect after the demotion is lost
	f.do(0, func(m *Manager, p *Peer) { m.markStale(p, f.clk) })
	held := 0
	for _, e := range f.m(0).st.Outbox {
		if !e.Done && e.Held != nil {
			held++
		}
	}
	if held != 1 || f.p(0).State != PeerStale {
		t.Fatalf("setup: stale %v, held %d (want stale, 1 kept)", f.p(0).State == PeerStale, held)
	}
	f.do(1, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	f.settle()
	f.advance(time.Hour)
	f.tick(0)
	f.tick(1)
	f.settle()
	if f.p(0).State != PeerActive {
		f.dump()
		t.Fatal("the peer's reconnect did not make the stale connection active")
	}
	if n := f.arrived(1, "held-at-stale"); n != 1 {
		f.dump()
		t.Fatalf("the message held at stale arrived %d times, want 1", n)
	}
	if !f.activity(0, "connection.active_again", f.id[0]) {
		t.Fatal("no connection.active_again feed item")
	}
	f.talks()
}

// Cause 2, responder: an entry waiting across the peer's reconnect is re-sealed
// under the new epoch, with the same inner id and a fresh ts, and arrives.
func TestR30WaitingResealedAtPeerReconnect(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e, before := f.waitingNote(0, "across-rekey")
	f.advance(10 * 24 * time.Hour)
	f.peerReconnects()
	f.deliver(1, 0, kHSInit)
	f.deliver(0, 1, kHSResp)
	f.deliver(1, 0, kHSFin) // side 0 activates the new epoch
	cur := f.m(0).sessions[f.p(0).ID].Current()
	after := f.sealedNote(0, e, cur)
	if after == nil {
		t.Fatal("the waiting entry was not re-sealed under the new epoch")
	}
	if after.ID != before.ID || !after.TS.Equal(f.clk) || after.TS.Equal(before.TS) {
		t.Fatalf("re-sealed: id %s (was %s), ts %v (was %v, now %v): want the same id and a fresh ts", after.ID, before.ID, after.TS, before.TS, f.clk)
	}
	f.release(0)
	f.settle()
	if n := f.arrived(1, "across-rekey"); n != 1 {
		f.dump()
		t.Fatalf("arrived %d times", n)
	}
}

// Cause 2, initiator: an entry waiting while its own reconnect's epoch is
// pending (§6.3.1) for longer than §8.4's 16 days is re-sealed at the
// confirmation and arrives (before 0.88.7: refused stale_or_future).
func TestR30PendingReconnectWaitResealed(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	f.deliver(0, 1, kHSInit)
	f.deliver(1, 0, kHSResp) // side 0 sends hs.fin: its epoch is pending
	if f.p(0).Pending == nil {
		t.Fatal("setup: no pending reconnect epoch")
	}
	f.note(0, "while-pending") // held behind the pending reconnect (§6.3.1)
	var e *OutboxEntry
	for _, x := range f.m(0).st.Outbox {
		if !x.Done && !x.Handshake && x.PeerID == f.p(0).ID && !x.Confirm {
			e = x
		}
	}
	old := f.m(0).sessions[f.p(0).ID].Current()
	before := f.sealedNote(0, e, old)
	if before == nil {
		t.Fatal("setup: the note is not sealed under the current epoch")
	}
	f.deliver(0, 1, kHSFin) // side 1 activates and queues hs.confirm
	f.advance(17 * 24 * time.Hour)
	f.deliver(1, 0, kConfirm) // side 0 confirms: the key change
	if f.p(0).Pending != nil {
		f.dump()
		t.Fatal("setup: not confirmed")
	}
	after := f.sealedNote(0, e, f.m(0).sessions[f.p(0).ID].Current())
	if !e.Done && (after == nil || after.ID != before.ID || !after.TS.Equal(f.clk)) {
		t.Fatalf("not re-sealed with the same id and a fresh ts: %+v", after)
	}
	f.settle()
	if n := f.arrived(1, "while-pending"); n != 1 {
		f.dump()
		t.Fatalf("a message that waited 17 days behind a pending reconnect arrived %d times", n)
	}
	if f.audited(1, "stale_or_future") {
		t.Fatal("the peer refused it for its ts")
	}
}

// lostAnswerRelay records a deposit to mailbox and then answers with a
// transport error (an answer lost after the relay accepted it).
type lostAnswerRelay struct {
	Relay
	mailbox string
	lose    bool
}

func (r *lostAnswerRelay) Deposit(ctx context.Context, url, mailbox, token string, payload []byte) (string, error) {
	id, err := r.Relay.Deposit(ctx, url, mailbox, token, payload)
	if err == nil && r.lose && mailbox == r.mailbox {
		return "", errors.New("transport: connection reset")
	}
	return id, err
}

// The "not safe" cases of §8.3: a copy may have reached the peer (Tried),
// so the re-seal keeps the ts and the inner id; the peer dedupes the second
// copy by its id (§8.2): its handler runs once.
func TestR30TriedKeepsTSAndDedupes(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	lr := &lostAnswerRelay{Relay: f.m(0).relay, mailbox: f.m(1).st.Relay.Mailbox, lose: true}
	f.m(0).relay = lr
	var e *OutboxEntry
	f.do(0, func(m *Manager, p *Peer) {
		m.sendTo(p, "test.note", []byte(`{"n":"lost-answer"}`), f.clk)
		e = m.st.Outbox[len(m.st.Outbox)-1]
	})
	lr.lose = false
	if e.Done || !e.Tried {
		t.Fatalf("setup: done %v, tried %v (want waiting, tried)", e.Done, e.Tried)
	}
	before := f.sealedNote(0, e, f.m(0).sessions[f.p(0).ID].Current())
	f.do(0, func(m *Manager, p *Peer) { e.NotBefore, e.AwaitToken = f.clk.Add(365*24*time.Hour), true })
	f.deliver(0, 1, kAny) // the first copy arrives
	f.advance(3 * 24 * time.Hour)
	f.peerReconnects()
	f.deliver(1, 0, kHSInit)
	f.deliver(0, 1, kHSResp)
	f.deliver(1, 0, kHSFin)
	after := f.sealedNote(0, e, f.m(0).sessions[f.p(0).ID].Current())
	if after == nil || after.ID != before.ID || !after.TS.Equal(before.TS) {
		t.Fatalf("a tried entry's re-seal: %+v, want the same id and ts as %+v", after, before)
	}
	f.release(0)
	f.settle()
	if n := f.arrived(1, "lost-answer"); n != 1 {
		t.Fatalf("handled %d times, want 1 (dedupe by inner id)", n)
	}
}

// A tried entry whose kept ts is past §8.4's 16 days at the key change is
// not delivered (the peer's dedupe may have forgotten the first copy).
func TestR30TriedPastWindowNotDelivered(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e, _ := f.waitingNote(0, "tried-old")
	f.do(0, func(m *Manager, p *Peer) { e.Tried = true })
	f.advance(17 * 24 * time.Hour)
	f.peerReconnects()
	f.deliver(1, 0, kHSInit)
	f.deliver(0, 1, kHSResp)
	f.deliver(1, 0, kHSFin)
	if !e.Done || !f.audited(0, "undelivered_window") {
		t.Fatalf("done %v, audited %v: want not delivered, told (drop.undelivered_window)", e.Done, f.audited(0, "undelivered_window"))
	}
	f.release(0)
	f.settle()
	if n := f.arrived(1, "tried-old"); n != 0 {
		t.Fatalf("arrived %d times", n)
	}
	f.talks()
}

// An entry from before 0.88.7 that already waited across a key change
// (sealed under an epoch whose send key is gone) cannot be re-sealed at the
// next one: it is not delivered, and told.
func TestR30UnreadableNotDelivered(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e, _ := f.waitingNote(0, "legacy")
	// Release 29's path: the key change leaves it sealed as it was.
	f.do(0, func(m *Manager, p *Peer) {
		kept := m.st.Outbox[:0]
		for _, x := range m.st.Outbox {
			if x != e {
				kept = append(kept, x)
			}
		}
		m.st.Outbox = kept
	})
	f.peerReconnects()
	f.deliver(1, 0, kHSInit)
	f.deliver(0, 1, kHSResp)
	f.deliver(1, 0, kHSFin)
	f.settle()
	f.do(0, func(m *Manager, p *Peer) { m.st.Outbox = append(m.st.Outbox, e) })
	f.peerReconnects()
	f.deliver(1, 0, kHSInit)
	f.deliver(0, 1, kHSResp)
	f.deliver(1, 0, kHSFin)
	if !e.Done || !f.audited(0, "undelivered_unreadable") {
		t.Fatalf("done %v, audited %v: want not delivered, told (drop.undelivered_unreadable)", e.Done, f.audited(0, "undelivered_unreadable"))
	}
	f.talks()
}

// mailbox_unknown ends the connection's waiting messages, told.
func TestR30MailboxUnknownNotDelivered(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e, _ := f.waitingNote(0, "gone")
	r := f.d[0].relay
	r.mu.Lock()
	r.failMailbox = map[string]error{f.m(1).st.Relay.Mailbox: &relayclient.Error{Status: 404, Code: CodeMailboxUnknown}}
	r.mu.Unlock()
	f.note(0, "trigger")
	f.release(0)
	if !e.Done || !f.audited(0, "undelivered_mailbox_unknown") {
		t.Fatalf("done %v, audited %v: want told (drop.undelivered_mailbox_unknown)", e.Done, f.audited(0, "undelivered_mailbox_unknown"))
	}
}

// The seam's audit kinds are drop.* entries in the audit log (§10.9).
func TestR30NotDeliveredAuditKind(t *testing.T) {
	for _, ev := range []string{"undelivered_unreadable", "undelivered_window", "undelivered_removed", "undelivered_mailbox_unknown", "held_unsealable"} {
		if k := auditKind(ev); k != "drop."+ev {
			t.Fatalf("%s: kind %q", ev, k)
		}
	}
}
