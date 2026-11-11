package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
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
// two R29RP_BURST alone. want is the verdict. 6650889704533313486 needs
// #216's quota fix too since the harness counts a re-sealed note against
// the standing quota (it did not before: its bytes had changed); with #216
// merged it converges.
var r30NoteSeeds = []struct {
	seed           uint64
	burst, refresh bool
	lost           bool // R29RP_LOSTANS
	want           string
}{
	{9545559820980032774, true, true, false, ""}, {8594494249170355390, true, true, false, ""},
	{8579791540454706926, true, true, false, ""}, {17172539816259494157, true, true, false, ""},
	{2741807807086018555, true, true, false, ""}, {16785278149167989050, true, true, false, ""},
	{15093282355162425551, true, true, false, ""}, {6650889704533313486, true, true, false, ""},
	{3269441301900938, true, false, false, ""}, {16236571777707351782, true, false, false, ""},
	// R29RP_REFRESH and R29RP_LOSTANS (the lead's re-check Low 1): a
	// re-sealed copy known by its bytes as the relay saw it, and the
	// receiver's stale_or_future for it judging the quota wait.
	{8495705468849050258, false, true, true, ""},
	{14452917345793243350, false, true, true, ""}, // was the lock-wait residual: #6875's re-stamp delivers it
}

func TestR30NoteLossSeeds(t *testing.T) {
	saved := rpRunModes
	t.Cleanup(func() { rpRunModes = saved })
	for _, c := range r30NoteSeeds {
		t.Run(strconv.FormatUint(c.seed, 10), func(t *testing.T) {
			rpRunModes = rpModes{refresh: c.refresh, lost: c.lost}
			if v, _ := rpRun(t, c.seed, 40, c.burst, false); v != c.want {
				t.Fatalf("verdict %q, want %q (no note lost)", v, c.want)
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
		// A refusal (429): the relay stored nothing, so Tried stays false.
		r.failMailbox = map[string]error{f.m(1 - s).st.Relay.Mailbox: &relayclient.Error{Status: 429, Code: "rate_limited"}}
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

// storeThenRefuse records a deposit to mailbox and then answers err: the
// relay stored it, and the answer the vault sees is a later attempt's or a
// failure after the commit (the lead's review H1).
type storeThenRefuse struct {
	Relay
	mailbox string
	err     error
}

func (r *storeThenRefuse) Deposit(ctx context.Context, url, mailbox, token string, payload []byte) (string, error) {
	id, err := r.Relay.Deposit(ctx, url, mailbox, token, payload)
	if err == nil && r.err != nil && mailbox == r.mailbox {
		return "", r.err
	}
	return id, err
}

// H1: an answer the vault cannot tell from a stored deposit marks it Tried;
// a refusal does not.
func TestR30MayHaveStored(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{nil, true},
		{errors.New("transport: connection reset"), true},
		{&relayclient.Error{Status: 500, Code: "internal"}, true},
		{&relayclient.Error{Status: 503, Code: "unavailable"}, true},
		{&relayclient.Error{Status: 502}, true},
		{&relayclient.Error{Status: 429, Code: CodeQuotaExceeded}, false},
		{&relayclient.Error{Status: 429, Code: "rate_limited"}, false},
		{&relayclient.Error{Status: 401, Code: CodeTokenExpired}, false},
	} {
		if got := mayHaveStored(c.err); got != c.want {
			t.Errorf("%v: %v, want %v", c.err, got, c.want)
		}
	}
}

// H1: a deposit is one relayclient attempt, so the answer the outbox sees
// is that attempt's; other calls keep relayclient's retries.
func TestR30DepositOneAttempt(t *testing.T) {
	r := NewClientRelay("https://relay.example", ed25519.NewKeyFromSeed(make([]byte, 32)), nil, nil)
	if n := r.depositClient("https://relay.example/").MaxAttempts; n != 1 {
		t.Fatalf("deposit attempts %d, want 1", n)
	}
	if n := r.client("https://relay.example").MaxAttempts; n != 3 {
		t.Fatalf("other calls' attempts %d, want relayclient's 3", n)
	}
}

// H1, at the client: the relay stores attempt 1 and its answer is lost;
// a second attempt would be answered 429 quota_exceeded. A deposit makes one
// attempt, so the vault sees the lost answer (possibly stored), not the 429.
func TestR30StoredThen429OneAttempt(t *testing.T) {
	var mu sync.Mutex
	stored := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		stored++
		n := stored
		mu.Unlock()
		if n == 1 {
			conn, _, err := w.(http.Hijacker).Hijack() // stored; the answer is lost
			if err == nil {
				conn.Close()
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(429)
		_, _ = w.Write([]byte(`{"code":"quota_exceeded","message":"token quota"}`))
	}))
	defer srv.Close()
	r := NewClientRelay(srv.URL, ed25519.NewKeyFromSeed(make([]byte, 32)), srv.Client(), nil)
	_, err := r.Deposit(withOneAttempt(context.Background()), srv.URL, "mbox", "v4.public.x", []byte("payload"))
	mu.Lock()
	n := stored
	mu.Unlock()
	if n != 1 || !mayHaveStored(err) {
		t.Fatalf("%d attempts, answer %v (possibly stored %v): want 1 attempt, possibly stored", n, err, mayHaveStored(err))
	}
	// L-c: a deposit outside the outbox (volatile, vault.locking) judges no
	// Tried and keeps relayclient's retries.
	mu.Lock()
	stored = 0
	mu.Unlock()
	_, err = r.Deposit(context.Background(), srv.URL, "mbox", "v4.public.x", []byte("payload"))
	mu.Lock()
	n = stored
	mu.Unlock()
	if n != 2 || RelayCode(err) != CodeQuotaExceeded {
		t.Fatalf("outside the outbox: %d attempts, answer %v: want the retry (2) and its 429", n, err)
	}
}

// H1, in the vault: stored, its answer lost; 17 days later a key change:
// the entry keeps its ts and is not delivered (told), never handled twice
// once the peer's dedupe has forgotten the first copy.
func TestR30StoredThenRefusedNoDuplicate(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	sr := &storeThenRefuse{Relay: f.m(0).relay, mailbox: f.m(1).st.Relay.Mailbox,
		err: errors.New("transport: connection reset after the relay stored it")}
	f.m(0).relay = sr
	var e *OutboxEntry
	f.do(0, func(m *Manager, p *Peer) {
		m.sendTo(p, "test.note", []byte(`{"n":"stored-429"}`), f.clk)
		e = m.st.Outbox[len(m.st.Outbox)-1]
	})
	sr.err = &relayclient.Error{Status: 429, Code: CodeQuotaExceeded}
	f.do(0, func(m *Manager, p *Peer) { e.NotBefore = time.Time{} }) // its retry: refused 429
	sr.err = nil
	if e.Done || !e.Tried {
		t.Fatalf("setup: done %v, tried %v (want waiting, tried)", e.Done, e.Tried)
	}
	f.do(0, func(m *Manager, p *Peer) { e.NotBefore, e.AwaitToken = f.clk.Add(365*24*time.Hour), true })
	f.deliver(0, 1, kAny) // the stored copy arrives and is handled
	f.advance(17 * 24 * time.Hour)
	f.tick(1) // the peer's dedupe forgets it (16 days and 5 minutes)
	f.peerReconnects()
	f.deliver(1, 0, kHSInit)
	f.deliver(0, 1, kHSResp)
	f.deliver(1, 0, kHSFin)
	f.release(0)
	f.settle()
	if n := f.arrived(1, "stored-429"); n != 1 {
		t.Fatalf("handled %d times, want once", n)
	}
	if !f.audited(0, "undelivered_window") {
		t.Fatal("the kept-ts copy was not told as not delivered (drop.undelivered_window)")
	}
}

// L1, #217 review 3: an ephemeral entry records Ephemeral when queued and
// ends silently at the next key change (not deposited, not told).
func TestR30EphemeralEndsAtKeyChange(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.do(0, func(m *Manager, p *Peer) {
		m.register(TypeSpec{Type: "test.eph", From: []string{KindConnection}, Connections: PeersBoth, Ephemeral: true},
			HandlerFunc(func(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) { return nil, nil }))
	})
	f.waitingNote(0, "first") // waits; the ephemeral queues behind it
	var eph *OutboxEntry
	f.do(0, func(m *Manager, p *Peer) {
		m.sendWith(p, "test.eph", []byte(`{}`), SendOptions{Exp: f.clk.Add(time.Hour)}, f.clk)
		eph = m.st.Outbox[len(m.st.Outbox)-1]
		eph.NotBefore, eph.AwaitToken = f.clk.Add(365*24*time.Hour), true
	})
	if !eph.Ephemeral {
		t.Fatal("Ephemeral not recorded at queue time")
	}
	before := append([]byte(nil), eph.Payload...)
	f.peerReconnects()
	f.deliver(1, 0, kHSInit)
	f.deliver(0, 1, kHSResp)
	f.deliver(1, 0, kHSFin)
	r := f.d[0].relay
	r.mu.Lock()
	sent := false
	for _, d := range r.deposits {
		sent = sent || bytes.Equal(d.payload, before)
	}
	r.mu.Unlock()
	if !eph.Done || sent || f.auditedRef(0, "undelivered_unreadable", eph.InnerID) {
		t.Fatalf("the ephemeral entry: done %v, deposited %v, told %v (want ended silently)", eph.Done, sent, f.auditedRef(0, "undelivered_unreadable", eph.InnerID))
	}
}

// N1: at a key change a waiting hs.confirm for the epoch being replaced is
// superseded (done), not sealed again under the new one.
func TestR30ConfirmSupersededAtKeyChange(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.waitingNote(0, "first")
	var c *OutboxEntry
	f.do(0, func(m *Manager, p *Peer) {
		m.queueConfirm(p, f.clk)
		c = m.st.Outbox[len(m.st.Outbox)-1]
		c.NotBefore, c.AwaitToken = f.clk.Add(365*24*time.Hour), true
	})
	if !c.Confirm {
		t.Fatal("setup: not an hs.confirm")
	}
	before := append([]byte(nil), c.Payload...)
	f.peerReconnects()
	f.deliver(1, 0, kHSInit)
	f.deliver(0, 1, kHSResp)
	f.deliver(1, 0, kHSFin)
	if !c.Done || !bytes.Equal(c.Payload, before) {
		t.Fatalf("the old hs.confirm: done %v, re-sealed %v (want superseded, not sealed again)", c.Done, !bytes.Equal(c.Payload, before))
	}
}

// L2, N-a: a release 29 state's sealed entries not done are taken as Tried
// at its first load (an attempt cut off by a lock is not counted); a 0.88.7
// state's are left as they are.
func TestR30LoadMarksAttemptedTried(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	w, _ := f.waitingNote(0, "sealed")
	sealed := w.Payload
	a := &OutboxEntry{Op: OpDeposit, Payload: sealed}             // never counted as attempted (cut off by a lock)
	b := &OutboxEntry{Op: OpDeposit, Held: []byte(`{}`)}          // held, never sealed
	c := &OutboxEntry{Op: OpDeposit, Payload: sealed, Done: true} // done
	st := &State{Outbox: []*OutboxEntry{a, b, c}}
	st.init()
	if !a.Tried || b.Tried || c.Tried || !st.OutboxTried {
		t.Fatalf("tried %v %v %v, marked %v (want true false false, true)", a.Tried, b.Tried, c.Tried, st.OutboxTried)
	}
	// A 0.88.7 state from a clean end keeps its exact Tried; one without
	// (a crash, card GC #6875) is marked as possibly tried.
	d := &OutboxEntry{Op: OpDeposit, Payload: sealed}
	st2 := &State{OutboxTried: true, CleanEnd: true, Outbox: []*OutboxEntry{d}}
	st2.init()
	if d.Tried {
		t.Fatal("a cleanly ended state's entry was marked (its Tried is exact)")
	}
	e := &OutboxEntry{Op: OpDeposit, Payload: sealed}
	st3 := &State{OutboxTried: true, Outbox: []*OutboxEntry{e}}
	st3.init()
	if !e.Tried {
		t.Fatal("a crashed state's entry wasn't marked possibly tried")
	}
}

// L3: an inner id is kept 16 days and 5 minutes, past the ts window for a
// first copy whose ts was up to 5 minutes ahead.
func TestR30SeenInnerOutlivesTSWindow(t *testing.T) {
	f := newR29Fx(t)
	f.do(0, func(m *Manager, p *Peer) {
		m.st.SeenInner["keep"] = f.clk.Add(-(DedupeRetention + 4*time.Minute))
		m.st.SeenInner["drop"] = f.clk.Add(-(DedupeRetention + 6*time.Minute))
		m.prune()
		if _, ok := m.st.SeenInner["keep"]; !ok {
			t.Fatal("an inner id within 16 days and 5 minutes was forgotten")
		}
		if _, ok := m.st.SeenInner["drop"]; ok {
			t.Fatal("an inner id past 16 days and 5 minutes was kept")
		}
	})
}

// L4 (proposed bound): a stale connection's held messages wait while the
// peer still holds a valid token this vault issued (it can come back), and
// end, told (drop.undelivered_stale), once none is valid.
func TestR30StaleHeldEndWhenPeerCannotReturn(t *testing.T) {
	f := demoted(t, nil)
	f.note(0, "held-stale")
	f.lose(0, 1, kAny)
	f.do(0, func(m *Manager, p *Peer) { m.markStale(p, f.clk) })
	var held *OutboxEntry
	for _, e := range f.m(0).st.Outbox {
		if !e.Done && e.Held != nil {
			held = e
		}
	}
	f.tick(0)
	if held == nil || held.Done {
		t.Fatal("a held entry ended while the peer can still come back")
	}
	f.do(0, func(m *Manager, p *Peer) {
		for i := range m.st.Issued {
			if m.st.Issued[i].PeerID == p.ID {
				m.st.Issued[i].Exp = f.clk.Add(time.Minute)
			}
		}
	})
	// A deposit of the peer's made just before the exp can sit at the relay
	// up to T, so the bound is the exp plus T plus the future skew.
	f.advance(14 * 24 * time.Hour)
	f.tick(0)
	if held.Done {
		t.Fatal("a held entry ended within T of the peer's last token exp")
	}
	f.advance(time.Hour)
	f.tick(0)
	if !held.Done || !f.auditedRef(0, "undelivered_stale", held.InnerID) || held.InnerID == "" {
		t.Fatalf("done %v, audited with its inner id %v: want ended, told", held.Done, f.auditedRef(0, "undelivered_stale", held.InnerID))
	}
}

// M-A: the peer's reconnect answered (its hs.resp's fresh tokens still in
// flight, in Awaiting) while the stale side's adopted tokens expire: the held
// messages wait, and the hs.fin revives the connection with them delivered.
func TestR30StaleHeldWaitForInFlightAnswer(t *testing.T) {
	f := demoted(t, nil)
	f.note(0, "held-in-flight")
	f.lose(0, 1, kAny)
	f.do(0, func(m *Manager, p *Peer) { m.markStale(p, f.clk) })
	f.peerReconnects()
	f.deliver(1, 0, kHSInit) // side 0 answers: the hs.resp's tokens are in Awaiting
	if len(f.m(0).st.Awaiting) == 0 {
		t.Fatal("setup: no answer awaiting hs.fin")
	}
	f.do(0, func(m *Manager, p *Peer) {
		for i := range m.st.Issued {
			if m.st.Issued[i].PeerID == p.ID {
				m.st.Issued[i].Exp = f.clk.Add(time.Minute)
			}
		}
	})
	f.advance(15 * 24 * time.Hour)
	f.tick(0)
	if f.audited(0, "undelivered_stale") {
		t.Fatal("the held messages ended while the answer's tokens were in flight")
	}
	f.deliver(0, 1, kHSResp)
	f.deliver(1, 0, kHSFin)
	f.settle()
	f.advance(time.Hour)
	f.tick(0)
	f.tick(1)
	f.settle()
	if f.p(0).State != PeerActive || f.arrived(1, "held-in-flight") != 1 {
		f.dump()
		t.Fatalf("active %v, arrived %d: want revived, delivered once", f.p(0).State == PeerActive, f.arrived(1, "held-in-flight"))
	}
}

// L-d: a sealed entry waiting for a token on a stale connection ends under
// the same bound (it would otherwise retry for good, silently).
func TestR30StaleSealedWaitingEnds(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e, in := f.waitingNote(0, "sealed-stale")
	f.do(0, func(m *Manager, p *Peer) {
		m.markStale(p, f.clk)
		for i := range m.st.Issued {
			if m.st.Issued[i].PeerID == p.ID {
				m.st.Issued[i].Exp = f.clk.Add(time.Minute)
			}
		}
	})
	f.advance(StaleReach + time.Hour)
	f.tick(0)
	if !e.Done || !f.auditedRef(0, "undelivered_stale", in.ID) {
		t.Fatalf("done %v, audited with its id %v: want ended, told", e.Done, f.auditedRef(0, "undelivered_stale", in.ID))
	}
}

// L-c: a 429's retry_after is the entry's next try.
func TestR30RetryAfterHonoured(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	r := f.d[0].relay
	r.mu.Lock()
	r.failMailbox = map[string]error{f.m(1).st.Relay.Mailbox: &relayclient.Error{Status: 429, Code: "rate_limited", RetryAfter: 600}}
	r.mu.Unlock()
	var e *OutboxEntry
	f.do(0, func(m *Manager, p *Peer) {
		m.sendTo(p, "test.note", []byte(`{"n":"later"}`), f.clk)
		e = m.st.Outbox[len(m.st.Outbox)-1]
	})
	if e.Done || e.NotBefore.Before(f.clk.Add(600*time.Second)) {
		t.Fatalf("not before %v, want %v (retry_after)", e.NotBefore, f.clk.Add(600*time.Second))
	}
}

// L-a: the peer's stale_or_future drop names the message's inner id.
func TestR30StaleOrFutureRef(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	var id string
	f.do(0, func(m *Manager, p *Peer) {
		in := &envelope.Inner{ID: m.newID(f.clk), Type: "test.note", TS: f.clk.Add(-17 * 24 * time.Hour), Body: []byte(`{"n":"old"}`)}
		raw, err := m.sealFor(p, m.sessions[p.ID].Current(), in)
		if err != nil {
			t.Fatal(err)
		}
		id = in.ID
		// Best effort: not a member deposit, so the sender's age check
		// (#6875) leaves its old ts for the peer to refuse.
		m.queueDeposit(&OutboxEntry{PeerID: p.ID, RelayURL: p.Relay.URL, Mailbox: p.Relay.Mailbox, Payload: raw, InnerID: id,
			BestEffort: true}, f.clk)
	})
	f.settle()
	if !f.auditedRef(1, "stale_or_future", id) {
		t.Fatal("drop.stale_or_future without the message's inner id")
	}
}

// N2: a stale service connection revived by a restore reconnect records one
// History line, connection.restored_reconnect (it names the restored
// epoch); connection.active_again is its feed item only.
func TestR30RestoreRevivalOneHistoryLine(t *testing.T) {
	f := newSvcFx(t, "service")
	f.build(3)
	e1 := f.ids[1]
	f.sink.got = nil
	f.d.m.mu.Lock()
	f.p.State = PeerStale
	f.d.m.mu.Unlock()
	f.at(10 * time.Hour)
	ini := f.initiate(e1, f.now(), nil)
	f.deliver(ini.Envelope(), "")
	if f.complete(ini) == nil {
		t.Fatal("no hs.resp")
	}
	if f.p.State != PeerActive {
		t.Fatal("not active again")
	}
	r, a := f.feedFor("connection.restored_reconnect"), f.feedFor("connection.active_again")
	if r == nil || !r.Audit || a == nil || a.Audit || !a.Feed {
		t.Fatalf("restored_reconnect %+v, active_again %+v: want one History line (the restore) and the feed item", r, a)
	}
}

// M2: the note oracle by inner id: a duplicate fails, a loss is excused
// only by a copy dropped at T behind a lock longer than T, the quota-wait
// residual is narrow, and no lock class absorbs a lost or duplicate note.
func TestR30NoteOracle(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	newW := func() *rpWorld {
		f.gotIDs = [3]map[string]int{{}, {}, {}}
		return &rpWorld{t: t, f: f, refused: map[string]int{}, ttlNote: map[string]bool{}, quotaNote: map[string]bool{}, staleNote: map[string]bool{}, fiveNote: map[string]bool{}, lockNote: map[string]bool{}}
	}
	long := [][2]time.Time{{f.clk.Add(-20 * 24 * time.Hour), f.clk}}
	for _, c := range []struct {
		name     string
		set      func(w *rpWorld)
		want     string
		residual string
	}{
		{"handled once", func(w *rpWorld) { f.gotIDs[1]["a"] = 1 }, "", ""},
		{"handled twice", func(w *rpWorld) { f.gotIDs[1]["a"] = 2 }, "note-duplicate@0", ""},
		{"lost", func(w *rpWorld) {}, "note-lost@0", ""},
		{"dropped at T, no long lock", func(w *rpWorld) { w.ttlNote["a"] = true }, "note-lost@0", ""},
		{"dropped at T, long lock", func(w *rpWorld) { w.ttlNote["a"] = true; w.locks[1] = long }, "", ""},
		{"long lock, not dropped at T", func(w *rpWorld) { w.locks[1] = long }, "note-lost@0", ""},
		{"quota wait, no stale copy", func(w *rpWorld) { w.quotaNote["a"] = true }, "note-lost@0", ""},
	} {
		w := newW()
		w.sent[0] = []string{"a"}
		c.set(w)
		lost, res := w.notesLost()
		if strings.Join(lost, ",") != c.want || res != c.residual {
			t.Errorf("%s: %v %q, want %q %q", c.name, lost, res, c.want, c.residual)
		}
	}
	// The quota-wait residual needs the receiver's stale_or_future too.
	w := newW()
	w.sent[0] = []string{"a"}
	w.staleNote["a"] = true
	if lost, res := w.notesLost(); len(lost) != 1 || res != "" {
		t.Fatalf("quota wait without the peer's stale_or_future: %v %q", lost, res)
	}
	f.do(1, func(m *Manager, p *Peer) { m.auditRef(f.clk, "stale_or_future", p.ID, "other") })
	if lost, res := w.notesLost(); len(lost) != 1 || res != "" {
		t.Fatalf("another note's stale_or_future: %v %q", lost, res)
	}
	// With #6875 the quota-wait and lock-wait shapes are losses, not
	// residuals: the re-stamp at deposit delivers such a note.
	f.do(1, func(m *Manager, p *Peer) { m.auditRef(f.clk, "stale_or_future", p.ID, "a") })
	if lost, res := w.notesLost(); len(lost) != 1 || res != "" {
		t.Fatalf("quota wait: %v %q, want lost (no longer a residual)", lost, res)
	}
	w = newW()
	w.sent[0] = []string{"b"}
	w.lockNote["b"] = true
	f.do(1, func(m *Manager, p *Peer) { m.auditRef(f.clk, "stale_or_future", p.ID, "b") })
	if lost, res := w.notesLost(); len(lost) != 1 || res != "" {
		t.Fatalf("lock wait: %v %q, want lost (no longer a residual)", lost, res)
	}
	// Told after a 5xx: only with the sender's undelivered_window.
	w = newW()
	w.sent[0] = []string{"a"}
	w.fiveNote["a"] = true
	if lost, res := w.notesLost(); len(lost) != 1 || res != "" {
		t.Fatalf("5xx without the sender's undelivered_window: %v %q", lost, res)
	}
	f.do(0, func(m *Manager, p *Peer) { m.auditRef(f.clk, "undelivered_window", p.ID, "other") })
	if lost, res := w.notesLost(); len(lost) != 1 || res != "" {
		t.Fatalf("another note's undelivered_window: %v %q", lost, res)
	}
	f.do(0, func(m *Manager, p *Peer) { m.auditRef(f.clk, "undelivered_window", p.ID, "a") })
	if lost, res := w.notesLost(); len(lost) != 0 || res != rpToldResidual {
		t.Fatalf("told after a 5xx: %v %q, want the residual", lost, res)
	}
	// Told after a crash: only with the sender's undelivered_window.
	w = newW()
	w.sent[0] = []string{"c"}
	w.crashNote = map[string]bool{"c": true}
	if lost, res := w.notesLost(); len(lost) != 1 || res != "" {
		t.Fatalf("a crash without the sender's undelivered_window: %v %q", lost, res)
	}
	f.do(0, func(m *Manager, p *Peer) { m.auditRef(f.clk, "undelivered_window", p.ID, "c") })
	if lost, res := w.notesLost(); len(lost) != 0 || res != rpCrashToldResidual {
		t.Fatalf("told after a crash: %v %q, want the residual", lost, res)
	}
	// A lost note behind a long lock is not absorbed by the lock class.
	w = newW()
	w.sent[0] = []string{"a"}
	w.locks[1] = long
	if v := w.verdict(); v != "diverged:note-lost@0" {
		t.Fatalf("verdict %q, want diverged:note-lost@0 (no lock class)", v)
	}
}

// ctxRelay records whether each deposit's context asked for one attempt.
type ctxRelay struct {
	Relay
	once []bool
}

func (r *ctxRelay) Deposit(ctx context.Context, url, mailbox, token string, payload []byte) (string, error) {
	r.once = append(r.once, ctx.Value(oneAttemptKey{}) != nil)
	return r.Relay.Deposit(ctx, url, mailbox, token, payload)
}

// H1, L-c: the outbox's deposits ask for one attempt.
func TestR30OutboxDepositsOneAttempt(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	cr := &ctxRelay{Relay: f.m(0).relay}
	f.m(0).relay = cr
	f.note(0, "once")
	if len(cr.once) == 0 || !cr.once[len(cr.once)-1] {
		t.Fatalf("the outbox deposit's context: %v (want one attempt)", cr.once)
	}
}

// L-b: a stale copy counts for the quota-wait residual only after a
// standing-quota refusal of this note, or of the entry directly ahead of it.
func TestR30QuotaWaitAhead(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e, in := f.waitingNote(0, "behind")
	for _, c := range []struct {
		name  string
		set   func(w *rpWorld)
		stale bool
	}{
		{"no refusal", func(w *rpWorld) {}, false},
		{"its own refusal", func(w *rpWorld) { w.quotaNote[in.ID] = true }, true},
		{"the entry ahead refused after its ts", func(w *rpWorld) {
			w.noteAhead[in.ID] = "ahead"
			w.quotaNote["ahead"], w.quotaLast["ahead"] = true, in.TS.Add(time.Minute)
		}, true},
		{"the entry ahead refused before its ts", func(w *rpWorld) {
			w.noteAhead[in.ID] = "ahead"
			w.quotaNote["ahead"], w.quotaLast["ahead"] = true, in.TS.Add(-time.Minute)
		}, false},
		{"the entry ahead not refused", func(w *rpWorld) { w.noteAhead[in.ID] = "ahead"; w.quotaNote["other"] = true }, false},
	} {
		w := &rpWorld{t: t, f: f, noteBytes: map[string]string{}, noteAhead: map[string]string{}, quotaNote: map[string]bool{},
			quotaLast: map[string]time.Time{}, sealed: map[string]rpSeal{}, staleNote: map[string]bool{}}
		w.seeEpoch(0)
		w.epochAt[0].since = in.TS
		w.seeNote(0, e.Payload)
		c.set(w)
		w.noteAccepted(0, e.Payload)
		if w.staleNote[in.ID] != c.stale {
			t.Errorf("%s: stale-copy %v, want %v", c.name, w.staleNote[in.ID], c.stale)
		}
	}
}

// Nit 1: with no token ever recorded for the peer the bound cannot be
// judged: a stale connection's waiting messages are kept.
func TestR30StaleNoTokenRecordKeeps(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e, _ := f.waitingNote(0, "no-record")
	f.do(0, func(m *Manager, p *Peer) {
		m.markStale(p, f.clk)
		kept := m.st.Issued[:0]
		for _, it := range m.st.Issued {
			if it.PeerID != p.ID {
				kept = append(kept, it)
			}
		}
		m.st.Issued = kept
	})
	f.advance(StaleReach + time.Hour)
	f.tick(0)
	if e.Done || f.audited(0, "undelivered_stale") {
		t.Fatal("ended with no token record to judge the bound by")
	}
}

// With #216: a quota refresh ended as not delivered forgets its request
// (no answer can come), as its other ends do.
func TestR30NotDeliveredEndsQuotaRefresh(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	r := f.d[0].relay
	r.mu.Lock()
	r.failMailbox = map[string]error{f.m(1).st.Relay.Mailbox: &relayclient.Error{Status: 429, Code: "rate_limited"}}
	r.mu.Unlock()
	var e *OutboxEntry
	f.do(0, func(m *Manager, p *Peer) {
		m.askQuotaRefresh(p, f.clk)
		for _, x := range m.st.Outbox {
			if x.QuotaRefresh && !x.Done {
				e = x
			}
		}
	})
	if e == nil || !slices.Contains(f.p(0).QuotaReqs, e.QuotaReq) {
		t.Fatal("setup: no open quota refresh")
	}
	f.do(0, func(m *Manager, p *Peer) { m.notDelivered(e, "undelivered_removed", f.clk) })
	if slices.Contains(f.p(0).QuotaReqs, e.QuotaReq) {
		t.Fatal("the refresh's request is still open after its entry ended")
	}
}

// #217 review 1: a fork suspension ends the connection's waiting messages,
// told (case 7).
func TestR30SuspendedNotDelivered(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e, in := f.waitingNote(0, "suspended")
	f.do(0, func(m *Manager, p *Peer) { m.suspendForkRef(p, "epoch", f.clk) })
	if !e.Done || !f.auditedRef(0, "undelivered_suspended", in.ID) {
		t.Fatalf("done %v, told %v: want ended, drop.undelivered_suspended with its id", e.Done, f.auditedRef(0, "undelivered_suspended", in.ID))
	}
}

// #217 review 2: a relay 4xx refusing a member deposit ends it, told (case
// 8); timestamp_stale and replay_detected are about the attempt and are
// retried.
func TestR30RefusedNotDelivered(t *testing.T) {
	for _, c := range []struct {
		err  *relayclient.Error
		told bool
	}{
		{&relayclient.Error{Status: 400, Code: "bad_request"}, true},
		{&relayclient.Error{Status: 413, Code: "payload_too_large"}, true},
		{&relayclient.Error{Status: 401, Code: CodeTimestampStale}, false},
		{&relayclient.Error{Status: 401, Code: CodeReplayDetected}, false},
	} {
		f := newR29Fx(t)
		f.longTokens()
		r := f.d[0].relay
		r.mu.Lock()
		r.failMailbox = map[string]error{f.m(1).st.Relay.Mailbox: c.err}
		r.mu.Unlock()
		var e *OutboxEntry
		f.do(0, func(m *Manager, p *Peer) {
			m.sendTo(p, "test.note", []byte(`{"n":"refused"}`), f.clk)
			e = m.st.Outbox[len(m.st.Outbox)-1]
		})
		told := f.auditedRef(0, "undelivered_refused", e.InnerID)
		if told != c.told || e.Done != c.told || f.audited(0, "deposit_refused") {
			t.Errorf("%s: done %v, told %v, deposit_refused %v (want told %v)", c.err.Code, e.Done, told, f.audited(0, "deposit_refused"), c.told)
		}
	}
}

// #217 review 4: an entry changed in place at a key change (held again, or
// sealed again) is unstored until a write stores it.
func TestR30ResealedUnstored(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e, _ := f.waitingNote(0, "unstored")
	m := f.m(0)
	m.mu.Lock()
	defer m.mu.Unlock()
	p := f.p(0)
	m.unstored = nil
	m.resealAtKeyChange(p, m.sessions[p.ID])
	if e.Held == nil || !m.unstored[e.ID] {
		t.Fatalf("held again %v, unstored %v (want both)", e.Held != nil, m.unstored[e.ID])
	}
	m.unstored = nil
	m.sealHeld(p)
	if e.Held != nil || !m.unstored[e.ID] {
		t.Fatalf("sealed again %v, unstored %v (want both)", e.Held == nil, m.unstored[e.ID])
	}
}

// #217 review 5: a relay holding messages longer than 14 days lengthens the
// stale bound to its TTL plus the skew.
func TestR30StaleReachRelayTTL(t *testing.T) {
	m := &Manager{}
	if got := m.staleReach(); got != StaleReach {
		t.Fatalf("no TTL: %v, want %v", got, StaleReach)
	}
	m.limits.MessageTTLSeconds = 14 * 24 * 3600
	if got := m.staleReach(); got != StaleReach {
		t.Fatalf("14 days: %v, want %v", got, StaleReach)
	}
	m.limits.MessageTTLSeconds = 20 * 24 * 3600
	if got := m.staleReach(); got != 20*24*time.Hour+envelope.MaxClockSkewFuture {
		t.Fatalf("20 days: %v", got)
	}
}

// #217 review 6: an entry that cannot be written back for holding is not
// delivered, told (case 1), at the caller's time.
func TestR30HoldMarshalFailNotDelivered(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e, in := f.waitingNote(0, "marshal")
	saved := marshalHeld
	marshalHeld = func(*envelope.Inner) ([]byte, error) { return nil, errors.New("test: cannot marshal") }
	t.Cleanup(func() { marshalHeld = saved })
	at := f.clk.Add(-time.Minute)
	f.do(0, func(m *Manager, p *Peer) { m.reholdAt(p, m.sessions[p.ID].Current(), true, at) })
	if !e.Done || !f.auditedRef(0, "undelivered_unreadable", in.ID) {
		t.Fatalf("done %v, told %v", e.Done, f.auditedRef(0, "undelivered_unreadable", in.ID))
	}
	for _, a := range f.m(0).st.Audit {
		if a.Event == "undelivered_unreadable" && !a.At.Equal(at) {
			t.Fatalf("audited at %v, want the caller's %v", a.At, at)
		}
	}
}

// #217 review 7: held_expired names the message's inner id.
func TestR30HeldExpiredRef(t *testing.T) {
	f := demoted(t, nil)
	var id string
	f.do(0, func(m *Manager, p *Peer) {
		id = m.sendWith(p, "test.note", []byte(`{"n":"exp"}`), SendOptions{Exp: f.clk.Add(time.Hour)}, f.clk)
	})
	f.advance(2 * time.Hour)
	f.tick(0)
	if id == "" || !f.auditedRef(0, "held_expired", id) {
		t.Fatal("drop.held_expired without the message's inner id")
	}
}

// #217 review 8: a run that ends stale still accounts for every note:
// waiting in its sender's outbox or told, else lost.
func TestR30StaleEndAccountsNotes(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.gotIDs = [3]map[string]int{{}, {}, {}}
	w := &rpWorld{t: t, f: f, ttlNote: map[string]bool{}, quotaNote: map[string]bool{}, staleNote: map[string]bool{}, fiveNote: map[string]bool{}, lockNote: map[string]bool{}}
	e, in := f.waitingNote(0, "kept")
	w.sent[0] = []string{in.ID}
	if why := w.notesUnaccounted(); len(why) != 0 {
		t.Fatalf("a note still waiting: %v", why)
	}
	f.do(0, func(m *Manager, p *Peer) { e.Done = true }) // gone, silently
	if why := w.notesUnaccounted(); len(why) != 1 || why[0] != "note-lost@0" {
		t.Fatalf("a note gone silently: %v, want note-lost@0", why)
	}
	f.do(0, func(m *Manager, p *Peer) { m.auditRef(f.clk, "undelivered_stale", p.ID, in.ID) })
	if why := w.notesUnaccounted(); len(why) != 0 {
		t.Fatalf("a note told: %v", why)
	}
}

// #217 review 3: an ephemeral entry sealed under an epoch whose send key
// is gone ends silently at a key change (never told as unreadable).
func TestR30EphemeralUnreadableSilent(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e, _ := f.waitingNote(0, "legacy-eph")
	f.do(0, func(m *Manager, p *Peer) {
		e.Ephemeral = true
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
	f.do(0, func(m *Manager, p *Peer) { m.resealAtKeyChange(p, m.sessions[p.ID]) })
	if !e.Done || f.audited(0, "undelivered_unreadable") {
		t.Fatalf("done %v, told %v: want ended silently", e.Done, f.audited(0, "undelivered_unreadable"))
	}
}

// #217 review 7: held_expired names the inner id when the expiry is found
// at sealing too.
func TestR30HeldExpiredRefAtSeal(t *testing.T) {
	f := demoted(t, nil)
	var id string
	f.do(0, func(m *Manager, p *Peer) {
		id = m.sendWith(p, "test.note", []byte(`{"n":"exp2"}`), SendOptions{Exp: f.clk.Add(time.Hour)}, f.clk)
	})
	f.advance(2 * time.Hour)
	m := f.m(0)
	m.mu.Lock()
	m.sealHeld(f.p(0))
	m.mu.Unlock()
	if id == "" || !f.auditedRef(0, "held_expired", id) {
		t.Fatal("drop.held_expired at sealing without the message's inner id")
	}
}

// #217 review 3: ephemeral entries are no member deposits: a removal ends
// them silently.
func TestR30EphemeralNotTold(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	e, _ := f.waitingNote(0, "eph-removed")
	f.do(0, func(m *Manager, p *Peer) {
		e.Ephemeral = true
		m.removePeer(p, "", f.clk)
	})
	if !e.Done || f.audited(0, "undelivered_removed") {
		t.Fatalf("done %v, told %v: want ended silently", e.Done, f.audited(0, "undelivered_removed"))
	}
}

// #217 final nits 1 and 2: replay_detected marks the entry possibly stored;
// a clock the relay keeps refusing (timestamp_stale) is noted once per
// entry.
func TestR30AttemptRefusals(t *testing.T) {
	for _, code := range []string{CodeReplayDetected, CodeTimestampStale} {
		f := newR29Fx(t)
		f.longTokens()
		r := f.d[0].relay
		r.mu.Lock()
		r.failMailbox = map[string]error{f.m(1).st.Relay.Mailbox: &relayclient.Error{Status: 401, Code: code}}
		r.mu.Unlock()
		var e *OutboxEntry
		f.do(0, func(m *Manager, p *Peer) {
			m.sendTo(p, "test.note", []byte(`{"n":"attempt"}`), f.clk)
			e = m.st.Outbox[len(m.st.Outbox)-1]
		})
		for i := 0; i < 5; i++ {
			f.do(0, func(m *Manager, p *Peer) { e.NotBefore = time.Time{} })
		}
		if e.Done {
			t.Fatalf("%s ended the entry", code)
		}
		if got := e.Tried; got != (code == CodeReplayDetected) {
			t.Fatalf("%s: tried %v", code, got)
		}
		if n := f.auditCount(0, "relay_clock_stale"); n != map[bool]int{true: 1, false: 0}[code == CodeTimestampStale] {
			t.Fatalf("%s: relay_clock_stale noted %d times", code, n)
		}
	}
}

// #217 final nit 3: an ephemeral entry queued before 0.88.7 (no flag) and
// still readable ends silently at a key change, by its type.
func TestR30LegacyEphemeralByType(t *testing.T) {
	f := newR29Fx(t)
	f.longTokens()
	f.do(0, func(m *Manager, p *Peer) {
		m.register(TypeSpec{Type: "test.eph", From: []string{KindConnection}, Connections: PeersBoth, Ephemeral: true},
			HandlerFunc(func(context.Context, *Session, *envelope.Inner) (json.RawMessage, error) { return nil, nil }))
	})
	f.waitingNote(0, "first")
	var eph *OutboxEntry
	f.do(0, func(m *Manager, p *Peer) {
		m.sendWith(p, "test.eph", []byte(`{}`), SendOptions{Exp: f.clk.Add(time.Hour)}, f.clk)
		eph = m.st.Outbox[len(m.st.Outbox)-1]
		eph.Ephemeral = false // as written before 0.88.7
		eph.NotBefore, eph.AwaitToken = f.clk.Add(365*24*time.Hour), true
	})
	f.do(0, func(m *Manager, p *Peer) { m.resealAtKeyChange(p, m.sessions[p.ID]) })
	if !eph.Done || f.audited(0, "undelivered_unreadable") {
		t.Fatalf("done %v, told %v: want ended silently", eph.Done, f.audited(0, "undelivered_unreadable"))
	}
}
