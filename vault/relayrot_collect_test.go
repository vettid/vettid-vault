package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// §3.4 "Collecting while a key is pending", §3.4 (a), §3.4.1 "Order of
// processing", §3.4.2 RK14 step 1: the vault's own mailboxes across its
// relay-key rotation.

// rotated is a rotFx after one completed rotation: its old mailbox and
// current one.
func rotated(t *testing.T) (fx *rotFx, old, cur string) {
	fx = newRotFx(t)
	old = fx.mailbox()
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	return fx, old, fx.mailbox()
}

func (fx *rotFx) step() int {
	fx.t.Helper()
	n, err := fx.m.Step(context.Background())
	if err != nil {
		fx.t.Fatal(err)
	}
	return n
}

func (fx *rotFx) worldLog() (collects, acks []string) {
	fx.w.mu.Lock()
	defer fx.w.mu.Unlock()
	return append([]string(nil), fx.w.collects...), append([]string(nil), fx.w.acks...)
}

func (fx *rotFx) old(i int) OldRelayKey {
	var o OldRelayKey
	fx.do(func(m *Manager) { o = m.st.Relay.Old[i] })
	return o
}

// After the second write the old mailbox is collected beside the current
// one; each round's messages from both are processed in (deposited_at,
// msg_id) order, and each is acked to the mailbox it came from.
func TestRelayRotCollectsBothMailboxesInOrder(t *testing.T) {
	fx, old, cur := rotated(t)
	t0 := fx.clk.Add(-10 * time.Minute)
	fx.w.put(old, "01A", t0.Add(2*time.Second), []byte("x"))
	fx.w.put(cur, "01B", t0.Add(1*time.Second), []byte("x"))
	fx.w.put(old, "01C", t0.Add(3*time.Second), []byte("x"))
	if n := fx.step(); n != 3 {
		t.Fatalf("collected %d", n)
	}
	collects, acks := fx.worldLog()
	if strings.Join(acks, ",") != cur+"/01B,"+old+"/01A,"+old+"/01C" {
		t.Fatalf("acks %v", acks)
	}
	if !strings.Contains(strings.Join(collects, ","), old) {
		t.Fatalf("old mailbox not collected: %v", collects)
	}
}

// Nothing deposited after the earliest collected-to time of the set is
// processed until every mailbox is collected past it: a collect start
// less the 90-second window.
func TestRelayRotHoldsWhatIsDepositedAfterCollectedTo(t *testing.T) {
	fx, old, _ := rotated(t)
	fx.w.put(old, "01A", fx.clk.Add(-30*time.Second), []byte("x"))
	if n := fx.step(); n != 0 {
		t.Fatalf("processed %d inside the freshness window", n)
	}
	fx.setClk(fx.clk.Add(2 * time.Minute))
	if n := fx.step(); n != 1 {
		t.Fatalf("processed %d once collected past it", n)
	}
}

// RK14 step 1: the old mailbox's collects end 13 days after its anchor,
// on the vault's clock, with last_msg_id kept and the telling queued in
// the write that records it; the old mailbox is not collected again.
func TestRelayRotOldMailboxStopsThirteenDaysAfterItsAnchor(t *testing.T) {
	fx, old, _ := rotated(t)
	anchor := fx.old(0).Anchor
	fx.w.put(old, "01A", fx.clk.Add(-5*time.Minute), []byte("x"))
	fx.step()
	if o := fx.old(0); o.Collect.LastMsgID != "01A" || !o.Collect.Stopped.IsZero() {
		t.Fatalf("before the stop %+v", o.Collect)
	}
	fx.setClk(anchor.Add(OldMailboxStop - time.Second))
	fx.step()
	if !fx.old(0).Collect.Stopped.IsZero() {
		t.Fatal("stopped before 13 days")
	}
	fx.setClk(anchor.Add(OldMailboxStop))
	fx.w.mu.Lock()
	fx.w.collects = nil
	fx.w.mu.Unlock()
	fx.step() // the collector built before the stop collects nothing more from it
	if collects, _ := fx.worldLog(); strings.Contains(strings.Join(collects, ","), old) {
		t.Fatalf("collected once the stop was due: %v", collects)
	}
	if o := fx.old(0); o.Collect.Stopped.IsZero() || !o.Collect.TellingDue || o.Collect.LastMsgID != "01A" {
		t.Fatalf("at 13 days %+v", o.Collect)
	}
	fx.w.mu.Lock()
	fx.w.collects = nil
	fx.w.mu.Unlock()
	fx.w.put(old, "01B", fx.clk.Add(-5*time.Minute), []byte("x"))
	fx.step()
	fx.crash()
	fx.step()
	if collects, _ := fx.worldLog(); strings.Contains(strings.Join(collects, ","), old) {
		t.Fatalf("collected after the stop: %v", collects)
	}
	if o := fx.old(0); o.Collect.Stopped.IsZero() {
		t.Fatal("the stop was not stored")
	}
}

// A second write made 13 days or more after the anchor stops the old
// mailbox's collects at once, in that write.
func TestRelayRotLateSecondWriteStopsAtOnce(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	fx.setClk(fx.clk.Add(OldMailboxStop + time.Hour))
	fx.restart()
	if o := fx.old(0); o.Collect.Stopped.IsZero() || !o.Collect.TellingDue {
		t.Fatalf("old %+v", o.Collect)
	}
}

// RK14 step 1: mailbox_unknown for an old mailbox ends its collects at
// once and for good, stored at once.
func TestRelayRotOldMailboxUnknownStopsAtOnce(t *testing.T) {
	fx, old, _ := rotated(t)
	fx.w.mu.Lock()
	fx.w.collectErr[old] = relayErr(404, CodeMailboxUnknown)
	fx.w.mu.Unlock()
	fx.step()
	if o := fx.old(0); o.Collect.Stopped.IsZero() || !o.Collect.TellingDue {
		t.Fatalf("old %+v", o.Collect)
	}
	fx.crash()
	if fx.old(0).Collect.Stopped.IsZero() {
		t.Fatal("not stored at once")
	}
}

// While a key is pending, mailbox_unknown for the current mailbox ends its
// collects for good (stored at once): the vault receives nothing from it,
// even in the refused state. The second write then queues its telling.
func TestRelayRotCurrentMailboxUnknownWhilePending(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(403, "forbidden")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	cur := fx.mailbox()
	fx.w.mu.Lock()
	fx.w.collectErr[cur] = relayErr(404, CodeMailboxUnknown)
	fx.w.mu.Unlock()
	if _, err := fx.m.Step(context.Background()); RelayCode(err) != CodeMailboxUnknown {
		t.Fatalf("step %v", err)
	}
	if err := fx.m.relayMailboxUnknown(context.Background()); err != nil {
		t.Fatal(err)
	}
	fx.m.Crash()
	m, _, err := fx.unlock(testPIN, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	fx.m = m
	var c MailboxCollect
	fx.do(func(m *Manager) { c = m.st.Relay.Collect })
	if c.Stopped.IsZero() || c.TellingDue {
		t.Fatalf("current %+v", c)
	}
	fx.w.rotate = []error{relayErr(403, "forbidden")} // the unlock's attempt is refused again
	if err := fx.m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	fx.w.mu.Lock()
	fx.w.collects = nil
	fx.w.mu.Unlock()
	fx.step()
	if collects, _ := fx.worldLog(); strings.Contains(strings.Join(collects, ","), cur) {
		t.Fatalf("collected the ended mailbox: %v", collects)
	}
	// A later unlock's attempt succeeds: the second write queues the
	// telling for the stopped mailbox.
	fx.restart()
	if fx.pending() != nil {
		t.Fatal("not completed")
	}
	if o := fx.old(0); o.Mailbox != cur || o.Collect.Stopped.IsZero() || !o.Collect.TellingDue {
		t.Fatalf("old %+v", o)
	}
}

// last_msg_id: the largest msg_id up to which every message given was
// processed and flushed; one left for redelivery holds it until it is
// processed.
func TestRelayRotLastMsgIDKeptPerMailbox(t *testing.T) {
	fx, _, _ := rotated(t)
	fx.do(func(m *Manager) {
		var c Collector = &fakeCollector{}
		rec := &m.st.Relay.Collect
		m.noteCollected(c, []Message{{MsgID: "03"}, {MsgID: "01"}, {MsgID: "02"}}, []bool{true, true, false})
		if rec.LastMsgID != "01" || rec.NoAckFloor != "02" {
			t.Fatalf("after a left message %+v", *rec)
		}
		m.noteCollected(c, []Message{{MsgID: "04"}}, []bool{true})
		if rec.LastMsgID != "01" {
			t.Fatalf("passed the floor %+v", *rec)
		}
		m.noteCollected(c, []Message{{MsgID: "02"}, {MsgID: "05"}}, []bool{true, true})
		if rec.LastMsgID != "05" || rec.NoAckFloor != "" {
			t.Fatalf("after the redelivery %+v", *rec)
		}
	})
}

// The mailbox a message was collected from travels with it (§3.4.1
// "Cut-off": a cut-off's mailbox, and "same mailbox" against it).
func TestRelayRotMessageCarriesItsMailbox(t *testing.T) {
	fx, old, _ := rotated(t)
	var got string
	fx.do(func(m *Manager) {
		m.register(TypeSpec{Type: "test.where", From: []string{KindApp}}, HandlerFunc(func(_ context.Context, _ *Session, _ *envelope.Inner) (json.RawMessage, error) {
			got = m.collectedFrom()
			return nil, nil
		}))
	})
	id, _ := envelope.NewULID(time.Now())
	raw, err := fx.ep.Seal(&envelope.Inner{ID: id, Type: "test.where", TS: time.Now(), Body: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	c := &oneMailboxCollector{mb: old}
	msg := Message{MsgID: "r1", Sender: fx.devSender(), Payload: raw}
	if err := fx.m.ProcessBatch(context.Background(), c, []Message{msg}); err != nil {
		t.Fatal(err)
	}
	if got != old {
		t.Fatalf("collected from %q, want %q", got, old)
	}
}

type oneMailboxCollector struct {
	fakeCollector
	mb string
}

func (c *oneMailboxCollector) mailboxOf(string) string { return c.mb }

// RK14 step 1 "The order once the anchor is old": while a key is pending
// and the current key's anchor is more than 13 days old, each collect of
// the current mailbox follows an attempt that got no 200 since the last
// one, whatever the sooner retries' wait.
func TestRelayRotOldAnchorAttemptsBeforeEachCollect(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, ""), relayErr(503, ""), relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	fx.setClk(fx.clk.Add(OldMailboxStop + time.Minute))
	fx.do(func(m *Manager) { m.rk.next = fx.clk.Add(time.Hour) })
	fx.step() // the rotation's own attempt got no 200: this collect needs none
	fx.step()
	fx.step()
	rot, _ := fx.w.log()
	if len(rot) != 3 {
		t.Fatalf("rotates %v: not one before each collect", rot)
	}
	fx.setClk(fx.clk.Add(-OldMailboxStop)) // a young anchor: the wait holds
	fx.do(func(m *Manager) { m.st.Relay.Anchor = fx.clk.Add(-time.Hour) })
	fx.step()
	if rot, _ := fx.w.log(); len(rot) != 3 {
		t.Fatalf("rotates %v with a young anchor", rot)
	}
}

func (fx *rotFx) devSender() string {
	var s string
	fx.do(func(m *Manager) { s = relayauth.EncodeKey(m.st.Devices["dev1"].Relay.PK) })
	return s
}

// The timed stop is made at each batch too (without a collect), and an
// old key with no anchor stops at once (a reading of this release).
func TestRelayRotStopAtTheBatchAndWithoutAnAnchor(t *testing.T) {
	fx, _, _ := rotated(t)
	fx.setClk(fx.old(0).Anchor.Add(OldMailboxStop))
	fx.batch()
	if fx.old(0).Collect.Stopped.IsZero() {
		t.Fatal("not stopped at the batch")
	}
	fx2, _, _ := rotated(t)
	fx2.do(func(m *Manager) {
		m.st.Relay.Old[0].Anchor = time.Time{}
		if !m.stopOldCollects(m.now()) {
			t.Fatal("an old key with no anchor is still collected")
		}
	})
}

// mailbox_unknown for the current mailbox with no key pending ends
// nothing: such a key registers again (§12.2).
func TestRelayRotCurrentMailboxUnknownWithoutAPendingKey(t *testing.T) {
	fx := newRotFx(t)
	fx.do(func(m *Manager) {
		if m.mailboxGone(m.st.Relay.Mailbox, m.now()) || !m.st.Relay.Collect.Stopped.IsZero() {
			t.Fatal("stopped the current mailbox with no key pending")
		}
	})
}

// §3.4.1 "Cut-off" across the vault's own mailboxes: a follow records the
// mailbox its message was collected from; a message from another of the
// vault's mailboxes is judged by its deposited_at, not its msg_id.
func TestRelayRotCutOffUsesTheCollectMailbox(t *testing.T) {
	fx, old, cur := rotated(t)
	fx.do(func(m *Manager) {
		p := m.st.Connections["c1"]
		k0 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, 32)) // c1's (asConnection's seed + 1)
		k1 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x91}, 32))
		cut := fx.clk.Add(-time.Hour)
		m.relayAt, m.msgID, m.msgMailbox = cut, "05", old
		if err := m.followRelayLinks(p, []*handshake.RelayLink{rkLink(t, k0, k1)}, rkAddr(k1)); err != nil {
			t.Fatal(err)
		}
		if e := p.EarlierRelays[len(p.EarlierRelays)-1]; e.CutMailbox != old {
			t.Fatalf("cut-off mailbox %q", e.CutMailbox)
		}
		// The same mailbox: by msg_id (an earlier one, deposited later).
		m.relayAt, m.msgID = cut.Add(time.Minute), "01"
		if s := m.relayStateOf(p, pubOf(k0)); s != relayEarlierBefore {
			t.Fatalf("state in the cut-off's mailbox %v", s)
		}
		// Another of the vault's mailboxes: by deposited_at.
		m.msgMailbox = cur
		if s := m.relayStateOf(p, pubOf(k0)); s != relayEarlierAfter {
			t.Fatalf("state in another mailbox %v", s)
		}
		m.relayAt, m.msgID, m.msgMailbox = time.Time{}, "", ""
	})
}
