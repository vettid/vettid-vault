package vault

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// The re-check's round: messages left unacked handed back, ids the relay
// no longer has, and blobs looked for in every own mailbox.

// leaseColl hands back a message until it is acked (the relay after a
// lease).
type leaseColl struct{ acked map[string]bool }

func (c *leaseColl) Next(context.Context) ([]Message, error) {
	if c.acked["01A"] {
		return nil, nil
	}
	return []Message{{MsgID: "01A", DepositedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)}}, nil
}
func (c *leaseColl) Ack(_ context.Context, id string) error { c.acked[id] = true; return nil }
func (c *leaseColl) Close() error                           { return nil }

// A message a batch left unacked (rule T's deferral, an inactive epoch) is
// released again when the relay hands it back, and its ack still goes to
// its mailbox.
func TestRelayRotRedeliveryAfterNoAckReleasedAgain(t *testing.T) {
	lc := &leaseColl{acked: map[string]bool{}}
	c := &multiCollector{parts: []*collectPart{{mailbox: "old", c: lc}, {mailbox: "cur", c: &leaseColl{acked: map[string]bool{"01A": true}}, main: true}},
		from: map[string]*collectPart{}, now: time.Now, idle: time.Millisecond, gone: func(string) {}, stopped: func(string) bool { return false },
		given: func(string, []string) {}}
	if out, _ := c.Next(context.Background()); len(out) != 1 {
		t.Fatalf("first %d", len(out))
	}
	// Left unacked: the relay hands it back after the lease.
	if out, _ := c.Next(context.Background()); len(out) != 1 {
		t.Fatal("a message left unacked is not released again")
	}
	if err := c.Ack(context.Background(), "01A"); err != nil || !lc.acked["01A"] {
		t.Fatal("the ack did not reach its mailbox")
	}
}

// An id given and never handed back again by a full drain of its mailbox
// more than two leases later (acked before a crash undid its processing,
// or dropped by the relay) no longer holds last_msg_id; one within that
// time, one handed back, or one still held does; a ceiling ages out the
// same way, once nothing from the mailbox is held or unprocessed.
func TestRelayRotUnhandedIDsPruned(t *testing.T) {
	t0 := time.Now()
	bound := 3 * time.Minute
	r := &MailboxCollect{}
	r.given("02", t0)
	r.given("03", t0)
	r.given("04", t0)
	r.processed("05")
	r.Ceiling, r.CeilingAt = "09", t0
	r.pruneUnhanded(map[string]bool{"03": true}, map[string]bool{"04": true}, t0.Add(bound-time.Second), bound)
	if len(r.Unprocessed) != 3 || r.Ceiling == "" {
		t.Fatalf("pruned within the bound: %+v", r)
	}
	r.pruneUnhanded(map[string]bool{"03": true}, map[string]bool{"04": true}, t0.Add(bound+time.Second), bound)
	if strings.Join(r.Unprocessed, ",") != "03,04" || r.Ceiling != "09" || r.GivenAt["02"] != (time.Time{}) {
		t.Fatalf("after the bound: %+v", r)
	}
	r.processed("03")
	r.processed("04")
	r.pruneUnhanded(nil, map[string]bool{"07": true}, t0.Add(bound+2*time.Second), bound)
	if r.Ceiling != "09" {
		t.Fatalf("ceiling cleared while a message is held: %+v", r)
	}
	r.pruneUnhanded(nil, nil, t0.Add(bound+3*time.Second), bound)
	if r.Ceiling != "" || r.LastMsgID != "05" {
		t.Fatalf("last %q, ceiling %q", r.LastMsgID, r.Ceiling)
	}
}

// The same through the collector: a message of the old mailbox the relay
// dropped stops holding last_msg_id after a later drain.
func TestRelayRotDroppedMessageReleasesLastMsgID(t *testing.T) {
	fx, old, _ := rotated(t)
	fx.w.put(old, "01A", fx.clk.Add(-time.Hour), []byte("x"))
	fx.do(func(m *Manager) {
		m.limits.VisibilityTimeoutSeconds = 30
		m.noteGiven(old, []string{"01A"})
	})
	fx.w.mu.Lock()
	fx.w.queue[old] = nil // the relay no longer has it
	fx.w.mu.Unlock()
	fx.w.put(old, "01B", fx.clk.Add(-time.Hour), []byte("x"))
	fx.setClk(fx.clk.Add(10 * time.Minute))
	fx.step()
	fx.step()
	if c := fx.old(0).Collect; c.LastMsgID != "01B" || len(c.Unprocessed) != 0 {
		t.Fatalf("collect %+v", c)
	}
}

// A blob recorded without a mailbox (before the first rotation, or with
// the switch off: the then-current one) or in the wrong own mailbox (a
// peer that changed the vault's address between its upload and its
// deposit) is looked for in the other own mailboxes still collected.
func TestRelayRotBlobLookedForInEveryOwnMailbox(t *testing.T) {
	fx, old, cur := rotated(t)
	content := append([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, bytes.Repeat([]byte{5}, 64)...)
	data, key, sum, err := envelope.SealBlob(content)
	if err != nil {
		t.Fatal(err)
	}
	fx.w.mu.Lock()
	fx.w.blobs[old] = map[string][]byte{"B6": data}
	fx.w.mu.Unlock()
	for _, mb := range []string{"", cur} {
		b := AttBlob{ID: "B6", Key: key, SHA256: sum[:], Size: len(content), Mailbox: mb}
		if got, _, why, err := fx.m.fetchBlob(context.Background(), b, 0); err != nil || !bytes.Equal(got, content) {
			t.Fatalf("recorded %q: %q %v", mb, why, err)
		}
	}
	fx.m.deleteBlobIn(context.Background(), cur, "B6")
	fx.w.mu.Lock()
	_, left := fx.w.blobs[old]["B6"]
	fx.w.mu.Unlock()
	if left {
		t.Fatal("the deletion did not reach the mailbox that holds it")
	}
}

// Attachment maintenance in an old mailbox still collected: a device's
// discarded upload nothing names is deleted there, and an orphan older
// than 24 hours is purged there; a fresh one stays.
func TestRelayRotDiscardAndPurgeInTheOldMailbox(t *testing.T) {
	fx, old, _ := rotated(t)
	fx.w.mu.Lock()
	fx.w.blobs[old] = map[string][]byte{"D1": {1}, "P1": {1}, "Q1": {1}}
	fx.w.blobInfo[old+"/D1"] = BlobEntry{Sender: "S", CreatedAt: fx.clk.UTC().Format(time.RFC3339)}
	fx.w.blobInfo[old+"/P1"] = BlobEntry{CreatedAt: fx.clk.Add(-48 * time.Hour).UTC().Format(time.RFC3339)}
	fx.w.blobInfo[old+"/Q1"] = BlobEntry{CreatedAt: fx.clk.UTC().Format(time.RFC3339)}
	fx.w.blobDeletes = nil
	fx.w.mu.Unlock()
	var r *attRunner
	fx.do(func(m *Manager) { r = m.att })
	if r == nil {
		t.Fatal("no attachment runner")
	}
	fx.m.attMaintain(r, &attWork{discards: []attDiscard{{blob: "D1", sender: "S"}}, needList: true, purge: true})
	fx.w.mu.Lock()
	dels := strings.Join(fx.w.blobDeletes, ",")
	fx.w.mu.Unlock()
	if !strings.Contains(dels, old+"/D1") || !strings.Contains(dels, old+"/P1") || strings.Contains(dels, old+"/Q1") {
		t.Fatalf("deletes %s", dels)
	}
}

// The current mailbox's own collector (no old one collected): a batch of
// fewer than max is a drain that prunes what the relay no longer has; a
// full batch is not.
func TestRelayRotSingleCollectorDrainPrunes(t *testing.T) {
	fx := newRotFx(t)
	fx.do(func(m *Manager) {
		m.limits.VisibilityTimeoutSeconds = 30
		m.noteGiven(m.st.Relay.Mailbox, []string{"05"})
	})
	fx.setClk(fx.clk.Add(10 * time.Minute))
	full := make([]Message, MaxBatch)
	for i := range full {
		full[i] = Message{MsgID: "x" + strings.Repeat("0", 3) + string(rune('a'+i%26)) + string(rune('a'+i/26))}
	}
	if err := fx.m.ProcessBatch(context.Background(), &fakeCollector{}, full); err != nil {
		t.Fatal(err)
	}
	var u []string
	fx.do(func(m *Manager) { u = append([]string(nil), m.st.Relay.Collect.Unprocessed...) })
	if len(u) == 0 || u[0] != "05" {
		t.Fatalf("pruned by a full batch: %v", u)
	}
	fx.batch()
	fx.do(func(m *Manager) { u = m.st.Relay.Collect.Unprocessed })
	if len(u) != 0 {
		t.Fatalf("not pruned by a drain: %v", u)
	}
}

// A relay that gave no visibility timeout: nothing is pruned (fail
// closed), however long ago the message was given.
func TestRelayRotNoPruneWithoutAVisibilityTimeout(t *testing.T) {
	fx := newRotFx(t)
	fx.do(func(m *Manager) {
		m.limits.VisibilityTimeoutSeconds = 0
		m.noteGiven(m.st.Relay.Mailbox, []string{"05"})
	})
	fx.setClk(fx.clk.Add(24 * time.Hour))
	fx.batch()
	var u []string
	fx.do(func(m *Manager) { u = m.st.Relay.Collect.Unprocessed })
	if len(u) != 1 || u[0] != "05" {
		t.Fatalf("pruned without a visibility timeout: %v", u)
	}
}
