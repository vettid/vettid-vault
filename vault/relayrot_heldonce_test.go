package vault

import (
	"context"
	"strings"
	"testing"
	"time"
)

// redeliverColl hands back the same message at every collect (the relay
// after each lease) until it is acked.
type redeliverColl struct{ acked bool }

func (c *redeliverColl) Next(context.Context) ([]Message, error) {
	if c.acked {
		return nil, nil
	}
	return []Message{{MsgID: "01A", DepositedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)}}, nil
}
func (c *redeliverColl) Ack(context.Context, string) error { c.acked = true; return nil }
func (c *redeliverColl) Close() error                      { return nil }

// failColl fails every collect until ok.
type failColl struct{ ok bool }

func (c *failColl) Next(context.Context) ([]Message, error) {
	if !c.ok {
		return nil, relayErr(503, "")
	}
	return nil, nil
}
func (c *failColl) Ack(context.Context, string) error { return nil }
func (c *failColl) Close() error                      { return nil }

// A message handed back while it is still held here (not yet released:
// an old mailbox holds the release back) is held once, and released once.
func TestRelayRotRedeliveryWhileHeldIsHeldOnce(t *testing.T) {
	old := &failColl{}
	c := &multiCollector{parts: []*collectPart{{mailbox: "old", c: old}, {mailbox: "cur", c: &redeliverColl{}, main: true}},
		from: map[string]*collectPart{}, now: time.Now, idle: time.Millisecond, gone: func(string) {}, stopped: func(string) bool { return false },
		given: func(string, []string) {}}
	for range 3 {
		if out, err := c.Next(context.Background()); err != nil || len(out) != 0 {
			t.Fatalf("released while the old mailbox holds it back: %d %v", len(out), err)
		}
	}
	if len(c.held) != 1 {
		t.Fatalf("held %d copies", len(c.held))
	}
	old.ok = true
	out, err := c.Next(context.Background())
	if err != nil || len(out) != 1 || out[0].MsgID != "01A" {
		t.Fatalf("released %v %v", out, err)
	}
}

// A message processed above a lower one still unprocessed (kept in Done)
// and given again (its ack lost) is not unprocessed again: it does not
// hold last_msg_id below itself.
func TestRelayRotGivenAgainAfterProcessingNotUnprocessed(t *testing.T) {
	t0 := time.Now()
	r := &MailboxCollect{}
	r.given("01", t0)
	r.given("02", t0)
	r.processed("02")
	r.advance()
	r.given("02", t0.Add(time.Minute))
	if strings.Join(r.Unprocessed, ",") != "01" {
		t.Fatalf("unprocessed %v", r.Unprocessed)
	}
	r.processed("01")
	r.advance()
	if r.LastMsgID != "02" {
		t.Fatalf("last %q", r.LastMsgID)
	}
}
