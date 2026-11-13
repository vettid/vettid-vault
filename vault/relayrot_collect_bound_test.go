package vault

import (
	"context"
	"testing"
	"time"
)

// An old mailbox whose collects keep failing (not mailbox_unknown) holds
// back the current mailbox's messages for oldFailBound at most; it is
// still collected, and after a collect that returns fewer than max its
// collected-to counts again.
func TestRelayRotFailingOldMailboxHoldsBackForABoundedTime(t *testing.T) {
	w := newRotWorld()
	t0 := time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC)
	clk := t0
	old := &collectPart{mailbox: "old", c: &rotCollector{w: w, mb: "old"}}
	cur := &collectPart{mailbox: "cur", c: &rotCollector{w: w, mb: "cur"}, main: true}
	c := &multiCollector{parts: []*collectPart{old, cur}, from: map[string]*collectPart{}, now: func() time.Time { return clk },
		idle: time.Millisecond, gone: func(string) {}, stopped: func(string) bool { return false }, given: func(string, []string) {}}
	next := func(at time.Duration) []Message {
		t.Helper()
		clk = t0.Add(at)
		out, err := c.Next(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	w.collectErr["old"] = relayErr(403, "forbidden")
	w.put("cur", "01A", t0.Add(-time.Hour), nil)
	if out := next(0); len(out) != 0 {
		t.Fatalf("released while the old mailbox was never collected: %d", len(out))
	}
	if out := next(oldFailBound - time.Second); len(out) != 0 {
		t.Fatalf("released before the bound: %d", len(out))
	}
	if out := next(oldFailBound); len(out) != 1 || out[0].MsgID != "01A" {
		t.Fatalf("held past the bound: %v", out)
	}
	if n := len(w.collects); n < 6 || w.collects[n-2] != "old" {
		t.Fatalf("the old mailbox is no longer collected: %v", w.collects)
	}
	// It collects again (fewer than max): its collected-to counts again,
	// and a later failure holds back anew.
	delete(w.collectErr, "old")
	if out := next(11 * time.Minute); len(out) != 0 {
		t.Fatalf("%v", out)
	}
	w.collectErr["old"] = relayErr(503, "")
	w.put("cur", "01B", t0.Add(11*time.Minute), nil)
	if out := next(15 * time.Minute); len(out) != 0 {
		t.Fatalf("released past the rejoined old mailbox's collected-to: %v", out)
	}
	if out := next(25 * time.Minute); len(out) != 1 || out[0].MsgID != "01B" {
		t.Fatalf("held past the bound again: %v", out)
	}
	if !old.unbound || old.failSince.IsZero() {
		t.Fatalf("old %+v", old)
	}
}
