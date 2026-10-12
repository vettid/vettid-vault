package vault

import (
	"testing"
	"time"
)

// VAULT-RELAY-SCALING §4 G: a poll waits a random whole number of
// seconds from 20 to 25, so vaults do not stay in step.
func TestPollWaitSpread(t *testing.T) {
	seen := map[time.Duration]int{}
	for i := 0; i < 2000; i++ {
		seen[pollWait(LongPollWait, LongPollSpread)]++
	}
	for d := 20 * time.Second; d <= 25*time.Second; d += time.Second {
		if seen[d] == 0 {
			t.Errorf("no poll waited %v", d)
		}
		delete(seen, d)
	}
	if len(seen) != 0 {
		t.Errorf("waits outside 20 to 25 whole seconds: %v", seen)
	}
	// A collector with a wait of its own (tests) does not vary it.
	if d := pollWait(time.Second, 0); d != time.Second {
		t.Errorf("fixed wait: %v", d)
	}
}

// The retry after a failed poll is never a fixed interval; it grows only
// while the relay keeps refusing the vault's polls (mailbox_unknown,
// timestamp_stale), up to about a minute.
func TestRetryWait(t *testing.T) {
	for _, c := range []struct {
		refused  int
		min, max time.Duration
	}{{0, 500 * time.Millisecond, 1500 * time.Millisecond}, {1, 500 * time.Millisecond, 1500 * time.Millisecond},
		{2, time.Second, 3 * time.Second}, {4, 4 * time.Second, 12 * time.Second}, {7, 30 * time.Second, 90 * time.Second},
		{1000, 30 * time.Second, 90 * time.Second}} {
		seen := map[time.Duration]bool{}
		for i := 0; i < 200; i++ {
			d := retryWait(c.refused)
			if d < c.min || d > c.max {
				t.Fatalf("refused %d times: wait %v outside %v to %v", c.refused, d, c.min, c.max)
			}
			seen[d] = true
		}
		if len(seen) < 100 {
			t.Errorf("refused %d times: only %d different waits in 200", c.refused, len(seen))
		}
	}
}
