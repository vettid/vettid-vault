package vault

import (
	"testing"
	"time"
)

// VAULT-MESSAGING 0.24.0 §14.2 "Debounce and limits", on the pure
// scheduler with explicit times.

func testSched() wakeSched {
	t := DefaultPushTiming
	t.Jitter = 0
	return newWakeSched(t)
}

var t0 = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

// send runs the pending wake at its time and reports it.
func sendAt(t *testing.T, s *wakeSched, now time.Time, r wakeResult) time.Time {
	t.Helper()
	at, ok := s.next(now)
	if !ok {
		t.Fatal("nothing pending")
	}
	s.start(at)
	s.done(at, r, 0)
	return at
}

func TestSchedDebounceAndMerge(t *testing.T) {
	s := testSched()
	if _, ok := s.next(t0); ok {
		t.Fatal("pending without a trigger")
	}
	s.trigger(false)
	if at, ok := s.next(t0); !ok || !at.Equal(t0) {
		t.Fatalf("first wake at %v", at)
	}
	s.start(t0)
	// In flight: nothing else goes; triggers wait for a later wake.
	s.trigger(false)
	if _, ok := s.next(t0.Add(time.Second)); ok {
		t.Fatal("second wake while one is in flight")
	}
	s.done(t0.Add(time.Second), wakeSent, 0)
	// Less than 5 s after the last wake: deferred until 5 s after it, and
	// every trigger meanwhile merges.
	s.trigger(false)
	s.trigger(true)
	at, ok := s.next(t0.Add(2 * time.Second))
	if !ok || !at.Equal(t0.Add(5*time.Second)) {
		t.Fatalf("deferred to %v", at)
	}
	s.start(at)
	s.done(at, wakeSent, 0)
	if _, ok := s.next(at.Add(time.Minute)); ok {
		t.Fatal("merged triggers sent twice")
	}
	if len(s.hour) != 2 || len(s.exemptHour) != 1 {
		t.Fatalf("counted %d / %d", len(s.hour), len(s.exemptHour))
	}
}

func TestSchedHourlyCap(t *testing.T) {
	s := testSched()
	now := t0
	for i := 0; i < 30; i++ {
		s.trigger(false)
		now = sendAt(t, &s, now, wakeSent).Add(10 * time.Second)
	}
	last := s.last
	// The 31st: at most one per 10 minutes past the cap.
	s.trigger(false)
	at, _ := s.next(now)
	if !at.Equal(last.Add(10 * time.Minute)) {
		t.Fatalf("over cap at %v, want %v", at, last.Add(10*time.Minute))
	}
	s.start(at)
	s.done(at, wakeSent, 0)
	// And again 10 minutes after that one.
	s.trigger(false)
	if at2, _ := s.next(at); !at2.Equal(at.Add(10 * time.Minute)) {
		t.Fatalf("next over cap at %v", at2)
	}
}

func TestSchedCapFallsBelow(t *testing.T) {
	s := testSched()
	// 30 wakes in the first 5 minutes.
	for i := 0; i < 30; i++ {
		s.trigger(false)
		sendAt(t, &s, t0.Add(time.Duration(i)*10*time.Second), wakeSent)
	}
	// Long after: the count fell below 30 when the first wake left the
	// hour, which is before last + 10 min? No: last + 10 min is earlier.
	s.trigger(false)
	at, _ := s.next(t0.Add(58 * time.Minute))
	if !at.Equal(t0.Add(58 * time.Minute)) {
		t.Fatalf("at %v", at) // 10 minutes since the last wake have passed
	}
	// With a recent last wake, the count falling below the cap decides.
	s = testSched()
	for i := 0; i < 30; i++ {
		s.trigger(false)
		sendAt(t, &s, t0.Add(time.Duration(i)*2*time.Minute), wakeSent) // the 30th at 58 min
	}
	s.trigger(false)
	at, _ = s.next(t0.Add(58*time.Minute + 30*time.Second))
	if want := t0.Add(time.Hour); !at.Equal(want) {
		t.Fatalf("at %v, want %v (the first wake leaves the hour)", at, want)
	}
}

func TestSchedExemptUpToTen(t *testing.T) {
	s := testSched()
	now := t0
	for i := 0; i < 30; i++ {
		s.trigger(false)
		now = sendAt(t, &s, now, wakeSent).Add(10 * time.Second)
	}
	// Exempt triggers skip the cap (still debounced) up to 10 per hour,
	// and count toward it.
	for i := 0; i < 10; i++ {
		s.trigger(true)
		at, _ := s.next(now)
		if want := later(now, s.last.Add(5*time.Second)); !at.Equal(want) {
			t.Fatalf("exempt %d at %v, want %v", i, at, want)
		}
		s.start(at)
		s.done(at, wakeSent, 0)
		now = at.Add(time.Second)
	}
	if len(s.hour) != 40 {
		t.Fatalf("hour count %d", len(s.hour))
	}
	s.trigger(true)
	if at, _ := s.next(now); !at.Equal(s.last.Add(10 * time.Minute)) {
		t.Fatalf("11th exempt at %v", at)
	}
}

func TestSchedRetries(t *testing.T) {
	s := testSched()
	s.trigger(false)
	at := sendAt(t, &s, t0, wakeFailed)
	for i, d := range []time.Duration{5 * time.Second, 30 * time.Second, 120 * time.Second} {
		n, ok := s.next(at)
		if !ok || !n.Equal(at.Add(d)) {
			t.Fatalf("retry %d at %v, want +%v", i, n, d)
		}
		s.start(n)
		s.done(n, wakeFailed, 0)
		at = n
	}
	if _, ok := s.next(at.Add(time.Hour)); ok {
		t.Fatal("wake not dropped after three retries")
	}
	if len(s.hour) != 1 {
		t.Fatalf("retries counted as wakes: %d", len(s.hour))
	}
	// Jitter stays within ±20 %.
	for i := 0; i < 100; i++ {
		if d := jitter(time.Second, 0.2); d < 800*time.Millisecond || d > 1200*time.Millisecond {
			t.Fatal(d)
		}
	}
}

func TestSchedRateLimited(t *testing.T) {
	s := testSched()
	s.trigger(false)
	s.start(t0)
	s.trigger(true) // merges into the retried wake
	s.done(t0, wakeRateLimited, 90*time.Second)
	if at, ok := s.next(t0); !ok || !at.Equal(t0.Add(90*time.Second)) || !s.exempt {
		t.Fatalf("at %v %v", at, s.exempt)
	}
	s.start(t0.Add(90 * time.Second))
	s.done(t0.Add(90*time.Second), wakeRateLimited, 10*time.Hour)
	if at, _ := s.next(t0); !at.Equal(t0.Add(90*time.Second + time.Hour)) {
		t.Fatalf("retry_after not capped at an hour: %v", at)
	}
	s.start(t0)
	s.done(t0, wakeGone, 0)
	if _, ok := s.next(t0); ok || len(s.hour) != 0 {
		t.Fatal("gone keeps state")
	}
}
