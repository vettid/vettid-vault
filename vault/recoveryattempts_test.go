package vault

import (
	"context"
	"testing"
	"time"
)

// The counter's record at a completed recovery (VAULT-MESSAGING §11.14.11,
// "The record a host cannot drop"): the completion reads the counter's
// status after its state is stored and writes recovery.attempt for each
// attempt, and recovery.attempts_used, once; the next owner check adds
// nothing it already wrote; a completion that fails writes nothing.

// attemptRefs is the refs of the sink's recovery.attempt and
// recovery.attempts_used activities, in order.
func attemptRefs(s *recSink) (attempts, used []string) {
	for _, a := range s.got {
		switch a.Kind {
		case "recovery.attempt":
			attempts = append(attempts, a.Ref)
		case "recovery.attempts_used":
			used = append(used, a.Ref)
		}
	}
	return attempts, used
}

func sameRefs(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// ownerCheckAttempts runs the recovery part of a passed owner check on m.
func ownerCheckAttempts(m *Manager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ownerCheckRecovery(context.Background(), testPIN, []byte(rPW), 0, true, m.now())
}

func flushManager(t *testing.T, m *Manager) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.flushIfDirty(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryOpenWritesTheCounterRecord(t *testing.T) {
	f := newOpenFixture(t)
	sink := &recSink{}
	f.opts.Features = append(f.opts.Features, sink)
	if m, out := f.open(testPIN, "wrong password one"); m != nil || out.Code != OpenWrong || out.Used != 1 {
		t.Fatalf("wrong: %+v", out)
	}
	if a, u := attemptRefs(sink); len(a)+len(u) != 0 {
		t.Fatalf("a wrong pair wrote the record: %v %v", a, u)
	}
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK || out.Used != 2 {
		t.Fatalf("right pair: %+v", out)
	}
	want := []string{"1/1/not_success/counter", "1/2/success/counter"}
	a, u := attemptRefs(sink)
	if !sameRefs(a, want) || !sameRefs(u, []string{"1/2"}) {
		t.Fatalf("at the completion: attempts %v, used %v", a, u)
	}
	for _, x := range sink.got {
		if x.Kind == "recovery.attempt" && (x.Priority != "" || !x.Audit || !x.Feed) {
			t.Fatalf("attempt in the recovered generation: %+v", x)
		}
	}
	// Stored with the next flush: the recovered phone's next owner check
	// adds nothing.
	flushManager(t, m)
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.clock = f.clock.Add(time.Hour)
	m2 := f.mustUnlock(testPIN, f.phoneUS)
	defer m2.Crash()
	ownerCheckAttempts(m2)
	if a, u := attemptRefs(sink); !sameRefs(a, want) || !sameRefs(u, []string{"1/2"}) {
		t.Fatalf("after the owner check: attempts %v, used %v", a, u)
	}
}

// A completion that fails at its state write writes no record; the resume
// through the `next` wrap (no new attempt) writes it once, with the success.
func TestRecoveryOpenFailedCompletionWritesNoRecord(t *testing.T) {
	f := newOpenFixture(t)
	sink := &recSink{}
	f.opts.Features = append(f.opts.Features, sink)
	f.st.failState = 1
	if m, out := f.open(testPIN, rPW); m != nil || out.OK || out.Code != OpenRetry || !out.Counted {
		t.Fatalf("failed completion: %+v", out)
	}
	if a, u := attemptRefs(sink); len(a)+len(u) != 0 {
		t.Fatalf("a failed completion wrote the record: %v %v", a, u)
	}
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK || out.Counted {
		t.Fatalf("resume: %+v", out)
	}
	want := []string{"1/1/success/counter"}
	a, u := attemptRefs(sink)
	if !sameRefs(a, want) || !sameRefs(u, []string{"1/1"}) {
		t.Fatalf("at the resume: attempts %v, used %v", a, u)
	}
	for _, x := range sink.got {
		if x.Kind == "recovery.attempt" && x.Priority != "" {
			t.Fatalf("attempt in the recovered generation: %+v", x)
		}
	}
	flushManager(t, m)
	ownerCheckAttempts(m)
	if a, u := attemptRefs(sink); !sameRefs(a, want) || !sameRefs(u, []string{"1/1"}) {
		t.Fatalf("after the owner check: attempts %v, used %v", a, u)
	}
	m.Crash()
}

// A completion whose step-3 header write fails: its state (step 2) is
// stored but the run answers retry and writes no record; the repeat after
// step 2 writes it once.
func TestRecoveryOpenPartialCompletionWritesNoRecord(t *testing.T) {
	f := newOpenFixture(t)
	sink := &recSink{}
	f.opts.Features = append(f.opts.Features, sink)
	f.st.passHeader, f.st.failHeader = 1, 1
	if m, out := f.open(testPIN, rPW); m != nil || out.Code != OpenRetry || !out.Counted {
		t.Fatalf("failed step 3: %+v", out)
	}
	if a, u := attemptRefs(sink); len(a)+len(u) != 0 {
		t.Fatalf("a partial completion wrote the record: %v %v", a, u)
	}
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK || out.Counted {
		t.Fatalf("repeat: %+v", out)
	}
	defer m.Crash()
	if a, u := attemptRefs(sink); !sameRefs(a, []string{"1/1/success/counter"}) || !sameRefs(u, []string{"1/1"}) {
		t.Fatalf("at the repeat: attempts %v, used %v", a, u)
	}
}
