package vault

import (
	"errors"
	"testing"
)

// A repeated recovery open makes the same event as a first open
// (§11.14.6 step 6, §11.14.2): the vault's keys rotated, or the rotation
// owed when it cannot be made.

func countActs(sink *recSink, kind string) int {
	n := 0
	for _, a := range sink.got {
		if a.Kind == kind {
			n++
		}
	}
	return n
}

// The first open's state write (step 2) fails after step 1 is stored; the
// repeat through the `next` wrap rotates the keys, as the first open did
// in the state that was not stored.
func TestRecoveryRepeatAfterStep1RotatesTheKeys(t *testing.T) {
	f := newOpenFixture(t)
	sink := &recSink{}
	f.opts.Features = append(f.opts.Features, sink)
	f.st.failState = 1
	if m, out := f.open(testPIN, rPW); m != nil || out.Code != OpenRetry || !out.Counted {
		t.Fatalf("first open: %+v", out)
	}
	sink.got = nil
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK || out.Counted {
		t.Fatalf("repeat: %+v", out)
	}
	defer m.Crash()
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.st.RotatedAt.Equal(f.clock) || len(m.st.Rotations) != 1 || m.st.RotationOwed != nil {
		t.Fatalf("rotated at %v, rotations %d, owed %+v", m.st.RotatedAt, len(m.st.Rotations), m.st.RotationOwed)
	}
	if countActs(sink, "identity.rotated") != 1 {
		t.Fatalf("identity.rotated %d", countActs(sink, "identity.rotated"))
	}
}

// The same when the rotation cannot be made: the repeat stores the
// rotation owed (ref = recovery_id) and audits identity.rotation_failed.
func TestRecoveryRepeatAfterStep1OwesAFailedRotation(t *testing.T) {
	f := newOpenFixture(t)
	sink := &recSink{}
	f.opts.Features = append(f.opts.Features, sink)
	f.opts.KeyRand = func(int) ([]byte, error) { return nil, errors.New("no randomness") }
	f.st.failState = 1
	if m, out := f.open(testPIN, rPW); m != nil || out.Code != OpenRetry {
		t.Fatalf("first open: %+v", out)
	}
	sink.got = nil
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("repeat: %+v", out)
	}
	defer m.Crash()
	m.mu.Lock()
	defer m.mu.Unlock()
	if o := m.st.RotationOwed; o == nil || o.Recovery != recID || !m.st.RotatedAt.IsZero() {
		t.Fatalf("owed %+v, rotated at %v", o, m.st.RotatedAt)
	}
	if countActs(sink, "identity.rotation_failed") != 1 {
		t.Fatalf("identity.rotation_failed %d", countActs(sink, "identity.rotation_failed"))
	}
}

// A repeat whose step 2 was stored makes no event of its own: the stored
// state already holds the first open's rotation, and nothing rotates
// again.
func TestRecoveryRepeatAfterStep2DoesNotRotateAgain(t *testing.T) {
	f := newOpenFixture(t)
	f.st.passHeader, f.st.failHeader = 1, 1 // step 1 written; step 3's header write fails
	if m, out := f.open(testPIN, rPW); m != nil || out.Code != OpenRetry {
		t.Fatalf("first open: %+v", out)
	}
	if h := f.storedHeader(); h.Next == nil || f.storedStateVersion() != h.Next.DEKVersion {
		t.Fatal("not a completion stopped after step 2")
	}
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("repeat: %+v", out)
	}
	defer m.Crash()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.st.Rotations) != 1 || m.st.RotationOwed != nil {
		t.Fatalf("rotations %d, owed %+v", len(m.st.Rotations), m.st.RotationOwed)
	}
}
