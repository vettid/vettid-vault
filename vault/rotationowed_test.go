package vault

import (
	"context"
	"errors"
	"testing"
)

// §11.14.6 step 6, §11.14.10 "The owed mark" and "Failure": a completed
// recovery rotates the vault's keys, and a rotation that cannot be made
// never fails the recovery: the state holds a rotation owed (ref = the
// recovery_id), audited identity.rotation_failed, which the next unlock
// retries. One rotation clears the mark and is audited identity.rotated
// with ref "recovery" (0.69.2).
func TestFailedRecoveryRotationIsRetriedAtTheNextUnlock(t *testing.T) {
	sink := &recSink{}
	f := newOpenFixture(t)
	f.opts.Features = append(f.opts.Features, sink)
	broken := errors.New("no entropy")
	f.opts.KeyRand = func(int) ([]byte, error) { return nil, broken }

	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("a rotation that cannot be made failed the recovery: %+v", out)
	}
	if len(m.st.Rotations) != 0 {
		t.Fatal("the rotation was made")
	}
	var failed int
	for _, a := range sink.got {
		if a.Kind == "identity.rotation_failed" && a.Ref == "recovery" && a.Audit {
			failed++
		}
	}
	if failed != 1 {
		t.Fatalf("identity.rotation_failed audited %d times", failed)
	}
	if m.st.RotationOwed == nil || m.st.RotationOwed.Recovery != recID {
		t.Fatalf("no rotation owed after a failure: %+v", m.st.RotationOwed)
	}
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}

	// The owed mark is in the stored state. Until the recovered phone has
	// paired (its recovery invite is pending) an unlock leaves it: the
	// phone's first handshake verifies the identity key it was given.
	f.opts.KeyRand = nil
	sink.got = nil
	m2 := f.mustUnlock(testPIN, f.phoneUS)
	defer m2.Crash()
	if m2.st.RotationOwed == nil || m2.st.RotationOwed.Recovery != recID || len(m2.st.Rotations) != 0 {
		t.Fatalf("the stored state lost the mark: %+v, %d rotations", m2.st.RotationOwed, len(m2.st.Rotations))
	}
	if err := m2.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(m2.st.Rotations) != 0 || m2.st.RotationOwed == nil || sink.has("identity.rotated") {
		t.Fatal("rotated while the recovered phone has not paired")
	}
	// The phone has paired (recoveredPhonePaired deletes the invite): the
	// next unlock, or the pairing itself, makes the rotation.
	m2.mu.Lock()
	for id, inv := range m2.st.Invites {
		if inv.CreatedBy == inviteByRecovery {
			delete(m2.st.Invites, id)
		}
	}
	m2.retryOwedRotation(m2.now())
	m2.mu.Unlock()
	if len(m2.st.Rotations) != 1 || m2.st.RotationOwed != nil {
		t.Fatalf("not retried after the pairing: %d rotations, owed %+v", len(m2.st.Rotations), m2.st.RotationOwed)
	}
	var rotated []Activity
	for _, a := range sink.got {
		if a.Kind == "identity.rotated" {
			rotated = append(rotated, a)
		}
	}
	if len(rotated) != 1 || rotated[0].Ref != "recovery" || !rotated[0].Audit {
		t.Fatalf("identity.rotated: %+v", rotated)
	}

	// Cleared, so a later unlock does not rotate again.
	if err := m2.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	m3 := f.mustUnlock(testPIN, f.phoneUS)
	defer m3.Crash()
	if err := m3.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(m3.st.Rotations) != 1 {
		t.Fatalf("rotated again at a later unlock: %d", len(m3.st.Rotations))
	}
}

// A failure at the retry keeps the mark and does not fail the unlock; a
// recovery whose rotation succeeds owes nothing, and its identity.rotated
// carries ref "recovery"; a rotation made on request with no mark owed has
// no ref.
func TestRotationOwedKeptOnRetryFailureAndClearedByAnyRotation(t *testing.T) {
	sink := &recSink{}
	f := newOpenFixture(t)
	f.opts.Features = append(f.opts.Features, sink)
	f.opts.KeyRand = func(int) ([]byte, error) { return nil, errors.New("no entropy") }
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("open: %+v", out)
	}
	if err := m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	m2 := f.mustUnlock(testPIN, f.phoneUS)
	defer m2.Crash()
	sink.got = nil
	m2.mu.Lock()
	for id, inv := range m2.st.Invites {
		if inv.CreatedBy == inviteByRecovery {
			delete(m2.st.Invites, id) // as the pairing does
		}
	}
	m2.mu.Unlock()
	if err := m2.Start(context.Background()); err != nil {
		t.Fatalf("a failed retry failed the unlock: %v", err)
	}
	if m2.st.RotationOwed == nil || m2.st.RotationOwed.Recovery != recID {
		t.Fatalf("mark lost by a failed retry: %+v", m2.st.RotationOwed)
	}
	if !sink.has("identity.rotation_failed") {
		t.Fatal("a failed retry is not audited")
	}
	// Any rotation clears the mark (here one asked for, §3.5.5).
	m2.opt.KeyRand = nil
	if err := m2.RotateIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m2.st.RotationOwed != nil {
		t.Fatal("a rotation left the mark")
	}
	var ref string
	for _, a := range sink.got {
		if a.Kind == "identity.rotated" {
			ref = a.Ref
		}
	}
	if ref != "recovery" {
		t.Fatalf("identity.rotated ref %q", ref)
	}
}

// With no rotation owed, identity.rotated has no ref.
func TestRotationWithoutMarkHasNoRef(t *testing.T) {
	d := newDevFixture(t)
	d.m.addFeature(&recSink{})
	if err := d.m.RotateIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	a := d.audits("identity.rotated")
	if len(a) != 1 || a[0].Ref != "" {
		t.Fatalf("%+v", a)
	}
}
