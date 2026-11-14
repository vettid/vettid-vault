package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"
)

// §3.4 "A recovery's inherited key" (0.85.4, O5b, "rule 2"); §3.4.2 RK14
// step 1 "At a recovery's open".

// inheritedOpen is a vault whose state holds a relay key left pending by
// an earlier run, opened by a recovery on a relay rw; k is the current
// key's mailbox, p the inherited key's.
type inheritedOpen struct {
	f    *openFixture
	rw   *rotWorld
	k, p string
	m    *Manager
	out  *RecoveryOpenOutcome
}

func newInheritedOpen(t *testing.T, script func(rw *rotWorld, k, p string)) *inheritedOpen {
	return newInheritedOpenAnchored(t, time.Time{}, script)
}

// newInheritedOpenAnchored is newInheritedOpen with the current key's
// anchor stored as anchor (zero: none).
func newInheritedOpenAnchored(t *testing.T, anchor time.Time, script func(rw *rotWorld, k, p string)) *inheritedOpen {
	return newInheritedOpenWith(t, func(m *Manager) { m.st.Relay.Anchor = anchor }, script)
}

// newInheritedOpenWith is newInheritedOpen with set applied to the stored
// state before the open.
func newInheritedOpenWith(t *testing.T, set func(m *Manager), script func(rw *rotWorld, k, p string)) *inheritedOpen {
	io := &inheritedOpen{rw: newRotWorld()}
	io.f = newOpenFixtureWith(t, func(f *openFixture) {
		f.m.mu.Lock()
		defer f.m.mu.Unlock()
		f.m.opt.RelayKeyRotation = true
		// Two rotations: the second, made while the first's key is
		// pending, owes a relay-key rotation.
		for range 2 {
			if err := f.m.rotateKeys(f.clock, true); err != nil {
				t.Fatal(err)
			}
		}
		if o := f.m.st.RotationOwed; o == nil || o.RelayKey.IsZero() {
			t.Fatal("no relay-key rotation owed")
		}
		io.k, io.p = f.m.st.Relay.Mailbox, f.m.pendingMailbox()
		set(f.m)
		if err := f.m.persist(context.Background(), false); err != nil {
			t.Fatal(err)
		}
	})
	io.f.opts.RelayKeyRotation, io.f.opts.RelayKeyRotationUnfinished = true, true
	io.f.opts.Relay = func(base string, key ed25519.PrivateKey) Relay {
		return &rotRelay{stubRelay: &stubRelay{base: base, key: key}, key: key, w: io.rw}
	}
	io.rw.live[io.k] = true
	if script != nil {
		script(io.rw, io.k, io.p)
	}
	m, out := io.f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("open %+v", out)
	}
	io.m, io.out = m, out
	t.Cleanup(m.Crash)
	return io
}

func (io *inheritedOpen) state() (RelayState, *RotationOwed) {
	io.m.mu.Lock()
	defer io.m.mu.Unlock()
	return io.m.st.Relay, io.m.st.RotationOwed
}

func (io *inheritedOpen) registered(mb string) bool {
	_, regs := io.rw.log()
	for _, r := range regs {
		if r == mb {
			return true
		}
	}
	return false
}

// The open's one attempt is answered (the rotate, then a registration that
// says the mailbox exists): the open cannot rule out that a lost run of it
// had the mailbox made afresh, so the key stays pending, marked Unconfirmed
// with the attempt's time and the attempt's start as the anchor. Once
// freshMailboxWait has run, the next attempt completes it (the old key's
// anchor the open's attempt's start), and the recovery's own new key is
// then stored as pending.
func TestRelayRotInheritedCompletedAtTheOpen(t *testing.T) {
	io := newInheritedOpen(t, nil)
	opened := io.f.clock
	rs, _ := io.state()
	if io.m.pendingMailbox() != io.p || rs.Pending.Unconfirmed.IsZero() || !rs.Pending.Created.IsZero() || !rs.Anchor.Equal(opened) {
		t.Fatalf("after the open: pending %s, relay %+v", io.m.pendingMailbox(), rs)
	}
	if rot, _ := io.rw.log(); len(rot) != 1 {
		t.Fatalf("rotates %v", rot)
	}
	io.f.clock = rs.Pending.Unconfirmed.Add(freshMailboxWait)
	if err := io.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	rs, owed := io.state()
	if len(rs.Old) < 1 || rs.Old[0].Mailbox != io.k || !rs.Old[0].Anchor.Equal(opened) {
		t.Fatalf("not completed after the wait: %+v", rs)
	}
	// The recovery's rotation owed a relay-key rotation: the completion
	// stores the owed next key, which meets the mark, and the same step
	// completes it at once (relayKeyStep): both keys are now old ones.
	if len(rs.Old) < 2 || rs.Old[1].Mailbox != io.p || rs.Pending != nil || owed != nil && !owed.RelayKey.IsZero() {
		t.Fatalf("the owed next key: relay %+v, owed %+v", rs, owed)
	}
}

// No definite answer: the key stays pending, the recovery's rotation owes
// a relay-key rotation, the open registers no key, and the attempt's start
// is the anchor.
func TestRelayRotInheritedNoAnswerAtTheOpen(t *testing.T) {
	io := newInheritedOpen(t, func(rw *rotWorld, _, _ string) { rw.rotate = []error{relayErr(503, "")} })
	rs, owed := io.state()
	if io.m.pendingMailbox() != io.p || owed == nil || owed.RelayKey.IsZero() || !rs.Anchor.Equal(io.f.clock) {
		t.Fatalf("pending %s, owed %+v, anchor %v", io.m.pendingMailbox(), owed, rs.Anchor)
	}
	if io.registered(io.k) {
		t.Fatal("the open registered the current key while a key is pending")
	}
	// An anchor already stored stays.
	a0 := io.f.clock.Add(-time.Hour)
	io2 := newInheritedOpenAnchored(t, a0, func(rw *rotWorld, _, _ string) { rw.rotate = []error{relayErr(503, "")} })
	if rs, _ := io2.state(); !rs.Anchor.Equal(a0) {
		t.Fatalf("anchor %v, want %v", rs.Anchor, a0)
	}
}

// A refused rotate: the inherited key is discarded and the recovery's own
// key stored as pending, meeting the relay-key rotation; the anchor is the
// attempt's start, unless the relay itself refused it (400, 401).
func TestRelayRotInheritedRotateRefusedAtTheOpen(t *testing.T) {
	for _, c := range []struct {
		err    error
		anchor bool
	}{{relayErr(403, "forbidden"), true}, {relayErr(400, "bad_request"), false}} {
		io := newInheritedOpen(t, func(rw *rotWorld, _, _ string) { rw.rotate = []error{c.err} })
		rs, owed := io.state()
		if rs.Pending == nil || rs.Pending.Refused != "" || io.m.pendingMailbox() == io.p || rs.Mailbox != io.k {
			t.Fatalf("%v: pending %s refused %v", c.err, io.m.pendingMailbox(), rs.Pending)
		}
		if owed != nil && !owed.RelayKey.IsZero() {
			t.Fatalf("%v: relay-key rotation still owed", c.err)
		}
		if rs.Anchor.IsZero() == c.anchor {
			t.Fatalf("%v: anchor %v", c.err, rs.Anchor)
		}
	}
}

// A refused registration (past the grace): a fresh key is registered and
// stored as current by the step-2 write, with every mark cleared; the old
// mailbox's collects ended (mailbox_unknown) with the telling queued.
func TestRelayRotInheritedRegistrationRefusedAtTheOpen(t *testing.T) {
	io := newInheritedOpen(t, func(rw *rotWorld, k, _ string) {
		delete(rw.live, k)
		rw.register = []error{relayErr(400, "bad_request")}
	})
	rs, owed := io.state()
	if rs.Pending != nil || rs.Mailbox == io.k || rs.Mailbox == io.p || !io.registered(rs.Mailbox) {
		t.Fatalf("relay %+v", rs)
	}
	if len(rs.Old) != 1 || rs.Old[0].Mailbox != io.k || rs.Old[0].Collect.Stopped.IsZero() || !rs.Old[0].Collect.TellingDue {
		t.Fatalf("old %+v", rs.Old)
	}
	if owed != nil {
		t.Fatalf("owed %+v", owed)
	}
}

// The fresh key's registration fails too: the inherited key stays, in the
// refused state, and no further key is generated.
func TestRelayRotInheritedFreshKeyRefusedAtTheOpen(t *testing.T) {
	io := newInheritedOpen(t, func(rw *rotWorld, k, _ string) {
		delete(rw.live, k)
		rw.register = []error{relayErr(400, "bad_request"), relayErr(400, "bad_request")}
	})
	rs, _ := io.state()
	if rs.Pending == nil || rs.Pending.Refused == "" || io.m.pendingMailbox() != io.p || rs.Mailbox != io.k || rs.Collect.Stopped.IsZero() {
		t.Fatalf("relay %+v", rs)
	}
	if io.registered(io.k) {
		t.Fatal("registered the gone mailbox's key")
	}
}

// The open's attempt registers the inherited key past the grace: its
// mailbox may have been made afresh at an id with a tombstone, so the key
// stays pending with the answer's time (stored by the step-2 write) and
// is made current, every held token minted again, only once
// freshMailboxWait has run after it.
func TestRelayRotInheritedRegisteredAtTheOpenWaits(t *testing.T) {
	io := newInheritedOpen(t, func(rw *rotWorld, k, _ string) { delete(rw.live, k) })
	rs := ownRelayState(io.m)
	if io.m.pendingMailbox() != io.p || rs.Pending.Created.IsZero() || !rs.Pending.Unconfirmed.IsZero() || !io.registered(io.p) {
		t.Fatalf("after the open: pending %s, relay %+v", io.m.pendingMailbox(), rs)
	}
	answered := rs.Pending.Created
	if err := io.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	if io.m.pendingMailbox() != io.p {
		t.Fatal("made current within the wait")
	}
	io.f.clock = answered.Add(freshMailboxWait)
	if err := io.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	// Made current (and, the recovery's rotation having owed one, the
	// next key after it).
	if rs := ownRelayState(io.m); len(rs.Old) < 2 || rs.Old[1].Mailbox != io.p && rs.Mailbox != io.p {
		t.Fatalf("not made current after the wait: %+v", rs)
	}
}

// newInheritedRepeat is newInheritedOpen whose first open's state write
// (step 2) fails after the inherited key's attempt; the repeat through the
// `next` wrap is io.m.
func newInheritedRepeat(t *testing.T, script func(rw *rotWorld, k, p string)) *inheritedOpen {
	return newInheritedRerun(t, false, script)
}

// newInheritedRerun is newInheritedRepeat whose first open fails at its
// step-1 header write instead (failHeader): nothing of it is stored, so
// the second open is a first open again.
func newInheritedRerun(t *testing.T, failHeader bool, script func(rw *rotWorld, k, p string)) *inheritedOpen {
	t.Helper()
	io := &inheritedOpen{rw: newRotWorld()}
	io.f = newOpenFixtureWith(t, func(f *openFixture) {
		f.m.mu.Lock()
		defer f.m.mu.Unlock()
		f.m.opt.RelayKeyRotation = true
		for range 2 {
			if err := f.m.rotateKeys(f.clock, true); err != nil {
				t.Fatal(err)
			}
		}
		io.k, io.p = f.m.st.Relay.Mailbox, f.m.pendingMailbox()
		if err := f.m.persist(context.Background(), false); err != nil {
			t.Fatal(err)
		}
	})
	io.f.opts.RelayKeyRotation, io.f.opts.RelayKeyRotationUnfinished = true, true
	io.f.opts.Relay = func(base string, key ed25519.PrivateKey) Relay {
		return &rotRelay{stubRelay: &stubRelay{base: base, key: key}, key: key, w: io.rw}
	}
	io.rw.live[io.k] = true
	if script != nil {
		script(io.rw, io.k, io.p)
	}
	if failHeader {
		io.f.st.failHeader = 1
	} else {
		io.f.st.failState = 1
	}
	if m, out := io.f.open(testPIN, rPW); m != nil || out.Code != OpenRetry {
		t.Fatalf("first open: %+v", out)
	}
	m, out := io.f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("repeat: %+v", out)
	}
	io.m, io.out = m, out
	t.Cleanup(m.Crash)
	return io
}

// The first open's rotate succeeds and the registration after it answers
// 201 (the successor made afresh), and its step-2 write fails: the answer's
// time is lost with it. At the repeat the rotate within the grace is
// answered again and the registration says the mailbox exists (200); the
// key is still taken as possibly made afresh and waits freshMailboxWait
// from that answer, so no token is minted that the relay refuses; it is
// made current after the wait.
func TestRelayRotInheritedRepeatKeepsTheFreshWait(t *testing.T) {
	io := newInheritedRepeat(t, func(rw *rotWorld, _, p string) {
		first := true
		rw.onRotate = func() {
			rw.mu.Lock()
			defer rw.mu.Unlock()
			if first { // the successor gone again before the registration
				delete(rw.live, p)
				first = false
			}
		}
	})
	rs := ownRelayState(io.m)
	if io.m.pendingMailbox() != io.p || rs.Pending.Unconfirmed.IsZero() || !rs.Pending.Created.IsZero() {
		t.Fatalf("after the repeat: pending %s, relay %+v", io.m.pendingMailbox(), rs)
	}
	answered := rs.Pending.Unconfirmed
	if err := io.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	if io.m.pendingMailbox() != io.p {
		t.Fatal("made current within the wait")
	}
	io.f.clock = answered.Add(freshMailboxWait)
	if err := io.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	if rs := ownRelayState(io.m); len(rs.Old) < 2 || (rs.Old[1].Mailbox != io.p && rs.Mailbox != io.p) {
		t.Fatalf("not made current after the wait: %+v", rs)
	}
}

// The same lost 201, and the repeat's own rotate gets no definite answer:
// the key, still pending, is stored with a wait from the repeat, so the
// next attempt within it (a collection's sooner retry) does not complete
// it; it is made current after the wait.
func TestRelayRotInheritedRepeatNoAnswerKeepsTheWait(t *testing.T) {
	io := newInheritedRepeat(t, func(rw *rotWorld, _, p string) {
		first := true
		rw.onRotate = func() {
			rw.mu.Lock()
			defer rw.mu.Unlock()
			if first {
				delete(rw.live, p)
				first = false
			}
		}
		rw.rotate = []error{nil, relayErr(503, "")} // the repeat's rotate: no answer
	})
	rs := ownRelayState(io.m)
	if io.m.pendingMailbox() != io.p || rs.Pending.Unconfirmed.IsZero() || !rs.Pending.Created.IsZero() {
		t.Fatalf("after the repeat: pending %s, relay %+v", io.m.pendingMailbox(), rs)
	}
	waitFrom := rs.Pending.Unconfirmed
	if err := io.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	if io.m.pendingMailbox() != io.p {
		t.Fatal("made current within the wait")
	}
	io.f.clock = waitFrom.Add(freshMailboxWait)
	if err := io.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	if rs := ownRelayState(io.m); len(rs.Old) < 1 || rs.Old[0].Mailbox != io.k {
		t.Fatalf("not made current after the wait: %+v", rs)
	}
}

// The lost run's registration said 201; at the repeat the current mailbox
// is gone (mailbox_unknown), the key's registration is refused for good, and
// so is the fresh key's: the key is left refused with no stored time, so the
// 201 of a later attempt (at an unlock) starts the wait instead of
// completing the key at once.
func TestRelayRotInheritedRepeatRefusedKeyGetsNoStamp(t *testing.T) {
	io := newInheritedRepeat(t, func(rw *rotWorld, k, _ string) {
		delete(rw.live, k) // the rotate meets mailbox_unknown; the registration goes on
		rw.register = []error{nil, relayErr(403, "forbidden"), relayErr(403, "forbidden")}
	})
	rs := ownRelayState(io.m)
	if rs.Pending == nil || rs.Pending.Refused == "" {
		t.Fatalf("not left refused: %+v", rs.Pending)
	}
	if !rs.Pending.Created.IsZero() || !rs.Pending.Unconfirmed.IsZero() {
		t.Fatalf("a refused key got a stored time: created %v, unconfirmed %v", rs.Pending.Created, rs.Pending.Unconfirmed)
	}
}

// The first open's rotate is answered and the registration after it says
// 201 (the successor made afresh), and its step-1 header write fails: nothing
// is stored, and the next open is a first open again. The relay says the
// mailbox exists; the open cannot rule out its lost run, so the key is
// marked Unconfirmed and waits freshMailboxWait from the mark, then is made
// current.
func TestRelayRotInheritedOpenAfterAFailedStep1KeepsTheWait(t *testing.T) {
	io := newInheritedRerun(t, true, func(rw *rotWorld, _, p string) {
		first := true
		rw.onRotate = func() {
			rw.mu.Lock()
			defer rw.mu.Unlock()
			if first {
				delete(rw.live, p)
				first = false
			}
		}
	})
	rs := ownRelayState(io.m)
	if io.m.pendingMailbox() != io.p || rs.Pending.Unconfirmed.IsZero() {
		t.Fatalf("after the open: pending %s, relay %+v", io.m.pendingMailbox(), rs)
	}
	mark := rs.Pending.Unconfirmed
	if err := io.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	if io.m.pendingMailbox() != io.p {
		t.Fatal("made current within the wait")
	}
	io.f.clock = mark.Add(freshMailboxWait)
	if err := io.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	if rs := ownRelayState(io.m); len(rs.Old) < 1 || rs.Old[0].Mailbox != io.k {
		t.Fatalf("not made current after the wait: %+v", rs)
	}
}

// The mark is stored with the key: after a lock, the recovered phone's
// unlock within the wait makes no attempt and is answered retry with what
// is left of it (as for a stored Created).
func TestRelayRotInheritedMarkHoldsAcrossALock(t *testing.T) {
	io := newInheritedOpen(t, func(rw *rotWorld, k, _ string) {
		delete(rw.live, k)
		rw.register = []error{relayErr(503, "")} // the open's attempt: no answer
	})
	mark := ownRelayState(io.m).Pending.Unconfirmed
	if mark.IsZero() {
		t.Fatal("no mark")
	}
	if err := io.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	io.f.clock = mark.Add(100 * time.Second)
	rot0, reg0 := io.rw.log()
	m, uo := io.f.phoneUnlockOut()
	if m != nil || uo.Code != CodeRetry || uo.RetryAfter != freshMailboxWait-100*time.Second {
		t.Fatalf("unlock within the wait: %+v", uo)
	}
	if rot, reg := io.rw.log(); len(rot) != len(rot0) || len(reg) != len(reg0) {
		t.Fatalf("relay calls within the wait: rotates %v, registers %v", rot[len(rot0):], reg[len(reg0):])
	}
}

// A repeat whose step 2 was not stored makes the first open's event again
// (recoveryEvent), the inherited key's attempt included: the first open's
// state write fails after its attempt (a rotate the relay took), and the
// repeat makes the attempt again. The relay answers that the key's mailbox
// exists; the repeat cannot tell whether the lost run made it afresh, so
// the key waits freshMailboxWait from that answer (its time is the
// attempt's mark), then is made current.
func TestRelayRotInheritedCompletedAtARepeatAfterStep1(t *testing.T) {
	io := newInheritedRepeat(t, nil)
	rs := ownRelayState(io.m)
	if io.m.pendingMailbox() != io.p || rs.Pending.Unconfirmed.IsZero() {
		t.Fatalf("no attempt at the repeat: pending %s, relay %+v", io.m.pendingMailbox(), rs)
	}
	io.f.clock = rs.Pending.Unconfirmed.Add(freshMailboxWait)
	if err := io.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	if rs := ownRelayState(io.m); len(rs.Old) < 1 || rs.Old[0].Mailbox != io.k {
		t.Fatalf("not completed after the wait: %+v", rs)
	}
}

// After the open's wait the inherited key and the owed next key are both
// completed before the recovered phone paired: the open's vault_bundle
// names a relay key two rotations old, and the phone's first handshake
// with it is answered under the current key, which it does not take. The
// phone's own unlock before its first handshake (resumeLostOK) carries the
// current address, as the apps do when their handshake is not answered.
func TestRelayRotInheritedPhoneUnlockAfterTheWaitNamesTheCurrentKey(t *testing.T) {
	io := newInheritedOpen(t, nil)
	if !bytes.Contains(io.out.VaultBundle, []byte(io.k)) {
		t.Fatal("the open's bundle does not name the current mailbox")
	}
	rs, _ := io.state()
	io.f.clock = rs.Pending.Unconfirmed.Add(freshMailboxWait)
	if err := io.m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	rs, _ = io.state()
	cur := rs.Mailbox
	if cur == io.k || cur == io.p || rs.Pending != nil {
		t.Fatalf("both keys not completed: %+v", rs)
	}
	if err := io.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	m, uo := io.f.phoneUnlockOut()
	if m == nil || !uo.OK {
		t.Fatalf("the phone's unlock: %+v", uo)
	}
	defer m.Crash()
	if !bytes.Contains(uo.VaultBundle, []byte(cur)) || bytes.Contains(uo.VaultBundle, []byte(io.k)) {
		t.Fatalf("the phone's bundle does not name the current mailbox %s: %s", cur, uo.VaultBundle)
	}
	pairRecoveredPhone(t, m, io.f.phone)
}

// An open while a stored mark's wait still runs makes no attempt (nothing
// sent, nothing audited): the wait holds at the open as at any attempt.
func TestRelayRotInheritedOpenInsideTheMarksWaitMakesNoAttempt(t *testing.T) {
	var marked time.Time
	io := newInheritedOpenWith(t, func(m *Manager) {
		// The open comes after the recovery's quiet period: a mark late
		// enough that the open's time falls inside its wait.
		marked = m.now().Add(365 * 24 * time.Hour).UTC()
		m.st.Relay.Pending.Unconfirmed = marked
	}, nil)
	if !io.f.clock.Before(marked.Add(freshMailboxWait)) {
		t.Fatalf("the open at %v is past the mark's wait (%v)", io.f.clock, marked)
	}
	if rot, regs := io.rw.log(); len(rot) != 0 || len(regs) != 0 {
		t.Fatalf("an attempt inside the mark's wait: rotates %v, registers %v", rot, regs)
	}
	rs := ownRelayState(io.m)
	if io.m.pendingMailbox() != io.p || rs.Pending.Unconfirmed.Before(marked) {
		t.Fatalf("after the open: pending %s, relay %+v", io.m.pendingMailbox(), rs)
	}
}

// An attempt stored by an earlier run (relayKeyAttempt) when a recovery's
// open inherits the key: the open clears it once its own mark or a 201's
// wait covers any answer of it, and keeps it for a key it leaves refused,
// whose next unlock then waits before its one attempt.
func TestRelayRotInheritedOpenClearsACoveredAttempt(t *testing.T) {
	far := 365 * 24 * time.Hour // past the recovery's quiet period: the open's time falls before it
	for _, tc := range []struct {
		name   string
		set    func(pr *PendingRelay, now time.Time)
		script func(rw *rotWorld, k, p string)
		kept   bool
	}{
		{"exists", nil, nil, false},
		{"no answer", nil, func(rw *rotWorld, _, _ string) { rw.rotate = []error{relayErr(503, "")} }, false},
		{"201", nil, func(rw *rotWorld, k, _ string) { delete(rw.live, k) }, false},
		{"refused", nil, func(rw *rotWorld, k, _ string) {
			delete(rw.live, k)
			rw.register = []error{relayErr(400, "bad_request"), relayErr(400, "bad_request")}
		}, true},
		// The open's early returns make no attempt: nothing covers it.
		{"retry_after running", func(pr *PendingRelay, now time.Time) { pr.RetryAfter = now.Add(far) }, nil, true},
		{"wait running", func(pr *PendingRelay, now time.Time) { pr.Unconfirmed = now.Add(far) }, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stored time.Time
			io := newInheritedOpenWith(t, func(m *Manager) {
				stored = m.now().UTC()
				m.st.Relay.Pending.Attempt = stored
				if tc.set != nil {
					tc.set(m.st.Relay.Pending, stored)
				}
			}, tc.script)
			rs, _ := io.state()
			if rs.Pending == nil {
				t.Fatalf("no pending key: %+v", rs)
			}
			if got := !rs.Pending.Attempt.IsZero(); got != tc.kept {
				t.Fatalf("attempt kept %v, want %v: %+v", got, tc.kept, rs.Pending)
			}
			if !tc.kept && rs.Pending.Created.IsZero() && rs.Pending.Unconfirmed.IsZero() {
				t.Fatalf("cleared with no wait covering it: %+v", rs.Pending)
			}
		})
	}
}
