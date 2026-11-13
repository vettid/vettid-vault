package vault

import (
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
}

func newInheritedOpen(t *testing.T, script func(rw *rotWorld, k, p string)) *inheritedOpen {
	return newInheritedOpenAnchored(t, time.Time{}, script)
}

// newInheritedOpenAnchored is newInheritedOpen with the current key's
// anchor stored as anchor (zero: none).
func newInheritedOpenAnchored(t *testing.T, anchor time.Time, script func(rw *rotWorld, k, p string)) *inheritedOpen {
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
		f.m.st.Relay.Anchor = anchor
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
	io.m = m
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

// The open's one attempt succeeds: its step-2 write is the inherited key's
// second write (with the attempt's start as the old key's anchor), and the
// recovery's own new key is stored as pending.
func TestRelayRotInheritedCompletedAtTheOpen(t *testing.T) {
	io := newInheritedOpen(t, nil)
	rs, _ := io.state()
	if rs.Mailbox != io.p || len(rs.Old) != 1 || rs.Old[0].Mailbox != io.k || !rs.Old[0].Anchor.Equal(io.f.clock) {
		t.Fatalf("relay %+v", rs)
	}
	if rs.Pending == nil || io.m.pendingMailbox() == io.p {
		t.Fatal("the recovery's own key is not pending")
	}
	if rot, _ := io.rw.log(); len(rot) != 1 {
		t.Fatalf("rotates %v", rot)
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
