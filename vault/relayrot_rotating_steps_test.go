package vault

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
)

// §3.4 "The order of a relay-key rotation", steps 1 to 3, and the crash
// between each two of them.

// A5: without Options.RelayKeyRotation a rotation rotates ik, kem and the
// wake key only: no pending key, no rotate, the same mailbox, and
// identity.rotated audited in its own write.
func TestRelayRotSwitchOffRotatesNoRelayKey(t *testing.T) {
	fx := newRotFx(t)
	fx.fixture.opts.RelayKeyRotation = false
	fx.restart()
	mb, ik := fx.mailbox(), fx.ik()
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	rot, _ := fx.w.log()
	if fx.pending() != nil || fx.mailbox() != mb || fx.ik() == ik || len(rot) != 0 {
		t.Fatalf("pending %v, mailbox moved %v, ik moved %v, rotates %v", fx.pending() != nil, fx.mailbox() != mb, fx.ik() != ik, rot)
	}
	if len(fx.acts("identity.rotated")) != 1 {
		t.Fatal("identity.rotated not audited at the rotation")
	}
}

// Step 1: the rotation's write stores the new key as pending with new
// tokens for every recipient, held; ik is current from it; nothing is
// audited and the current key stays current.
func TestRelayRotStep1StoresPendingWithHeldTokens(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, "unavailable")} // stop after step 1
	mb, ik := fx.mailbox(), fx.ik()
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	pr := fx.pending()
	if pr == nil || fx.mailbox() != mb || fx.ik() == ik {
		t.Fatalf("pending %v, mailbox moved %v, ik moved %v", pr != nil, fx.mailbox() != mb, fx.ik() != ik)
	}
	pmb := fx.pendingMailbox()
	fx.do(func(m *Manager) {
		for _, id := range []string{"dev1", "c1"} {
			h := pr.Held[id]
			if h == nil || h.Standing == "" || (id == "c1") != (h.Reconnect != "") {
				t.Fatalf("held tokens of %s: %+v", id, h)
			}
			p := m.peer(id)
			c, err := relayauth.ParseToken(h.Standing, pubOf(m.keys.pendingRelay))
			if err != nil || c.Iss != pmb || !bytes.Equal(c.SubKey, p.Relay.PK) {
				t.Fatalf("held standing token of %s: %+v %v", id, c, err)
			}
			for _, it := range m.st.Issued {
				for _, ht := range h.Issued {
					if it.JTI == ht.JTI {
						t.Fatalf("a held token of %s is in the registry before the second write", id)
					}
				}
			}
		}
	})
	if len(fx.acts("identity.rotated")) != 0 {
		t.Fatal("identity.rotated audited at the first write")
	}
	fx.w.rotate = []error{relayErr(503, "unavailable")}
	fx.crash()
	if p := fx.pendingMailbox(); p != pmb {
		t.Fatalf("stored pending %q, want %q", p, pmb)
	}
}

// Store first: a pending key not yet stored is never sent to the relay,
// whatever starts step 2.
func TestRelayRotStep2OnlyForAStoredKey(t *testing.T) {
	fx := newRotFx(t)
	fx.fs.setFail(1 << 20) // no write stores it (the attachment run writes too)
	fx.do(func(m *Manager) {
		if err := m.rotateKeys(m.now(), true); err != nil {
			t.Fatal(err)
		}
		m.st.Relay.Anchor = m.now()                 // kept from an earlier attempt: no anchor write before this one
		m.relayKeyStep(context.Background(), false) // as any trigger after a write would
	})
	if rot, _ := fx.w.log(); len(rot) != 0 {
		t.Fatalf("rotated before the key was stored: %v", rot)
	}
}

// Step 2: the rotate is signed by the current key, with the pending key,
// after a write of its own that stores the current key's anchor (§3.4.2
// RK14 step 1); a failed anchor write sends nothing.
func TestRelayRotStep2AnchorStoredBeforeTheRotate(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, "unavailable")}
	fx.fs.setFail(0)
	var anchorAtRotate time.Time
	fx.w.onRotate = func() { anchorAtRotate = fx.m.st.Relay.Anchor } // the lock is held
	mb := fx.mailbox()
	fx.do(func(m *Manager) {
		if err := m.rotateKeys(m.now(), true); err != nil {
			t.Fatal(err)
		}
		if err := m.persist(context.Background(), false); err != nil {
			t.Fatal(err)
		}
		fx.fs.setFail(1) // the anchor's write
		m.relayKeyStep(context.Background(), false)
		if !m.st.Relay.Anchor.IsZero() {
			t.Fatal("an anchor not stored is kept in memory")
		}
	})
	if rot, _ := fx.w.log(); len(rot) != 0 {
		t.Fatalf("rotated without the anchor stored: %v", rot)
	}
	fx.setClk(fx.clk.Add(time.Minute)) // past the sooner retries' first backoff after the failed write
	fx.batch()
	rot, _ := fx.w.log()
	if len(rot) != 1 || rot[0] != mb+">"+fx.pendingMailbox() || !anchorAtRotate.Equal(fx.clk) {
		t.Fatalf("rotates %v, anchor at the rotate %v", rot, anchorAtRotate)
	}
	// Stored: a crash after the attempt keeps it, and it is not set again.
	fx.setClk(fx.clk.Add(time.Hour))
	fx.w.rotate = []error{relayErr(503, "unavailable")}
	fx.crash()
	if a := fx.m.RelayKeyStatus().Anchor; !a.Equal(anchorAtRotate) {
		t.Fatalf("anchor after the crash %v, want %v", a, anchorAtRotate)
	}
}

// Step 3: on success the second write makes the key current; the old key
// is kept with its anchor; the held tokens enter the registry; each
// recipient's key for the vault is the old key and S1's clock starts
// (§3.4.1 S1, §3.4.2 RK13); identity.rotated is audited there, once.
func TestRelayRotStep3SecondWrite(t *testing.T) {
	fx := newRotFx(t)
	mb := fx.mailbox()
	var oldSub string
	fx.do(func(m *Manager) { oldSub = relayauth.EncodeKey(pubOf(m.keys.relay)) })
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	st := fx.m.RelayKeyStatus()
	if st.PendingMailbox != "" || st.Mailbox == mb || len(st.OldMailboxes) != 1 || st.OldMailboxes[0] != mb || !st.Anchor.IsZero() {
		t.Fatalf("after the second write: %+v", st)
	}
	fx.do(func(m *Manager) {
		if o := m.st.Relay.Old[0]; !o.Anchor.Equal(fx.clk) || !o.MadeOld.Equal(fx.clk) {
			t.Fatalf("old key %+v", o)
		}
		for _, id := range []string{"dev1", "c1"} {
			r := m.st.Relay.Recipients[id]
			if r == nil || r.KeyFor != oldSub || !r.S1Since.Equal(fx.clk) || r.Standing == "" || !r.UpdateDue {
				t.Fatalf("recipient %s: %+v", id, r)
			}
			c, err := relayauth.ParseToken(r.Standing, pubOf(m.keys.relay))
			if err != nil || c.Iss != m.st.Relay.Mailbox {
				t.Fatalf("token of %s %+v %v", id, c, err)
			}
			found := false
			for _, it := range m.st.Issued {
				found = found || it.JTI == c.Jti
			}
			if !found {
				t.Fatalf("%s's new token is not in the registry", id)
			}
		}
	})
	if a := fx.acts("identity.rotated"); len(a) != 1 || a[0].Ref != "" {
		t.Fatalf("identity.rotated %+v", a)
	}
	cur := fx.mailbox()
	fx.crash()
	if fx.mailbox() != cur || fx.pending() != nil {
		t.Fatal("the second write was not stored")
	}
	if _, regs := fx.w.log(); regs[len(regs)-1] != cur {
		t.Fatalf("the unlock after the second write registered %v", regs)
	}
}

// A crash between step 1 and step 2: the next unlock calls the rotate with
// the same key (and registers no key), and completes it.
func TestRelayRotCrashAfterStep1(t *testing.T) {
	fx := newRotFx(t)
	mb := fx.mailbox()
	fx.do(func(m *Manager) {
		if err := m.rotateKeys(m.now(), true); err != nil {
			t.Fatal(err)
		}
		if err := m.persist(context.Background(), false); err != nil {
			t.Fatal(err)
		}
	})
	pmb := fx.pendingMailbox()
	_, regs0 := fx.w.log()
	fx.crash()
	rot, regs := fx.w.log()
	for _, r := range regs[len(regs0):] {
		if r == mb {
			t.Fatalf("the unlock registered the current key while a key is pending: %v", regs)
		}
	}
	if len(rot) != 1 || rot[0] != mb+">"+pmb || fx.mailbox() != pmb {
		t.Fatalf("rotates %v, mailbox %s, want %s", rot, fx.mailbox(), pmb)
	}
	if len(fx.acts("identity.rotation_failed")) != 0 || len(fx.acts("identity.rotated")) != 1 {
		t.Fatal("an unlock that completes the key audits identity.rotated only")
	}
}

// A crash between the rotate and the second write: the attempt stored
// before the call tells the next run that an answer may have been lost (a
// 201 that made the mailbox afresh cannot be ruled out), so the key waits
// freshMailboxWait from that run; then the rotate is called again with the
// same key, which the relay answers with the same mailbox, and the second
// write follows.
func TestRelayRotCrashBetweenRotateAndSecondWrite(t *testing.T) {
	fx := newRotFx(t)
	mb := fx.mailbox()
	fx.w.onRotate = func() { fx.fs.setFail(1 << 20) } // every write after the rotate fails
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	pmb := fx.pendingMailbox()
	if pmb == "" && fx.mailbox() == mb {
		t.Fatal("no rotation")
	}
	fx.w.onRotate = nil
	fx.fs.setFail(0)
	// Memory went ahead; the store still holds the key pending, with its
	// attempt.
	fx.crash()
	if rot, _ := fx.w.log(); len(rot) != 1 {
		t.Fatalf("rotates %v: the unlock did not wait", rot)
	}
	pr := fx.pending()
	if pr == nil || pr.Unconfirmed.IsZero() || !pr.Attempt.IsZero() {
		t.Fatalf("pending %+v: want marked Unconfirmed, the attempt cleared", pr)
	}
	fx.setClk(pr.Unconfirmed.Add(freshMailboxWait))
	fx.batch()
	rot, _ := fx.w.log()
	if len(rot) != 2 || rot[0] != rot[1] {
		t.Fatalf("rotates %v: not the same key again", rot)
	}
	if fx.pending() != nil || fx.mailbox() == mb || len(fx.m.RelayKeyStatus().OldMailboxes) != 1 {
		t.Fatalf("not completed after the crash: %+v", fx.m.RelayKeyStatus())
	}
}

// A crash after the second write was stored: nothing is rotated again.
func TestRelayRotCrashAfterSecondWrite(t *testing.T) {
	fx := newRotFx(t)
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	cur := fx.mailbox()
	fx.crash()
	if rot, _ := fx.w.log(); len(rot) != 1 || fx.mailbox() != cur {
		t.Fatalf("rotates %v", rot)
	}
}
