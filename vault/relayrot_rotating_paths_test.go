package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
)

// §3.4 "Owed marks", "A rotation made while a relay key is pending", "The
// way out of the refused state", "The three paths" (§11.14.6 step 6,
// §11.14.10, §3.5.5), "Resending the new address" (a): the old key kept for
// deposits, and the second write's recipients.

// A rotation made while a key is pending rotates ik, kem and the wake key,
// keeps the pending key and owes a relay-key rotation (its time kept by a
// later one); the pending key's second write stores the next key, which
// meets the mark, and the next key's own second write follows.
func TestRelayRotRotationWhilePendingOwesTheNextKey(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	k1, ik1 := fx.pendingMailbox(), fx.ik()
	t0 := fx.clk
	// The sooner retry's wait (full jitter) is past the two rotations below.
	fx.do(func(m *Manager) { m.rk.next = fx.clk.Add(time.Minute) })
	if err := fx.m.RotateIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	fx.setClk(fx.clk.Add(time.Second))
	if err := fx.m.RotateIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	var owed *RotationOwed
	fx.do(func(m *Manager) { owed = m.st.RotationOwed })
	if fx.pendingMailbox() != k1 || fx.ik() == ik1 || owed == nil || !owed.RelayKey.Equal(t0) {
		t.Fatalf("pending moved %v, ik moved %v, owed %+v", fx.pendingMailbox() != k1, fx.ik() != ik1, owed)
	}
	fx.setClk(fx.clk.Add(time.Hour))
	fx.batch() // K1 completes; K2 is stored in its second write and completed at once
	rot, _ := fx.w.log()
	if len(rot) != 3 || fx.pending() != nil {
		t.Fatalf("rotates %v, pending %v", rot, fx.pending() != nil)
	}
	st := fx.m.RelayKeyStatus()
	if len(st.OldMailboxes) != 2 || st.OldMailboxes[1] != k1 || st.Mailbox == k1 {
		t.Fatalf("after K2: %+v", st)
	}
	fx.do(func(m *Manager) {
		if m.st.RotationOwed != nil {
			t.Fatalf("marks left %+v", m.st.RotationOwed)
		}
	})
	if len(fx.acts("identity.rotated")) != 2 {
		t.Fatalf("identity.rotated %d", len(fx.acts("identity.rotated")))
	}
}

// The next key's step: crash after the pending key's second write (which
// stored the next key) and before the next key's rotate: the next unlock
// completes the next key, and the mark stays met.
func TestRelayRotCrashAfterTheSecondWriteThatStoredTheNextKey(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	if err := fx.m.RotateIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	k1 := fx.pendingMailbox()
	fx.w.rotate = []error{nil, relayErr(503, "")} // K1 completes; K2's rotate gets no answer
	fx.setClk(fx.clk.Add(time.Hour))
	fx.batch()
	k2 := fx.pendingMailbox()
	if k2 == "" || k2 == k1 || fx.mailbox() != k1 {
		t.Fatalf("K2 not stored: pending %q, mailbox %q", k2, fx.mailbox())
	}
	fx.crash()
	st := fx.m.RelayKeyStatus()
	if st.PendingMailbox != "" || st.Mailbox != k2 || len(st.OldMailboxes) != 2 || st.OldMailboxes[1] != k1 {
		t.Fatalf("after the crash: %+v", st)
	}
}

// The way out of the refused state is credential.rotate: it discards the
// refused key and stores a new one, which meets any relay-key rotation
// owed; the current key's anchor stays. Any other rotation keeps the
// refused key and owes a relay-key rotation.
func TestRelayRotWayOutOfTheRefusedState(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, ""), relayErr(403, "forbidden")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	fx.setClk(fx.clk.Add(2 * time.Minute))
	fx.batch()
	k1, anchor := fx.pendingMailbox(), fx.m.RelayKeyStatus().Anchor
	if pr := fx.pending(); pr == nil || pr.Refused == "" || anchor.IsZero() {
		t.Fatal("not refused")
	}
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.m.RotateIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	var owed *RotationOwed
	fx.do(func(m *Manager) { owed = m.st.RotationOwed })
	if fx.pendingMailbox() != k1 || fx.pending().Refused == "" || owed == nil || owed.RelayKey.IsZero() {
		t.Fatalf("a rotation not by credential.rotate replaced the refused key: owed %+v", owed)
	}
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	fx.do(func(m *Manager) { owed = m.st.RotationOwed })
	pr := fx.pending()
	if pr == nil || pr.Refused != "" || fx.pendingMailbox() == k1 || owed != nil || !fx.m.RelayKeyStatus().Anchor.Equal(anchor) {
		t.Fatalf("way out: pending %+v, owed %+v, anchor %v", pr, owed, fx.m.RelayKeyStatus().Anchor)
	}
	rot, _ := fx.w.log()
	if last := rot[len(rot)-1]; last != fx.mailbox()+">"+fx.pendingMailbox() {
		t.Fatalf("the new key's rotate %v", rot)
	}
}

// Owed marks (§11.14.10): the transfer's mark is not cleared at the first
// write; while its key is pending, the unlock's retry is that key's
// completion, not another rotation of ik; the second write clears it and
// audits identity.rotated with the transfer_id.
func TestRelayRotOwedMarkClearsAtTheSecondWrite(t *testing.T) {
	fx := newRotFx(t)
	fx.do(func(m *Manager) {
		m.st.RotationOwed = &RotationOwed{Transfer: "t1", At: fx.clk}
		m.dirty = true
	})
	fx.w.rotate = []error{relayErr(503, ""), relayErr(503, "")}
	fx.restart() // Start's retryOwedRotation rotates; its rotate gets no answer
	ik := fx.ik()
	var owed *RotationOwed
	fx.do(func(m *Manager) { owed = m.st.RotationOwed })
	if fx.pending() == nil || owed == nil || owed.Transfer != "t1" || len(fx.acts("identity.rotated")) != 0 {
		t.Fatalf("pending %v, owed %+v", fx.pending() != nil, owed)
	}
	fx.restart() // again no answer: no new rotation of ik
	if fx.ik() != ik {
		t.Fatal("the unlock rotated ik again for a mark whose key is pending")
	}
	fx.restart()
	fx.do(func(m *Manager) { owed = m.st.RotationOwed })
	if a := fx.acts("identity.rotated"); len(a) != 1 || a[0].Ref != "t1" || owed != nil {
		t.Fatalf("identity.rotated %+v, owed %+v", a, owed)
	}
	// Only the unlock that found the key left pending audits it.
	if a := fx.acts("identity.rotation_failed"); len(a) != 1 || a[0].Ref != "t1" {
		t.Fatalf("rotation_failed %+v", a)
	}
}

// The second write takes the recipients again: one added since gets
// tokens, one removed since gets none; a held standing token with less
// than 10 days left is re-minted, a fresher one kept.
func TestRelayRotSecondWriteTakesTheRecipientsAgain(t *testing.T) {
	fx := newRotFx(t)
	fx.asConnection(t, "c2", 0x50)
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	fx.addDevice(t, "dev2", KindDesktop, 0x58)
	fx.do(func(m *Manager) {
		delete(m.st.Connections, "c2")
		m.dirty = true
	})
	held := fx.pending().Held
	c1, dev1 := held["c1"].Standing, held["dev1"].Standing
	c1Re := held["c1"].Reconnect
	fx.do(func(m *Manager) {
		// dev1's held standing token is near its end.
		h := held["dev1"]
		it, _ := issuedOf(h.Issued, TokStanding)
		it.Exp = fx.clk.Add(9 * 24 * time.Hour)
		h.Issued = replaceIssued(h.Issued, it)
	})
	fx.setClk(fx.clk.Add(2 * time.Minute))
	fx.batch()
	fx.do(func(m *Manager) {
		r := m.st.Relay.Recipients
		if r["c2"] != nil || r["dev2"] == nil || r["dev2"].Standing == "" {
			t.Fatalf("recipients %v", r)
		}
		if r["c1"].Standing != c1 || r["c1"].Reconnect != c1Re || r["dev1"].Standing == dev1 {
			t.Fatalf("re-minted c1 %v, kept dev1 %v", r["c1"].Standing != c1, r["dev1"].Standing == dev1)
		}
		for _, it := range m.st.Issued {
			if it.PeerID == "c2" && it.Sub != "" && it.Exp.After(fx.clk.Add(25*24*time.Hour)) {
				t.Fatal("a removed recipient's held token entered the registry")
			}
		}
	})
}

// "Resending the new address" (a): after the second write the old key is
// kept for deposits: a deposit on a token a recipient issued to the old
// key is signed with the old key; one on a token for the current key with
// the current key.
func TestRelayRotOldKeyKeptForDeposits(t *testing.T) {
	fx := newRotFx(t)
	old := fx.mailbox()
	var oldKey ed25519.PrivateKey
	fx.do(func(m *Manager) { oldKey = m.keys.relay })
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	cur := fx.mailbox()
	connKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, 32))
	tokFor := func(sub ed25519.PrivateKey) string {
		tok, err := relayauth.MintToken(connKey, relayauth.Claims{Iss: mailboxOf(connKey), Sub: relayauth.EncodeKey(pubOf(sub)),
			Aud: "https://relay.example.org", Iat: fx.clk.Add(-time.Minute), Exp: fx.clk.Add(time.Hour), Jti: "j", Scope: relayauth.ScopeDeposit})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	fx.do(func(m *Manager) {
		if r := m.relayFor(tokFor(oldKey)).(*rotRelay); mailboxOf(r.key) != old {
			t.Fatal("a token for the old key is not deposited with it")
		}
		if r := m.relayFor(tokFor(m.keys.relay)).(*rotRelay); mailboxOf(r.key) != cur {
			t.Fatal("a token for the current key is not deposited with it")
		}
		if m.relayFor("v4.public.VEVTVA") != m.relay {
			t.Fatal("an unreadable token is not deposited with the current key")
		}
	})
	// A blob upload too, its Relay taken with its token.
	fx.do(func(m *Manager) { m.st.Connections["c1"].Standing.Token = tokFor(oldKey) })
	if _, _, err := fx.m.PutBlobTo(context.Background(), "c1", []byte("x")); err != nil {
		t.Fatal(err)
	}
	fx.w.mu.Lock()
	defer fx.w.mu.Unlock()
	if len(fx.w.blobSigners) != 1 || fx.w.blobSigners[0] != old {
		t.Fatalf("blob upload signed by %v", fx.w.blobSigners)
	}
}

// The unlock with a key pending registers no key and uses the limits last
// registered; the registration after a successful rotate gives the new
// mailbox's.
func TestRelayRotUnlockWithAKeyPendingRegistersNoKey(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, ""), relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	_, before := fx.w.log()
	fx.restart()
	_, after := fx.w.log()
	if len(after) != len(before) {
		t.Fatalf("registered %v at an unlock with a key pending", after[len(before):])
	}
	var lim Limits
	fx.do(func(m *Manager) { lim = m.limits })
	if lim.MaxTokenLifetimeSeconds == 0 || lim.OpenTokenMaxLifetimeSeconds == 0 {
		t.Fatalf("limits %+v", lim)
	}
}

// §11.14.10: a transfer's owed rotation, after the old phone's notice,
// stores the relay key as pending; the notice was signed with the key it
// was issued to; the rotate follows, and the second write clears the mark
// with identity.rotated naming the transfer.
func TestRelayRotTransferPath(t *testing.T) {
	w := newTRWorld(t)
	rw := newRotWorld()
	w.fixture.opts.RelayKeyRotation, w.fixture.opts.RelayKeyRotationUnfinished = true, true
	w.fixture.opts.Relay = func(base string, key ed25519.PrivateKey) Relay {
		w.fixture.relay = &stubRelay{base: base, key: key}
		rw.live[mailboxOf(key)] = true
		return &rotRelay{stubRelay: w.fixture.relay, key: key, w: rw}
	}
	w.reopen()
	mb := ""
	w.m.mu.Lock()
	mb = w.m.st.Relay.Mailbox
	w.m.mu.Unlock()
	w.start()
	rot, _ := rw.log()
	w.m.mu.Lock()
	o, cur, old := w.m.st.RotationOwed, w.m.st.Relay.Mailbox, len(w.m.st.Relay.Old)
	w.m.mu.Unlock()
	if len(rot) != 1 || cur == mb || old != 1 || o != nil {
		t.Fatalf("rotates %v, mailbox moved %v, old %d, owed %+v", rot, cur != mb, old, o)
	}
	if r := w.activities("identity.rotated"); len(r) != 1 || r[0].Ref != w.id {
		t.Fatalf("identity.rotated %+v", r)
	}
}

// §11.14.6 step 6: a recovery stores the relay key as pending in its
// step-2 write, with the limits of the open's registration; its rotate
// waits for the recovered phone's first handshake (a reading of this
// release), then the second write clears the recovery's mark.
func TestRelayRotRecoveryPath(t *testing.T) {
	f := newOpenFixture(t)
	rw := newRotWorld()
	f.opts.RelayKeyRotation, f.opts.RelayKeyRotationUnfinished = true, true
	f.opts.Relay = func(base string, key ed25519.PrivateKey) Relay {
		rw.live[mailboxOf(key)] = true
		return &rotRelay{stubRelay: &stubRelay{base: base, key: key}, key: key, w: rw}
	}
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("open %+v", out)
	}
	defer m.Crash()
	m.mu.Lock()
	pr, owed := m.st.Relay.Pending, m.st.RotationOwed
	m.mu.Unlock()
	if pr == nil || pr.Limits == nil || owed == nil || owed.Recovery == "" {
		t.Fatalf("pending %+v, owed %+v", pr, owed)
	}
	if err := m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	if rot, _ := rw.log(); len(rot) != 0 {
		t.Fatalf("rotated before the recovered phone paired: %v", rot)
	}
	m.mu.Lock()
	for id, inv := range m.st.Invites {
		if inv.CreatedBy == inviteByRecovery {
			delete(m.st.Invites, id) // as the phone's first handshake does
		}
	}
	m.dirty = true
	m.mu.Unlock()
	if err := m.ProcessBatch(context.Background(), &fakeCollector{}, nil); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	pr, owed = m.st.Relay.Pending, m.st.RotationOwed
	m.mu.Unlock()
	if rot, _ := rw.log(); len(rot) != 1 || pr != nil || owed != nil {
		t.Fatalf("rotates %v, pending %v, owed %+v", rot, pr != nil, owed)
	}
}

// A recipient removed since an earlier rotation leaves the recipients at
// the next second write.
func TestRelayRotRemovedRecipientLeavesTheRecord(t *testing.T) {
	fx := newRotFx(t)
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	fx.do(func(m *Manager) {
		if m.st.Relay.Recipients["c1"] == nil {
			t.Fatal("no record")
		}
		delete(m.st.Connections, "c1")
		m.dirty = true
	})
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	fx.do(func(m *Manager) {
		if m.st.Relay.Recipients["c1"] != nil || m.st.Relay.Recipients["dev1"] == nil {
			t.Fatalf("recipients %v", m.st.Relay.Recipients)
		}
	})
}

// §12.5 with a key pending: the deletion also deletes the pending key's
// mailbox, which a rotate may have made.
func TestRelayRotDeleteWithAKeyPending(t *testing.T) {
	fx := newRotFx(t)
	fx.w.rotate = []error{relayErr(503, "")}
	if err := fx.credRotate(); err != nil {
		t.Fatal(err)
	}
	cur, pmb := fx.mailbox(), fx.pendingMailbox()
	if err := fx.m.Delete(context.Background()); err != nil {
		t.Fatal(err)
	}
	fx.w.mu.Lock()
	defer fx.w.mu.Unlock()
	if len(fx.w.deleted) != 2 || fx.w.deleted[0] != cur || fx.w.deleted[1] != pmb {
		t.Fatalf("deleted %v", fx.w.deleted)
	}
}

// The attachment workers run without the vault's lock while the second
// write replaces the current Relay under it: they read it through
// ownRelays, and an upload takes its Relay with its token under the lock
// (run with -race).
func TestRelayRotSecondWriteDoesNotRaceTheAttachmentWorkers(t *testing.T) {
	fx := newRotFx(t)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = fx.m.ownRelays()[0].BaseURL()
			_, _, _ = fx.m.PutBlobTo(context.Background(), "c1", []byte("x"))
		}
	}()
	for range 3 {
		if err := fx.credRotate(); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	<-done
	if len(fx.m.RelayKeyStatus().OldMailboxes) != 3 {
		t.Fatal("not rotated")
	}
}
