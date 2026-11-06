package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// §3.4: a handshake the vault began under an identity key a rotation then
// replaced does not restore at the next unlock or recovery open
// (RestoreInitiator refuses it). It is cleaned up as an aborted one is
// (handleResp): its hs.init is not sent, the tokens it minted are revoked
// at the relay, and a new connection's devices hear it failed.

// reconnectOf starts a reconnect to p and returns its record.
func reconnectOf(t *testing.T, m *Manager, p *Peer) *OutgoingHS {
	t.Helper()
	m.startReconnect(p, m.now())
	for _, og := range m.st.Outgoing {
		if og.PeerID == p.ID && og.Purpose == handshake.PurposeReconnect {
			if og.InitOutbox == "" || len(og.Issued) == 0 {
				t.Fatalf("reconnect without its hs.init or tokens: %+v", og)
			}
			return og
		}
	}
	t.Fatal("no reconnect started")
	return nil
}

// checkAbandonedAt checks that the reconnect ogID is gone, its hs.init is
// not to be sent, and each token it minted has a revoke queued; atRestore:
// the abandonment is the
// restore's (audited handshake_not_restored), not the rotation's own (S5,
// 0.86.0, which abandons the vault's open reconnects in the rotation's
// write).
func checkAbandonedAt(t *testing.T, m *Manager, ogID, initOutbox string, issued []IssuedToken, atRestore bool, relays ...*stubRelay) {
	t.Helper()
	if m.st.Outgoing[ogID] != nil || m.outgoing[ogID] != nil {
		t.Fatal("the reconnect under the old identity key was restored")
	}
	for _, e := range m.st.Outbox {
		if e.ID == initOutbox && !e.Done {
			t.Fatal("its hs.init is still to be sent")
		}
	}
	for _, it := range issued {
		revoked := false
		for _, e := range m.st.Outbox {
			if e.Op == OpRevoke && e.Kind == "jti" && e.Value == it.JTI {
				revoked = true
			}
		}
		if sr, ok := m.relay.(*stubRelay); ok {
			relays = append(relays, sr)
		}
		for _, sr := range relays {
			if atRestore {
				break
			}
			// S5: revoked at the rotation, perhaps sent already.
			sr.mu.Lock()
			for _, r := range sr.revoked {
				revoked = revoked || r == "jti:"+it.JTI
			}
			sr.mu.Unlock()
		}
		if !revoked {
			t.Fatalf("token %s (%s) it minted is not revoked", it.JTI, it.Kind)
		}
	}
	audited := !atRestore
	for _, a := range m.st.Audit {
		audited = audited || a.Event == "handshake_not_restored"
	}
	if !audited {
		t.Fatal("no handshake_not_restored audit entry")
	}
}

// (a) A reconnect begun under the old ik, the rotation stored but not
// drained, a crash, an unlock.
func TestRotatedReconnectAbandonedAtUnlock(t *testing.T) {
	d := newDevFixture(t)
	d.asConnection(t, "c1", 0x70)
	d.m.mu.Lock()
	p := d.m.st.Connections["c1"]
	// asConnection makes the connection directly; give it what a
	// reconnect needs: a held reconnect token and an epoch to name.
	p.Reconnect = HeldToken{Token: "v4.public.VEVTVA", Exp: d.m.now().Add(24 * time.Hour)}
	p.LastEpochID = bytes.Repeat([]byte{0xe1}, 16)
	og := reconnectOf(t, d.m, p)
	ogID, initOutbox, issued := og.ID, og.InitOutbox, append([]IssuedToken(nil), og.Issued...)
	err := managerHost{d.m}.RotateIdentity(d.m.now())
	if err == nil {
		err = d.m.persist(context.Background(), false) // stored, not yet sent
	}
	d.m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	d.m.Crash()
	m, _, err := d.fixture.unlock(testPIN, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Crash()
	m.mu.Lock()
	// 0.86.0 (S5): the rotation's own write abandoned the reconnect begun
	// under the old ik (and started one under the new ik), so the restore
	// finds nothing to clean up.
	checkAbandonedAt(t, m, ogID, initOutbox, issued, false)
	m.mu.Unlock()
	// A reconnect's cleanup tells the devices nothing: the connection
	// stays (only a new connection's devices hear that it failed).
	d.m = m
	_ = d.appInbox()
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, ev := range d.appInbox() {
		if ev.Type == "connection.event" {
			t.Fatalf("a reconnect's cleanup sent connection.event %s", ev.Body)
		}
	}
}

// A rekey records its hs.init's outbox entry, so one abandoned before the
// deposit (a restore that refuses it) sends nothing.
func TestRekeyAbandonedSendsNoInit(t *testing.T) {
	d := newDevFixture(t)
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	var dev *Peer
	for _, p := range d.m.st.Devices {
		dev = p
	}
	d.m.dropRekey(dev.ID)
	d.m.startRekey(dev, d.m.now())
	var og *OutgoingHS
	for _, o := range d.m.st.Outgoing {
		if o.PeerID == dev.ID && o.Purpose == handshake.PurposeRekey {
			og = o
		}
	}
	if og == nil || og.InitOutbox == "" {
		t.Fatalf("the rekey's hs.init is not recorded: %+v", og)
	}
	init := og.InitOutbox
	d.m.abandonOutgoing(og.ID, d.m.now())
	for _, e := range d.m.st.Outbox {
		if e.ID == init && !e.Done {
			t.Fatal("the abandoned rekey's hs.init is still to be sent")
		}
	}
}

// (b) A new connection (the vault accepted an invitation) still waiting
// for hs.resp under the old ik, with the same sequence: after the next
// unlock's drain the devices hear it failed, and its hs.init never
// reaches the inviter.
func TestRotatedConnectionRequestAbandonedAtUnlock(t *testing.T) {
	a, b := newVaultPair(t)
	_, link := a.linkFor(t, time.Hour)
	b.m.mu.Lock()
	og, err := b.m.acceptInvite(context.Background(), link, "", b.m.now())
	if err != nil {
		b.m.mu.Unlock()
		t.Fatal(err)
	}
	if og.New == nil || og.InitOutbox == "" {
		b.m.mu.Unlock()
		t.Fatalf("not a new connection with its hs.init: %+v", og)
	}
	ogID, cid := og.ID, og.PeerID
	var minted []string
	for _, it := range b.m.st.Issued {
		if it.PeerID == cid && it.Kind != TokOpen {
			minted = append(minted, it.JTI)
		}
	}
	if len(minted) == 0 {
		b.m.mu.Unlock()
		t.Fatal("no request token minted")
	}
	err = managerHost{b.m}.RotateIdentity(b.m.now())
	if err == nil {
		err = b.m.persist(context.Background(), false) // stored, not yet sent
	}
	b.m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	inviter := a.m.st.Relay.Mailbox
	b.m.Crash()
	m, _, err := b.fixture.unlock(testPIN, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	b.m = m
	defer m.Crash()
	if got := b.appInbox(); len(got) != 0 {
		t.Fatalf("the unlock delivered before a write stored it: %d messages", len(got)) // nothing is drained before the first write
	}
	m.mu.Lock()
	if m.st.Outgoing[ogID] != nil || m.outgoing[ogID] != nil {
		m.mu.Unlock()
		t.Fatal("the request under the old identity key was restored")
	}
	for _, jti := range minted {
		revoked := false
		for _, e := range m.st.Outbox {
			revoked = revoked || e.Op == OpRevoke && e.Kind == "jti" && e.Value == jti
		}
		if !revoked {
			m.mu.Unlock()
			t.Fatalf("its request token %s is not revoked", jti)
		}
	}
	m.mu.Unlock()
	// The next unlock's start: its write, then its drain.
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	failed := false
	for _, ev := range b.appInbox() {
		if ev.Type == "connection.event" && bodyStr(t, ev, "connection_id") == cid {
			if bodyStr(t, ev, "event") != "failed" {
				t.Fatalf("connection.event %s", ev.Body)
			}
			failed = true
		}
	}
	if !failed {
		t.Fatal("the devices did not hear that the request failed")
	}
	b.relay.mu.Lock()
	defer b.relay.mu.Unlock()
	for _, dep := range b.relay.deposits {
		if dep.mailbox == inviter {
			t.Fatal("a deposit for the abandoned request reached the inviter")
		}
	}
}

// (c) The same at a recovery open (completeRecoveryR): a reconnect under
// the old ik, rotated and stored, then the lock and the recovery.
func TestRotatedReconnectAbandonedAtRecoveryOpen(t *testing.T) {
	var ogID, initOutbox string
	var issued []IssuedToken
	var before *stubRelay
	f := newOpenFixtureWith(t, func(f *openFixture) {
		m := f.m
		before, _ = m.relay.(*stubRelay)
		m.mu.Lock()
		defer m.mu.Unlock()
		now := m.now()
		ik := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, 32))
		kem, _ := suite.NewPrivateKey(bytes.Repeat([]byte{0x72}, 32))
		rk := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x73}, 32))
		pk := rk.Public().(ed25519.PublicKey)
		p := &Peer{ID: "c1", Kind: KindConnection, State: PeerActive, IK: ik.Public().(ed25519.PublicKey), KEM: kem.Public().Bytes(),
			Relay:     PeerRelay{URL: "https://relay.example.org", Mailbox: relayauth.MailboxID(pk), PK: pk},
			Reconnect: HeldToken{Token: "v4.public.VEVTVA", Exp: now.Add(24 * time.Hour)}, LastEpochID: bytes.Repeat([]byte{0xe1}, 16)}
		m.st.Connections[p.ID] = p
		og := reconnectOf(t, m, p)
		ogID, initOutbox, issued = og.ID, og.InitOutbox, append([]IssuedToken(nil), og.Issued...)
		if err := (managerHost{m}).RotateIdentity(now); err != nil {
			t.Fatal(err)
		}
		if err := m.persist(context.Background(), false); err != nil {
			t.Fatal(err)
		}
	})
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("recovery open: %+v", out)
	}
	defer m.Crash()
	m.mu.Lock()
	defer m.mu.Unlock()
	checkAbandonedAt(t, m, ogID, initOutbox, issued, false, before) // S5 (0.86.0): abandoned in the rotation's write
}
