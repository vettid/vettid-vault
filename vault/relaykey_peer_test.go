package vault

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// Two vaults across a relay-key rotation (§3.4): the receiving vault keeps
// the rotating vault's earlier relay key as its sender until the grace
// ends, and the rotating vault accepts tokens for its old keys.

// rkPump moves from's deposits for any of to's mailboxes (the current one
// and the old ones still in the grace) into to, in one batch, as the relay
// would: the collect sender is the depositing key, the jti the token's; a
// deposit on a token or sub to has revoked is refused. It returns how many
// were delivered.
func rkPump(t *testing.T, from, to *devFixture) int {
	t.Helper()
	from.m.mu.Lock()
	from.m.flushThenDrain(context.Background())
	from.m.mu.Unlock()
	to.m.mu.Lock()
	boxes := map[string]bool{to.m.st.Relay.Mailbox: true}
	for _, o := range to.m.st.Relay.Old {
		if !o.Gone {
			boxes[o.Mailbox] = true
		}
	}
	to.m.mu.Unlock()
	revoked := map[string]bool{}
	tr := to.relay.top()
	tr.mu.Lock()
	for _, v := range tr.revoked {
		revoked[v] = true
	}
	tr.mu.Unlock()
	var msgs []Message
	fr := from.relay.top()
	fr.mu.Lock()
	kept := fr.deposits[:0]
	for _, dep := range fr.deposits {
		if !boxes[dep.mailbox] {
			kept = append(kept, dep)
			continue
		}
		c, _ := stubClaims(dep.token)
		if revoked["sub:"+c.Sub] || revoked["jti:"+c.Jti] {
			continue // refused token_revoked
		}
		pumped++
		msgs = append(msgs, Message{MsgID: fmt.Sprintf("rkp%d", pumped), Sender: relayauth.EncodeKey(dep.sender), JTI: c.Jti, Payload: dep.payload})
	}
	fr.deposits = kept
	fr.mu.Unlock()
	if len(msgs) > 0 {
		if err := to.m.ProcessBatch(context.Background(), &fakeCollector{}, msgs); err != nil {
			t.Fatal(err)
		}
	}
	return len(msgs)
}

// settle pumps both ways until nothing moves.
func settle(t *testing.T, a, b *devFixture) {
	t.Helper()
	for range 12 {
		if rkPump(t, a, b)+rkPump(t, b, a) == 0 {
			return
		}
	}
}

// rkConnect connects two vaults (b accepts a's invitation) and returns
// each side's connection id.
func rkConnect(t *testing.T, a, b *devFixture) (aConn, bConn string) {
	t.Helper()
	_, link := a.linkFor(t, time.Hour)
	return rkAccept(t, a, b, link)
}

func rkAccept(t *testing.T, a, b *devFixture, link string) (aConn, bConn string) {
	t.Helper()
	r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
	bConn = bodyStr(t, r, "connection_id")
	rkPump(t, b, a)
	rkPump(t, a, b)
	b.appInbox()
	rkPump(t, b, a)
	aPend := event(a.appInbox(), "connection.request.pending")
	if aPend == nil {
		t.Fatal("no connection request")
	}
	a.request(t, "connection.approve", `{"pending_id":"`+bodyStr(t, aPend, "pending_id")+`"}`)
	rkPump(t, a, b)
	b.request(t, "connection.approve", `{"connection_id":"`+bConn+`"}`)
	settle(t, a, b)
	for id, p := range a.m.st.Connections {
		if p.State == PeerActive {
			aConn = id
		}
	}
	if aConn == "" || b.m.st.Connections[bConn] == nil || b.m.st.Connections[bConn].State != PeerActive {
		t.Fatal("not connected")
	}
	a.appInbox()
	b.appInbox()
	return aConn, bConn
}

// rkRotate rotates a's keys (a credential.rotate) and completes its relay
// key, as a batch's flush does.
func rkRotate(t *testing.T, a *devFixture) {
	t.Helper()
	a.m.mu.Lock()
	defer a.m.mu.Unlock()
	if err := a.m.rotateKeys(a.m.now(), true); err != nil {
		t.Fatal(err)
	}
	if err := completeRelayKey(a.m); err != nil {
		t.Fatal(err)
	}
}

// sendConn queues a message from a to its connection and returns its inner
// id.
func sendConn(a *devFixture, conn, typ string) string {
	a.m.mu.Lock()
	defer a.m.mu.Unlock()
	return a.m.sendTo(a.m.st.Connections[conn], typ, []byte(`{}`), a.m.now())
}

// handled reports whether b handled a message with inner id from its
// connection (recorded for dedupe, §8.2).
func handled(b *devFixture, id string) bool {
	b.m.mu.Lock()
	defer b.m.mu.Unlock()
	for k := range b.m.st.SeenInner {
		if strings.HasSuffix(k, id) {
			return true
		}
	}
	return false
}

func audited(d *devFixture, ev string) bool {
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	for _, a := range d.m.st.Audit {
		if a.Event == ev {
			return true
		}
	}
	return false
}

// A rotates; B follows the update. A's deposits with K0 that the relay
// accepted after B followed are still B's (B keeps K0 as A's sender until
// the grace and denylists nothing yet); the rekey A started under the old
// keys finishes though its hs.fin comes with K1 (the hs.fin sender
// substitution); B's tokens for K1 reach A, which then deposits with K1;
// after the grace B denylists K0.
func TestRelayKeyPeerVaultFollows(t *testing.T) {
	a, b := newVaultPair(t)
	aConn, bConn := rkConnect(t, a, b)
	k0 := relayauth.EncodeKey(pubOf(a.m.keys.relay))
	rkRotate(t, a)
	rkPump(t, a, b) // identity.rotate, the rekey's hs.init, the update: all with K0
	pb := b.m.st.Connections[bConn]
	if pb.Relay.Mailbox != a.m.st.Relay.Mailbox || len(pb.PrevRelay) != 1 {
		t.Fatalf("B did not follow: %s vs %s", pb.Relay.Mailbox, a.m.st.Relay.Mailbox)
	}
	if slices.Contains(b.relay.top().revoked, "sub:"+k0) {
		t.Fatal("B denylisted A's old key at once")
	}
	// A deposits with K0 (it has no token for K1 from B yet).
	id := sendConn(a, aConn, "profile.get")
	rkPump(t, a, b)
	if !handled(b, id) || audited(b, "unknown_kid") {
		t.Fatal("a deposit with the old key after B followed was lost")
	}
	settle(t, a, b)
	if audited(b, "hs_fin_rejected") || len(b.m.st.Awaiting) != 0 {
		t.Fatal("the rekey's hs.fin with the new key was refused")
	}
	if u := a.m.st.Relay.Updates[aConn]; u == nil || !u.Acked {
		t.Fatal("B's token for the new key did not reach A")
	}
	id = sendConn(a, aConn, "profile.get")
	a.m.mu.Lock()
	a.m.flushThenDrain(context.Background())
	a.m.mu.Unlock()
	for _, d := range a.relay.top().deposits {
		if d.mailbox == pb.Relay.Mailbox || d.mailbox == b.m.st.Relay.Mailbox {
			if !d.sender.Equal(pubOf(a.m.keys.relay)) {
				t.Fatal("A still deposits with K0 after B's token for K1")
			}
		}
	}
	rkPump(t, a, b)
	if !handled(b, id) {
		t.Fatal("not delivered with K1")
	}
	// After the grace, K0's tokens are denylisted.
	later := time.Now().Add(PeerRelayGrace + time.Minute)
	b.m.mu.Lock()
	b.m.now = func() time.Time { return later }
	b.m.housekeeping(later)
	b.m.flushThenDrain(context.Background())
	b.m.mu.Unlock()
	if len(pb.PrevRelay) != 0 || !slices.Contains(b.relay.top().revoked, "sub:"+k0) {
		t.Fatal("A's old key not denylisted after the grace")
	}
}

// B is locked while A rotates: at its unlock B collects everything at once
// (the update, then later deposits with K0) and loses nothing.
func TestRelayKeyPeerVaultLockedDuringRotation(t *testing.T) {
	a, b := newVaultPair(t)
	aConn, bConn := rkConnect(t, a, b)
	if err := b.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	rkRotate(t, a)
	id := sendConn(a, aConn, "profile.get")
	a.m.mu.Lock()
	a.m.flushThenDrain(context.Background())
	a.m.mu.Unlock()
	m, _, err := b.unlock(testPIN, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	b.fixture.m = m
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	rkPump(t, a, b)
	if !handled(b, id) || audited(b, "unknown_kid") {
		t.Fatal("a deposit with K0 after the update was lost")
	}
	if b.m.st.Connections[bConn].Relay.Mailbox != a.m.st.Relay.Mailbox {
		t.Fatal("B did not follow")
	}
	settle(t, a, b)
	if u := a.m.st.Relay.Updates[aConn]; u == nil || !u.Acked {
		t.Fatal("not acknowledged")
	}
}

// Chained K1→K2 before B acts on K1: B follows both updates (the second
// comes with K0 too), its tokens for K1 are taken by A as tokens for an old
// key (deposited with K1), and its tokens for K2 acknowledge.
func TestRelayKeyPeerVaultChained(t *testing.T) {
	a, b := newVaultPair(t)
	aConn, bConn := rkConnect(t, a, b)
	a.relay.top().rot = &stubRot{rotate: func(string) error { return &relayclient.Error{Status: 503, Code: "internal"} }}
	rkRotate(t, a) // K1 pending
	a.m.mu.Lock()
	if err := a.m.rotateKeys(a.m.now(), false); err != nil { // R2: a relay-key rotation owed
		t.Fatal(err)
	}
	a.relay.top().rot.rotate = nil
	a.m.rk.next = time.Time{}
	if err := completeRelayKey(a.m); err != nil { // K1 current, K2 stored and completed
		t.Fatal(err)
	}
	a.m.mu.Unlock()
	if a.m.st.Relay.Pending != nil || len(a.m.st.Relay.Old) != 2 {
		t.Fatalf("not chained: pending %v, %d old keys", a.m.st.Relay.Pending != nil, len(a.m.st.Relay.Old))
	}
	rkPump(t, a, b) // both updates, with K0: B follows K1 and refuses the second from K0
	pb := b.m.st.Connections[bConn]
	if pb.Relay.Mailbox != relayauth.MailboxID(pubOf(a.m.keys.oldRelay[1])) || !audited(b, "earlier_key_refused") {
		t.Fatal("B did not follow K1, or took K2's update from K0")
	}
	// B's tokens for K1 reach A, which sends K2's update again with K1.
	settle(t, a, b)
	if pb.Relay.Mailbox != a.m.st.Relay.Mailbox {
		t.Fatal("B did not follow K2")
	}
	if u := a.m.st.Relay.Updates[aConn]; u == nil || !u.Acked || !a.m.ownSubIs(a.m.st.Connections[aConn].Standing.Token) {
		t.Fatal("A holds no token of B's for K2")
	}
	if audited(a, "bad_issued_token") || audited(b, "unknown_kid") || audited(b, "hs_fin_rejected") {
		t.Fatal("a token or a deposit was lost across the chain")
	}
}

// ownSubIs reports whether tok was issued to m's current relay key.
func (m *Manager) ownSubIs(tok string) bool {
	sub, _, ok := heldTokenClaims(tok)
	return ok && sub == m.ownSub()
}

// An invitation made under the old relay key (here while the new key was
// pending: the identity key it names is already the new one) is claimed on
// the old address after the second write: the handshake and the approvals
// run on the old key and mailbox, and when the connection is active the
// new peer is sent the new address, follows it, and counts like every
// recipient.
func TestRelayKeyInvitationClaimedOnTheOldAddress(t *testing.T) {
	a, b := newVaultPair(t)
	a.relay.top().rot = &stubRot{rotate: func(string) error { return &relayclient.Error{Status: 503, Code: "internal"} }}
	rkRotate(t, a) // ik, kem rotated; the relay key pending
	_, link := a.linkFor(t, time.Hour)
	a.relay.top().rot.rotate = nil
	a.m.mu.Lock()
	a.m.rk.next = time.Time{}
	a.m.relayKeyStep(context.Background(), false)
	a.m.mu.Unlock()
	if a.m.st.Relay.Pending != nil {
		t.Fatal("not completed")
	}
	var inv *Invite
	for _, i := range a.m.st.Invites {
		inv = i
	}
	if inv == nil || inv.Mailbox != a.m.st.Relay.Old[0].Mailbox {
		t.Fatal("the invitation was not stamped with the old mailbox")
	}
	a.m.mu.Lock()
	a.m.pruneOldRelayKeys(a.m.now())
	retired := a.m.st.Relay.Old[0].Retired
	a.m.mu.Unlock()
	if retired {
		t.Fatal("the old key's use ended while an invitation made under it lives")
	}
	aConn, bConn := rkAccept(t, a, b, link)
	if b.m.st.Connections[bConn].Relay.Mailbox != a.m.st.Relay.Mailbox {
		t.Fatal("the new connection did not follow the new address")
	}
	if u := a.m.st.Relay.Updates[aConn]; u == nil || !u.Acked {
		t.Fatal("the new connection is not a recipient that followed")
	}
}

// An invitation made while the new relay key was pending, stamped with
// the old mailbox, that cannot finish before that mailbox is gone ends:
// the member is told (invite.expired).
func TestRelayKeyInvitationOldMailboxGone(t *testing.T) {
	a, _ := newVaultPair(t)
	sink := sinkOf(a)
	a.relay.top().rot = &stubRot{rotate: func(string) error { return &relayclient.Error{Status: 503, Code: "internal"} }}
	rkRotate(t, a)
	a.linkFor(t, time.Hour)
	a.relay.top().rot.rotate = nil
	a.m.mu.Lock()
	a.m.rk.next = time.Time{}
	a.m.relayKeyStep(context.Background(), false)
	a.m.mu.Unlock()
	if n := len(sink.kinds("invite.expired")); n != 0 {
		t.Fatal("an invitation made under the new ik expired")
	}
	a.m.oldMailboxGone(a.m.st.Relay.Old[0].Mailbox)
	if len(sink.kinds("invite.expired")) != 1 {
		t.Fatal("the member was not told")
	}
	a.m.mu.Lock()
	a.m.housekeeping(a.m.now())
	n := len(a.m.st.Invites)
	a.m.mu.Unlock()
	if n != 0 {
		t.Fatal("the invitation still lives")
	}
}

// Owner decision (a), 2026-11-05: at a key change's first write every
// unclaimed invitation and pairing, and every first contact the vault
// began, made under the old ik, expires at once with invite.expired; a
// begun one is aborted (its hs.init not sent, connection.event{failed}).
func TestRelayKeyFirstContactsUnderTheOldIKExpire(t *testing.T) {
	a, b := newVaultPair(t)
	sinkA, sinkB := sinkOf(a), sinkOf(b)
	a.linkFor(t, time.Hour) // a's invitation, unclaimed
	_, link := a.linkFor(t, time.Hour)
	b.m.mu.Lock()
	og, err := b.m.acceptInvite(context.Background(), link, "", b.m.now()) // b's first contact, begun
	b.m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	b.appInbox()
	rkRotate(t, a)
	rkRotate(t, b)
	if n := len(sinkA.kinds("invite.expired")); n != 2 {
		t.Fatalf("a's invitations: %d invite.expired", n)
	}
	if n := len(sinkB.kinds("invite.expired")); n != 1 || b.m.st.Outgoing[og.ID] != nil {
		t.Fatal("b's begun first contact did not expire")
	}
	b.m.mu.Lock()
	b.m.flushThenDrain(context.Background())
	b.m.mu.Unlock()
	if ev := event(b.appInbox(), "connection.event"); ev == nil || bodyStr(t, ev, "event") != "failed" {
		t.Fatal("b's devices were not told it failed")
	}
	a.m.mu.Lock()
	a.m.housekeeping(a.m.now())
	n := len(a.m.st.Invites)
	stamped := false
	for _, inv := range a.m.st.Invites {
		stamped = stamped || inv.Mailbox != ""
	}
	a.m.mu.Unlock()
	if n != 0 || stamped {
		t.Fatal("an invitation under the old ik lives on, or was stamped")
	}
	if rkPump(t, b, a) != 0 {
		t.Fatal("b's hs.init under the old ik was sent")
	}
}

// The relay's checks the stub makes (RELAY-PROTOCOL §5.3): a token's sub is
// the depositing key and its iss the mailbox.
func TestStubRelayChecksTokens(t *testing.T) {
	d := newDevFixture(t)
	pk := pubOf(d.devKey)
	c := relayclient.New(rkBase, d.devKey)
	tok, _ := c.MintToken(relayauth.EncodeKey(pubOf(d.m.keys.relay)), rkBase, relayclient.TokenOptions{TTL: time.Hour})
	if _, err := d.relay.Deposit(context.Background(), rkBase, relayauth.MailboxID(pk), tok, []byte("x")); err != nil {
		t.Fatal(err)
	}
	other := d.relay.WithKey(ed25519.NewKeyFromSeed(make([]byte, 32)))
	if _, err := other.Deposit(context.Background(), rkBase, relayauth.MailboxID(pk), tok, []byte("x")); RelayCode(err) != "token_invalid" {
		t.Fatalf("a deposit signed by another key: %v", err)
	}
	if _, err := d.relay.Deposit(context.Background(), rkBase, "elsewhere", tok, []byte("x")); RelayCode(err) != "token_invalid" {
		t.Fatalf("a deposit to another mailbox: %v", err)
	}
	_ = envelope.ModeSession
	_ = handshake.PurposeRekey
}

// capture takes from's queued deposits for to's current mailbox off the
// relay: what a holder of from's present copy could deposit later.
func capture(t *testing.T, from, to *devFixture) []stubDeposit {
	t.Helper()
	from.m.mu.Lock()
	from.m.flushThenDrain(context.Background())
	from.m.mu.Unlock()
	fr := from.relay.top()
	fr.mu.Lock()
	defer fr.mu.Unlock()
	var out []stubDeposit
	kept := fr.deposits[:0]
	for _, d := range fr.deposits {
		if d.mailbox == to.m.st.Relay.Mailbox {
			out = append(out, d)
		} else {
			kept = append(kept, d)
		}
	}
	fr.deposits = kept
	return out
}

// inject delivers deposits to to as collected, past any relay check (a
// relay that did not apply the denylist yet).
func inject(t *testing.T, to *devFixture, deps []stubDeposit) {
	t.Helper()
	var msgs []Message
	for _, d := range deps {
		c, _ := stubClaims(d.token)
		pumped++
		msgs = append(msgs, Message{MsgID: fmt.Sprintf("inj%d", pumped), Sender: relayauth.EncodeKey(d.sender), JTI: c.Jti, Payload: d.payload})
	}
	if err := to.m.ProcessBatch(context.Background(), &fakeCollector{}, msgs); err != nil {
		t.Fatal(err)
	}
}

// N1: the holder of A's old copy (its relay key K0, B's tokens for K0 and
// the old epoch's keys) cannot, after B followed A's new address, get an
// address update or a reconnect hs.init accepted as A; once A deposited
// with its new key, nothing from K0 is A's any more and K0 is denylisted.
func TestRelayKeyOldCopyCannotActAsThePeer(t *testing.T) {
	a, b := newVaultPair(t)
	aConn, bConn := rkConnect(t, a, b)
	k0 := relayauth.EncodeKey(pubOf(a.m.keys.relay))
	// What the old copy can make: a session message, an address update to
	// a mailbox of its choosing, a reconnect.
	msgID := sendConn(a, aConn, "profile.get")
	session := capture(t, a, b)
	evil := ed25519.NewKeyFromSeed(make([]byte, 32))
	ec := relayclient.New(rkBase, evil)
	etok, _ := ec.MintToken(relayauth.EncodeKey(pubOf(b.m.keys.relay)), rkBase, relayclient.TokenOptions{TTL: time.Hour})
	a.m.mu.Lock()
	evilMB := relayauth.MailboxID(pubOf(evil))
	a.m.sendTo(a.m.st.Connections[aConn], TypeAddressUpdate, []byte(`{"relay":{"url":"`+rkBase+`","mailbox":"`+evilMB+
		`","pk":"`+relayauth.EncodeKey(pubOf(evil))+`"},"token":"`+etok+`"}`), a.m.now())
	a.m.mu.Unlock()
	update := capture(t, a, b)
	a.m.mu.Lock()
	a.m.startReconnect(a.m.st.Connections[aConn], a.m.now())
	a.m.mu.Unlock()
	reconnect := capture(t, a, b)
	if len(session) == 0 || len(update) == 0 || len(reconnect) == 0 {
		t.Fatal("nothing captured")
	}
	// A rotates; B follows (K0 is A's earlier key now).
	rkRotate(t, a)
	rkPump(t, a, b)
	pb := b.m.st.Connections[bConn]
	if len(pb.PrevRelay) != 1 {
		t.Fatal("B did not follow")
	}
	want := pb.Relay.Mailbox
	inject(t, b, update)
	refusals := func() int {
		n := 0
		for _, a := range b.m.st.Audit {
			if a.Event == "earlier_key_refused" {
				n++
			}
		}
		return n
	}
	before := refusals()
	inject(t, b, reconnect)
	if refusals() != before+1 {
		t.Fatal("the reconnect hs.init from the earlier key was not refused before any handshake work")
	}
	if pb.Relay.Mailbox != want || pb.Relay.Mailbox == evilMB {
		t.Fatal("an address update from the earlier key was taken")
	}
	for _, aw := range b.m.st.Awaiting {
		if aw.Purpose == handshake.PurposeReconnect {
			t.Fatal("a reconnect from the earlier key was answered")
		}
	}
	if !audited(b, "earlier_key_refused") {
		t.Fatal("not audited")
	}
	// A deposits with K1 (and no handshake of its waits): K0 ends.
	settle(t, a, b)
	if len(pb.PrevRelay) != 0 || !slices.Contains(b.relay.top().revoked, "sub:"+k0) {
		t.Fatal("A's earlier key not ended at its first deposit with the new one")
	}
	inject(t, b, session)
	if handled(b, msgID) {
		t.Fatal("a session message from the earlier key was taken after A moved")
	}
}

// N1 (a): with no handshake of A's awaiting, A's first deposit with its
// current key ends its earlier keys (and denylists them).
func TestRelayKeyPeerEarlierKeyEndsAtACurrentDeposit(t *testing.T) {
	a, b := newVaultPair(t)
	aConn, bConn := rkConnect(t, a, b)
	rkRotate(t, a)
	settle(t, a, b)
	pb := b.m.st.Connections[bConn]
	k0 := []byte(pubOf(a.m.keys.oldRelay[0]))
	pb.PrevRelay = []PrevRelayKey{{PK: k0, Until: time.Now().Add(time.Hour)}}
	sendConn(a, aConn, "profile.get")
	rkPump(t, a, b)
	if len(pb.PrevRelay) != 0 || !slices.Contains(b.relay.top().revoked, "sub:"+relayauth.EncodeKey(k0)) {
		t.Fatal("not ended at a deposit with the current key")
	}
}
