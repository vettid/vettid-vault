package vault

import (
	"bytes"
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
	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/suite"
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
		msgs = append(msgs, Message{MsgID: fmt.Sprintf("rkp%d", pumped), Sender: relayauth.EncodeKey(dep.sender), JTI: c.Jti, Payload: dep.payload,
			DepositedAt: dep.at.UTC().Format(time.RFC3339Nano)})
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
		msgs = append(msgs, Message{MsgID: fmt.Sprintf("inj%d", pumped), Sender: relayauth.EncodeKey(d.sender), JTI: c.Jti, Payload: d.payload,
			DepositedAt: time.Now().UTC().Format(time.RFC3339Nano)})
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
	if !ended(pb) || !slices.Contains(b.relay.top().revoked, "sub:"+k0) {
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
	if !ended(pb) || !slices.Contains(b.relay.top().revoked, "sub:"+relayauth.EncodeKey(k0)) {
		t.Fatal("not ended at a deposit with the current key")
	}
}

// ended reports whether every earlier relay key of p has ended.
func ended(p *Peer) bool {
	for _, k := range p.PrevRelay {
		if k.EndedAt.IsZero() {
			return false
		}
	}
	return true
}

// Round 4, item 1: A moved K1→K2, B followed, A had not yet collected B's
// token for K2, and A rotated again (R3): identity.rotate and the rekey
// went out with K1 and B refused them by rule. Once A holds B's token for
// its current key it sends them again, and B follows A's identity key.
func TestRelayKeyRefusedKeyChangeIsSentAgain(t *testing.T) {
	a, b := newVaultPair(t)
	aConn, bConn := rkConnect(t, a, b)
	rkRotate(t, a)
	settle(t, a, b)
	rkRotate(t, a)  // K2
	rkPump(t, a, b) // B follows K2; its tokens for K2 wait in its outbox
	rkRotate(t, a)  // R3: sent with B's token for K1
	rkPump(t, a, b)
	if !audited(b, "earlier_key_refused") {
		t.Fatal("B took a key change from an earlier key")
	}
	settle(t, a, b)
	pb := b.m.st.Connections[bConn]
	if !suite.EqualPublic(pb.IK, pubOf(a.m.keys.ik)) {
		t.Fatal("B stays pinned to A's old identity key")
	}
	if audited(b, "bad_rotation") {
		t.Fatal("a link B had followed, sent again, was audited bad_rotation")
	}
	if pb.Relay.Mailbox != a.m.st.Relay.Mailbox {
		t.Fatal("B did not follow A's last address")
	}
	id := sendConn(a, aConn, "profile.get")
	settle(t, a, b)
	if !handled(b, id) || a.m.hasOutgoing(aConn, handshake.PurposeRekey) {
		t.Fatal("the session or the rekey did not recover")
	}
}

// Round 4, item 2: once A holds B's first token for its current key it
// deposits with that key at once, so B ends A's earlier keys without
// waiting for other traffic (here no rekey runs).
func TestRelayKeyEarlierKeysEndWithoutTraffic(t *testing.T) {
	a, b := newVaultPair(t)
	aConn, bConn := rkConnect(t, a, b)
	rkRotate(t, a)
	a.m.mu.Lock()
	a.m.dropRekey(aConn)
	a.m.st.Connections[aConn].OwnChainAtEpoch = len(a.m.st.Rotations) // as if the rekey had completed: nothing to send again
	a.m.mu.Unlock()
	rkPump(t, a, b) // B follows
	pb := b.m.st.Connections[bConn]
	if ended(pb) || len(pb.PrevRelay) != 1 {
		t.Fatal("ended too soon")
	}
	rkPump(t, b, a) // A stores B's token for its current key
	rkPump(t, a, b)
	if !ended(pb) {
		t.Fatal("B's view of A's earlier key did not end without further traffic")
	}
}

// Round 4, item 4: a deposit by an earlier key that the relay took before
// the key was ended still counts; one after it does not.
func TestRelayKeyEndedKeyKeepsEarlierDeposits(t *testing.T) {
	a, b := newVaultPair(t)
	aConn, bConn := rkConnect(t, a, b)
	rkRotate(t, a)
	rkPump(t, a, b) // B follows
	id := sendConn(a, aConn, "profile.get")
	late := capture(t, a, b) // deposited with K0 now, delivered late
	settle(t, a, b)
	pb := b.m.st.Connections[bConn]
	if !ended(pb) {
		t.Fatal("not ended")
	}
	var msgs []Message
	for _, d := range late {
		c, _ := stubClaims(d.token)
		pumped++
		msgs = append(msgs, Message{MsgID: fmt.Sprintf("late%d", pumped), Sender: relayauth.EncodeKey(d.sender), JTI: c.Jti, Payload: d.payload,
			DepositedAt: d.at.UTC().Format(time.RFC3339Nano)})
	}
	if err := b.m.ProcessBatch(context.Background(), &fakeCollector{}, msgs); err != nil {
		t.Fatal(err)
	}
	if !handled(b, id) {
		t.Fatal("a message deposited before the cut-off was lost")
	}
}

// Round 4, item 7: a renewal of a token for the same old key sends no
// update again; item 8: a resend of an address already followed, from an
// earlier key, is not audited as refused.
func TestRelayKeyRenewalAndFollowedResend(t *testing.T) {
	a, b := newVaultPair(t)
	aConn, _ := rkConnect(t, a, b)
	rkRotate(t, a)
	rkPump(t, a, b) // B follows
	a.m.mu.Lock()
	u := a.m.st.Relay.Updates[aConn]
	sendCount := func() int {
		n := 0
		for _, e := range a.m.st.Outbox {
			if e.AddressUpdate && !e.Done {
				n++
			}
		}
		return n
	}
	before := sendCount()
	a.m.sendAddressUpdate(a.m.st.Connections[aConn], u, a.m.now()) // a resend, with K0
	a.m.mu.Unlock()
	rkPump(t, a, b)
	if audited(b, "earlier_key_refused") {
		t.Fatal("a resend of a followed address was audited as refused")
	}
	// A renewal on the same old key: no resend.
	a.m.mu.Lock()
	p := a.m.st.Connections[aConn]
	if !a.m.onOldKey(p.Standing.Token) {
		a.m.mu.Unlock()
		t.Fatal("A holds no token for its old key")
	}
	a.m.mu.Unlock()
	tok := relayclient.New(rkBase, b.m.keys.relay)
	renewal, _ := tok.MintToken(relayauth.EncodeKey(pubOf(a.m.keys.oldRelay[0])), rkBase, relayclient.TokenOptions{TTL: 40 * 24 * time.Hour})
	a.m.mu.Lock()
	before = sendCount()
	a.m.storeIssuedTo(p, peerwire.TokenIssuedBody(TokStanding, renewal), a.m.now())
	after := sendCount()
	a.m.mu.Unlock()
	if after != before {
		t.Fatal("a renewal on the same key sent the update again")
	}
}

// Round 4, item 9: B's own reconnect, answered by A with a key B already
// knows as A's earlier one, completes (an hs.resp is no new handshake).
func TestRelayKeyReconnectAnsweredWithAnEarlierKey(t *testing.T) {
	a, b := newVaultPair(t)
	aConn, bConn := rkConnect(t, a, b)
	b.m.mu.Lock()
	b.m.startReconnect(b.m.st.Connections[bConn], b.m.now())
	b.m.mu.Unlock()
	init := capture(t, b, a) // B's hs.init, held
	rkRotate(t, a)
	a.m.mu.Lock()
	a.m.dropRekey(aConn)
	a.m.mu.Unlock()
	rkPump(t, a, b) // B follows: K0 is A's earlier key
	var msgs []Message
	for _, d := range init {
		c, _ := stubClaims(d.token)
		pumped++
		msgs = append(msgs, Message{MsgID: fmt.Sprintf("ri%d", pumped), Sender: relayauth.EncodeKey(d.sender), JTI: c.Jti, Payload: d.payload})
	}
	if err := a.m.ProcessBatch(context.Background(), &fakeCollector{}, msgs); err != nil {
		t.Fatal(err)
	}
	// A answers with B's reconnect hs.init's token: for A's K0.
	rkPump(t, a, b)
	if audited(b, "earlier_key_refused") {
		t.Fatal("A's hs.resp from its earlier key was refused")
	}
	settle(t, a, b)
	if b.m.hasOutgoing(bConn, handshake.PurposeReconnect) {
		t.Fatal("B's reconnect did not complete")
	}
}

// Round 5, R1 and R2: A's reconnect, answered by B while A was on K0, is
// collected by A late, after A moved to K1 and B ended K0. A keeps its
// tokens for its current key (the hs.resp's tokens for K0 are older), B
// keeps its tokens for A's current mailbox (the hs.init's are A's old
// mailbox's), and traffic goes both ways afterwards.
func TestRelayKeyReconnectRespAfterTheCutOff(t *testing.T) {
	a, b := newVaultPair(t)
	aConn, bConn := rkConnect(t, a, b)
	c := newDevFixture(t)
	c.relay.claims = a.relay.claims
	rkConnect(t, a, c) // C never collects after A rotates: K0 stays in use for it
	a.m.mu.Lock()
	a.m.startReconnect(a.m.st.Connections[aConn], a.m.now())
	a.m.mu.Unlock()
	rkPump(t, a, b) // B answers A's reconnect while A is on K0
	resp := capture(t, b, a)
	if len(resp) == 0 {
		t.Fatal("no hs.resp")
	}
	rkRotate(t, a)
	a.m.mu.Lock()
	a.m.dropRekey(aConn)
	a.m.mu.Unlock()
	rkPump(t, a, b) // B follows K1
	rkPump(t, b, a) // A stores B's token for K1, deposits with K1
	rkPump(t, a, b) // B ends K0
	if !ended(b.m.st.Connections[bConn]) {
		t.Fatal("B did not end K0")
	}
	inject(t, a, resp) // B's hs.resp, collected late from A's old mailbox
	if a.m.onOldKey(a.m.st.Connections[aConn].Standing.Token) {
		t.Fatal("the late hs.resp put A back on its old key")
	}
	settle(t, a, b)
	id := sendConn(a, aConn, "profile.get")
	settle(t, a, b)
	if !handled(b, id) {
		t.Fatal("A's session message after the reconnect never reached B")
	}
	id2 := sendConn(b, bConn, "profile.get")
	settle(t, a, b)
	if !handled(a, id2) {
		t.Fatal("B's session message after the reconnect never reached A")
	}
}

// Round 5, R3: B's reconnect, begun before it followed A's new address,
// is answered by A after B ended A's earlier key, on the hs.init's token
// for that key: the relay still takes it (B revoked that key's other
// tokens by jti, not the key), the reconnect finishes, and B revokes the
// key once it has.
//
// "A keeps K0": another recipient still holds it, so A answers with K0 and
// B's deferral of the key's revocation lets it through. "A retired K0": A
// answers with its current key on B's token for it, and B takes the
// hs.resp from A's current key for the K0 its hs.init pinned (M3).
func TestRelayKeyReconnectInProgressFinishesAfterTheCutOff(t *testing.T) {
	for _, keep := range []bool{true, false} {
		t.Run(fmt.Sprintf("A keeps K0=%v", keep), func(t *testing.T) { reconnectInProgress(t, keep) })
	}
}

func reconnectInProgress(t *testing.T, keepK0 bool) {
	a, b := newVaultPair(t)
	aConn, bConn := rkConnect(t, a, b)
	if keepK0 {
		c := newDevFixture(t)
		c.relay.claims = a.relay.claims
		rkConnect(t, a, c) // C never collects after A rotates: K0 stays in use for it
	}
	k0 := relayauth.EncodeKey(pubOf(a.m.keys.relay))
	// A rotates; its relay key stays pending a while: B follows A's new ik
	// (still on K0), then begins a reconnect, pinned to the new ik and K0.
	a.relay.top().rot = &stubRot{rotate: func(string) error { return &relayclient.Error{Status: 503, Code: "internal"} }}
	rkRotate(t, a)
	a.m.mu.Lock()
	a.m.dropRekey(aConn)
	a.m.mu.Unlock()
	rkPump(t, a, b)
	if !suite.EqualPublic(b.m.st.Connections[bConn].IK, pubOf(a.m.keys.ik)) {
		t.Fatal("B did not follow A's new ik")
	}
	b.m.mu.Lock()
	b.m.startReconnect(b.m.st.Connections[bConn], b.m.now())
	b.m.mu.Unlock()
	init := capture(t, b, a) // B's hs.init, held on the way
	a.relay.top().rot.rotate = nil
	a.m.mu.Lock()
	a.m.rk.next = time.Time{}
	a.m.relayKeyStep(context.Background(), false) // K1 current
	a.m.mu.Unlock()
	rkPump(t, a, b) // B follows K1
	rkPump(t, b, a) // A stores B's token for K1, deposits with K1
	rkPump(t, a, b) // B ends K0
	pb := b.m.st.Connections[bConn]
	if !ended(pb) || slices.Contains(b.relay.top().revoked, "sub:"+k0) {
		t.Fatal("not ended, or the key revoked while B's reconnect under it is in progress")
	}
	if !keepK0 {
		// N2: the fallback takes the peer's reconnect token for the current
		// key only while it is valid.
		a.m.mu.Lock()
		pa := a.m.st.Connections[aConn]
		saved := pa.Reconnect
		pa.Reconnect.Exp = time.Now().Add(-time.Minute)
		a.m.mu.Unlock()
		inject(t, a, init)
		if !audited(a, "reconnect_bad_token") {
			t.Fatal("answered on an expired reconnect token")
		}
		a.m.mu.Lock()
		pa.Reconnect = saved
		a.m.mu.Unlock()
		for i := range init {
			init[i].payload = append([]byte(nil), init[i].payload...)
		}
		a.m.mu.Lock()
		for k := range a.m.st.SeenInit {
			delete(a.m.st.SeenInit, k) // the same hs.init again, as a retransmission
		}
		a.m.mu.Unlock()
	}
	inject(t, a, init) // A answers
	if rkPump(t, a, b) == 0 {
		t.Fatal("the relay refused A's answer")
	}
	a.m.mu.Lock()
	k0Kept := !a.m.st.Relay.Old[0].Retired
	a.m.mu.Unlock()
	if k0Kept != keepK0 {
		t.Fatalf("setup: A keeps K0 %v", k0Kept)
	}
	settle(t, a, b)
	if b.m.hasOutgoing(bConn, handshake.PurposeReconnect) {
		t.Fatal("B's reconnect did not finish")
	}
	b.m.mu.Lock()
	b.m.housekeeping(b.m.now())
	b.m.flushThenDrain(context.Background())
	b.m.mu.Unlock()
	if !slices.Contains(b.relay.top().revoked, "sub:"+k0) {
		t.Fatal("the key not revoked once the reconnect finished")
	}
}

// Round 5, M1: the cut-off is the relay's time of the deposit that showed
// A's current key, not when B handles it: B locked, A deposits with K1 at
// T1, a holder of A's old copy deposits with K0 at T2 > T1, B unlocks and
// collects both at T3: the K0 deposit is not A's.
func TestRelayKeyCutOffIsTheDepositTime(t *testing.T) {
	a, b := newVaultPair(t)
	aConn, bConn := rkConnect(t, a, b)
	msgID := sendConn(a, aConn, "profile.get")
	thief := capture(t, a, b) // what the old copy can deposit with K0
	rkRotate(t, a)
	a.m.mu.Lock()
	a.m.dropRekey(aConn)
	a.m.mu.Unlock()
	rkPump(t, a, b) // B follows K1
	rkPump(t, b, a) // A stores B's token for K1: its prompt deposit with K1 waits
	k1 := capture(t, a, b)
	if len(k1) == 0 {
		t.Fatal("no deposit with K1")
	}
	t1 := time.Now().Add(-time.Minute)
	var batch []stubDeposit
	for _, d := range k1 {
		d.at = t1
		batch = append(batch, d)
	}
	for _, d := range thief {
		d.at = t1.Add(time.Second) // after A's cut-off, before B handles it
		batch = append(batch, d)
	}
	var msgs []Message
	for _, d := range batch {
		c, _ := stubClaims(d.token)
		pumped++
		msgs = append(msgs, Message{MsgID: fmt.Sprintf("co%d", pumped), Sender: relayauth.EncodeKey(d.sender), JTI: c.Jti, Payload: d.payload,
			DepositedAt: d.at.UTC().Format(time.RFC3339Nano)})
	}
	if err := b.m.ProcessBatch(context.Background(), &fakeCollector{}, msgs); err != nil {
		t.Fatal(err)
	}
	pb := b.m.st.Connections[bConn]
	if !ended(pb) || !pb.PrevRelay[0].EndedAt.Equal(t1.UTC().Truncate(time.Nanosecond)) && pb.PrevRelay[0].EndedAt.Sub(t1) > time.Millisecond {
		t.Fatalf("cut-off %v, want the deposit's time %v", pb.PrevRelay[0].EndedAt, t1)
	}
	if handled(b, msgID) {
		t.Fatal("a K0 deposit after A's cut-off was taken")
	}
}

// oldCopyAnswer: B begins a reconnect to A; A answers it before its own
// key change (what the holder of A's old copy can answer later, with K0
// and the old ik): the hs.resp is returned, held, and B's connection id.
func oldCopyAnswer(t *testing.T) (a, b *devFixture, aConn, bConn string, resp []stubDeposit) {
	a, b = newVaultPair(t)
	aConn, bConn = rkConnect(t, a, b)
	b.m.mu.Lock()
	b.m.startReconnect(b.m.st.Connections[bConn], b.m.now())
	b.m.mu.Unlock()
	inject(t, a, capture(t, b, a))
	resp = capture(t, a, b)
	if len(resp) == 0 {
		t.Fatal("no hs.resp")
	}
	return
}

// Round 6, H1: the holder of A's old copy answers B's reconnect, begun
// before A's credential.rotate, with A's old ik and K0, before and after
// B's cut-off of K0: B never goes back to A's old ik nor makes an epoch
// with it.
func TestRelayKeyOldCopyCannotRollBackTheIK(t *testing.T) {
	for _, afterCutOff := range []bool{false, true} {
		t.Run(fmt.Sprintf("after the cut-off=%v", afterCutOff), func(t *testing.T) {
			a, b, aConn, bConn, resp := oldCopyAnswer(t)
			rkRotate(t, a)
			a.m.mu.Lock()
			a.m.dropRekey(aConn)
			a.m.mu.Unlock()
			rkPump(t, a, b) // B follows A's new ik and K1
			if afterCutOff {
				settle(t, a, b)
				if !ended(b.m.st.Connections[bConn]) {
					t.Fatal("not ended")
				}
			}
			pb := b.m.st.Connections[bConn]
			newIK := append([]byte(nil), pb.IK...)
			epoch := append([]byte(nil), pb.LastEpochID...)
			inject(t, b, resp)
			if !suite.EqualPublic(pb.IK, newIK) || !bytes.Equal(pb.LastEpochID, epoch) {
				t.Fatal("B took A's old ik back, or made an epoch with the old copy")
			}
		})
	}
}

// H1 part 2: following identity.rotate abandons the handshakes B began
// pinned to A's earlier ik and begins them again under the new one.
func TestRelayKeyFollowingARotationRestartsHandshakes(t *testing.T) {
	a, b, aConn, bConn, _ := oldCopyAnswer(t)
	var old string
	for id, og := range b.m.st.Outgoing {
		if og.PeerID == bConn && og.Purpose == handshake.PurposeReconnect {
			old = id
		}
	}
	rkRotate(t, a)
	a.m.mu.Lock()
	a.m.dropRekey(aConn)
	a.m.mu.Unlock()
	rkPump(t, a, b)
	if b.m.st.Outgoing[old] != nil {
		t.Fatal("the reconnect pinned to the old ik is still open")
	}
	var again bool
	for id, og := range b.m.st.Outgoing {
		if og.PeerID == bConn && og.Purpose == handshake.PurposeReconnect && suite.EqualPublic(b.m.outgoing[id].ResponderIK(), pubOf(a.m.keys.ik)) {
			again = true
		}
	}
	if !again {
		t.Fatal("no reconnect begun again under the new ik")
	}
}

// followByHand makes B know A's new ik as a reconnect's rotations would,
// without the identity.rotate handler (so its handshakes stay open).
func followByHand(t *testing.T, a, b *devFixture, bConn string) {
	pb := b.m.st.Connections[bConn]
	pb.Chain = append(pb.Chain, a.m.st.Rotations...)
	pb.IK = append([]byte(nil), pubOf(a.m.keys.ik)...)
}

// H1 part 1: an hs.resp signed by an ik the peer has rotated away from is
// refused, whatever handshake it answers.
func TestRelayKeyRespFromAnAncestorIKRefused(t *testing.T) {
	a, b, _, bConn, resp := oldCopyAnswer(t)
	rkRotate(t, a)
	followByHand(t, a, b, bConn)
	pb := b.m.st.Connections[bConn]
	newIK := append([]byte(nil), pb.IK...)
	inject(t, b, resp)
	if !suite.EqualPublic(pb.IK, newIK) || !audited(b, "rotation_rollback_refused") {
		t.Fatal("an answer under an ancestor ik was taken")
	}
}

// H1 part 3: a handshake pinned to an ik the peer has rotated away from
// does not hold back the revocation of the peer's earlier relay key.
func TestRelayKeyOldIKHandshakeDoesNotDeferTheRevocation(t *testing.T) {
	a, b, _, bConn, _ := oldCopyAnswer(t)
	k0 := pubOf(a.m.keys.relay)
	rkRotate(t, a)
	followByHand(t, a, b, bConn)
	pb := b.m.st.Connections[bConn]
	pb.PrevRelay = []PrevRelayKey{{PK: append([]byte(nil), k0...), Until: time.Now().Add(time.Hour)}}
	b.m.mu.Lock()
	b.m.endPrevRelay(pb, b.m.now())
	b.m.flushThenDrain(context.Background())
	b.m.mu.Unlock()
	if pb.PrevRelay[0].SubPending || !slices.Contains(b.relay.top().revoked, "sub:"+relayauth.EncodeKey(k0)) {
		t.Fatal("a handshake under the old ik kept the earlier key's tokens")
	}
}
