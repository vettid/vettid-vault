package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// newcomer is a principal about to pair or connect.
type newcomer struct {
	ik    ed25519.PrivateKey
	relay ed25519.PrivateKey
	kem   *suite.PrivateKey
	addr  handshake.RelayAddr
}

func newNewcomer(t testing.TB, base byte) *newcomer {
	kem, _ := suite.NewPrivateKey(bytes.Repeat([]byte{base + 1}, 32))
	rk := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{base + 2}, 32))
	pk := rk.Public().(ed25519.PublicKey)
	return &newcomer{ik: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{base}, 32)), relay: rk, kem: kem,
		addr: handshake.RelayAddr{URL: "https://relay.example.org", Mailbox: relayauth.MailboxID(pk), PK: pk}}
}

// hsInit sends the newcomer's hs.init for (purpose, ctx) into the vault.
func (n *newcomer) hsInit(t testing.TB, m *Manager, purpose handshake.Purpose, ctxID, msgID string) {
	t.Helper()
	n.hsInitAttest(t, m, purpose, ctxID, msgID, nil)
}

func (n *newcomer) hsInitAttest(t testing.TB, m *Manager, purpose handshake.Purpose, ctxID, msgID string, da *altchan.DeviceAttest) {
	t.Helper()
	vaultPK := m.keys.relay.Public().(ed25519.PublicKey)
	rc := relayclient.New(n.addr.URL, n.relay)
	tok, err := rc.MintToken(relayauth.EncodeKey(vaultPK), n.addr.URL, relayclient.TokenOptions{TTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	cfg := handshake.InitiatorConfig{Purpose: purpose, Ctx: ctxID, Identity: n.ik, StaticKEM: n.kem.Public(), Relay: n.addr,
		Token: tok, ResponderIK: m.keys.ik.Public().(ed25519.PublicKey), ResponderEK: m.keys.kem.Public(),
		ResponderRelayKey: m.keys.relay.Public().(ed25519.PublicKey), Policy: policyFor(string(purpose)), Now: m.now(),
		DeviceAttest: da}
	if purpose == handshake.PurposeConnection {
		cfg.ReconnectToken = tok
	}
	ini, err := handshake.NewInitiator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{{MsgID: msgID, Sender: relayauth.EncodeKey(n.addr.PK), Payload: ini.Envelope()}})
}

func (d *devFixture) depositsTo(mailbox string) int {
	d.relay.mu.Lock()
	defer d.relay.mu.Unlock()
	n := 0
	for _, dep := range d.relay.deposits {
		if dep.mailbox == mailbox {
			n++
		}
	}
	return n
}

func (d *devFixture) audited(event string) bool {
	for _, a := range d.m.Audit() {
		if a.Event == event {
			return true
		}
	}
	return false
}

func (d *devFixture) invite(t testing.TB, kind string, ttl time.Duration) *Invite {
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	inv, _, err := d.m.createInvite(context.Background(), kind, ttl, "dev1", d.m.now())
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

// §6.7: the vault MUST NOT send hs.resp before approval; the paired app is
// asked, with the SAS.
func TestPairingApprovalFirst(t *testing.T) {
	d := newDevFixture(t)
	inv := d.invite(t, KindDesktop, PairingApprovalTTL)
	n := newNewcomer(t, 0x50)
	n.hsInit(t, d.m, handshake.PurposeDesktop, inv.ID, "p1")
	if len(d.m.st.Inbound) != 1 || d.depositsTo(n.addr.Mailbox) != 0 {
		t.Fatal("hs.resp sent before approval")
	}
	evs := d.responses(t)
	if len(evs) != 1 || evs[0].Type != "device.pair.pending" || !strings.Contains(string(evs[0].Body), `"sas"`) {
		t.Fatalf("pending event: %+v", evs)
	}
	for id := range d.m.st.Inbound {
		d.m.mu.Lock()
		if err := d.m.approveInbound(context.Background(), id, d.m.now()); err != nil {
			t.Fatal(err)
		}
		d.m.drainOutbox(context.Background())
		d.m.mu.Unlock()
	}
	if d.depositsTo(n.addr.Mailbox) != 1 {
		t.Fatal("no hs.resp after approval")
	}
}

// §6.7, §11.7: an app pairs with device attestation; the vault verifies
// it against the challenge of the hs.init (inner id as request_id, empty
// vault id, inner ts) and carries the binding into
// the device record (and so the header's
// unlock keys). Without attestation, or with a failing one, the hs.init is
// dropped and audited.
func TestPairingDeviceAttestation(t *testing.T) {
	d := newDevFixture(t)
	var gotChallenge [32]byte
	fail := false
	d.m.opt.DeviceAttest = func(da *altchan.DeviceAttest, ch [32]byte, _ time.Time) (json.RawMessage, error) {
		gotChallenge = ch
		if fail {
			return nil, errors.New("attestation")
		}
		return json.RawMessage(`{"platform":"android","pk":"AQ==","counter":0}`), nil
	}
	da := &altchan.DeviceAttest{Platform: altchan.PlatformAndroid, Chain: [][]byte{{1}}}
	inv := d.invite(t, KindApp, PairingApprovalTTL)
	n := newNewcomer(t, 0x50)
	n.hsInitAttest(t, d.m, handshake.PurposeApp, inv.ID, "p1", nil)
	if len(d.m.st.Inbound) != 0 || !d.audited("pairing_attestation_missing") {
		t.Fatal("app paired without device attestation")
	}
	inv = d.invite(t, KindApp, PairingApprovalTTL)
	fail = true
	n.hsInitAttest(t, d.m, handshake.PurposeApp, inv.ID, "p2", da)
	if len(d.m.st.Inbound) != 0 || !d.audited("pairing_attestation_failed") {
		t.Fatal("failed attestation accepted")
	}
	inv = d.invite(t, KindApp, PairingApprovalTTL)
	fail = false
	n.hsInitAttest(t, d.m, handshake.PurposeApp, inv.ID, "p3", da)
	if len(d.m.st.Inbound) != 1 {
		t.Fatal("attested app not pending")
	}
	for id, ib := range d.m.st.Inbound {
		pi := d.m.inbound[id]
		want, _ := altchan.DevattChallenge(pi.Inner().ID, "", envelope.FormatTS(pi.Inner().TS))
		if gotChallenge != want {
			t.Fatal("challenge is not bound to the hs.init")
		}
		if len(ib.Attestation) == 0 {
			t.Fatal("binding not kept")
		}
		d.m.mu.Lock()
		if err := d.m.approveInbound(context.Background(), id, d.m.now()); err != nil {
			t.Fatal(err)
		}
		d.m.mu.Unlock()
		if aw := d.m.st.Awaiting[id]; aw == nil || len(aw.New.Attestation) == 0 {
			t.Fatal("binding not carried to the device record")
		}
	}
}

// §6.4: every invite is single use; the vault accepts at most one hs.init
// per invite_id.
func TestInviteSingleUse(t *testing.T) {
	d := newDevFixture(t)
	inv := d.invite(t, KindConnection, 10*time.Minute)
	newNewcomer(t, 0x50).hsInit(t, d.m, handshake.PurposeConnection, inv.ID, "c1")
	newNewcomer(t, 0x60).hsInit(t, d.m, handshake.PurposeConnection, inv.ID, "c2")
	if len(d.m.st.Inbound) != 1 || !d.audited("invite_invalid") {
		t.Fatal("second hs.init on a used invite accepted")
	}
	// The used open token is denylisted and the claim deleted.
	d.m.mu.Lock()
	d.m.drainOutbox(context.Background())
	d.m.mu.Unlock()
	if !containsStr(d.relay.revoked, "jti:"+inv.OpenJTI) {
		t.Fatal("open token not denylisted")
	}
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// §6.4 revocation and §7.4: cancelling denylists the jti and deletes the
// claim; a later hs.init is rejected.
func TestInviteCancelled(t *testing.T) {
	d := newDevFixture(t)
	inv := d.invite(t, KindConnection, 10*time.Minute)
	if err := d.send("connection.invite.cancel", []byte(`{"invite_id":"`+inv.ID+`"}`)); err != nil {
		t.Fatal(err)
	}
	if rs := d.responses(t); len(rs) != 1 || rs[0].Status != envelope.StatusOK {
		t.Fatalf("cancel: %+v", rs)
	}
	if !containsStr(d.relay.revoked, "jti:"+inv.OpenJTI) {
		t.Fatal("jti not denylisted")
	}
	newNewcomer(t, 0x50).hsInit(t, d.m, handshake.PurposeConnection, inv.ID, "c1")
	if len(d.m.st.Inbound) != 0 || !d.audited("invite_invalid") {
		t.Fatal("cancelled invite accepted")
	}
}

// §6.7, §7.4: a pairing not answered within 10 minutes is dropped and its
// jti denylisted; expired invites are rejected.
func TestInviteExpiry(t *testing.T) {
	d := newDevFixture(t)
	inv := d.invite(t, KindAgent, PairingApprovalTTL)
	later := time.Now().Add(11 * time.Minute)
	d.m.now = func() time.Time { return later }
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	if _, ok := d.m.st.Invites[inv.ID]; ok || !containsStr(d.relay.revoked, "jti:"+inv.OpenJTI) {
		t.Fatal("expired pairing not cleaned up")
	}
	// A pending pairing also expires after 10 minutes without approval.
	inv2 := d.invite(t, KindAgent, PairingApprovalTTL)
	newNewcomer(t, 0x50).hsInit(t, d.m, handshake.PurposeAgent, inv2.ID, "a1")
	if len(d.m.st.Inbound) != 1 {
		t.Fatal("no pending pairing")
	}
	later2 := later.Add(11 * time.Minute)
	d.m.now = func() time.Time { return later2 }
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	if len(d.m.st.Inbound) != 0 {
		t.Fatal("unapproved pairing kept past 10 minutes")
	}
}

// §6.4: a remote invite stays pending until the owner approves; no
// auto-approval even when the owner enabled it for in-person invites.
func TestRemoteInviteStaysPending(t *testing.T) {
	d := newDevFixture(t)
	d.m.st.Settings.AutoApproveInPerson = true
	inv := d.invite(t, KindConnection, time.Hour)
	if !inv.Remote {
		t.Fatal("1 h invite not remote")
	}
	n := newNewcomer(t, 0x50)
	n.hsInit(t, d.m, handshake.PurposeConnection, inv.ID, "c1")
	if len(d.m.st.Inbound) != 1 || d.depositsTo(n.addr.Mailbox) != 0 {
		t.Fatal("remote invite auto-approved")
	}
	evs := d.responses(t)
	if len(evs) != 1 || !strings.Contains(string(evs[0].Body), `"remote":true`) {
		t.Fatalf("pending event: %+v", evs)
	}
	// In person with auto-approval: answered at once.
	inv2 := d.invite(t, KindConnection, 10*time.Minute)
	n2 := newNewcomer(t, 0x60)
	n2.hsInit(t, d.m, handshake.PurposeConnection, inv2.ID, "c2")
	if d.depositsTo(n2.addr.Mailbox) != 1 {
		t.Fatal("in-person auto-approval did not answer")
	}
}

// §6.7: a re-paired device MUST use a new relay key.
func TestRepairWithOldRelayKeyRefused(t *testing.T) {
	d := newDevFixture(t)
	d.m.mu.Lock()
	d.m.removePeer(d.devPeer, "device.unlinked", d.m.now())
	d.m.mu.Unlock()
	inv := d.invite(t, KindApp, PairingApprovalTTL)
	n := newNewcomer(t, 0x50)
	n.relay, n.addr = d.devKey, handshake.RelayAddr{URL: "https://relay.example.org", Mailbox: d.devPeer.Relay.Mailbox, PK: d.devPeer.Relay.PK}
	n.hsInit(t, d.m, handshake.PurposeApp, inv.ID, "r1")
	if len(d.m.st.Inbound) != 0 || !d.audited("hs_init_from_revoked_key") {
		t.Fatal("re-pairing with a revoked relay key accepted")
	}
}

// §6.6 permitted use, by the collect jti (RELAY-PROTOCOL 0.4.0): a
// connection's message on its reconnect token, or without a jti, is
// dropped and audited unless it is a sealed reconnect hs.init; on a
// standing token it is processed.
func TestReconnectTokenMisuseDropped(t *testing.T) {
	d := newDevFixture(t)
	p := d.devPeer
	delete(d.m.st.Devices, p.ID)
	p.Kind = KindConnection
	d.m.st.Connections[p.ID] = p
	sub := relayauth.EncodeKey(p.Relay.PK)
	far := time.Now().Add(300 * 24 * time.Hour)
	d.m.st.Issued = []IssuedToken{
		{JTI: "standing-1", Kind: TokStanding, Sub: sub, PeerID: p.ID, Exp: time.Now().Add(20 * 24 * time.Hour)},
		{JTI: "reconnect-1", Kind: TokReconnect, Sub: sub, PeerID: p.ID, Exp: far},
	}
	send := func(msgID, jti string) {
		id, _ := envelope.NewULID(time.Now())
		raw, _ := d.ep.Seal(&envelope.Inner{ID: id, Type: "relay.token.refresh", TS: time.Now(), Body: []byte(`{}`)})
		_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{{MsgID: msgID, Sender: sub, JTI: jti, Payload: raw}})
	}
	for _, c := range []struct{ msgID, jti string }{{"m1", "reconnect-1"}, {"m2", ""}} {
		before := len(d.m.Audit())
		send(c.msgID, c.jti)
		if rs := d.responses(t); len(rs) != 0 || len(d.m.Audit()) == before || !d.audited("reconnect_token_misuse") {
			t.Fatalf("jti %q: message on a reconnect token processed", c.jti)
		}
	}
	send("m3", "standing-1")
	if rs := d.responses(t); len(rs) != 1 || rs[0].Type != "relay.token.refresh" {
		t.Fatalf("standing-token message not processed: %+v", rs)
	}
}

// §6.4 / §6.7 who approves: only apps pair; agents never handle
// connections.
func TestApprovalRoles(t *testing.T) {
	d := newDevFixture(t)
	for _, kind := range []string{KindDesktop, KindAgent} {
		d.devPeer.Kind = kind
		_ = d.send("device.pair.create", []byte(`{"role":"desktop"}`))
		_ = d.send("device.pair.approve", []byte(`{"pairing_id":"x"}`))
		for _, r := range d.responses(t) {
			if r.Error == nil || r.Error.Code != "forbidden" {
				t.Fatalf("%s: pairing request not forbidden: %+v", kind, r)
			}
		}
	}
	d.devPeer.Kind = KindAgent
	for _, typ := range []string{"connection.invite.create", "connection.approve", "connection.decline", "connection.invite.accept"} {
		_ = d.send(typ, []byte(`{}`))
		rs := d.responses(t)
		if len(rs) != 1 || rs[0].Error == nil || rs[0].Error.Code != "forbidden" {
			t.Fatalf("agent %s not forbidden: %+v", typ, rs)
		}
	}
	d.devPeer.Kind = KindDesktop
	_ = d.send("connection.decline", []byte(`{"pending_id":"x"}`))
	if rs := d.responses(t); len(rs) != 1 || rs[0].Error == nil || rs[0].Error.Code != "not_found" {
		t.Fatalf("desktop may decide connections: %+v", rs)
	}
}

// §6.4: a pending connection request is dropped after 7 days.
func TestPendingConnectionExpires(t *testing.T) {
	d := newDevFixture(t)
	inv := d.invite(t, KindConnection, 7*24*time.Hour)
	newNewcomer(t, 0x50).hsInit(t, d.m, handshake.PurposeConnection, inv.ID, "c1")
	if len(d.m.st.Inbound) != 1 {
		t.Fatal("no pending request")
	}
	in6 := time.Now().Add(6 * 24 * time.Hour)
	d.m.now = func() time.Time { return in6 }
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	if len(d.m.st.Inbound) != 1 {
		t.Fatal("dropped before 7 days")
	}
	in8 := time.Now().Add(8 * 24 * time.Hour)
	d.m.now = func() time.Time { return in8 }
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	if len(d.m.st.Inbound) != 0 {
		t.Fatal("pending request kept past 7 days")
	}
}

// §7.1 token parameters.
func TestTokenQuotas(t *testing.T) {
	d := newDevFixture(t)
	claims := func(tok string) relayauth.Claims {
		msg, err := relayauth.VerifyToken(tok, d.m.keys.relay.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		c, err := relayauth.ParseClaims(msg)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	now := time.Now()
	conn := &Peer{ID: "c", Kind: KindConnection, Relay: d.devPeer.Relay}
	tok, _, _ := d.m.mintStanding(conn, now, nil)
	c := claims(tok)
	if c.Quota == nil || *c.Quota.Msgs != 20000 || *c.Quota.Bytes != 512<<20 || c.Exp.Sub(c.Iat) > 30*24*time.Hour {
		t.Fatalf("peer standing token: %+v", c)
	}
	tok, _, _ = d.m.mintStanding(d.devPeer, now, nil)
	if c := claims(tok); c.Quota != nil {
		t.Fatal("device standing token has a quota")
	}
	tok, _, _ = d.m.mintReconnect(conn, now, nil)
	c = claims(tok)
	if c.Quota == nil || *c.Quota.Msgs != 4 || *c.Quota.Bytes != 65536 || c.Exp.Sub(c.Iat) > 365*24*time.Hour {
		t.Fatalf("reconnect token: %+v", c)
	}
}

// §7.2: on unlock (and periodically) standing tokens with < 10 days left
// are re-minted and delivered as relay.token.issued.
func TestRemintStanding(t *testing.T) {
	d := newDevFixture(t)
	for i := range d.m.st.Issued {
		d.m.st.Issued[i].Exp = time.Now().Add(5 * 24 * time.Hour)
	}
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	evs := d.responses(t)
	if len(evs) != 1 || evs[0].Type != "relay.token.issued" {
		t.Fatalf("re-mint: %+v", evs)
	}
}

// §8.3: acks only after the flush; a crash right after the flush acks
// nothing.
func TestAckOnlyAfterFlush(t *testing.T) {
	d := newDevFixture(t)
	d.m.opt.Hooks.AfterFlush = func() error { return errors.New("crash") }
	id, _ := envelope.NewULID(time.Now())
	raw, _ := d.ep.Seal(&envelope.Inner{ID: id, Type: "vault.status", TS: time.Now(), Body: []byte(`{}`)})
	c := &fakeCollector{}
	err := d.m.ProcessBatch(context.Background(), c, []Message{{MsgID: "k", Sender: relayauth.EncodeKey(d.devPeer.Relay.PK), Payload: raw}})
	if !errors.Is(err, ErrCrash) || len(c.acked) != 0 {
		t.Fatalf("err %v, acked %v", err, c.acked)
	}
	if d.depositsTo(d.devPeer.Relay.Mailbox) != 0 {
		t.Fatal("outbox deposited before the ack point")
	}
}

// §8.1: a response matching no pending request is dropped.
func TestUnmatchedResponseDropped(t *testing.T) {
	d := newDevFixture(t)
	id, _ := envelope.NewULID(time.Now())
	re, _ := envelope.NewULID(time.Now())
	raw, _ := d.ep.Seal(&envelope.Inner{ID: id, Type: "relay.token.refresh", TS: time.Now(), Re: re, Status: "ok", Body: []byte(`{}`)})
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{{MsgID: "u", Sender: relayauth.EncodeKey(d.devPeer.Relay.PK), Payload: raw}})
	if len(d.responses(t)) != 0 {
		t.Fatal("unmatched response answered")
	}
}
