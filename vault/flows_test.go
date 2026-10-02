package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

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
	vaultPK := m.keys.relay.Public().(ed25519.PublicKey)
	rc := relayclient.New(n.addr.URL, n.relay)
	tok, err := rc.MintToken(relayauth.EncodeKey(vaultPK), n.addr.URL, relayclient.TokenOptions{TTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	cfg := handshake.InitiatorConfig{Purpose: purpose, Ctx: ctxID, Identity: n.ik, StaticKEM: n.kem.Public(), Relay: n.addr,
		Token: tok, ResponderIK: m.keys.ik.Public().(ed25519.PublicKey), ResponderEK: m.keys.kem.Public(),
		ResponderRelayKey: m.keys.relay.Public().(ed25519.PublicKey), Policy: policyFor(string(purpose)), Now: m.now()}
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

// §6.6 permitted use: a connection with no live standing token can only
// have used its reconnect token, which carries nothing but a reconnect
// hs.init; anything else is dropped and audited.
func TestReconnectTokenMisuseDropped(t *testing.T) {
	d := newDevFixture(t)
	p := d.devPeer
	delete(d.m.st.Devices, p.ID)
	p.Kind = KindConnection
	d.m.st.Connections[p.ID] = p
	d.m.st.Issued = nil // no standing token issued to it is live
	id, _ := envelope.NewULID(time.Now())
	raw, _ := d.ep.Seal(&envelope.Inner{ID: id, Type: "connection.list", TS: time.Now(), Body: []byte(`{}`)})
	env, _ := envelope.Parse(raw)
	in, ep, err := d.m.sessions[p.ID].Open(env, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	d.m.mu.Lock()
	d.m.dispatch(context.Background(), p, in, ep, raw, p.Relay.PK, time.Now())
	d.m.mu.Unlock()
	if !d.audited("reconnect_token_misuse") || len(d.responses(t)) != 0 {
		t.Fatal("message on a reconnect token processed")
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
