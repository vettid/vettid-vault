package vault

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
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

	// The last handshake: its initiator, hs.init inner id and ts, and
	// after finish its epoch, SAS and the vault's token from hs.resp.
	ini    *handshake.Initiator
	initID string
	initTS time.Time
	ep     *handshake.Epoch
	sas    string
	tok    string
	n      int
	// noAPIKey leaves api_key out of a transfer's hs.init.
	noAPIKey bool
	// noProfile: a connection hs.init without the core names (§6.2).
	noProfile bool
}

// testAppKeyDER is a fixed P-256 app key's SPKI DER (scalar 32 x b), TEST
// ONLY.
func testAppKeyDER(t testing.TB, b byte) []byte {
	t.Helper()
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), bytes.Repeat([]byte{b | 1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
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
	now := m.now().UTC().Truncate(time.Millisecond)
	id, _ := envelope.NewULID(now)
	cfg := handshake.InitiatorConfig{Purpose: purpose, Ctx: ctxID, Identity: n.ik, StaticKEM: n.kem.Public(), Relay: n.addr,
		Token: tok, ResponderIK: m.keys.ik.Public().(ed25519.PublicKey), ResponderEK: m.keys.kem.Public(),
		ResponderRelayKey: m.keys.relay.Public().(ed25519.PublicKey), Policy: policyFor(string(purpose)), Now: now,
		DeviceAttest: da, ID: id}
	if purpose == handshake.PurposeConnection && !n.noProfile {
		cfg.Profile = json.RawMessage(`{"first_name":"Nora","last_name":"Newcomer"}`) // §6.2 (0.18.0)
	}
	if inv := m.st.Invites[ctxID]; inv != nil && inv.Transfer && !n.noAPIKey {
		cfg.APIKey = testAppKeyDER(t, n.ik[0]) // a transfer's new app (0.15.0, §6.2)
	}
	ini, err := handshake.NewInitiator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	n.ini, n.initID, n.initTS, n.ep, n.sas, n.tok = ini, id, now, nil, "", ""
	_ = m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{{MsgID: msgID, Sender: relayauth.EncodeKey(n.addr.PK), Payload: ini.Envelope()}})
}

// finish takes the vault's hs.resp to n from the stub relay, completes
// the handshake and sends hs.fin on the token hs.resp carried (§6.3,
// 0.10.3). It returns n's SAS.
func (n *newcomer) finish(t testing.TB, d *devFixture) string {
	t.Helper()
	m := d.m
	var resp []byte
	d.relay.mu.Lock()
	for i, dep := range d.relay.deposits {
		env, err := envelope.Parse(dep.payload)
		if err == nil && dep.mailbox == n.addr.Mailbox && env.Mode() == envelope.ModeSealed && env.RecipientKid().Equal(n.ini.EphKid()) {
			resp = dep.payload
			d.relay.deposits = append(d.relay.deposits[:i:i], d.relay.deposits[i+1:]...)
			break
		}
	}
	d.relay.mu.Unlock()
	if resp == nil {
		t.Fatal("no hs.resp for the newcomer")
	}
	res, err := n.ini.HandleResp(resp, m.keys.relay.Public().(ed25519.PublicKey), m.now())
	if err != nil {
		t.Fatalf("hs.resp: %v", err)
	}
	n.ep, n.sas, n.tok = res.Epoch, res.SAS, res.Resp.Token
	n.deliver(t, d, res.Fin)
	return n.sas
}

// deliver hands the vault one deposit from n, made on the token hs.resp
// gave n (its jti decides the token class, §6.6, §7.1).
func (n *newcomer) deliver(t testing.TB, d *devFixture, payload []byte) {
	t.Helper()
	n.n++
	jti := ""
	if n.tok != "" {
		if c, err := relayauth.ParseToken(n.tok, d.m.keys.relay.Public().(ed25519.PublicKey)); err == nil {
			jti = c.Jti
		}
	}
	msg := Message{MsgID: fmt.Sprintf("n%x-%d", n.addr.PK[:4], n.n), Sender: relayauth.EncodeKey(n.addr.PK), JTI: jti, Payload: payload}
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg})
}

// send seals a message to the vault in n's epoch and delivers it.
func (n *newcomer) send(t testing.TB, d *devFixture, typ string, body []byte) string {
	t.Helper()
	id, _ := envelope.NewULID(time.Now())
	raw, err := n.ep.Seal(&envelope.Inner{ID: id, Type: typ, TS: time.Now(), Body: body})
	if err != nil {
		t.Fatal(err)
	}
	n.deliver(t, d, raw)
	return id
}

// received decrypts (and removes) the vault's deposits to n in n's epoch.
func (n *newcomer) received(d *devFixture) []*envelope.Inner {
	var out []*envelope.Inner
	d.relay.mu.Lock()
	defer d.relay.mu.Unlock()
	kept := d.relay.deposits[:0]
	for _, dep := range d.relay.deposits {
		env, err := envelope.Parse(dep.payload)
		if err == nil && dep.mailbox == n.addr.Mailbox && env.Mode() == envelope.ModeSession && n.ep != nil {
			var kr handshake.Keyring
			kr.Activate(n.ep, time.Now())
			if in, _, err := kr.Open(env, time.Now()); err == nil {
				out = append(out, in)
				continue
			}
		}
		kept = append(kept, dep)
	}
	d.relay.deposits = kept
	return out
}

// firstContact counts first-contact handshakes and requests in progress.
func (d *devFixture) firstContact() int {
	n := len(d.m.st.Requests)
	for _, aw := range d.m.st.Awaiting {
		if aw.New != nil {
			n++
		}
	}
	return n
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

// transferInvite opens a direct transfer from the fixture's app (§6.7.1).
func (d *devFixture) transferInvite(t testing.TB) *Invite {
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	id, _, _, err := d.m.createTransfer(context.Background(), "dev1", d.m.now())
	if err != nil {
		t.Fatal(err)
	}
	return d.m.st.Invites[id]
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

// §6.7 (0.10.3): the vault answers hs.init at once with a request token;
// the paired app is asked, with the SAS, only once hs.fin checked out; the
// device gets nothing but the handshake before the owner's approval, which
// activates the epoch and sends device.paired with the standing token.
func TestPairingHandshakeThenApproval(t *testing.T) {
	d := newDevFixture(t)
	inv := d.invite(t, KindDesktop, PairingApprovalTTL)
	n := newNewcomer(t, 0x50)
	n.hsInit(t, d.m, handshake.PurposeDesktop, inv.ID, "p1")
	if d.firstContact() != 1 || d.depositsTo(n.addr.Mailbox) != 1 {
		t.Fatal("hs.resp not sent at once")
	}
	if d.depositsTo(d.devPeer.Relay.Mailbox) != 0 {
		t.Fatal("the app was asked before hs.fin")
	}
	sas := n.finish(t, d)
	c, err := relayauth.ParseToken(n.tok, d.m.keys.relay.Public().(ed25519.PublicKey))
	if err != nil || c.Quota == nil || *c.Quota.Msgs != RequestTokenQuotaMsgs || *c.Quota.Bytes != RequestTokenQuotaBytes ||
		c.Exp.Sub(c.Iat) > RequestTokenDevice || d.m.issuedKind(c.Jti) != TokRequest {
		t.Fatalf("hs.resp token is not a request token: %+v %v", c, err)
	}
	evs := d.responses(t)
	if len(evs) != 1 || evs[0].Type != "device.pair.pending" || bodyStr(t, evs[0], "sas") != sas || len(sas) != 6 {
		t.Fatalf("pending event: %+v (sas %s)", evs, sas)
	}
	if len(d.m.st.Devices) != 1 {
		t.Fatal("device record before approval")
	}
	// Before approval the device's messages are dropped (§6.7).
	n.send(t, d, "vault.status", []byte(`{}`))
	if !d.audited("unapproved_peer") || len(n.received(d)) != 0 {
		t.Fatal("message before approval not dropped")
	}
	if err := d.send("device.pair.approve", []byte(`{"pairing_id":"`+inv.ID+`"}`)); err != nil {
		t.Fatal(err)
	}
	got := n.received(d)
	if r := find(d.responses(t), func(in *envelope.Inner) bool { return in.Re != "" }); r == nil || r.Status != envelope.StatusOK {
		t.Fatalf("approve: %+v", r)
	}
	if len(got) != 1 || got[0].Type != "device.paired" || bodyStr(t, got[0], "token") == "" {
		t.Fatalf("device.paired: %+v", got)
	}
	if c, err := relayauth.ParseToken(bodyStr(t, got[0], "token"), d.m.keys.relay.Public().(ed25519.PublicKey)); err != nil || c.Quota != nil {
		t.Fatal("device.paired token is not a standing token")
	}
	if len(d.m.st.Devices) != 2 || d.firstContact() != 0 {
		t.Fatal("not active after approval")
	}
}

// §6.3 (0.10.3): an hs.fin whose sig_I verifies but whose n_I does not
// open sas_commit aborts the handshake: the request is dropped, never
// shown, and its request token denylisted.
func TestSASCommitMismatch(t *testing.T) {
	d := newDevFixture(t)
	inv := d.invite(t, KindConnection, time.Hour)
	n := newNewcomer(t, 0x50)
	n.hsInit(t, d.m, handshake.PurposeConnection, inv.ID, "c1")
	var resp []byte
	for _, dep := range d.relay.deposits {
		if dep.mailbox == n.addr.Mailbox {
			resp = dep.payload
		}
	}
	res, err := n.ini.HandleResp(resp, d.m.keys.relay.Public().(ed25519.PublicKey), d.m.now())
	if err != nil {
		t.Fatal(err)
	}
	n.ep, n.tok = res.Epoch, res.Resp.Token
	th := handshake.Th(n.ini.Envelope(), resp[:envelope.HeaderSealed])
	sig, _ := handshake.SignFin(n.ik, th)
	fb, _ := (&handshake.Fin{Sig: sig, SASNonce: bytes.Repeat([]byte{9}, 32)}).Marshal(handshake.PurposeConnection)
	n.send(t, d, handshake.TypeFin, fb)
	if !d.audited("sas_commit_mismatch") || d.firstContact() != 0 {
		t.Fatal("commitment mismatch not aborted")
	}
	c, _ := relayauth.ParseToken(n.tok, d.m.keys.relay.Public().(ed25519.PublicKey))
	d.m.mu.Lock()
	d.m.drainOutbox(context.Background())
	d.m.mu.Unlock()
	if !containsStr(d.relay.revoked, "jti:"+c.Jti) {
		t.Fatal("request token not denylisted")
	}
	for _, ev := range d.responses(t) {
		if ev.Type == "connection.request.pending" {
			t.Fatal("aborted request shown")
		}
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
	// One app per vault (0.9.0): an app pairing that is not a transfer is
	// dropped whatever it carries.
	plain := d.invite(t, KindApp, PairingApprovalTTL)
	n := newNewcomer(t, 0x50)
	n.hsInitAttest(t, d.m, handshake.PurposeApp, plain.ID, "p0", da)
	if d.firstContact() != 0 || !d.audited("one_app") {
		t.Fatal("a second app reached approval")
	}
	inv := d.transferInvite(t)
	n.hsInitAttest(t, d.m, handshake.PurposeApp, inv.ID, "p1", nil)
	if d.firstContact() != 0 || !d.audited("pairing_attestation_missing") {
		t.Fatal("app paired without device attestation")
	}
	fail = true
	n.hsInitAttest(t, d.m, handshake.PurposeApp, inv.ID, "p2", da)
	if d.firstContact() != 0 || !d.audited("pairing_attestation_failed") {
		t.Fatal("failed attestation accepted")
	}
	fail = false
	n.hsInitAttest(t, d.m, handshake.PurposeApp, inv.ID, "p3", da)
	if d.firstContact() != 1 {
		t.Fatal("attested app not pending")
	}
	want, _ := altchan.DevattChallenge(n.initID, "", envelope.FormatTS(n.initTS))
	if gotChallenge != want {
		t.Fatal("challenge is not bound to the hs.init")
	}
	for _, aw := range d.m.st.Awaiting {
		if aw.New == nil || len(aw.New.Attestation) == 0 {
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
	if d.firstContact() != 1 || !d.audited("invite_invalid") {
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
	if d.firstContact() != 0 || !d.audited("invite_invalid") {
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
	n := newNewcomer(t, 0x50)
	n.hsInit(t, d.m, handshake.PurposeAgent, inv2.ID, "a1")
	n.finish(t, d)
	if d.firstContact() != 1 || len(d.m.st.Requests) != 1 {
		t.Fatal("no pending pairing")
	}
	later2 := later.Add(11 * time.Minute)
	d.m.now = func() time.Time { return later2 }
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	if d.firstContact() != 0 {
		t.Fatal("unapproved pairing kept past 10 minutes")
	}
	c, _ := relayauth.ParseToken(n.tok, d.m.keys.relay.Public().(ed25519.PublicKey))
	if !containsStr(d.relay.revoked, "jti:"+c.Jti) {
		t.Fatal("request token of an expired pairing not denylisted")
	}
}

// §6.4: a remote invite stays pending until the owner approves; no
// auto-approval even when the owner enabled it for in-person invites.
// Since 0.10.3 hs.resp goes out at once in both cases; the approval is
// connection.approved.
func TestRemoteInviteStaysPending(t *testing.T) {
	d := newDevFixture(t)
	d.m.st.Settings.AutoApproveInPerson = true
	inv := d.invite(t, KindConnection, time.Hour)
	if !inv.Remote {
		t.Fatal("1 h invite not remote")
	}
	n := newNewcomer(t, 0x50)
	n.hsInit(t, d.m, handshake.PurposeConnection, inv.ID, "c1")
	n.finish(t, d)
	if len(d.m.st.Requests) != 1 || len(n.received(d)) != 0 {
		t.Fatal("remote invite auto-approved")
	}
	evs := d.responses(t)
	if len(evs) != 1 || !strings.Contains(string(evs[0].Body), `"remote":true`) || bodyStr(t, evs[0], "state") != "pending" {
		t.Fatalf("pending event: %+v", evs)
	}
	// In person with auto-approval: approved at hs.fin, still shown.
	inv2 := d.invite(t, KindConnection, 10*time.Minute)
	n2 := newNewcomer(t, 0x60)
	n2.hsInit(t, d.m, handshake.PurposeConnection, inv2.ID, "c2")
	n2.finish(t, d)
	if got := n2.received(d); len(got) != 1 || got[0].Type != "connection.approved" {
		t.Fatalf("in-person auto-approval did not approve: %+v", got)
	}
	evs = d.responses(t)
	if len(evs) != 1 || bodyStr(t, evs[0], "state") != "approved" || len(bodyStr(t, evs[0], "sas")) != 6 {
		t.Fatalf("auto-approved pending event: %+v", evs)
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
	if d.firstContact() != 0 || !d.audited("hs_init_from_revoked_key") {
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
	d.devPeer.Access = &AccessSession{ID: "s1", Expires: time.Now().Add(time.Hour)} // §6.8
	_ = d.send("connection.decline", []byte(`{"pending_id":"x"}`))
	if rs := d.responses(t); len(rs) != 1 || rs[0].Error == nil || rs[0].Error.Code != "not_found" {
		t.Fatalf("desktop may decide connections: %+v", rs)
	}
}

// §6.4: a pending connection request is dropped 7 days after its hs.init
// (announced as sync.event{connection.request, expired}); an approved one
// is kept 16 days for the peer's approval.
func TestPendingConnectionExpires(t *testing.T) {
	d := newDevFixture(t)
	inv := d.invite(t, KindConnection, 7*24*time.Hour)
	n := newNewcomer(t, 0x50)
	n.hsInit(t, d.m, handshake.PurposeConnection, inv.ID, "c1")
	n.finish(t, d)
	if len(d.m.st.Requests) != 1 {
		t.Fatal("no pending request")
	}
	d.responses(t)
	in6 := time.Now().Add(6 * 24 * time.Hour)
	d.m.now = func() time.Time { return in6 }
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	if len(d.m.st.Requests) != 1 {
		t.Fatal("dropped before 7 days")
	}
	in8 := time.Now().Add(8 * 24 * time.Hour)
	d.m.now = func() time.Time { return in8 }
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	if len(d.m.st.Requests) != 0 {
		t.Fatal("pending request kept past 7 days")
	}
	var expired bool
	for _, ev := range d.responses(t) {
		expired = expired || ev.Type == "sync.event" && bodyStr(t, ev, "kind") == "connection.request" && bodyStr(t, ev, "state") == "expired"
	}
	if !expired {
		t.Fatal("expiry not announced")
	}
	// Approved: kept until 16 days after the hs.init.
	d.m.now = time.Now
	inv = d.invite(t, KindConnection, 7*24*time.Hour)
	n2 := newNewcomer(t, 0x60)
	n2.hsInit(t, d.m, handshake.PurposeConnection, inv.ID, "c2")
	n2.finish(t, d)
	var pid string
	for id := range d.m.st.Requests {
		pid = id
	}
	_ = d.send("connection.approve", []byte(`{"pending_id":"`+pid+`"}`))
	d.m.now = func() time.Time { return in8 }
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	if d.m.st.Requests[pid] == nil {
		t.Fatal("approved request dropped after 8 days")
	}
	in17 := time.Now().Add(17 * 24 * time.Hour)
	d.m.now = func() time.Time { return in17 }
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, nil)
	if d.m.st.Requests[pid] != nil {
		t.Fatal("approved request kept past 16 days")
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
