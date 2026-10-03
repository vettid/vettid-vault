package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// tdev is an extra owner device of a devFixture, paired in process.
type tdev struct {
	peer *Peer
	ep   *handshake.Epoch
}

// addDevice pairs another device of the given kind with a real handshake.
func (d *devFixture) addDevice(t testing.TB, id, kind string, seed byte) *tdev {
	t.Helper()
	m := d.m
	ik := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	rk := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed + 1}, 32))
	kem, _ := suite.NewPrivateKey(bytes.Repeat([]byte{seed + 2}, 32))
	pk := rk.Public().(ed25519.PublicKey)
	addr := handshake.RelayAddr{URL: "https://relay.example.org", Mailbox: relayauth.MailboxID(pk), PK: pk}
	now := time.Now()
	purpose := handshake.Purpose(kind)
	ini, err := handshake.NewInitiator(handshake.InitiatorConfig{Purpose: purpose, Ctx: "01JB2Z6V9K3M4N5P6Q7R8S9T0V",
		Identity: ik, StaticKEM: kem.Public(), Relay: addr, Token: "v4.public.VEVTVA",
		ResponderIK: m.keys.ik.Public().(ed25519.PublicKey), ResponderEK: m.keys.kem.Public(), ResponderRelayKey: m.keys.relay.Public().(ed25519.PublicKey),
		Policy: handshake.PolicyVaultToDevice, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	pi, err := handshake.OpenInit(ini.Envelope(), m.lookupKEM, now)
	if err != nil {
		t.Fatal(err)
	}
	resp, renv, err := pi.Respond(handshake.ResponderConfig{Identity: m.keys.ik, Token: "v4.public.VEVTVA", Policy: handshake.PolicyVaultToDevice, CollectSender: pk, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	res, err := ini.HandleResp(renv, m.keys.relay.Public().(ed25519.PublicKey), now)
	if err != nil {
		t.Fatal(err)
	}
	vep, _, err := resp.HandleFin(res.Fin, pk, now)
	if err != nil {
		t.Fatal(err)
	}
	p := &Peer{ID: id, Kind: kind, Name: id + "-name", State: PeerActive, IK: ik.Public().(ed25519.PublicKey), KEM: kem.Public().Bytes(),
		Relay: PeerRelay{URL: addr.URL, Mailbox: addr.Mailbox, PK: pk}, Standing: HeldToken{Token: "v4.public.VEVTVA", Exp: now.Add(20 * 24 * time.Hour)}}
	m.mu.Lock()
	m.st.Devices[id] = p
	m.sessions[id] = &handshake.Keyring{}
	m.sessions[id].Activate(vep, now)
	m.mu.Unlock()
	return &tdev{peer: p, ep: res.Epoch}
}

// sendAs sends a message from td (the fixture's own device is d.self()).
func (d *devFixture) sendAs(td *tdev, typ, body string) string {
	d.seq++
	id, _ := envelope.NewULID(time.Now())
	raw, err := td.ep.Seal(&envelope.Inner{ID: id, Type: typ, TS: time.Now(), Body: []byte(body)})
	if err != nil {
		panic(err)
	}
	msg := Message{MsgID: fmt.Sprintf("b%d", d.seq), Sender: relayauth.EncodeKey(td.peer.Relay.PK), Payload: raw}
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg})
	return id
}

func (d *devFixture) self() *tdev { return &tdev{peer: d.devPeer, ep: d.ep} }

// inbox decrypts and clears the vault's deposits, by device.
func (d *devFixture) inbox(devs ...*tdev) map[string][]*envelope.Inner {
	out := map[string][]*envelope.Inner{}
	d.relay.mu.Lock()
	defer d.relay.mu.Unlock()
	for _, dep := range d.relay.deposits {
		env, err := envelope.Parse(dep.payload)
		if err != nil || env.Mode() != envelope.ModeSession {
			continue
		}
		for _, td := range devs {
			if dep.mailbox != td.peer.Relay.Mailbox {
				continue
			}
			var kr handshake.Keyring
			kr.Activate(td.ep, time.Now())
			if in, _, err := kr.Open(env, time.Now()); err == nil {
				out[td.peer.ID] = append(out[td.peer.ID], in)
			}
		}
	}
	d.relay.deposits = nil
	return out
}

func find(ins []*envelope.Inner, pred func(*envelope.Inner) bool) *envelope.Inner {
	for _, in := range ins {
		if pred(in) {
			return in
		}
	}
	return nil
}

func ofType(typ string) func(*envelope.Inner) bool {
	return func(in *envelope.Inner) bool { return in.Type == typ && in.Re == "" }
}

func reply(id string) func(*envelope.Inner) bool {
	return func(in *envelope.Inner) bool { return in.Re == id }
}

func bodyStr(t testing.TB, in *envelope.Inner, k string) string {
	t.Helper()
	o, err := strictjson.ParseObject(in.Body)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := o.String(k)
	return v
}

func errCode(in *envelope.Inner) string {
	if in == nil || in.Error == nil {
		return ""
	}
	return in.Error.Code
}

// §6.8: desktops act only within an app-approved access session; step-up
// types are held for an app's approval; sessions end and expire.
func TestAccessSessions(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	desk := d.addDevice(t, "desk1", KindDesktop, 0x60)

	id := d.sendAs(desk, "connection.list", `{}`)
	if r := find(d.inbox(desk)["desk1"], reply(id)); errCode(r) != "session_required" {
		t.Fatalf("no session: %+v", r)
	}
	id = d.sendAs(desk, "vault.status", `{}`)
	if r := find(d.inbox(desk)["desk1"], reply(id)); r == nil || r.Status != envelope.StatusOK {
		t.Fatal("vault.status needs no session")
	}
	// §9.1: no fan-out to a desktop without a session.
	d.sendAs(app, "settings.set", `{"version":0,"set":{"app.a":"1"}}`)
	if ev := find(d.inbox(app, desk)["desk1"], ofType("sync.event")); ev != nil {
		t.Fatal("fan-out reached a desktop without a session")
	}
	// Roles: apps never request, desktops never approve.
	id = d.sendAs(app, "device.session.request", `{}`)
	if r := find(d.inbox(app)["dev1"], reply(id)); errCode(r) != "forbidden" {
		t.Fatalf("app requested a session: %+v", r)
	}
	for _, body := range []string{`{"seconds":59}`, `{"seconds":86401}`, `{"seconds":"60"}`} {
		id = d.sendAs(desk, "device.session.request", body)
		if r := find(d.inbox(desk)["desk1"], reply(id)); errCode(r) != "bad_request" {
			t.Fatalf("%s accepted", body)
		}
	}
	id = d.sendAs(desk, "device.session.request", `{"seconds":600}`)
	in := d.inbox(app, desk)
	if r := find(in["desk1"], reply(id)); r == nil || r.Status != envelope.StatusOK {
		t.Fatal("request refused")
	}
	pend := find(in["dev1"], ofType("device.session.pending"))
	if pend == nil || bodyStr(t, pend, "device_id") != "desk1" || bodyStr(t, pend, "role") != KindDesktop {
		t.Fatalf("apps not asked: %+v", in["dev1"])
	}
	rid := bodyStr(t, pend, "request_id")
	id = d.sendAs(desk, "device.session.approve", `{"request_id":"`+rid+`"}`)
	if r := find(d.inbox(desk)["desk1"], reply(id)); errCode(r) != "forbidden" {
		t.Fatal("a desktop approved a session")
	}
	id = d.sendAs(app, "device.session.approve", `{"request_id":"`+rid+`"}`)
	in = d.inbox(app, desk)
	if r := find(in["dev1"], reply(id)); r == nil || r.Status != envelope.StatusOK {
		t.Fatalf("approve: %+v", r)
	}
	if find(in["desk1"], ofType("device.session.granted")) == nil {
		t.Fatal("desktop not told")
	}
	if exp := time.Until(desk.peer.Access.Expires); exp < 9*time.Minute || exp > 11*time.Minute {
		t.Fatalf("session length %v", exp)
	}
	id = d.sendAs(desk, "connection.list", `{}`)
	if r := find(d.inbox(desk)["desk1"], reply(id)); r == nil || r.Status != envelope.StatusOK {
		t.Fatal("connection.list refused within the session")
	}
	d.sendAs(app, "settings.set", `{"version":1,"set":{"app.a":"2"}}`)
	if ev := find(d.inbox(app, desk)["desk1"], ofType("sync.event")); ev == nil {
		t.Fatal("no fan-out to a desktop within its session")
	}
	id = d.sendAs(app, "device.list", `{}`)
	if r := find(d.inbox(app)["dev1"], reply(id)); r == nil || !strings.Contains(string(r.Body), `"session_expires_at"`) {
		t.Fatal("device.list lacks the session")
	}

	// Step-up: settings.set from a desktop is held; the app approves.
	id = d.sendAs(desk, "settings.set", `{"version":2,"set":{"app.theme":"dark"}}`)
	in = d.inbox(app, desk)
	if find(in["desk1"], reply(id)) != nil {
		t.Fatal("held request answered at once")
	}
	if w := find(in["desk1"], ofType("approval.waiting")); w == nil || bodyStr(t, w, "request_id") != id {
		t.Fatal("no approval.waiting")
	}
	ap := find(in["dev1"], ofType("approval.pending"))
	if ap == nil || bodyStr(t, ap, "type") != "settings.set" || !strings.Contains(string(ap.Body), "app.theme") {
		t.Fatalf("approval.pending: %+v", in["dev1"])
	}
	aid := bodyStr(t, ap, "approval_id")
	// A retransmission while held is absorbed (§8.2).
	if len(d.m.st.Held) != 1 {
		t.Fatal("not held")
	}
	did := d.sendAs(app, "approval.decide", `{"approval_id":"`+aid+`","approve":true}`)
	in = d.inbox(app, desk)
	if r := find(in["dev1"], reply(did)); r == nil || bodyStr(t, r, "result") != "ok" {
		t.Fatalf("decide: %+v", r)
	}
	if r := find(in["desk1"], reply(id)); r == nil || r.Status != envelope.StatusOK || d.m.st.Settings.App["app.theme"] != "dark" {
		t.Fatalf("held request not executed: %+v", r)
	}
	// Denied, and timed out.
	id = d.sendAs(desk, "settings.set", `{"version":3,"set":{"app.theme":"light"}}`)
	aid = bodyStr(t, find(d.inbox(app, desk)["dev1"], ofType("approval.pending")), "approval_id")
	d.sendAs(app, "approval.decide", `{"approval_id":"`+aid+`","approve":false}`)
	if r := find(d.inbox(desk)["desk1"], reply(id)); errCode(r) != "denied" || d.m.st.Settings.App["app.theme"] != "dark" {
		t.Fatalf("denied: %+v", r)
	}
	id = d.sendAs(desk, "settings.set", `{"version":3,"set":{"app.theme":"light"}}`)
	d.inbox(app, desk)
	d.m.now = func() time.Time { return time.Now().Add(ApprovalTTL + time.Second) }
	d.sendAs(app, "vault.status", `{}`)
	d.m.now = time.Now
	if r := find(d.inbox(desk)["desk1"], reply(id)); errCode(r) != "approval_timeout" {
		t.Fatalf("timeout: %+v", r)
	}

	// The app ends the session: the desktop is told and refused again.
	id = d.sendAs(app, "device.session.end", `{"device_id":"desk1"}`)
	in = d.inbox(app, desk)
	if r := find(in["dev1"], reply(id)); r == nil || r.Status != envelope.StatusOK {
		t.Fatal("end refused")
	}
	if e := find(in["desk1"], ofType("device.session.ended")); e == nil || bodyStr(t, e, "reason") != "ended" {
		t.Fatal("desktop not told of the end")
	}
	id = d.sendAs(desk, "connection.list", `{}`)
	if r := find(d.inbox(desk)["desk1"], reply(id)); errCode(r) != "session_required" {
		t.Fatal("session survived its end")
	}
	// Deny a request; expiry of a session.
	d.sendAs(desk, "device.session.request", `{}`)
	rid = bodyStr(t, find(d.inbox(app, desk)["dev1"], ofType("device.session.pending")), "request_id")
	d.sendAs(app, "device.session.deny", `{"request_id":"`+rid+`"}`)
	if e := find(d.inbox(desk)["desk1"], ofType("device.session.ended")); e == nil || bodyStr(t, e, "reason") != "denied" {
		t.Fatal("denial not sent")
	}
	d.sendAs(desk, "device.session.request", `{"seconds":60}`)
	rid = bodyStr(t, find(d.inbox(app, desk)["dev1"], ofType("device.session.pending")), "request_id")
	d.sendAs(app, "device.session.approve", `{"request_id":"`+rid+`"}`)
	d.inbox(app, desk)
	d.m.now = func() time.Time { return time.Now().Add(61 * time.Second) }
	defer func() { d.m.now = time.Now }()
	id = d.sendAs(desk, "connection.list", `{}`)
	if r := find(d.inbox(desk)["desk1"], reply(id)); errCode(r) != "session_required" {
		t.Fatal("expired session accepted")
	}
	// Unlinking ends everything of the device.
	d.m.now = time.Now
	d.sendAs(desk, "device.session.request", `{}`)
	d.sendAs(app, "device.unlink", `{"device_id":"desk1"}`)
	if len(d.m.st.AccessRequests) != 0 {
		t.Fatal("request outlived the device")
	}
}

// agentPolicy is a LEASH stand-in.
type agentPolicy struct {
	recSink
	decide map[string]AgentDecision
	asked  []string
}

func (a *agentPolicy) AgentDecision(_ *Session, typ string, _ json.RawMessage) AgentDecision {
	a.asked = append(a.asked, typ)
	return a.decide[typ]
}

// §6.8 LEASH hook: an agent gets nothing beyond its listed types unless
// the policy allows an owner type or refers it to an app; app-only types
// are never offered to the policy.
func TestAgentPolicyHook(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	ag := d.addDevice(t, "agent1", KindAgent, 0x70)
	id := d.sendAs(ag, "settings.get", `{}`)
	if r := find(d.inbox(ag)["agent1"], reply(id)); errCode(r) != "forbidden" {
		t.Fatalf("no policy: %+v", r)
	}
	pol := &agentPolicy{decide: map[string]AgentDecision{"settings.get": AgentAllow, "settings.set": AgentAsk, "device.pair.create": AgentAllow}}
	d.m.addFeature(pol)
	id = d.sendAs(ag, "settings.get", `{}`)
	if r := find(d.inbox(ag)["agent1"], reply(id)); errCode(r) != "forbidden" {
		t.Fatalf("without a session the policy is not asked: %+v", r)
	}
	ag.peer.Access = &AccessSession{ID: "s", Expires: time.Now().Add(time.Hour)}
	id = d.sendAs(ag, "settings.get", `{}`)
	if r := find(d.inbox(ag)["agent1"], reply(id)); r == nil || r.Status != envelope.StatusOK {
		t.Fatalf("allowed type refused: %+v", r)
	}
	id = d.sendAs(ag, "device.pair.create", `{"role":"agent"}`)
	if r := find(d.inbox(ag)["agent1"], reply(id)); errCode(r) != "forbidden" {
		t.Fatal("app-only type delegated")
	}
	for _, typ := range pol.asked {
		if typ == "device.pair.create" {
			t.Fatal("policy asked about an app-only type")
		}
	}
	id = d.sendAs(ag, "settings.set", `{"version":0,"set":{"app.x":"1"}}`)
	in := d.inbox(app, ag)
	ap := find(in["dev1"], ofType("approval.pending"))
	if ap == nil || bodyStr(t, ap, "role") != KindAgent {
		t.Fatal("ask not referred to the apps")
	}
	d.sendAs(app, "approval.decide", `{"approval_id":"`+bodyStr(t, ap, "approval_id")+`","approve":true}`)
	if r := find(d.inbox(ag)["agent1"], reply(id)); r == nil || r.Status != envelope.StatusOK {
		t.Fatal("approved agent request not executed")
	}
}

// connObserver records ConnectionRemoved calls.
type connObserver struct {
	recSink
	removed []string
}

func (c *connObserver) ConnectionRemoved(_ *Session, id string) { c.removed = append(c.removed, id) }

// addConnection inserts an active connection record (no session).
func (d *devFixture) addConnection(id string, seed byte) *Peer {
	ik := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)).Public().(ed25519.PublicKey)
	rk := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed + 1}, 32)).Public().(ed25519.PublicKey)
	p := &Peer{ID: id, Kind: KindConnection, Name: "Peer " + id, State: PeerActive, IK: ik, CreatedAt: time.Now(),
		Relay: PeerRelay{URL: "https://relay.example.org", Mailbox: relayauth.MailboxID(rk), PK: rk}}
	d.m.mu.Lock()
	d.m.st.Connections[id] = p
	d.m.mu.Unlock()
	return p
}

// §7.4, §10.4: blocking a connection removes it (sub denylisted) and
// refuses its identity in any later handshake; a pending request can be
// blocked; unblocking lifts the refusal.
func TestBlocks(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	obs := &connObserver{}
	d.m.addFeature(obs)
	n := newNewcomer(t, 0x80)
	c := d.addConnection("c1", 0x80) // same ik as the newcomer
	id := d.sendAs(app, "block.add", `{"connection_id":"c1","note":"spam"}`)
	in := d.inbox(app)["dev1"]
	r := find(in, reply(id))
	if r == nil || r.Status != envelope.StatusOK {
		t.Fatalf("block.add: %+v", r)
	}
	if d.m.st.Connections["c1"] != nil || len(obs.removed) != 1 {
		t.Fatal("blocked connection not removed")
	}
	assertTokensDenied(t, d, "c1", c)
	if find(in, func(e *envelope.Inner) bool {
		return e.Type == "connection.event" && bodyStr(t, e, "event") == "removed"
	}) == nil {
		t.Fatal("no connection.event removed")
	}
	if !obs.has("connection.blocked") {
		t.Fatal("not audited")
	}
	// The blocked identity is refused on a new invite, even from a new relay key.
	inv := d.invite(t, KindConnection, time.Hour)
	n.relay = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x99}, 32))
	pk := n.relay.Public().(ed25519.PublicKey)
	n.addr.PK, n.addr.Mailbox = pk, relayauth.MailboxID(pk)
	n.hsInit(t, d.m, handshake.PurposeConnection, inv.ID, "h1")
	if len(d.m.st.Inbound) != 0 || !d.audited("blocked") {
		t.Fatal("blocked identity accepted")
	}
	// Duplicates, bad bodies, list and remove.
	for body, code := range map[string]string{`{}`: "bad_request", `{"connection_id":"c1","pending_id":"x"}`: "bad_request",
		`{"connection_id":"nope"}`: "not_found", `{"pending_id":"nope"}`: "not_found"} {
		id = d.sendAs(app, "block.add", body)
		if r := find(d.inbox(app)["dev1"], reply(id)); errCode(r) != code {
			t.Fatalf("%s: %+v", body, r)
		}
	}
	id = d.sendAs(app, "block.list", `{}`)
	r = find(d.inbox(app)["dev1"], reply(id))
	if r == nil || !strings.Contains(string(r.Body), `"note":"spam"`) {
		t.Fatalf("block.list: %+v", r)
	}
	bid := ""
	for k := range d.m.st.Blocks {
		bid = k
	}
	d.sendAs(app, "block.remove", `{"block_id":"`+bid+`"}`)
	d.inbox(app)
	inv = d.invite(t, KindConnection, time.Hour)
	n.hsInit(t, d.m, handshake.PurposeConnection, inv.ID, "h2")
	if len(d.m.st.Inbound) != 1 {
		t.Fatal("unblocked identity still refused")
	}
	// Block the pending request itself.
	var pid string
	for k := range d.m.st.Inbound {
		pid = k
	}
	id = d.sendAs(app, "block.add", `{"pending_id":"`+pid+`"}`)
	if r := find(d.inbox(app)["dev1"], reply(id)); r == nil || r.Status != envelope.StatusOK || len(d.m.st.Inbound) != 0 || len(d.m.st.Blocks) != 1 {
		t.Fatalf("pending block: %+v", r)
	}
	// A desktop's block.remove is a step-up type (§6.8).
	desk := d.addDevice(t, "desk1", KindDesktop, 0x60)
	desk.peer.Access = &AccessSession{ID: "s", Expires: time.Now().Add(time.Hour)}
	for k := range d.m.st.Blocks {
		bid = k
	}
	d.sendAs(desk, "block.remove", `{"block_id":"`+bid+`"}`)
	if find(d.inbox(app, desk)["dev1"], ofType("approval.pending")) == nil {
		t.Fatal("desktop unblock not referred to the apps")
	}
}

// §10.4: the owner's own metadata about a connection, versioned (§10.1),
// in the listings and never sent to the peer.
func TestConnectionUpdate(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	d.addConnection("c1", 0x80)
	id := d.sendAs(app, "connection.update", `{"connection_id":"c1","version":0,"alias":"Mum","tags":["family"],"favorite":true}`)
	if r := find(d.inbox(app)["dev1"], reply(id)); r == nil || string(r.Body) != `{"version":1}` {
		t.Fatalf("update: %+v", r)
	}
	id = d.sendAs(app, "connection.update", `{"connection_id":"c1","version":0,"note":"x"}`)
	if r := find(d.inbox(app)["dev1"], reply(id)); errCode(r) != "conflict" {
		t.Fatal("stale version accepted")
	}
	for _, body := range []string{`{"connection_id":"c1","version":1}`, `{"connection_id":"c1","version":1,"tags":["Bad Tag"]}`,
		`{"connection_id":"c1","version":1,"tags":["a","a"]}`, `{"connection_id":"c1","version":1,"favorite":"yes"}`,
		`{"connection_id":"c1","version":1,"alias":"` + strings.Repeat("x", MaxAlias+1) + `"}`} {
		id = d.sendAs(app, "connection.update", body)
		if r := find(d.inbox(app)["dev1"], reply(id)); errCode(r) != "bad_request" {
			t.Fatalf("%s accepted", body)
		}
	}
	id = d.sendAs(app, "connection.get", `{"connection_id":"c1"}`)
	r := find(d.inbox(app)["dev1"], reply(id))
	for _, want := range []string{`"alias":"Mum"`, `"tags":["family"]`, `"favorite":true`, `"version":1`, `"created_at"`} {
		if r == nil || !strings.Contains(string(r.Body), want) {
			t.Fatalf("connection.get lacks %s: %+v", want, r)
		}
	}
	if d.depositsTo(d.m.st.Connections["c1"].Relay.Mailbox) != 0 {
		t.Fatal("metadata sent to the peer")
	}
}

func FuzzParseMetaUpdate(f *testing.F) {
	f.Add([]byte(`{"connection_id":"c1","version":0,"alias":"Mum","tags":["family"],"favorite":true,"archived":false,"note":"n"}`))
	f.Add([]byte(`{"connection_id":"c1","version":3,"tags":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		u, err := ParseMetaUpdate(b)
		if err != nil {
			return
		}
		if len(u.Tags) > MaxTags || u.Alias != nil && len(*u.Alias) > MaxAlias || u.Note != nil && len(*u.Note) > MaxNote {
			t.Fatal("limits not enforced")
		}
	})
}

// assertTokensDenied checks §7.4 for a removed connection: every token
// issued to it denylisted by jti (revocations queued), its relay key not
// denylisted as a whole.
func assertTokensDenied(t *testing.T, d *devFixture, id string, p *Peer) {
	t.Helper()
	n := 0
	for _, it := range d.m.st.Issued {
		if it.PeerID == id {
			n++
			if !it.Denied {
				t.Fatalf("token %s of the removed connection not denied", it.JTI)
			}
		}
	}
	if n == 0 {
		t.Fatal("no tokens were issued to the connection")
	}
	revoked := map[string]bool{}
	for _, e := range d.m.st.Outbox {
		if e.Op == OpRevoke {
			revoked[e.Kind+":"+e.Value] = true
		}
	}
	for _, it := range d.m.st.Issued {
		if it.PeerID == id && !revoked["jti:"+it.JTI] && !d.relayRevoked("jti", it.JTI) {
			t.Fatalf("jti %s not revoked at the relay", it.JTI)
		}
	}
	if d.m.subDenied(p.Relay.PK) || d.relayRevoked("sub", relayauth.EncodeKey(p.Relay.PK)) {
		t.Fatal("the peer's relay key was denylisted as a whole")
	}
}

func (d *devFixture) relayRevoked(kind, value string) bool {
	d.relay.mu.Lock()
	defer d.relay.mu.Unlock()
	for _, r := range d.relay.revoked {
		if r == kind+":"+value || r == value {
			return true
		}
	}
	return false
}

// §7.4 (0.5.0): after a removal the same peer, with the same relay key,
// can connect again through a new invitation and the owner's approval.
func TestReconnectAfterRemoval(t *testing.T) {
	d := newDevFixture(t)
	app := d.self()
	n := newNewcomer(t, 0x80)
	inv := d.invite(t, KindConnection, time.Hour)
	n.hsInit(t, d.m, handshake.PurposeConnection, inv.ID, "h1")
	var pid string
	for k := range d.m.st.Inbound {
		pid = k
	}
	if pid == "" {
		t.Fatal("no pending request")
	}
	// Removal of a connection record with this identity and relay key.
	old := d.addConnection("old", 0x80)
	old.Relay.PK = n.addr.PK
	old.Relay.Mailbox = n.addr.Mailbox
	d.sendAs(app, "connection.remove", `{"connection_id":"old"}`)
	d.inbox(app)
	assertTokensDenied(t, d, "old", old)
	// The earlier pending request still needs the owner's approval; a new
	// one from the same relay key is accepted as a pending request too.
	inv2 := d.invite(t, KindConnection, time.Hour)
	n.hsInit(t, d.m, handshake.PurposeConnection, inv2.ID, "h2")
	if len(d.m.st.Inbound) != 2 || d.audited("hs_init_from_revoked_key") {
		t.Fatal("re-invitation of a removed peer refused")
	}
}
