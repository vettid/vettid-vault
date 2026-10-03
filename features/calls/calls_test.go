package calls

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/callwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

var t0 = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

const sdpOffer = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\n"

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func obj(t *testing.T, raw []byte) strictjson.Object {
	t.Helper()
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func str(t *testing.T, raw []byte, k string) string {
	t.Helper()
	v, _ := obj(t, raw).String(k)
	return v
}

// side is one vault of a call: its feature and fake host.
type side struct {
	f *Feature
	h *featuretest.Host
}

func newSide(conn string) *side {
	h := featuretest.NewHost()
	s := &side{f: New(Options{}), h: h}
	s.addConn(conn)
	h.AddDevice("dev-app", "app")
	h.AddDevice("dev-desktop", "desktop")
	return s
}

// peerVault is the identity key of the vault behind a test connection.
func peerVault(conn string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("peer-vault|" + conn))
	return ed25519.NewKeyFromSeed(seed[:])
}

// addConn adds a connection whose pinned ik is peerVault(conn).
func (s *side) addConn(conn string) {
	s.h.AddConnection(conn)
	p := s.h.Conns[conn]
	p.IK = peerVault(conn).Public().(ed25519.PublicKey)
	s.h.Conns[conn] = p
}

// peerOffer is a call.offer from conn's vault, vouched as §10.10 says.
func peerOffer(conn, id, media string, ek []byte) string {
	dev := featuretest.DeviceKey("peer-device")
	m := callwire.ShareMessage(callwire.RoleOffer, id, media, ek)
	ds, _ := callwire.SignShare(dev, m)
	devPub := dev.Public().(ed25519.PublicKey)
	vs, _ := suite.Sign(peerVault(conn), callwire.LabelVouch, callwire.VouchMessage(devPub, m))
	return `{"call_id":"` + id + `","media":"` + media + `","sdp":"v=0","ek":"` + b64(ek) + `","device_ik":"` + b64(devPub) +
		`","device_sig":"` + b64(ds) + `","vault_sig":"` + b64(vs) + `"}`
}

// link makes a and b each other's connection with their real vault keys.
func link(a, b *side) {
	a.h.SetIdentity(1)
	b.h.SetIdentity(2)
	pa, pb := a.h.Conns["cB"], b.h.Conns["cA"]
	pa.IK, pb.IK = b.h.IK, a.h.IK
	a.h.Conns["cB"], b.h.Conns["cA"] = pa, pb
}

func (s *side) sent(t *testing.T, to, typ string) featuretest.Sent {
	t.Helper()
	for _, m := range s.h.Sent {
		if m.To == to && m.Type == typ {
			return m
		}
	}
	t.Fatalf("no %s to %s in %+v", typ, to, s.h.Sent)
	return featuretest.Sent{}
}

func (s *side) none(t *testing.T, typ string) {
	t.Helper()
	if len(s.h.SentOfType(typ)) != 0 {
		t.Fatalf("unexpected %s: %+v", typ, s.h.SentOfType(typ))
	}
}

var nextID = map[string]int{}

func startBody(conn string, ek []byte) string { return startBodyID(conn, newCallID(conn), ek) }

func newCallID(conn string) string {
	nextID[conn]++
	id, _ := envelope.NewULID(t0.Add(time.Duration(nextID[conn]) * time.Millisecond))
	return id
}

// startBodyID is a call.start from dev-app, its share signed.
func startBodyID(conn, id string, ek []byte) string {
	sig, _ := callwire.SignShare(featuretest.DeviceKey("dev-app"), callwire.ShareMessage(callwire.RoleOffer, id, "video", ek))
	return `{"connection_id":"` + conn + `","call_id":"` + id + `","media":"video","sdp":"` + strings.ReplaceAll(sdpOffer, "\r\n", `\r\n`) +
		`","ek":"` + b64(ek) + `","ek_sig":"` + b64(sig) + `"}`
}

func answerBody(dev, id string, enc []byte) string {
	sig, _ := callwire.SignShare(featuretest.DeviceKey(dev), callwire.ShareMessage(callwire.RoleAnswer, id, "", enc))
	return `{"call_id":"` + id + `","sdp":"v=0","enc":"` + b64(enc) + `","enc_sig":"` + b64(sig) + `"}`
}

// The full flow between two vaults (§10.10): offer with exp, ICE
// configuration signed by each vault for its own devices, ringing, answer
// to the calling device only, answered_elsewhere for the callee's other
// devices, device-to-device media key, trickle ICE to the call's device,
// hang-up on both sides.
func TestCallFlow(t *testing.T) {
	a, b := newSide("cB"), newSide("cA")
	link(a, b)
	sk, _ := callwire.NewOfferKey()
	r := featuretest.Call(a.f, a.h, t0, "app", "call.start", startBody("cB", sk.Public().Bytes()))
	if !r.OK() {
		t.Fatalf("start: %s", r.Code)
	}
	callID := str(t, r.Body, "call_id")
	cfg, _ := r.Obj(t).Base64("ice_config", -1)
	sig, _ := r.Obj(t).Base64("ice_sig", -1)
	if _, err := callwire.VerifyICE(a.h.IK, cfg, sig, callID, t0); err != nil {
		t.Fatalf("caller's ICE config: %v", err)
	}
	off := a.sent(t, "cB", "call.offer")
	if !a.h.HasActivity("call.outgoing") {
		t.Error("call.outgoing not audited")
	}
	if off.Opt.Exp.Sub(t0) != OfferTTL || off.Opt.MemoryOnly {
		t.Fatalf("offer options %+v", off.Opt)
	}
	if c, _ := a.f.Get(callID); c.Device != "dev-app" || c.State != StateRinging {
		t.Fatalf("caller record %+v", c)
	}

	// The callee rings its apps and desktops, with its own ICE config.
	if r := featuretest.CallExp(b.f, b.h, t0, off.Opt.Exp, "connection:cA", "call.offer", string(off.Body)); !r.OK() {
		t.Fatal(r.Code)
	}
	ring := b.sent(t, "devices", "call.offer")
	if ring.Opt.Exp != off.Opt.Exp || str(t, ring.Body, "connection_id") != "cA" {
		t.Fatalf("callee devices' offer: %+v", ring)
	}
	bcfg, _ := obj(t, ring.Body).Base64("ice_config", -1)
	bsig, _ := obj(t, ring.Body).Base64("ice_sig", -1)
	if _, err := callwire.VerifyICE(b.h.IK, bcfg, bsig, callID, t0); err != nil {
		t.Fatalf("callee's ICE config: %v", err)
	}
	// A retransmitted offer is idempotent.
	b.h.Reset()
	featuretest.CallExp(b.f, b.h, t0, off.Opt.Exp, "connection:cA", "call.offer", string(off.Body))
	b.none(t, "call.offer")

	// Ringing: once, memory-only, to the calling device.
	featuretest.CallExp(b.f, b.h, t0, t0.Add(30*time.Second), "desktop", "call.ringing", `{"call_id":"`+callID+`"}`)
	featuretest.CallExp(b.f, b.h, t0, t0.Add(30*time.Second), "app", "call.ringing", `{"call_id":"`+callID+`"}`)
	if rs := b.h.SentOfType("call.ringing"); len(rs) != 1 || rs[0].To != "cA" || !rs[0].Opt.MemoryOnly || rs[0].Opt.Exp.IsZero() {
		t.Fatalf("ringing: %+v", rs)
	}
	featuretest.CallExp(a.f, a.h, t0, t0.Add(30*time.Second), "connection:cB", "call.ringing", `{"call_id":"`+callID+`"}`)
	if rs := a.h.SentOfType("call.ringing"); len(rs) != 1 || rs[0].To != "dev-app" {
		t.Fatalf("caller ringing: %+v", rs)
	}

	// The callee's app answers with enc; the desktop stops ringing.
	ek, _ := obj(t, ring.Body).Base64("ek", callwire.EKSize)
	enc, kB, err := callwire.Answer(ek, callID)
	if err != nil {
		t.Fatal(err)
	}
	ans := answerBody("dev-app", callID, enc)
	b.h.Reset()
	featuretest.Call(b.f, b.h, t0.Add(5*time.Second), "app", "call.answer", ans)
	fwd := b.sent(t, "cA", "call.answer")
	if e := b.sent(t, "devices-except:dev-app", "call.end"); str(t, e.Body, "reason") != "answered_elsewhere" {
		t.Fatal("other devices not stopped")
	}
	// A second answer (the desktop) is told the call is gone.
	b.h.Reset()
	featuretest.Call(b.f, b.h, t0.Add(6*time.Second), "desktop", "call.answer", ans)
	if e := b.sent(t, "dev-desktop", "call.end"); str(t, e.Body, "reason") != "unavailable" {
		t.Fatal("late answer not refused")
	}
	b.none(t, "call.answer")

	a.h.Reset()
	featuretest.Call(a.f, a.h, t0.Add(5*time.Second), "connection:cB", "call.answer", string(fwd.Body))
	got := a.sent(t, "dev-app", "call.answer")
	if !a.h.HasActivity("call.answered") {
		t.Error("call.answered not audited")
	}
	genc, _ := obj(t, got.Body).Base64("enc", callwire.EncSize)
	kA, err := callwire.Accept(sk, genc, callID)
	if err != nil || !bytes.Equal(kA, kB) {
		t.Fatal("devices derived different media keys")
	}
	if strings.Contains(string(fwd.Body), b64(kB)) {
		t.Fatal("media key relayed")
	}

	// Trickle ICE: device → peer vault → the call's device, memory-only.
	ice := `{"call_id":"` + callID + `","candidates":[{"candidate":"candidate:1 1 udp 1 192.0.2.1 5000 typ host","sdp_mid":"0","sdp_mline_index":0}]}`
	a.h.Reset()
	featuretest.CallExp(a.f, a.h, t0, t0.Add(30*time.Second), "app", "call.ice", ice)
	io := a.sent(t, "cB", "call.ice")
	if !io.Opt.MemoryOnly || io.Opt.Exp.IsZero() {
		t.Fatal("ICE not ephemeral")
	}
	featuretest.CallExp(a.f, a.h, t0, t0.Add(30*time.Second), "desktop", "call.ice", ice) // not the call's device
	if len(a.h.SentOfType("call.ice")) != 1 {
		t.Fatal("ICE from another device forwarded")
	}
	b.h.Reset()
	featuretest.CallExp(b.f, b.h, t0, t0.Add(30*time.Second), "connection:cA", "call.ice", string(io.Body))
	if ii := b.sent(t, "dev-app", "call.ice"); !ii.Opt.MemoryOnly {
		t.Fatal("ICE to the device not memory-only")
	}

	// Hang-up by the caller's device ends both sides.
	a.h.Reset()
	featuretest.Call(a.f, a.h, t0.Add(time.Minute), "app", "call.end", `{"call_id":"`+callID+`","reason":"hangup"}`)
	end := a.sent(t, "cB", "call.end")
	b.h.Reset()
	featuretest.Call(b.f, b.h, t0.Add(time.Minute), "connection:cA", "call.end", string(end.Body))
	b.sent(t, "devices", "call.end")
	if c, _ := b.f.Get(callID); c.State != StateEnded || c.Reason != "hangup" {
		t.Fatalf("callee record %+v", c)
	}
	if b.h.HasActivity("call.missed") {
		t.Fatal("an answered call is missed")
	}
	// History, newest first, and persistence.
	r = featuretest.Call(a.f, a.h, t0, "desktop", "call.list", `{}`)
	if !r.OK() || !strings.Contains(string(r.Body), `"state":"ended"`) || !strings.Contains(string(r.Body), `"answered_at"`) {
		t.Fatalf("history: %s", r.Body)
	}
	g := New(Options{})
	featuretest.RoundTrip(t, a.f, g)
	if c, ok := g.Get(callID); !ok || c.State != StateEnded {
		t.Fatal("call history not persisted")
	}
	if !a.h.HasActivity("call.ended") {
		t.Error("caller audit lacks call.ended")
	}
}

func featuretestSession(s *side) *vault.Session {
	return vault.NewSession(context.Background(), s.h, vault.PeerInfo{}, t0, nil)
}

// One call at a time: a second offer is answered busy (and is a missed
// call); a call.start while in a call is refused busy.
func TestBusy(t *testing.T) {
	b := newSide("cA")
	b.addConn("cC")
	sk, _ := callwire.NewOfferKey()
	offer := func(conn, id string) {
		featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:"+conn, "call.offer", peerOffer(conn, id, "audio", sk.Public().Bytes()))
	}
	offer("cA", "01JB2Z6V9K3M4N5P6Q7R8S9T0A")
	b.h.Reset()
	offer("cC", "01JB2Z6V9K3M4N5P6Q7R8S9T0B")
	if e := b.sent(t, "cC", "call.end"); str(t, e.Body, "reason") != "busy" {
		t.Fatal("not busy")
	}
	b.none(t, "call.offer")
	if !b.h.HasActivity("call.missed") {
		t.Fatal("busy call not in the feed")
	}
	r := featuretest.Call(b.f, b.h, t0, "app", "call.start", startBody("cC", sk.Public().Bytes()))
	if r.Code != "busy" {
		t.Fatalf("start while ringing: %q", r.Code)
	}
	// After the offer's exp, the ringing call no longer counts.
	if r := featuretest.Call(b.f, b.h, t0.Add(OfferTTL+time.Second), "app", "call.start", startBody("cC", sk.Public().Bytes())); !r.OK() {
		t.Fatalf("start after expiry: %s", r.Code)
	}
}

// A caller's hang-up before an answer is a missed call; any owner device
// may decline a ringing call; peers act only on their own calls.
func TestMissedDeclineAndAuthority(t *testing.T) {
	b := newSide("cA")
	b.addConn("cX")
	sk, _ := callwire.NewOfferKey()
	id := "01JB2Z6V9K3M4N5P6Q7R8S9T0A"
	body := peerOffer("cA", id, "audio", sk.Public().Bytes())
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", body)
	// Another connection cannot end, answer or trickle into it.
	b.h.Reset()
	featuretest.Call(b.f, b.h, t0, "connection:cX", "call.end", `{"call_id":"`+id+`","reason":"hangup"}`)
	if c, _ := b.f.Get(id); c.State != StateRinging || len(b.h.Sent) != 0 {
		t.Fatal("foreign connection ended the call")
	}
	featuretest.Call(b.f, b.h, t0, "connection:cA", "call.end", `{"call_id":"`+id+`","reason":"timeout"}`)
	if !b.h.HasActivity("call.missed") {
		t.Fatal("unanswered call not missed")
	}
	// Decline from the desktop.
	id2 := "01JB2Z6V9K3M4N5P6Q7R8S9T0B"
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id2, "audio", sk.Public().Bytes()))
	b.h.Reset()
	featuretest.Call(b.f, b.h, t0, "desktop", "call.end", `{"call_id":"`+id2+`","reason":"decline"}`)
	if e := b.sent(t, "cA", "call.end"); str(t, e.Body, "reason") != "decline" {
		t.Fatal("decline not sent")
	}
	b.sent(t, "devices-except:dev-desktop", "call.end")
	// Offers without exp, or with a far exp, are refused.
	id3 := "01JB2Z6V9K3M4N5P6Q7R8S9T0C"
	b3 := peerOffer("cA", id3, "audio", sk.Public().Bytes())
	if r := featuretest.Call(b.f, b.h, t0, "connection:cA", "call.offer", b3); r.Code != "bad_request" {
		t.Fatal("offer without exp accepted")
	}
	if r := featuretest.CallExp(b.f, b.h, t0, t0.Add(time.Hour), "connection:cA", "call.offer", b3); r.Code != "bad_request" {
		t.Fatal("offer with a far exp accepted")
	}
	// Removing the connection ends its live calls.
	id4 := "01JB2Z6V9K3M4N5P6Q7R8S9T0D"
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer("cA", id4, "audio", sk.Public().Bytes()))
	b.h.Reset()
	b.f.ConnectionRemoved(featuretestSession(b), "cA")
	if c, _ := b.f.Get(id4); c.State != StateEnded || c.Reason != "unavailable" {
		t.Fatal("call outlived its connection")
	}
}

// Roles (§10.10): devices start and list; peers offer; agents nothing.
func TestAuthorization(t *testing.T) {
	s := newSide("c1")
	for _, c := range []struct{ kind, typ string }{
		{"agent", "call.start"}, {"agent", "call.list"}, {"agent", "call.end"}, {"agent", "call.ice"},
		{"connection:c1", "call.start"}, {"connection:c1", "call.list"}, {"app", "call.offer"}, {"desktop", "call.offer"},
	} {
		if r := featuretest.Call(s.f, s.h, t0, c.kind, c.typ, `{}`); r.Code != "forbidden" {
			t.Errorf("%s %s: %q", c.kind, c.typ, r.Code)
		}
	}
}

func TestBadBodies(t *testing.T) {
	s := newSide("c1")
	sk, _ := callwire.NewOfferKey()
	ek := b64(sk.Public().Bytes())
	for _, body := range []string{
		`{}`,
		`{"connection_id":"c1","media":"fax","sdp":"v=0","ek":"` + ek + `"}`,
		`{"connection_id":"c1","media":"audio","sdp":"","ek":"` + ek + `"}`,
		`{"connection_id":"c1","media":"audio","sdp":"` + strings.Repeat("x", MaxSDP+1) + `","ek":"` + ek + `"}`,
		`{"connection_id":"c1","media":"audio","sdp":"v=0","ek":"AAAA"}`,
		`{"connection_id":"c1","media":"audio","sdp":"v=0","ek":"` + ek + `","ek":"` + ek + `"}`,
	} {
		if r := featuretest.Call(s.f, s.h, t0, "app", "call.start", body); r.Code != "bad_request" {
			t.Errorf("%.80s: %q", body, r.Code)
		}
	}
	if r := featuretest.Call(s.f, s.h, t0, "app", "call.start", startBody("nope", sk.Public().Bytes())); r.Code != "not_found" {
		t.Errorf("unknown connection: %q", r.Code)
	}
	s.h.DownConns["c1"] = true
	if r := featuretest.Call(s.f, s.h, t0, "app", "call.start", startBody("c1", sk.Public().Bytes())); r.Code != "connection_unavailable" {
		t.Errorf("down connection: %q", r.Code)
	}
	if _, err := ParseICE([]byte(`{"call_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0A","candidates":[]}`)); err == nil {
		t.Error("empty candidates accepted")
	}
	if _, err := ParseEnd([]byte(`{"call_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0A","reason":"bored"}`)); err == nil {
		t.Error("unknown reason accepted")
	}
	if r := featuretest.Call(s.f, s.h, t0, "app", "call.list", `{"limit":0}`); r.Code != "bad_request" {
		t.Error("limit 0 accepted")
	}
}

// CALLING-SERVICE §5: coturn use-auth-secret credentials.
func TestCoturnIssuer(t *testing.T) {
	c := Coturn{STUN: []string{"stun:stun.example.org:3478"}, TURN: []string{"turns:turn.example.org:5349?transport=tcp"},
		Secret: []byte("shared"), Now: func() time.Time { return t0 }}
	servers, err := c.Issue(context.Background(), "01JB2Z6V9K3M4N5P6Q7R8S9T0A", time.Hour)
	if err != nil || len(servers) != 2 {
		t.Fatal(err)
	}
	user := servers[1].Username
	if want := "1791032400:01JB2Z6V9K3M4N5P6Q7R8S9T0A"; user != want {
		t.Fatalf("username %q", user)
	}
	mac := hmac.New(sha1.New, []byte("shared"))
	mac.Write([]byte(user))
	if servers[1].Credential != b64(mac.Sum(nil)) {
		t.Fatal("credential")
	}
	if s, _ := (NoServers{}).Issue(context.Background(), "x", time.Hour); len(s) != 0 {
		t.Fatal("NoServers issued servers")
	}
	f := New(Options{ICE: c})
	h := featuretest.NewHost()
	h.AddConnection("c1")
	h.AddDevice("dev-app", "app")
	sk, _ := suite.GeneratePrivateKey()
	r := featuretest.Call(f, h, t0, "app", "call.start", startBody("c1", sk.Public().Bytes()))
	cfg, _ := r.Obj(t).Base64("ice_config", -1)
	if !strings.Contains(string(cfg), `"username":"`) || !strings.Contains(string(cfg), "turns:turn.example.org") {
		t.Fatalf("issued config %s", cfg)
	}
}

func FuzzParseStart(f *testing.F) {
	sk, _ := suite.NewPrivateKey(bytes.Repeat([]byte{1}, 32))
	f.Add([]byte(startBody("c1", sk.Public().Bytes())))
	f.Fuzz(func(t *testing.T, b []byte) {
		if s, err := ParseStart(b); err == nil && (len(s.EK) != callwire.EKSize || len(s.SDP) > MaxSDP) {
			t.Fatal("invalid start accepted")
		}
	})
}

func FuzzParseOffer(f *testing.F) {
	sk, _ := suite.NewPrivateKey(bytes.Repeat([]byte{1}, 32))
	f.Add([]byte(peerOffer("c1", "01JB2Z6V9K3M4N5P6Q7R8S9T0A", "audio", sk.Public().Bytes())))
	f.Fuzz(func(t *testing.T, b []byte) {
		if o, err := ParseOffer(b); err == nil && (len(o.EK) != callwire.EKSize || o.Media != "audio" && o.Media != "video") {
			t.Fatal("invalid offer accepted")
		}
	})
}

func FuzzParseAnswer(f *testing.F) {
	f.Add([]byte(answerBody("dev-app", "01JB2Z6V9K3M4N5P6Q7R8S9T0A", make([]byte, callwire.EncSize))), false)
	f.Add([]byte(`{"call_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0A","sdp":"v=0","enc":"`+b64(make([]byte, callwire.EncSize))+
		`","device_ik":"`+b64(make([]byte, 32))+`","device_sig":"`+b64(make([]byte, 64))+`","vault_sig":"`+b64(make([]byte, 64))+`"}`), true)
	f.Fuzz(func(t *testing.T, b []byte, peer bool) {
		a, err := ParseAnswer(b, peer)
		if err == nil && (len(a.Enc) != callwire.EncSize || peer && len(a.VaultSig) != 64 || !peer && len(a.EncSig) != 64) {
			t.Fatal("invalid answer accepted")
		}
	})
}

func FuzzParseEnd(f *testing.F) {
	f.Add([]byte(`{"call_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0A","reason":"hangup"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if e, err := ParseEnd(b); err == nil && !Reasons[e.Reason] {
			t.Fatal("invalid reason accepted")
		}
	})
}

func FuzzParseICE(f *testing.F) {
	f.Add([]byte(`{"call_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0A","candidates":[{"candidate":"candidate:1 1 udp 1 192.0.2.1 5000 typ host","sdp_mid":"0","sdp_mline_index":0}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		ic, err := ParseICE(b)
		if err != nil {
			return
		}
		arr, err := strictjson.ParseObject(append(append([]byte(`{"c":`), ic.Candidates...), '}'))
		if err != nil {
			t.Fatal("re-encoded candidates do not parse")
		}
		if a, _ := arr.Array("c"); len(a) == 0 || len(a) > MaxCandidates {
			t.Fatal("candidate count")
		}
	})
}

// §10.10: every party checks the key-exchange shares. The device's own
// vault refuses a share its device did not sign; the peer vault refuses
// one its peer vault did not vouch for (a swapped ek or enc), so nothing
// rings and no answer is passed on; the device checks both signatures
// under the connection's ik.
func TestSwappedShares(t *testing.T) {
	a, b := newSide("cB"), newSide("cA")
	link(a, b)
	sk, _ := callwire.NewOfferKey()
	other, _ := callwire.NewOfferKey()
	// A share not signed by the requesting device (or for another ek).
	id := newCallID("x")
	body := startBodyID("cB", id, sk.Public().Bytes())
	swapped := strings.Replace(body, b64(sk.Public().Bytes()), b64(other.Public().Bytes()), 1)
	if r := featuretest.Call(a.f, a.h, t0, "app", "call.start", swapped); r.Code != "bad_request" {
		t.Fatalf("unsigned share vouched: %q", r.Code)
	}
	if r := featuretest.Call(a.f, a.h, t0, "desktop", "call.start", body); r.Code != "bad_request" {
		t.Fatalf("another device's signature vouched: %q", r.Code)
	}
	r := featuretest.Call(a.f, a.h, t0, "app", "call.start", body)
	if !r.OK() {
		t.Fatal(r.Code)
	}
	off := a.sent(t, "cB", "call.offer")
	// The relay path swaps ek: the callee's vault refuses it.
	tampered := strings.Replace(string(off.Body), b64(sk.Public().Bytes()), b64(other.Public().Bytes()), 1)
	featuretest.CallExp(b.f, b.h, t0, off.Opt.Exp, "connection:cA", "call.offer", tampered)
	b.none(t, "call.offer")
	if !b.h.HasActivity("drop.call_share") {
		t.Fatal("swapped share not audited")
	}
	// A vault that is not the connection's cannot vouch either.
	featuretest.CallExp(b.f, b.h, t0, off.Opt.Exp, "connection:cA", "call.offer", peerOffer("cA", newCallID("y"), "video", sk.Public().Bytes()))
	b.none(t, "call.offer")
	// The genuine offer rings, and the device can verify it.
	featuretest.CallExp(b.f, b.h, t0, off.Opt.Exp, "connection:cA", "call.offer", string(off.Body))
	ring := b.sent(t, "devices", "call.offer")
	o := obj(t, ring.Body)
	peer, _ := o.Base64("peer_ik", 32)
	dev, _ := o.Base64("device_ik", 32)
	ds, _ := o.Base64("device_sig", 64)
	vs, _ := o.Base64("vault_sig", 64)
	m := callwire.ShareMessage(callwire.RoleOffer, id, "video", sk.Public().Bytes())
	if callwire.VerifyShare(peer, dev, m, ds, vs) != nil {
		t.Fatal("device cannot verify the offer")
	}
	if callwire.VerifyShare(peer, dev, callwire.ShareMessage(callwire.RoleOffer, id, "video", other.Public().Bytes()), ds, vs) == nil {
		t.Fatal("device accepts a swapped ek")
	}
	// A swapped enc in the answer is refused by the caller's vault.
	enc, _, _ := callwire.Answer(sk.Public().Bytes(), id)
	b.h.Reset()
	featuretest.Call(b.f, b.h, t0, "app", "call.answer", answerBody("dev-app", id, enc))
	fwd := b.sent(t, "cA", "call.answer")
	enc2, _, _ := callwire.Answer(sk.Public().Bytes(), id)
	a.h.Reset()
	featuretest.Call(a.f, a.h, t0, "connection:cB", "call.answer", strings.Replace(string(fwd.Body), b64(enc), b64(enc2), 1))
	a.none(t, "call.answer")
	if c, _ := a.f.Get(id); c.State != StateRinging {
		t.Fatal("swapped answer accepted")
	}
	featuretest.Call(a.f, a.h, t0, "connection:cB", "call.answer", string(fwd.Body))
	a.sent(t, "dev-app", "call.answer")
}
