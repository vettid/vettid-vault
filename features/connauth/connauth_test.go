package connauth

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
)

var t0 = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

// window is a credential unlock window under test control.
type window struct {
	key  ed25519.PrivateKey
	open bool
}

func (w *window) UseKey(time.Time, time.Duration) (ed25519.PrivateKey, bool) {
	if !w.open {
		return nil, false
	}
	return w.key, true
}

type side struct {
	f *Feature
	h *featuretest.Host
	w *window
}

// pair returns two vaults connected to each other (a's "cB" is b, b's
// "cA" is a), with consistent identity keys.
func pair() (a, b *side) {
	a = &side{h: featuretest.NewHost(), w: &window{key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xaa}, 32))}}
	b = &side{h: featuretest.NewHost(), w: &window{key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xbb}, 32))}}
	a.f, b.f = New(a.w), New(b.w)
	a.h.IK = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey)
	b.h.IK = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)).Public().(ed25519.PublicKey)
	a.h.Conns["cB"] = vault.PeerInfo{ID: "cB", Kind: vault.KindConnection, State: vault.PeerActive, IK: b.h.IK}
	b.h.Conns["cA"] = vault.PeerInfo{ID: "cA", Kind: vault.KindConnection, State: vault.PeerActive, IK: a.h.IK}
	return a, b
}

func last(t *testing.T, h *featuretest.Host, typ string) featuretest.Sent {
	t.Helper()
	s := h.SentOfType(typ)
	if len(s) == 0 {
		t.Fatalf("no %s in %+v", typ, h.Sent)
	}
	return s[len(s)-1]
}

func field(t *testing.T, raw []byte, k string) string {
	t.Helper()
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := o.String(k)
	return v
}

// run makes a challenge from a to b and returns b's response body.
func run(t *testing.T, a, b *side, approve bool) []byte {
	t.Helper()
	r := featuretest.Call(a.f, a.h, t0, "desktop", "connection.authenticate.request", `{"connection_id":"cB","context":"sign-in"}`)
	if !r.OK() {
		t.Fatalf("request: %s", r.Code)
	}
	ch := last(t, a.h, "connection.authenticate.challenge")
	if ch.To != "cB" || ch.Opt.Exp.IsZero() {
		t.Fatalf("challenge: %+v", ch)
	}
	featuretest.CallExp(b.f, b.h, t0, ch.Opt.Exp, "connection:cA", "connection.authenticate.challenge", string(ch.Body))
	pend := last(t, b.h, "connection.authenticate.pending")
	if field(t, pend.Body, "context") != "sign-in" || field(t, pend.Body, "connection_id") != "cA" {
		t.Fatalf("pending: %s", pend.Body)
	}
	id := field(t, pend.Body, "request_id")
	typ := "connection.authenticate.deny"
	if approve {
		typ = "connection.authenticate.approve"
	}
	if r := featuretest.Call(b.f, b.h, t0, "app", typ, `{"request_id":"`+id+`"}`); !r.OK() {
		t.Fatalf("%s: %s", typ, r.Code)
	}
	return last(t, b.h, "connection.authenticate.response").Body
}

// The member signs with the credential key within the unlock window; the
// requester verifies over both vaults' identity keys, pins the key and
// reports a change.
func TestAuthenticate(t *testing.T) {
	a, b := pair()
	// Outside the unlock window the approval fails (credential_locked).
	featuretest.Call(a.f, a.h, t0, "app", "connection.authenticate.request", `{"connection_id":"cB"}`)
	ch := last(t, a.h, "connection.authenticate.challenge")
	featuretest.CallExp(b.f, b.h, t0, ch.Opt.Exp, "connection:cA", "connection.authenticate.challenge", string(ch.Body))
	id := field(t, last(t, b.h, "connection.authenticate.pending").Body, "request_id")
	if r := featuretest.Call(b.f, b.h, t0, "app", "connection.authenticate.approve", `{"request_id":"`+id+`"}`); r.Code != "credential_locked" {
		t.Fatalf("approve without the window: %q", r.Code)
	}
	if r := featuretest.Call(b.f, b.h, t0, "desktop", "connection.authenticate.approve", `{"request_id":"`+id+`"}`); r.Code != "forbidden" {
		t.Fatal("a desktop approved")
	}

	b.w.open = true
	resp := run(t, a, b, true)
	if !b.h.HasActivity("connection.authenticate.signed") {
		t.Fatal("signing not audited")
	}
	a.h.Reset()
	featuretest.Call(a.f, a.h, t0, "connection:cB", "connection.authenticate.response", string(resp))
	res := last(t, a.h, "connection.authenticate.result")
	if !strings.Contains(string(res.Body), `"authenticated":true`) || !strings.Contains(string(res.Body), `"key_changed":false`) {
		t.Fatalf("result: %s", res.Body)
	}
	// A replayed response matches no pending request.
	a.h.Reset()
	featuretest.Call(a.f, a.h, t0, "connection:cB", "connection.authenticate.response", string(resp))
	if len(a.h.SentOfType("connection.authenticate.result")) != 0 {
		t.Fatal("replayed response accepted")
	}
	// A new credential key verifies but is reported as a change.
	b.w.key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xcc}, 32))
	resp = run(t, a, b, true)
	featuretest.Call(a.f, a.h, t0, "connection:cB", "connection.authenticate.response", string(resp))
	if res := last(t, a.h, "connection.authenticate.result"); !strings.Contains(string(res.Body), `"key_changed":true`) {
		t.Fatalf("key change not reported: %s", res.Body)
	}
	// A signature over another challenge (the requester expects another
	// responder identity) fails.
	resp = run(t, a, b, true)
	a.h.Conns["cB"] = vault.PeerInfo{ID: "cB", Kind: vault.KindConnection, State: vault.PeerActive, IK: a.h.IK}
	featuretest.Call(a.f, a.h, t0, "connection:cB", "connection.authenticate.response", string(resp))
	if res := last(t, a.h, "connection.authenticate.result"); !strings.Contains(string(res.Body), `"reason":"bad_signature"`) {
		t.Fatalf("bad signature accepted: %s", res.Body)
	}
	a.h.Conns["cB"] = vault.PeerInfo{ID: "cB", Kind: vault.KindConnection, State: vault.PeerActive, IK: b.h.IK}
	// Denied.
	resp = run(t, a, b, false)
	featuretest.Call(a.f, a.h, t0, "connection:cB", "connection.authenticate.response", string(resp))
	if res := last(t, a.h, "connection.authenticate.result"); !strings.Contains(string(res.Body), `"reason":"denied"`) {
		t.Fatalf("denial: %s", res.Body)
	}
	// The listing keeps the pinned key and the last result; persistence.
	r := featuretest.Call(a.f, a.h, t0, "app", "connection.authenticate.list", `{}`)
	if !strings.Contains(string(r.Body), `"last_result":"denied"`) || !strings.Contains(string(r.Body), `"key"`) {
		t.Fatalf("list: %s", r.Body)
	}
	g := New(nil)
	featuretest.RoundTrip(t, a.f, g)
	if r := featuretest.Call(g, a.h, t0, "app", "connection.authenticate.list", `{}`); !strings.Contains(string(r.Body), `"verified_at"`) {
		t.Fatal("state not persisted")
	}
	// Removing the connection forgets it.
	a.f.ConnectionRemoved(nil, "cB")
	if r := featuretest.Call(a.f, a.h, t0, "app", "connection.authenticate.list", `{}`); string(r.Body) != `{"states":[]}` {
		t.Fatalf("after removal: %s", r.Body)
	}
}

// Expiry, limits, roles and bad bodies.
func TestLimitsAndRoles(t *testing.T) {
	a, b := pair()
	for range MaxPendingOut {
		if r := featuretest.Call(a.f, a.h, t0, "app", "connection.authenticate.request", `{"connection_id":"cB"}`); !r.OK() {
			t.Fatal(r.Code)
		}
	}
	if r := featuretest.Call(a.f, a.h, t0, "app", "connection.authenticate.request", `{"connection_id":"cB"}`); r.Code != "limit" {
		t.Fatalf("pending limit: %q", r.Code)
	}
	if r := featuretest.Call(a.f, a.h, t0.Add(ChallengeTTL+time.Second), "app", "connection.authenticate.request", `{"connection_id":"cB"}`); !r.OK() {
		t.Fatal("expired challenges still counted")
	}
	chs := a.h.SentOfType("connection.authenticate.challenge")
	for _, ch := range chs[:MaxPendingIn+2] {
		featuretest.CallExp(b.f, b.h, t0, ch.Opt.Exp, "connection:cA", "connection.authenticate.challenge", string(ch.Body))
	}
	if n := len(b.h.SentOfType("connection.authenticate.pending")); n != MaxPendingIn {
		t.Fatalf("%d challenges accepted", n)
	}
	for _, c := range []struct{ kind, typ string }{
		{"agent", "connection.authenticate.request"}, {"agent", "connection.authenticate.list"},
		{"connection:cA", "connection.authenticate.request"}, {"app", "connection.authenticate.challenge"},
		{"app", "connection.authenticate.response"},
	} {
		if r := featuretest.Call(b.f, b.h, t0, c.kind, c.typ, `{}`); r.Code != "forbidden" {
			t.Errorf("%s %s: %q", c.kind, c.typ, r.Code)
		}
	}
	for _, body := range []string{`{}`, `{"connection_id":"cB","context":"` + strings.Repeat("x", MaxContext+1) + `"}`} {
		if r := featuretest.Call(a.f, a.h, t0, "app", "connection.authenticate.request", body); r.Code != "bad_request" {
			t.Errorf("%.40s: %q", body, r.Code)
		}
	}
	if r := featuretest.Call(a.f, a.h, t0, "app", "connection.authenticate.request", `{"connection_id":"nope"}`); r.Code != "not_found" {
		t.Error("unknown connection")
	}
	if r := featuretest.Call(b.f, b.h, t0, "app", "connection.authenticate.approve", `{"request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V"}`); r.Code != "not_found" {
		t.Error("unknown request")
	}
}

func FuzzParseChallenge(f *testing.F) {
	f.Add([]byte(`{"request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","context":"x"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if c, err := ParseChallenge(b); err == nil && (len(c.Nonce) != NonceSize || len(c.Context) > MaxContext) {
			t.Fatal("invalid challenge accepted")
		}
	})
}

func FuzzParseResponse(f *testing.F) {
	f.Add([]byte(`{"request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","status":"denied"}`))
	f.Add([]byte(`{"request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","status":"signed","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","sig":"` +
		strings.Repeat("A", 86) + `==","signed_at":"2026-10-01T12:00:00.000Z"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := ParseResponse(b)
		if err == nil && r.Status == StatusSigned && (len(r.Key) != ed25519.PublicKeySize || len(r.Sig) != ed25519.SignatureSize) {
			t.Fatal("invalid response accepted")
		}
	})
}
