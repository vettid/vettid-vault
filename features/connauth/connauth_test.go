package connauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/peerwire"
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
	if r := featuretest.Call(a.f, a.h, t0.Add(peerwire.ConnAuthChallengeTTL+time.Second), "app", "connection.authenticate.request", `{"connection_id":"cB"}`); !r.OK() {
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
	for _, body := range []string{`{}`, `{"connection_id":"cB","context":"` + strings.Repeat("x", peerwire.ConnAuthMaxContext+1) + `"}`} {
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

func rotate(t *testing.T, b *side, seed byte) {
	t.Helper()
	nk := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	r, err := credwire.NewKeyRotation(b.w.key, nk)
	if err != nil {
		t.Fatal(err)
	}
	b.w.key = nk
	b.f.CredentialKeyRotated(vault.NewSession(context.Background(), b.h, vault.PeerInfo{}, t0, nil), r)
}

func result(t *testing.T, a, b *side) string {
	t.Helper()
	resp := run(t, a, b, true)
	featuretest.Call(a.f, a.h, t0, "connection:cB", "connection.authenticate.response", string(resp))
	return string(last(t, a.h, "connection.authenticate.result").Body)
}

// §10.4: a credential-key rotation statement, signed by the old and the
// new key, is delivered to the connections that pinned the old key and
// moves their pin; a missed delivery is caught up in the next response;
// a forged statement is rejected and the new key is reported as changed.
func TestKeyRotationFollowed(t *testing.T) {
	a, b := pair()
	b.w.open = true
	if r := result(t, a, b); !strings.Contains(r, `"key_changed":false`) {
		t.Fatal(r)
	}
	// Delivered: A follows, and the next authentication is no change.
	b.h.Reset()
	rotate(t, b, 0xc1)
	msg := last(t, b.h, "connection.authenticate.rotated")
	if msg.To != "cA" {
		t.Fatalf("delivered to %s", msg.To)
	}
	a.h.Reset()
	featuretest.Call(a.f, a.h, t0, "connection:cB", "connection.authenticate.rotated", string(msg.Body))
	if k := last(t, a.h, "connection.authenticate.key"); !strings.Contains(string(k.Body), `"connection_id":"cB"`) || !a.h.HasActivity("connection.authenticate.key_rotated") {
		t.Fatal("rotation not followed")
	}
	if r := result(t, a, b); !strings.Contains(r, `"key_changed":false`) {
		t.Fatalf("followed rotation reported: %s", r)
	}
	// Missed: two rotations whose messages never arrive; the response
	// carries the chain from the key A pinned.
	rotate(t, b, 0xc2)
	rotate(t, b, 0xc3)
	if r := result(t, a, b); !strings.Contains(r, `"key_changed":false`) {
		t.Fatalf("missed rotations not caught up: %s", r)
	}
	// Forged (signed by an attacker's key as "old"): rejected, pin kept,
	// and the key is then reported as changed.
	evil := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xee}, 32))
	nk := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xc4}, 32))
	forged, _ := credwire.NewKeyRotation(evil, nk)
	forged.Old = b.w.key.Public().(ed25519.PublicKey)
	a.h.Reset()
	featuretest.Call(a.f, a.h, t0, "connection:cB", "connection.authenticate.rotated", `{"rotations":[`+string(forged.Marshal())+`]}`)
	if !a.h.HasActivity("connection.authenticate.rotation_rejected") || len(a.h.SentOfType("connection.authenticate.key")) != 0 {
		t.Fatal("forged rotation accepted")
	}
	b.w.key = nk // B's vault now signs with a key no valid statement leads to
	if r := result(t, a, b); !strings.Contains(r, `"key_changed":true`) {
		t.Fatalf("unsigned key change not reported: %s", r)
	}
	// Bad bodies.
	for _, body := range []string{`{}`, `{"rotations":[]}`, `{"rotations":[{"v":1}]}`} {
		if r := featuretest.Call(a.f, a.h, t0, "connection:cB", "connection.authenticate.rotated", body); r.Code != "bad_request" {
			t.Errorf("%s: %q", body, r.Code)
		}
	}
}

// challengeWith has a request a challenge of b with purpose and delivers
// it; it returns the challenge a sent.
func challengeWith(t *testing.T, a, b *side, purpose string, at time.Time) featuretest.Sent {
	t.Helper()
	body := `{"connection_id":"cB","context":"example.org, Firefox on Linux"`
	if purpose != "" {
		body += `,"purpose":"` + purpose + `"`
	}
	if r := featuretest.Call(a.f, a.h, at, "app", "connection.authenticate.request", body+`}`); !r.OK() {
		t.Fatalf("request %s: %s", purpose, r.Code)
	}
	ch := last(t, a.h, "connection.authenticate.challenge")
	featuretest.CallExp(b.f, b.h, at, ch.Opt.Exp, "connection:cA", "connection.authenticate.challenge", string(ch.Body))
	return ch
}

// 0.65.0 §10.4 and §10.4.1: the purpose travels to the member's devices,
// is signed over and echoed, and reported in the result exactly when the
// signature commits to it; a signin decline cools down only signin
// challenges, for an hour, and never pauses; at most 2 signin challenges
// wait; a response to the wrong purpose is bad_signature, and one from a
// vault before 0.65.0 (no purpose) authenticates without it.
func TestPurpose(t *testing.T) {
	a, b := pair()
	b.h.AsksOn = true
	b.w.open = true
	if r := featuretest.Call(a.f, a.h, t0, "app", "connection.authenticate.request", `{"connection_id":"cB","purpose":"vote"}`); r.Code != "bad_request" {
		t.Fatalf("unknown purpose: %q", r.Code)
	}

	// Sign-in, approved: the purpose all the way through.
	ch := challengeWith(t, a, b, peerwire.PurposeSignIn, t0)
	if field(t, ch.Body, "purpose") != "signin" {
		t.Fatalf("challenge %s", ch.Body)
	}
	pend := last(t, b.h, "connection.authenticate.pending")
	if field(t, pend.Body, "purpose") != "signin" {
		t.Fatalf("pending %s", pend.Body)
	}
	id := field(t, pend.Body, "request_id")
	if r := featuretest.Call(b.f, b.h, t0, "app", "connection.authenticate.approve", `{"request_id":"`+id+`"}`); !r.OK() {
		t.Fatal(r.Code)
	}
	resp := last(t, b.h, "connection.authenticate.response").Body
	if field(t, resp, "purpose") != "signin" {
		t.Fatalf("response %s", resp)
	}
	featuretest.Call(a.f, a.h, t0, "connection:cB", "connection.authenticate.response", string(resp))
	if res := last(t, a.h, "connection.authenticate.result"); field(t, res.Body, "purpose") != "signin" ||
		!strings.Contains(string(res.Body), `"authenticated":true`) {
		t.Fatalf("result %s", res.Body)
	}

	// The same signature relabelled as an approval: bad_signature.
	ch = challengeWith(t, a, b, peerwire.PurposeSignIn, t0)
	id = field(t, last(t, b.h, "connection.authenticate.pending").Body, "request_id")
	featuretest.Call(b.f, b.h, t0, "app", "connection.authenticate.approve", `{"request_id":"`+id+`"}`)
	resp = last(t, b.h, "connection.authenticate.response").Body
	forged := strings.Replace(string(resp), `"purpose":"signin"`, `"purpose":"approval"`, 1)
	featuretest.Call(a.f, a.h, t0, "connection:cB", "connection.authenticate.response", forged)
	if res := last(t, a.h, "connection.authenticate.result"); !strings.Contains(string(res.Body), `"reason":"bad_signature"`) {
		t.Fatalf("relabelled: %s", res.Body)
	}

	// A vault before 0.65.0 answers a signin challenge without a purpose:
	// authenticated, no purpose in the result.
	ch = challengeWith(t, a, b, peerwire.PurposeSignIn, t0)
	wc, err := peerwire.ParseConnAuthChallenge(ch.Body)
	if err != nil {
		t.Fatal(err)
	}
	wc.Purpose = ""
	old, err := peerwire.SignConnAuth(b.w.key, a.h.IK, b.h.IK, wc, t0, nil)
	if err != nil {
		t.Fatal(err)
	}
	featuretest.Call(a.f, a.h, t0, "connection:cB", "connection.authenticate.response", string(old.Marshal()))
	if res := last(t, a.h, "connection.authenticate.result"); strings.Contains(string(res.Body), "purpose") ||
		!strings.Contains(string(res.Body), `"authenticated":true`) {
		t.Fatalf("legacy result %s", res.Body)
	}

	// Pending: b holds one unanswered signin challenge (the legacy one);
	// one more passes, a third waits too many.
	b.h.Reset()
	challengeWith(t, a, b, peerwire.PurposeSignIn, t0)
	challengeWith(t, a, b, peerwire.PurposeSignIn, t0)
	if n := len(b.h.SentOfType("connection.authenticate.pending")); n != 1 {
		t.Fatalf("%d sign-ins reached the member with one already waiting", n)
	}
	if !b.h.HasActivity("drop.ask_pending") {
		t.Fatal("the third waiting sign-in was not suppressed as pending")
	}

	// "Not me": deny a sign-in. Further sign-ins are cooled for an hour;
	// approvals and challenges without a purpose still reach the member;
	// no decline is counted toward a pause.
	id = field(t, last(t, b.h, "connection.authenticate.pending").Body, "request_id")
	if r := featuretest.Call(b.f, b.h, t0, "app", "connection.authenticate.deny", `{"request_id":"`+id+`"}`); !r.OK() {
		t.Fatal(r.Code)
	}
	st := b.h.Asks["cA"]
	if len(st.Declines) != 0 || st.Paused() {
		t.Fatalf("a sign-in decline counted: %+v", st)
	}
	for k := range b.f.d.In {
		delete(b.f.d.In, k) // the member answered the rest
	}
	b.h.Reset()
	at := t0.Add(time.Minute)
	challengeWith(t, a, b, peerwire.PurposeSignIn, at)
	if len(b.h.SentOfType("connection.authenticate.pending")) != 0 || !b.h.HasActivity("drop.ask_cooldown") {
		t.Fatal("a sign-in reached the member within the hour")
	}
	for _, p := range []string{peerwire.PurposeApproval, ""} {
		b.h.Reset()
		challengeWith(t, a, b, p, at)
		if len(b.h.SentOfType("connection.authenticate.pending")) != 1 {
			t.Fatalf("%q after a sign-in decline did not reach the member", p)
		}
	}
	b.h.Reset()
	challengeWith(t, a, b, peerwire.PurposeSignIn, t0.Add(time.Hour)) // the decline was at t0
	if len(b.h.SentOfType("connection.authenticate.pending")) != 1 {
		t.Fatal("a sign-in after the hour did not reach the member")
	}

	// Persistence keeps a received challenge's purpose (the earlier ones
	// have expired by now).
	g := New(nil)
	featuretest.RoundTrip(t, b.f, g)
	if len(g.d.In) != 1 {
		t.Fatalf("%d challenges after a round trip", len(g.d.In))
	}
	for _, c := range g.d.In {
		if c.Purpose != peerwire.PurposeSignIn {
			t.Fatalf("purpose %q after a round trip", c.Purpose)
		}
	}
}

// The ask gate's bucket names are the purposes.
func TestBucketsArePurposes(t *testing.T) {
	if vault.AskBucketSignIn != peerwire.PurposeSignIn || vault.AskBucketApproval != peerwire.PurposeApproval || vault.AskBucketGeneral != "" {
		t.Fatal("bucket names differ from the purposes")
	}
}

// A signed response whose purpose member is not the challenge's known
// purpose (here: on a challenge without one, and an empty one on a signin
// challenge) is reported bad_signature, not dropped (0.65.0 §10.4).
func TestPurposeMismatchReported(t *testing.T) {
	a, b := pair()
	b.w.open = true
	for _, tc := range []struct{ purpose, from, to string }{
		{"", `"signed_at"`, `"purpose":"signin","signed_at"`},
		{peerwire.PurposeSignIn, `"purpose":"signin"`, `"purpose":""`},
	} {
		challengeWith(t, a, b, tc.purpose, t0)
		id := field(t, last(t, b.h, "connection.authenticate.pending").Body, "request_id")
		featuretest.Call(b.f, b.h, t0, "app", "connection.authenticate.approve", `{"request_id":"`+id+`"}`)
		resp := strings.Replace(string(last(t, b.h, "connection.authenticate.response").Body), tc.from, tc.to, 1)
		a.h.Reset()
		featuretest.Call(a.f, a.h, t0, "connection:cB", "connection.authenticate.response", resp)
		if res := last(t, a.h, "connection.authenticate.result"); !strings.Contains(string(res.Body), `"reason":"bad_signature"`) {
			t.Fatalf("%q: %s", tc.purpose, res.Body)
		}
	}
}

// §10.4.2: a received challenge waiting for the member is listed as the
// body of its connection.authenticate.pending event (purpose included),
// until it is decided or expires.
func TestOpenAsksRepeatTheEvent(t *testing.T) {
	a, b := pair()
	if got := b.f.OpenAsks(t0); len(got) != 0 {
		t.Fatalf("before a challenge: %+v", got)
	}
	featuretest.Call(a.f, a.h, t0, "app", "connection.authenticate.request", `{"connection_id":"cB","context":"sign-in","purpose":"signin"}`)
	ch := last(t, a.h, "connection.authenticate.challenge")
	featuretest.CallExp(b.f, b.h, t0, ch.Opt.Exp, "connection:cA", "connection.authenticate.challenge", string(ch.Body))
	ev := last(t, b.h, "connection.authenticate.pending")
	id := field(t, ev.Body, "request_id")
	got := b.f.OpenAsks(t0.Add(time.Minute))
	if len(got) != 1 || got[0].Kind != vault.PendingAuthenticate || got[0].ID != id || string(got[0].Body) != string(ev.Body) ||
		field(t, got[0].Body, "purpose") != "signin" {
		t.Fatalf("listed %+v, event %s", got, ev.Body)
	}
	if got := b.f.OpenAsks(t0.Add(peerwire.ConnAuthChallengeTTL + time.Second)); len(got) != 0 {
		t.Fatalf("expired: %+v", got)
	}
	featuretest.Call(b.f, b.h, t0, "app", "connection.authenticate.deny", `{"request_id":"`+id+`"}`)
	if got := b.f.OpenAsks(t0.Add(time.Minute)); len(got) != 0 {
		t.Fatalf("after a decision: %+v", got)
	}
}

// matchReq makes a request with a raw extra member, delivers the
// challenge to b and returns the challenge sent and b's pending event.
func matchReq(t *testing.T, a, b *side, extra string) (featuretest.Sent, featuretest.Sent) {
	t.Helper()
	body := `{"connection_id":"cB","context":"sign in"` + extra + `}`
	if r := featuretest.Call(a.f, a.h, t0, "app", "connection.authenticate.request", body); !r.OK() {
		t.Fatalf("request %s: %s", extra, r.Code)
	}
	ch := last(t, a.h, "connection.authenticate.challenge")
	featuretest.CallExp(b.f, b.h, t0, ch.Opt.Exp, "connection:cA", "connection.authenticate.challenge", string(ch.Body))
	return ch, last(t, b.h, "connection.authenticate.pending")
}

func hasMatch(raw []byte) bool { return strings.Contains(string(raw), "match_code") }

// 0.79.0 §10.4: a valid code on a sign-in reaches .pending and
// pending.list, survives a restart, "07" stays "07", and the response is
// signed as without it and carries no code.
func TestMatchCode(t *testing.T) {
	a, b := pair()
	b.w.open = true
	ch, pend := matchReq(t, a, b, `,"purpose":"signin","match_code":"07"`)
	if field(t, ch.Body, "match_code") != "07" || field(t, pend.Body, "match_code") != "07" {
		t.Fatalf("challenge %s pending %s", ch.Body, pend.Body)
	}
	if got := b.f.OpenAsks(t0.Add(time.Minute)); len(got) != 1 || field(t, got[0].Body, "match_code") != "07" || string(got[0].Body) != string(pend.Body) {
		t.Fatalf("list %+v", got)
	}
	// Restart.
	b2 := New(b.w)
	featuretest.RoundTrip(t, b.f, b2)
	if got := b2.OpenAsks(t0.Add(time.Minute)); len(got) != 1 || field(t, got[0].Body, "match_code") != "07" || string(got[0].Body) != string(pend.Body) {
		t.Fatalf("after restart %+v", got)
	}
	// Approve; signature verifies at a, and the response has no code.
	id := field(t, pend.Body, "request_id")
	if r := featuretest.Call(b.f, b.h, t0, "app", "connection.authenticate.approve", `{"request_id":"`+id+`"}`); !r.OK() {
		t.Fatal(r.Code)
	}
	resp := last(t, b.h, "connection.authenticate.response").Body
	if hasMatch(resp) {
		t.Fatalf("response %s", resp)
	}
	featuretest.Call(a.f, a.h, t0, "connection:cB", "connection.authenticate.response", string(resp))
	if res := last(t, a.h, "connection.authenticate.result"); hasMatch(res.Body) || !strings.Contains(string(res.Body), `"authenticated":true`) {
		t.Fatalf("result %s", res.Body)
	}
}

// A malformed code is dropped and the challenge still handled; a code
// without a sign-in purpose is ignored. Both on the wire from a peer
// (a hand-made challenge) and in an owner device's request.
func TestMatchCodeIgnored(t *testing.T) {
	for _, extra := range []string{
		`"match_code":42`, `"match_code":null`, `"match_code":"4"`, `"match_code":"1234"`,
		`"match_code":"٤٢"`, `"match_code":"4a"`, `"match_code":""`,
	} {
		a, b := pair()
		_, pend := matchReq(t, a, b, `,"purpose":"signin",`+extra)
		if hasMatch(pend.Body) || field(t, pend.Body, "purpose") != "signin" {
			t.Errorf("%s: pending %s", extra, pend.Body)
		}
		if got := b.f.OpenAsks(t0); len(got) != 1 || hasMatch(got[0].Body) {
			t.Errorf("%s: list %+v", extra, got)
		}
	}
	for _, extra := range []string{`,"purpose":"approval","match_code":"42"`, `,"match_code":"42"`} {
		a, b := pair()
		ch, pend := matchReq(t, a, b, extra)
		if hasMatch(ch.Body) || hasMatch(pend.Body) {
			t.Errorf("%s: challenge %s pending %s", extra, ch.Body, pend.Body)
		}
		if got := b.f.OpenAsks(t0); len(got) != 1 || hasMatch(got[0].Body) {
			t.Errorf("%s: list %+v", extra, got)
		}
	}

	// From a peer: hand-made challenges, malformed or on the wrong purpose.
	for _, extra := range []string{
		`,"purpose":"signin","match_code":42`, `,"purpose":"signin","match_code":null`, `,"purpose":"signin","match_code":"123456"`,
		`,"purpose":"approval","match_code":"42"`, `,"match_code":"42"`, `,"purpose":"vote","match_code":"42"`,
	} {
		a, b := pair()
		a.w.open = true
		featuretest.Call(a.f, a.h, t0, "app", "connection.authenticate.request", `{"connection_id":"cB","purpose":"signin"}`)
		ch := last(t, a.h, "connection.authenticate.challenge")
		body := strings.TrimSuffix(string(ch.Body), `,"purpose":"signin"}`)
		body = strings.TrimSuffix(body, `}`) + extra + `}`
		featuretest.CallExp(b.f, b.h, t0, ch.Opt.Exp, "connection:cA", "connection.authenticate.challenge", body)
		pend := last(t, b.h, "connection.authenticate.pending")
		if hasMatch(pend.Body) {
			t.Errorf("%s: pending %s", extra, pend.Body)
		}
		if got := b.f.OpenAsks(t0); len(got) != 1 {
			t.Errorf("%s: challenge not handled: %+v", extra, got)
		}
	}
}

// §6.4: of its peer types only the challenge is declared for a service
// connection (the vault gate also demands a known purpose).
func TestServiceConnectionTypes(t *testing.T) {
	for _, ts := range New(nil).Types() {
		want := ts.Type == peerwire.TypeConnAuthChallenge
		if (ts.Connections != vault.PeersPerson) != want {
			t.Errorf("%s: Connections %v", ts.Type, ts.Connections)
		}
	}
}
