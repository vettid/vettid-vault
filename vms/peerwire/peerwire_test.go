package peerwire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/credwire"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func key(seed byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)) }

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

const reqID = "01JB2Z6V9K3M4N5P6Q7R8S9T0V"

// §10.4: a challenge round trip, the signature bound to both vaults' keys
// in their roles and to every challenge field, and the pin.
func TestConnAuth(t *testing.T) {
	a, b, cred := pub(key(1)), pub(key(2)), key(3)
	c, err := NewConnAuthChallenge(reqID, "sign-in")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := ParseConnAuthChallenge(c.Marshal())
	if err != nil || pc.RequestID != reqID || pc.Context != "sign-in" || !bytes.Equal(pc.Nonce, c.Nonce) {
		t.Fatalf("challenge round trip: %+v %v", pc, err)
	}
	r, err := SignConnAuth(cred, a, b, c, t0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(r.Marshal()), `{"request_id":"`+reqID+`","status":"signed","key":"`) ||
		!strings.HasSuffix(string(r.Marshal()), `","signed_at":"2026-10-01T12:00:00.000Z"}`) {
		t.Fatalf("response %s", r.Marshal())
	}
	pr, err := ParseConnAuthResponse(r.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConnAuthResponse(pr, a, b, c); err != nil {
		t.Fatal(err)
	}
	other := *c
	other.Context = "other"
	for name, f := range map[string]func() error{
		"swapped": func() error { return VerifyConnAuthResponse(pr, b, a, c) },
		"context": func() error { return VerifyConnAuthResponse(pr, a, b, &other) },
		"denied":  func() error { return VerifyConnAuthResponse(DeniedConnAuth(reqID), a, b, c) },
	} {
		if f() == nil {
			t.Errorf("%s verifies", name)
		}
	}
	if got := string(DeniedConnAuth(reqID).Marshal()); got != `{"request_id":"`+reqID+`","status":"denied"}` {
		t.Fatal(got)
	}
	// Pinning: no pin and the same key are no change; another key is one
	// unless a valid chain leads to it.
	rot, err := credwire.NewKeyRotation(key(4), cred)
	if err != nil {
		t.Fatal(err)
	}
	if PinnedKeyChanged(nil, pub(cred), nil) || PinnedKeyChanged(pub(cred), pub(cred), nil) ||
		PinnedKeyChanged(pub(key(4)), pub(cred), []*credwire.KeyRotation{rot}) || !PinnedKeyChanged(pub(key(4)), pub(cred), nil) ||
		!PinnedKeyChanged(pub(key(5)), pub(cred), []*credwire.KeyRotation{rot}) {
		t.Fatal("pin")
	}
	if _, err := NewConnAuthChallenge(reqID, strings.Repeat("x", ConnAuthMaxContext+1)); err == nil {
		t.Fatal("long context")
	}
}

// 0.65.0 §10.4 "Signed with the purpose": a challenge's purpose is signed
// under its own label and echoed; a signature for one purpose never
// verifies for another, nor as one without a purpose; a response without
// a purpose (a vault before 0.65.0) verifies over the message alone; an
// unknown purpose in a challenge is treated as absent.
func TestConnAuthPurpose(t *testing.T) {
	a, b, cred := pub(key(1)), pub(key(2)), key(3)
	withPurpose := func(p string) *ConnAuthChallenge {
		c, err := NewConnAuthChallenge(reqID, "example.org, Firefox on Linux")
		if err != nil {
			t.Fatal(err)
		}
		c.Purpose = p
		return c
	}
	signin := withPurpose(PurposeSignIn)
	pc, err := ParseConnAuthChallenge(signin.Marshal())
	if err != nil || pc.Purpose != PurposeSignIn || !strings.HasSuffix(string(signin.Marshal()), `,"purpose":"signin"}`) {
		t.Fatalf("challenge %s: %+v %v", signin.Marshal(), pc, err)
	}
	r, err := SignConnAuth(cred, a, b, signin, t0, nil)
	if err != nil || r.Purpose != PurposeSignIn {
		t.Fatalf("%+v %v", r, err)
	}
	m := signin.Message(a, b)
	want := append([]byte{6}, append([]byte("signin"), m...)...)
	if !ed25519.Verify(pub(cred), append([]byte("vettid/vms/2/conn-auth-purpose"), want...), r.Sig) {
		t.Fatal("not signed over len(purpose) || purpose || m under the purpose label")
	}
	pr, err := ParseConnAuthResponse(r.Marshal())
	if err != nil || pr.Purpose != PurposeSignIn {
		t.Fatalf("response %s: %+v %v", r.Marshal(), pr, err)
	}
	if err := VerifyConnAuthResponse(pr, a, b, signin); err != nil {
		t.Fatal(err)
	}

	// The same signature presented for another purpose, or with the
	// purpose taken off, does not verify.
	approval := *signin
	approval.Purpose = PurposeApproval
	none := *signin
	none.Purpose = ""
	stripped := *pr
	stripped.Purpose = ""
	relabelled := *pr
	relabelled.Purpose = PurposeApproval
	for name, f := range map[string]func() error{
		"for an approval":           func() error { return VerifyConnAuthResponse(pr, a, b, &approval) },
		"for a challenge without":   func() error { return VerifyConnAuthResponse(pr, a, b, &none) },
		"purpose stripped":          func() error { return VerifyConnAuthResponse(&stripped, a, b, signin) },
		"purpose relabelled":        func() error { return VerifyConnAuthResponse(&relabelled, a, b, &approval) },
		"unknown purpose in answer": func() error { x := *pr; x.Purpose = "vote"; return VerifyConnAuthResponse(&x, a, b, signin) },
	} {
		if f() == nil {
			t.Errorf("%s verifies", name)
		}
	}

	// A vault before 0.65.0 ignores the purpose: it signs m under the old
	// label and sends no purpose; that verifies, committing to none.
	old, err := SignConnAuth(cred, a, b, &none, t0, nil)
	if err != nil || old.Purpose != "" {
		t.Fatalf("%+v %v", old, err)
	}
	if err := VerifyConnAuthResponse(old, a, b, signin); err != nil || old.Purpose != "" {
		t.Fatalf("a response without purpose to a signin challenge: %v", err)
	}

	// An unknown purpose is absent: not sent, not signed over.
	for _, body := range []string{
		`{"request_id":"` + reqID + `","nonce":"` + strings.Repeat("A", 43) + `=","purpose":"vote"}`,
		`{"request_id":"` + reqID + `","nonce":"` + strings.Repeat("A", 43) + `=","purpose":""}`,
	} {
		c, err := ParseConnAuthChallenge([]byte(body))
		if err != nil || c.Purpose != "" {
			t.Fatalf("%s: %+v %v", body, c, err)
		}
	}
	vote := withPurpose("vote")
	if strings.Contains(string(vote.Marshal()), "purpose") {
		t.Fatal("an unknown purpose was sent")
	}
	if l, _ := vote.Signed(a, b); l != ConnAuthLabel {
		t.Fatal("an unknown purpose was signed over")
	}
	// Any other value, a string or not, is absent too.
	for _, v := range []string{`7`, `null`, `true`, `{"x":1}`} {
		body := `{"request_id":"` + reqID + `","nonce":"` + strings.Repeat("A", 43) + `=","purpose":` + v + `}`
		if c, err := ParseConnAuthChallenge([]byte(body)); err != nil || c.Purpose != "" {
			t.Fatalf("%s: %+v %v", body, c, err)
		}
	}
	// A response's purpose member that is present but not the challenge's
	// known purpose (empty, unknown, long, not a string) parses and fails
	// verification, also against a challenge without a purpose, so the
	// challenger reports bad_signature.
	sb := string(r.Marshal())
	for _, bad := range []string{`"purpose":""`, `"purpose":"` + strings.Repeat("p", 300) + `"`, `"purpose":true`, `"purpose":null`} {
		pr, err := ParseConnAuthResponse([]byte(strings.Replace(sb, `"purpose":"signin"`, bad, 1)))
		if err != nil || !pr.HasPurpose {
			t.Fatalf("response with %s: %+v %v", bad, pr, err)
		}
		for _, c := range []*ConnAuthChallenge{signin, &none} {
			if VerifyConnAuthResponse(pr, a, b, c) == nil {
				t.Errorf("response with %s verifies for purpose %q", bad, c.Purpose)
			}
		}
	}
	// Even over a plain signature: a legacy answer with an empty purpose
	// member added does not pass as one without.
	leg := strings.Replace(string(old.Marshal()), `"signed_at"`, `"purpose":"","signed_at"`, 1)
	if pl, err := ParseConnAuthResponse([]byte(leg)); err != nil || VerifyConnAuthResponse(pl, a, b, &none) == nil {
		t.Fatalf("a plain signature with an empty purpose member verifies: %v", err)
	}
}

func TestConnAuthBadBodies(t *testing.T) {
	nonce := `"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`
	for _, b := range []string{`{}`, `[]`, `{"request_id":"x","nonce":` + nonce + `}`, `{"request_id":"` + reqID + `","nonce":"AAAA"}`,
		`{"request_id":"` + reqID + `","nonce":` + nonce + `,"context":"` + strings.Repeat("x", 257) + `"}`,
		`{"request_id":"` + reqID + `","nonce":` + nonce + `,"context":1}`} {
		if _, err := ParseConnAuthChallenge([]byte(b)); err == nil {
			t.Errorf("challenge %s accepted", b)
		}
	}
	for _, b := range []string{`{"request_id":"` + reqID + `","status":"maybe"}`, `{"request_id":"` + reqID + `","status":"signed"}`,
		`{"request_id":"x","status":"denied"}`} {
		if _, err := ParseConnAuthResponse([]byte(b)); err == nil {
			t.Errorf("response %s accepted", b)
		}
	}
	for _, b := range []string{`{}`, `{"rotations":[]}`, `{"rotations":[{"v":1}]}`} {
		if _, err := ParseConnAuthRotated([]byte(b)); err == nil {
			t.Errorf("rotated %s accepted", b)
		}
	}
}

func FuzzParseConnAuthChallenge(f *testing.F) {
	f.Add([]byte(`{"request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","context":"x"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := ParseConnAuthChallenge(b)
		if err == nil && (len(c.Nonce) != ConnAuthNonceSize || len(c.Context) > ConnAuthMaxContext) {
			t.Fatal("invalid challenge accepted")
		}
		if err == nil {
			if again, err := ParseConnAuthChallenge(c.Marshal()); err != nil || again.RequestID != c.RequestID || again.Context != c.Context {
				t.Fatal("re-encoded challenge")
			}
		}
	})
}

func FuzzParseConnAuthResponse(f *testing.F) {
	f.Add([]byte(`{"request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","status":"denied"}`))
	f.Add([]byte(`{"request_id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","status":"signed","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","sig":"` +
		strings.Repeat("A", 86) + `==","signed_at":"2026-10-01T12:00:00.000Z"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := ParseConnAuthResponse(b)
		if err == nil && r.Status == ConnAuthSigned && (len(r.Key) != ed25519.PublicKeySize || len(r.Sig) != ed25519.SignatureSize) {
			t.Fatal("invalid response accepted")
		}
	})
}

func FuzzParseRotations(f *testing.F) {
	r, _ := credwire.NewKeyRotation(key(1), key(2))
	f.Add([]byte(`[` + string(r.Marshal()) + `]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if c, err := ParseRotations(b); err == nil && (len(c) == 0 || len(c) > credwire.MaxKeyChain) {
			t.Fatal("chain length")
		}
	})
}

// §7.1: a held token is the peer's deposit token for our relay key at the
// peer's relay and mailbox.
func TestVerifyHeldToken(t *testing.T) {
	peer, own, stranger := key(1), key(2), key(3)
	mailbox := relayauth.MailboxID(pub(peer))
	const url = "https://relay.example.org"
	mint := func(signer ed25519.PrivateKey, edit func(*relayauth.Claims)) string {
		c := relayauth.Claims{Iss: mailbox, Sub: relayauth.EncodeKey(pub(own)), Aud: url + "/", Iat: t0, Exp: t0.Add(StandingMax),
			Jti: "j1", Scope: relayauth.ScopeDeposit}
		if edit != nil {
			edit(&c)
		}
		tok, err := relayauth.MintToken(signer, c)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	c, err := VerifyHeldToken(mint(peer, nil), pub(peer), mailbox, url, pub(own))
	if err != nil || !c.Exp.Equal(t0.Add(StandingMax)) || c.Jti != "j1" {
		t.Fatalf("%+v %v", c, err)
	}
	for name, tok := range map[string]string{
		"signer": mint(stranger, nil),
		"iss":    mint(peer, func(c *relayauth.Claims) { c.Iss = relayauth.MailboxID(pub(stranger)) }),
		"sub":    mint(peer, func(c *relayauth.Claims) { c.Sub = relayauth.EncodeKey(pub(stranger)) }),
		"aud":    mint(peer, func(c *relayauth.Claims) { c.Aud = "https://other.example.org" }),
		"scope":  mint(peer, func(c *relayauth.Claims) { c.Scope = relayauth.ScopeDepositOpen; c.Sub = "*" }),
		"junk":   "v4.public.junk",
	} {
		if _, err := VerifyHeldToken(tok, pub(peer), mailbox, url, pub(own)); err != ErrToken {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The token and lifecycle bodies, byte for byte as the vault sends them.
func TestBodies(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{string(TokenIssuedBody(TokenReconnect, "T")), `{"kind":"reconnect","token":"T"}`},
		{string(TokenRefreshBody()), `{}`},
		{string(TooSoonBody(t0)), `{"allowed_after":"2026-10-01T12:00:00.000Z"}`},
		{string(ConnectionApprovedBody("S", "R")), `{"token":"S","reconnect_token":"R"}`},
		{string(ConnectionDeclinedBody()), `{}`},
		{string(ConnectionRemovedBody()), `{}`},
		{string(ProfileUpdateBody(7, "Ada", "King", make([]byte, 32), nil)),
			`{"version":7,"first_name":"Ada","last_name":"King","ik":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","items":[]}`},
		{string(ProfileUpdateBody(1, "A", "B", make([]byte, 32), []byte(`{"name":"N","items":[]}`))),
			`{"version":1,"first_name":"A","last_name":"B","ik":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","name":"N","items":[]}`},
	} {
		if c.got != c.want {
			t.Errorf("got %s, want %s", c.got, c.want)
		}
	}
	if k, tok, err := ParseTokenIssued([]byte(`{"kind":"reconnect","token":"T"}`)); err != nil || k != TokenReconnect || tok != "T" {
		t.Error("issued")
	}
	// kind absent or not a string: "" (the vault takes it as standing).
	if k, _, err := ParseTokenIssued([]byte(`{"kind":1,"token":"T"}`)); err != nil || k != "" {
		t.Error("issued without a kind")
	}
	if _, _, err := ParseTokenIssued([]byte(`{"kind":"standing"}`)); err == nil {
		t.Error("issued without a token")
	}
	if at, err := ParseTooSoon(TooSoonBody(t0)); err != nil || !at.Equal(t0) {
		t.Error("too_soon")
	}
	if _, err := ParseTooSoon([]byte(`{"allowed_after":"soon"}`)); err == nil {
		t.Error("too_soon accepted a bad time")
	}
	if s, r, err := ParseConnectionApproved(ConnectionApprovedBody("S", "R")); err != nil || s != "S" || r != "R" {
		t.Error("approved")
	}
	if _, _, err := ParseConnectionApproved([]byte(`{"token":"S"}`)); err == nil {
		t.Error("approved without a reconnect token")
	}
	if ParseConnectionDeclined([]byte(`{}`)) != nil || ParseConnectionRemoved([]byte(`{"x":1}`)) != nil || ParseConnectionRemoved([]byte(`[]`)) == nil {
		t.Error("empty bodies")
	}
}

// §10.8: the core, with Malformed rather than an error for a bad core.
func TestProfile(t *testing.T) {
	ik := pub(key(1))
	u, err := ParseProfileUpdate(ProfileUpdateBody(3, "Ada", "King", ik, nil))
	if err != nil || u.Version != 3 || u.FirstName != "Ada" || u.LastName != "King" || !bytes.Equal(u.IK, ik) || u.Malformed || len(u.Items) != 0 {
		t.Fatalf("%+v %v", u, err)
	}
	if u, err := ParseProfileUpdate([]byte(`{"version":1,"first_name":"","last_name":"K","ik":"AAAA","items":[]}`)); err != nil || !u.Malformed {
		t.Fatal("malformed core")
	}
	for _, b := range []string{`{"version":0,"first_name":"A","last_name":"B","ik":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","items":[]}`,
		`{"version":1,"first_name":"A","last_name":"B","ik":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
		`{"version":1,"items":[` + strings.Repeat(`{},`, MaxProfileItems) + `{}]}`,
		`{"version":1,"items":[],"pad":"` + strings.Repeat("x", MaxProfileUpdate) + `"}`} {
		if _, err := ParseProfileUpdate([]byte(b)); err == nil {
			t.Errorf("accepted %.80s", b)
		}
	}
	if !ValidAccountName("Ada") || ValidAccountName("") || ValidAccountName("A ") || ValidAccountName("A\x7f") ||
		ValidAccountName(strings.Repeat("x", MaxAccountName+1)) || ValidAccountName("\xff") || !ValidAccountName(strings.Repeat("x", MaxAccountName)) {
		t.Fatal("ValidAccountName")
	}
	if !ValidHandshakeProfile([]byte(`{"first_name":"A","last_name":"B","name":"N"}`)) || ValidHandshakeProfile(nil) ||
		ValidHandshakeProfile([]byte(`{"first_name":"A"}`)) {
		t.Fatal("ValidHandshakeProfile")
	}
}

// 0.79.0 §10.4 "Match code": 2-3 ASCII digits as a string, signin only,
// dropped when malformed, and never part of what is signed.
func TestConnAuthMatchCode(t *testing.T) {
	a, b, cred := pub(key(1)), pub(key(2)), key(3)
	base := `{"request_id":"` + reqID + `","nonce":"` + base64.StdEncoding.EncodeToString(make([]byte, ConnAuthNonceSize)) + `"`
	parse := func(extra string) *ConnAuthChallenge {
		t.Helper()
		c, err := ParseConnAuthChallenge([]byte(base + extra + `}`))
		if err != nil {
			t.Fatalf("%s: challenge refused: %v", extra, err)
		}
		return c
	}
	for in, want := range map[string]string{
		`,"purpose":"signin","match_code":"42"`:   "42",
		`,"purpose":"signin","match_code":"07"`:   "07",
		`,"purpose":"signin","match_code":"123"`:  "123",
		`,"purpose":"signin","match_code":42`:     "",
		`,"purpose":"signin","match_code":null`:   "",
		`,"purpose":"signin","match_code":"4"`:    "",
		`,"purpose":"signin","match_code":"1234"`: "",
		`,"purpose":"signin","match_code":"٤٢"`:   "",
		`,"purpose":"signin","match_code":"+4"`:   "",
		`,"purpose":"signin","match_code":" 42"`:  "",
		`,"purpose":"signin","match_code":""`:     "",
		`,"purpose":"approval","match_code":"42"`: "",
		`,"match_code":"42"`:                      "",
		`,"purpose":"vote","match_code":"42"`:     "",
	} {
		if got := parse(in).MatchCode; got != want {
			t.Errorf("%s: MatchCode %q, want %q", in, got, want)
		}
	}
	// Marshal repeats a valid code on a sign-in and nothing else.
	c := parse(`,"purpose":"signin","match_code":"07"`)
	if !strings.Contains(string(c.Marshal()), `"match_code":"07"`) {
		t.Fatalf("%s", c.Marshal())
	}
	c.Purpose = PurposeApproval
	if strings.Contains(string(c.Marshal()), "match_code") {
		t.Fatalf("%s", c.Marshal())
	}
	// Not signed: same signature input and a response verifies with or
	// without the code.
	with := parse(`,"purpose":"signin","match_code":"42"`)
	without := parse(`,"purpose":"signin"`)
	l1, m1 := with.Signed(a, b)
	l2, m2 := without.Signed(a, b)
	if l1 != l2 || !bytes.Equal(m1, m2) {
		t.Fatal("match_code changed the signed bytes")
	}
	r, err := SignConnAuth(cred, a, b, with, t0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(r.Marshal()), "match_code") {
		t.Fatalf("response carries the code: %s", r.Marshal())
	}
	if err := VerifyConnAuthResponse(r, a, b, without); err != nil {
		t.Fatal(err)
	}
}
