package vectors

import (
	"crypto/ed25519"
	"testing"

	"github.com/vettid/vettid-vault/vms/peerwire"
)

func TestConnAuthPurposeVectors(t *testing.T) { checkConnAuthPurposeVectors(t, Dir) }

// checkConnAuthPurposeVectors re-derives connauth_purpose.json (0.65.0,
// §10.4) by hand from connauth.json's keys and message: for each purpose
// the signed bytes len(purpose) || purpose || message and the Ed25519
// signature under the purpose label; then through peerwire's receiving
// functions: the bodies parse and re-encode to the same bytes, each
// response verifies for its own purpose only, and the legacy response
// (no purpose) verifies for the signin challenge, committing to none.
func checkConnAuthPurposeVectors(t *testing.T, dir string) {
	base := load(t, dir, "connauth.json")
	d := load(t, dir, "connauth_purpose.json")
	if d.str("label_purpose") != "vettid/vms/2/conn-auth-purpose" || peerwire.ConnAuthPurposeLabel != d.str("label_purpose") {
		t.Fatalf("label %q", d.str("label_purpose"))
	}
	seed := func(name string) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(base.sub(name).hex("seed_hex")) }
	pub := func(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
	challenger, responder, cred := pub(seed("challenger_ik")), pub(seed("responder_ik")), seed("credential_new")
	m := base.hex("message_hex")

	challenges := map[string]*peerwire.ConnAuthChallenge{}
	responses := map[string]*peerwire.ConnAuthResponse{}
	for _, p := range []string{"signin", "approval"} {
		v := d.sub(p)
		mp := append(append([]byte{byte(len(p))}, p...), m...)
		eq(t, p+" message", mp, v.hex("message_purpose_hex"))
		sig := ed25519.Sign(cred, append([]byte("vettid/vms/2/conn-auth-purpose"), mp...))
		eq(t, p+" sig", sig, v.b64("sig_b64"))

		c, err := peerwire.ParseConnAuthChallenge([]byte(v.str("challenge_body")))
		if err != nil || c.Purpose != p || c.RequestID != base.str("request_id") || c.Context != base.str("context") {
			t.Fatalf("%s challenge: %+v %v", p, c, err)
		}
		eq(t, p+" challenge nonce", c.Nonce, base.hex("nonce_hex"))
		eq(t, p+" challenge body", c.Marshal(), []byte(v.str("challenge_body")))
		r, err := peerwire.ParseConnAuthResponse([]byte(v.str("response_body")))
		if err != nil || r.Purpose != p || r.Status != peerwire.ConnAuthSigned {
			t.Fatalf("%s response: %+v %v", p, r, err)
		}
		eq(t, p+" response sig", r.Sig, sig)
		eq(t, p+" response key", r.Key, pub(cred))
		eq(t, p+" response re-encoded", r.Marshal(), []byte(v.str("response_body")))
		if err := peerwire.VerifyConnAuthResponse(r, challenger, responder, c); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		resigned, err := peerwire.SignConnAuth(cred, challenger, responder, c, r.SignedAt, nil)
		if err != nil {
			t.Fatal(err)
		}
		eq(t, p+" (peerwire.SignConnAuth)", resigned.Marshal(), []byte(v.str("response_body")))
		challenges[p], responses[p] = c, r
	}
	// A signature for one purpose never stands for the other.
	if peerwire.VerifyConnAuthResponse(responses["signin"], challenger, responder, challenges["approval"]) == nil ||
		peerwire.VerifyConnAuthResponse(responses["approval"], challenger, responder, challenges["signin"]) == nil {
		t.Fatal("a response verifies for the other purpose")
	}

	// A vault before 0.65.0: no purpose, over the message alone.
	legacy, err := peerwire.ParseConnAuthResponse([]byte(d.str("legacy_response_body")))
	if err != nil || legacy.Purpose != "" {
		t.Fatalf("legacy: %+v %v", legacy, err)
	}
	eq(t, "legacy sig", legacy.Sig, ed25519.Sign(cred, append([]byte("vettid/vms/2/conn-auth"), m...)))
	if err := peerwire.VerifyConnAuthResponse(legacy, challenger, responder, challenges["signin"]); err != nil || legacy.Purpose != "" {
		t.Fatalf("legacy response to the signin challenge: %v", err)
	}
}
