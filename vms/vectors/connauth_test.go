package vectors

import (
	"crypto/ed25519"
	"testing"

	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

func TestConnAuthVectors(t *testing.T) { checkConnAuthVectors(t, Dir) }

// checkConnAuthVectors re-derives connauth.json (§10.4) by hand (the keys
// from their seeds, the signed message, the Ed25519 signature over label ||
// message) and through peerwire's receiving functions: every body parses
// and re-encodes to the same bytes, the response verifies over the
// challenge, and the rotation leads from the pinned key to the signing one.
func checkConnAuthVectors(t *testing.T, dir string) {
	d := load(t, dir, "connauth.json")
	if d.str("label") != "vettid/vms/2/conn-auth" || peerwire.ConnAuthLabel != d.str("label") {
		t.Fatalf("label %q", d.str("label"))
	}
	key := func(name string) ed25519.PrivateKey {
		k := ed25519.NewKeyFromSeed(d.sub(name).hex("seed_hex"))
		eq(t, name, k.Public().(ed25519.PublicKey), d.sub(name).b64("pk_b64"))
		return k
	}
	pub := func(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
	challenger, responder := pub(key("challenger_ik")), pub(key("responder_ik"))
	credOld, credNew := key("credential_old"), key("credential_new")
	id, nonce, ctxt := d.str("request_id"), d.hex("nonce_hex"), d.str("context")

	// The signed message and signature, by hand.
	var m []byte
	m = append(m, challenger...)
	m = append(m, responder...)
	m = append(m, nonce...)
	m = append(m, id...)
	m = append(m, ctxt...)
	eq(t, "message", m, d.hex("message_hex"))
	eq(t, "message (peerwire)", peerwire.ConnAuthMessage(challenger, responder, nonce, id, ctxt), m)
	sig := ed25519.Sign(credNew, append([]byte("vettid/vms/2/conn-auth"), m...))
	eq(t, "sig", sig, d.b64("sig_b64"))

	// The challenge.
	c, err := peerwire.ParseConnAuthChallenge([]byte(d.str("challenge_body")))
	if err != nil {
		t.Fatal(err)
	}
	if c.RequestID != id || c.Context != ctxt {
		t.Fatalf("challenge %+v", c)
	}
	eq(t, "challenge nonce", c.Nonce, nonce)
	eq(t, "challenge body", c.Marshal(), []byte(d.str("challenge_body")))

	// The responses: without and with the rotation from the pinned key.
	signedAt, err := envelope.ParseTS(d.str("signed_at"))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"response_body", "response_rotated_body"} {
		body := []byte(d.str(k))
		r, err := peerwire.ParseConnAuthResponse(body)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		if r.Status != peerwire.ConnAuthSigned || r.RequestID != id || !r.SignedAt.Equal(signedAt) {
			t.Fatalf("%s: %+v", k, r)
		}
		eq(t, k+" key", r.Key, pub(credNew))
		eq(t, k+" sig", r.Sig, sig)
		eq(t, k+" re-encoded", r.Marshal(), body)
		if err := peerwire.VerifyConnAuthResponse(r, challenger, responder, c); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		// The challenger and responder roles are not interchangeable.
		if peerwire.VerifyConnAuthResponse(r, responder, challenger, c) == nil {
			t.Fatalf("%s verifies with the roles swapped", k)
		}
		changed := peerwire.PinnedKeyChanged(pub(credOld), r.Key, r.Rotations)
		if want := k == "response_body"; changed != want {
			t.Fatalf("%s: key changed %v", k, changed)
		}
		if peerwire.PinnedKeyChanged(pub(credNew), r.Key, r.Rotations) {
			t.Fatalf("%s: the pinned key itself reported as a change", k)
		}
		resigned, err := peerwire.SignConnAuth(credNew, challenger, responder, c, signedAt, r.Rotations)
		if err != nil {
			t.Fatal(err)
		}
		eq(t, k+" (peerwire.SignConnAuth)", resigned.Marshal(), body)
	}

	// The refusal and the rotated message.
	dr, err := peerwire.ParseConnAuthResponse([]byte(d.str("denied_body")))
	if err != nil || dr.Status != peerwire.ConnAuthDenied || dr.RequestID != id {
		t.Fatalf("denied: %+v %v", dr, err)
	}
	eq(t, "denied body", peerwire.DeniedConnAuth(id).Marshal(), []byte(d.str("denied_body")))
	rs, err := peerwire.ParseConnAuthRotated([]byte(d.str("rotated_body")))
	if err != nil || len(rs) != 1 {
		t.Fatalf("rotated: %v", err)
	}
	end, err := credwire.FollowChain(pub(credOld), rs)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "rotated to", end, pub(credNew))
	eq(t, "rotated body", peerwire.ConnAuthRotatedBody(rs), []byte(d.str("rotated_body")))
}
