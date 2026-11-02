package vectors

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// The values of RELAY-PROTOCOL §9, copied from the spec text.
const (
	specRecipientSeed    = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	specRecipientPub     = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="
	specRecipientMailbox = "gr2q7gf5lh6pzfdnurnkvputhp"
	specSenderSeed       = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	specSenderPub        = "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q="
	specSenderMailbox    = "ni4ahvpqlgicuhdnv66jxjdssi"

	specClaims = `{"iss":"gr2q7gf5lh6pzfdnurnkvputhp","sub":"gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=","aud":"https://relay.example.vettid.org","iat":"2026-06-10T00:00:00Z","exp":"2026-07-10T00:00:00Z","jti":"01JXAMPLE0000000000000000","scope":"deposit"}`
	specToken  = "v4.public.eyJpc3MiOiJncjJxN2dmNWxoNnB6ZmRudXJua3ZwdXRocCIsInN1YiI6ImdUbDNEcWg5RjE5V28xUm13MHgrek11TmlwRzA3amVpWGZZUFc0L0pzNVE9IiwiYXVkIjoiaHR0cHM6Ly9yZWxheS5leGFtcGxlLnZldHRpZC5vcmciLCJpYXQiOiIyMDI2LTA2LTEwVDAwOjAwOjAwWiIsImV4cCI6IjIwMjYtMDctMTBUMDA6MDA6MDBaIiwianRpIjoiMDFKWEFNUExFMDAwMDAwMDAwMDAwMDAwMCIsInNjb3BlIjoiZGVwb3NpdCJ9rWQjEmgif2o_c9SNTUXzHPPLWKZCPMAPUk3VPpbWkTIY0pfihNHpVZeX-YDM35FN_u1FVYPHj4BrO4sGJQj6BA"

	specPath      = "/v1/mailbox/gr2q7gf5lh6pzfdnurnkvputhp"
	specBody      = `{"payload":"b3BhcXVlLWNpcGhlcnRleHQtYnl0ZXM="}`
	specBodyHex   = "0237514b3df17b219036f1b8fa6ca70d4ca597eb630933841707380055d7e12a"
	specTimestamp = "2026-06-10T12:00:00Z"
	specCanonical = "POST\n/v1/mailbox/gr2q7gf5lh6pzfdnurnkvputhp\n2026-06-10T12:00:00Z\n0237514b3df17b219036f1b8fa6ca70d4ca597eb630933841707380055d7e12a"
	specDigestB64 = "l+mc5XMNElCBLC49xJH4Lc8LHEAlAK1HunqaS+LZ33k="
	specSigB64    = "pOZT7Pb981+3K4wWv6Zryb43miSLBfKdCZ4Wc/qNzQyxFtOPrsSSkK1Gj5mF+Zb3z3yC4Bi7AyjIyVkeN+nsDA=="
)

// checkRelayVectors checks relay.json against the RELAY-PROTOCOL §9 values
// and recomputes every one with the relay's own code (relayauth) and the
// mailbox derivation of the handshake package.
func checkRelayVectors(t *testing.T, dir string) {
	d := load(t, dir, "relay.json")
	key := func(who doc, seed, pub, mbx string) ed25519.PrivateKey {
		if who.str("seed_b64") != seed || who.str("pubkey_b64") != pub || who.str("mailbox_id") != mbx {
			t.Error("§9.1 value differs from the spec")
		}
		s, err := base64.StdEncoding.DecodeString(seed)
		if err != nil || len(s) != 32 {
			t.Fatal("seed")
		}
		priv := ed25519.NewKeyFromSeed(s)
		p := priv.Public().(ed25519.PublicKey)
		if relayauth.EncodeKey(p) != pub {
			t.Errorf("pubkey %s", relayauth.EncodeKey(p))
		}
		if relayauth.MailboxID(p) != mbx || handshake.MailboxID(p) != mbx || !relayauth.ValidMailboxID(mbx) {
			t.Errorf("mailbox_id %s", relayauth.MailboxID(p))
		}
		return priv
	}
	recipient := key(d.sub("recipient"), specRecipientSeed, specRecipientPub, specRecipientMailbox)
	sender := key(d.sub("sender"), specSenderSeed, specSenderPub, specSenderMailbox)
	rpub := recipient.Public().(ed25519.PublicKey)
	spub := sender.Public().(ed25519.PublicKey)

	// §9.2: the claims, the token and its signature.
	tk := d.sub("token")
	if tk.str("claims") != specClaims || tk.str("token") != specToken {
		t.Error("§9.2 value differs from the spec")
	}
	m, err := relayauth.VerifyToken(specToken, rpub)
	if err != nil || string(m) != specClaims {
		t.Fatalf("token does not verify under the recipient key: %v", err)
	}
	if _, err := relayauth.VerifyToken(specToken, spub); err == nil {
		t.Error("token verifies under the sender key")
	}
	iat, _ := time.Parse(time.RFC3339, "2026-06-10T00:00:00Z")
	exp, _ := time.Parse(time.RFC3339, "2026-07-10T00:00:00Z")
	minted, err := relayauth.MintToken(recipient, relayauth.Claims{
		Iss: specRecipientMailbox, Sub: specSenderPub, Aud: "https://relay.example.vettid.org", Iat: iat, Exp: exp,
		Jti: "01JXAMPLE0000000000000000", Scope: relayauth.ScopeDeposit,
	})
	if err != nil || minted != specToken {
		t.Errorf("minted token differs from the spec: %v", err)
	}
	c, err := relayauth.ParseToken(specToken, rpub)
	if err != nil {
		t.Fatal(err)
	}
	if c.Iss != specRecipientMailbox || c.Sub != specSenderPub || c.Aud != "https://relay.example.vettid.org" ||
		!c.Iat.Equal(iat) || !c.Exp.Equal(exp) || c.Jti != "01JXAMPLE0000000000000000" || c.Scope != "deposit" || c.Open() {
		t.Errorf("claims %+v", c)
	}
	if !spubEqual(c.SubKey, spub) {
		t.Error("sub key")
	}

	// §9.3: the signed deposit request.
	rq := d.sub("request")
	if rq.str("method") != "POST" || rq.str("path") != specPath || rq.str("body") != specBody ||
		rq.str("body_sha256_hex") != specBodyHex || rq.str("canonical") != specCanonical ||
		rq.str("canonical_sha256_b64") != specDigestB64 || rq.str("x_vettid_key") != specSenderPub ||
		rq.str("x_vettid_timestamp") != specTimestamp || rq.str("x_vettid_sig") != specSigB64 {
		t.Error("§9.3 value differs from the spec")
	}
	if specPath != "/v1/mailbox/"+specRecipientMailbox {
		t.Error("path is not the recipient's mailbox")
	}
	bh := relayauth.BodyHash([]byte(specBody))
	if hex.EncodeToString(bh[:]) != specBodyHex {
		t.Error("sha256(body)")
	}
	if string(relayauth.Canonical("POST", specPath, specTimestamp, bh)) != specCanonical {
		t.Error("canonical string")
	}
	dg := relayauth.Digest("POST", specPath, specTimestamp, bh)
	cd := sha256.Sum256([]byte(specCanonical))
	if base64.StdEncoding.EncodeToString(dg[:]) != specDigestB64 || dg != cd {
		t.Error("sha256(canonical)")
	}
	sig := relayauth.SignRequest(sender, "POST", specPath, specTimestamp, bh)
	if base64.StdEncoding.EncodeToString(sig) != specSigB64 {
		t.Error("signature")
	}
	ts, _ := time.Parse(time.RFC3339, specTimestamp)
	h := http.Header{}
	relayauth.SetHeaders(h, sender, "POST", specPath, ts, bh)
	if h.Get(relayauth.HeaderKey) != specSenderPub || h.Get(relayauth.HeaderTimestamp) != specTimestamp || h.Get(relayauth.HeaderSig) != specSigB64 {
		t.Errorf("headers %v", h)
	}
	sr, err := relayauth.ParseHeaders(h)
	if err != nil {
		t.Fatal(err)
	}
	if err := sr.Verify("POST", specPath, bh, ts); err != nil {
		t.Errorf("the spec's request does not verify: %v", err)
	}
	if err := sr.Verify("POST", specPath+"x", bh, ts); err == nil {
		t.Error("the request verifies for another path")
	}
}

func spubEqual(a, b ed25519.PublicKey) bool { return string(a) == string(b) }
