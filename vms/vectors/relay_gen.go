//go:build vmsvectors

package vectors

import (
	"crypto/ed25519"
	"encoding/hex"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
)

// The inputs of RELAY-PROTOCOL §9: seeds of all 0x01 and all 0x02 bytes,
// the token's claims and the deposit request. Everything else in
// relay.json is computed by the relay's own library code, relayauth.
const (
	relayAud       = "https://relay.example.vettid.org"
	relayJTI       = "01JXAMPLE0000000000000000"
	relayBody      = `{"payload":"b3BhcXVlLWNpcGhlcnRleHQtYnl0ZXM="}`
	relayRequestTS = "2026-06-10T12:00:00Z"
)

// genRelay builds relay.json: the RELAY-PROTOCOL §9.1 keys and mailbox ids,
// the §9.2 deposit token (claims and PASETO v4.public token) and the §9.3
// signed deposit request.
func genRelay() (obj, error) {
	recipient := ed25519.NewKeyFromSeed(rep(0x01, 32))
	sender := ed25519.NewKeyFromSeed(rep(0x02, 32))
	rpub := recipient.Public().(ed25519.PublicKey)
	spub := sender.Public().(ed25519.PublicKey)
	rmbx, smbx := relayauth.MailboxID(rpub), relayauth.MailboxID(spub)

	iat, _ := time.Parse(time.RFC3339, "2026-06-10T00:00:00Z")
	exp, _ := time.Parse(time.RFC3339, "2026-07-10T00:00:00Z")
	token, err := relayauth.MintToken(recipient, relayauth.Claims{
		Iss: rmbx, Sub: relayauth.EncodeKey(spub), Aud: relayAud, Iat: iat, Exp: exp, Jti: relayJTI, Scope: relayauth.ScopeDeposit,
	})
	if err != nil {
		return nil, err
	}
	claims, err := relayauth.VerifyToken(token, rpub)
	if err != nil {
		return nil, err
	}

	path := "/v1/mailbox/" + rmbx
	bh := relayauth.BodyHash([]byte(relayBody))
	canon := relayauth.Canonical("POST", path, relayRequestTS, bh)
	digest := relayauth.Digest("POST", path, relayRequestTS, bh)
	sig := relayauth.SignRequest(sender, "POST", path, relayRequestTS, bh)

	return obj{
		{"description", "RELAY-PROTOCOL §9 test vectors, copied from the spec and recomputed with the relay's relayauth package: the keys and mailbox ids (§9.1), the deposit token (§9.2) and the signed deposit request (§9.3). Seeds are 32 x 0x01 (recipient) and 32 x 0x02 (sender); all keys are fixed, public and TEST-ONLY. Standard base64 with padding throughout; mailbox_id = lowercase base32 (no padding) of SHA-256(pubkey), first 26 characters. The token is PASETO v4.public: the claims are the exact signed bytes (compact JSON, this key order), the signature is Ed25519 over the PASETO pre-authentication encoding of the header \"v4.public.\" and the claims, and is deterministic. The request signature is Ed25519 over SHA-256(canonical), canonical = METHOD \\n path \\n timestamp \\n lowercase hex SHA-256(body)."},
		{"recipient", obj{
			{"seed_b64", b64(rep(0x01, 32))},
			{"pubkey_b64", relayauth.EncodeKey(rpub)},
			{"mailbox_id", rmbx},
		}},
		{"sender", obj{
			{"seed_b64", b64(rep(0x02, 32))},
			{"pubkey_b64", relayauth.EncodeKey(spub)},
			{"mailbox_id", smbx},
		}},
		{"token", obj{
			{"signed_by", "recipient"},
			{"claims", string(claims)},
			{"token", token},
		}},
		{"request", obj{
			{"signed_by", "sender"},
			{"method", "POST"},
			{"path", path},
			{"body", relayBody},
			{"body_sha256_hex", hex.EncodeToString(bh[:])},
			{"canonical", string(canon)},
			{"canonical_sha256_b64", b64(digest[:])},
			{"x_vettid_key", relayauth.EncodeKey(spub)},
			{"x_vettid_timestamp", relayRequestTS},
			{"x_vettid_sig", b64(sig)},
		}},
	}, nil
}
