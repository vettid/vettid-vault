package vectors

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/vettid/vettid-vault/vms/handshake"
)

// checkRelayRotateVectors checks relay_rotate.json from the receiving
// side: every key from its seed, every link's signed bytes and both
// signatures recomputed with plain Ed25519, and each case's chain judged
// by handshake.VerifyRelayChain as its "valid" says.
func checkRelayRotateVectors(t *testing.T, dir string) {
	d := load(t, dir, "relay_rotate.json")
	var keys []map[string]any
	if err := json.Unmarshal(d.m["keys"], &keys); err != nil {
		t.Fatal(err)
	}
	priv := map[string]ed25519.PrivateKey{} // pk_b64 -> key
	for _, k := range keys {
		s, err := hex.DecodeString(k["seed_hex"].(string))
		if err != nil || len(s) != 32 {
			t.Fatal("seed")
		}
		p := ed25519.NewKeyFromSeed(s)
		if rr64(p.Public().(ed25519.PublicKey)) != k["pk_b64"] {
			t.Fatalf("key %v: pk", k["index"])
		}
		priv[k["pk_b64"].(string)] = p
	}
	var cases []map[string]json.RawMessage
	if err := json.Unmarshal(d.m["cases"], &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no cases")
	}
	for _, cm := range cases {
		c := doc{t, cm}
		t.Run(c.str("name"), func(t *testing.T) {
			var raws, signed []json.RawMessage
			if json.Unmarshal(c.m["relay_links"], &raws) != nil || json.Unmarshal(c.m["signed_bytes_hex"], &signed) != nil || len(raws) != len(signed) {
				t.Fatal("links")
			}
			var valid bool
			if json.Unmarshal(c.m["valid"], &valid) != nil {
				t.Fatal("valid")
			}
			var links []*handshake.RelayLink
			for i, raw := range raws {
				l, err := handshake.ParseRelayLink(raw)
				if err != nil {
					t.Fatalf("link %d: %v", i, err)
				}
				var sh string
				_ = json.Unmarshal(signed[i], &sh)
				m := append(append([]byte("vettid/vms/2/relay-rotate"), l.Old...), l.New...)
				if hex.EncodeToString(m) != sh || hex.EncodeToString(handshake.RelayLinkSigned(l.Old, l.New)) != sh {
					t.Fatalf("link %d: signed bytes", i)
				}
				// Recompute both signatures (deterministic Ed25519); a vector
				// whose signature was altered on purpose differs here only.
				po, pn := priv[rr64(l.Old)], priv[rr64(l.New)]
				if po == nil || pn == nil {
					t.Fatalf("link %d: key not in keys", i)
				}
				sigOK := hex.EncodeToString(ed25519.Sign(po, m)) == hex.EncodeToString(l.SigOld) &&
					hex.EncodeToString(ed25519.Sign(pn, m)) == hex.EncodeToString(l.SigNew)
				if sigOK != (l.Verify() == nil) {
					t.Fatalf("link %d: Verify disagrees with Ed25519", i)
				}
				links = append(links, l)
			}
			err := handshake.VerifyRelayChain(c.b64("first_b64"), c.b64("announced_b64"), links)
			if (err == nil) != valid {
				t.Fatalf("VerifyRelayChain: %v, want valid %v", err, valid)
			}
			if len(links) <= handshake.MaxRelayLinks {
				if _, err := handshake.ParseRelayLinks(raws); err != nil {
					t.Fatal(err)
				}
			} else if _, err := handshake.ParseRelayLinks(raws); err == nil {
				t.Fatal("more than 32 links parsed")
			}
		})
	}
}

func rr64(v []byte) string { return base64.StdEncoding.EncodeToString(v) }
