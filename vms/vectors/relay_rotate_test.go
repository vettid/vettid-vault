package vectors

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/vettid/vettid-vault/vms/handshake"
)

// checkRelayRotateVectors checks relay_rotate.json from the receiving
// side, twice: an independent verdict as an app would compute it (plain
// Ed25519 and the rules of 0.90.3 §3.4.1 rule U, no vms code), and the
// library's (handshake.ParseRelayLinks and VerifyRelayChain). Both must
// match each case's "valid". The keys are re-derived from their seeds and
// every listed signed byte string recomputed.
func checkRelayRotateVectors(t *testing.T, dir string) {
	d := load(t, dir, "relay_rotate.json")
	var keys []map[string]any
	if err := json.Unmarshal(d.m["keys"], &keys); err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		s, err := hex.DecodeString(k["seed_hex"].(string))
		if err != nil || len(s) != 32 {
			t.Fatal("seed")
		}
		if rr64(ed25519.NewKeyFromSeed(s).Public().(ed25519.PublicKey)) != k["pk_b64"] {
			t.Fatalf("key %v: pk", k["index"])
		}
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
				t.Fatal("relay_links")
			}
			var valid bool
			if json.Unmarshal(c.m["valid"], &valid) != nil {
				t.Fatal("valid")
			}
			first, announced := c.b64("first_b64"), c.b64("announced_b64")
			for i, raw := range raws {
				var l struct{ Old, New string }
				_ = json.Unmarshal(raw, &l)
				o, _ := base64.StdEncoding.DecodeString(l.Old)
				n, _ := base64.StdEncoding.DecodeString(l.New)
				var sh string
				_ = json.Unmarshal(signed[i], &sh)
				if hex.EncodeToString(relayM(o, n)) != sh {
					t.Fatalf("link %d: signed bytes", i)
				}
			}
			if got := plainRelayVerdict(raws, first, announced); got != valid {
				t.Fatalf("the independent check says valid %v, the vector %v", got, valid)
			}
			lib := false
			if ls, err := handshake.ParseRelayLinks(raws); err == nil {
				lib = handshake.VerifyRelayChain(first, announced, ls) == nil
			}
			if lib != valid {
				t.Fatalf("vms says valid %v, the vector %v", lib, valid)
			}
		})
	}
}

func relayM(old, new []byte) []byte {
	return append(append([]byte("vettid/vms/2/relay-rotate"), old...), new...)
}

// plainRelayVerdict judges a chain by rule U with no vms code: 1 to 32
// links, each {v: 1, suite: 2} with 32-byte keys, old != new, and both
// Ed25519 signatures over m; contiguous; no key twice; from first to
// announced.
func plainRelayVerdict(raws []json.RawMessage, first, announced []byte) bool {
	if len(raws) < 1 || len(raws) > 32 {
		return false
	}
	cur := first
	seen := [][]byte{first}
	for _, raw := range raws {
		var l struct{ Old, New string }
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil {
			return false
		}
		if string(m["v"]) != "1" || string(m["suite"]) != "2" {
			return false
		}
		_ = json.Unmarshal(raw, &l)
		var s struct {
			SigOld string `json:"sig_old"`
			SigNew string `json:"sig_new"`
		}
		_ = json.Unmarshal(raw, &s)
		o, e1 := base64.StdEncoding.DecodeString(l.Old)
		n, e2 := base64.StdEncoding.DecodeString(l.New)
		so, e3 := base64.StdEncoding.DecodeString(s.SigOld)
		sn, e4 := base64.StdEncoding.DecodeString(s.SigNew)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || len(o) != 32 || len(n) != 32 {
			return false
		}
		if bytes.Equal(o, n) || !ed25519.Verify(o, relayM(o, n), so) || !ed25519.Verify(n, relayM(o, n), sn) {
			return false
		}
		if !bytes.Equal(o, cur) {
			return false
		}
		for _, k := range seen {
			if bytes.Equal(k, n) {
				return false
			}
		}
		seen = append(seen, n)
		cur = n
	}
	return bytes.Equal(cur, announced)
}

func rr64(v []byte) string { return base64.StdEncoding.EncodeToString(v) }
