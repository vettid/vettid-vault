package vectors

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
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
			form := false
			if txt, ok := c.m["relay_links_json"]; ok {
				// a form case: the exact array text, as a string
				var s string
				if json.Unmarshal(txt, &s) != nil || json.Unmarshal([]byte(s), &raws) != nil {
					t.Fatal("relay_links_json")
				}
				form = true
			} else if json.Unmarshal(c.m["relay_links"], &raws) != nil {
				t.Fatal("relay_links")
			}
			if json.Unmarshal(c.m["signed_bytes_hex"], &signed) != nil || len(raws) != len(signed) {
				t.Fatal("signed_bytes_hex")
			}
			var valid bool
			if json.Unmarshal(c.m["valid"], &valid) != nil {
				t.Fatal("valid")
			}
			first, announced := c.b64("first_b64"), c.b64("announced_b64")
			for i, raw := range raws {
				if form {
					break // the form is malformed on purpose: the listed bytes are the well-formed link's
				}
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
			if form {
				var refusal, text string
				_ = json.Unmarshal(c.m["refusal"], &refusal)
				_ = json.Unmarshal(c.m["relay_links_json"], &text)
				if got := plainFormRefusal(raws); got != refusal {
					t.Fatalf("the independent check classes it %q, the vector %q", got, refusal)
				}
				if got := vmsFormRefusal(t, text, announced); got != refusal {
					t.Fatalf("vms classes it %q, the vector %q", got, refusal)
				}
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
// links, each a JSON object with no member twice, v and suite exactly the
// numbers 1 and 2, keys and signatures canonical standard base64 of 32 and
// 64 bytes, old != new, and both Ed25519 signatures over m; contiguous; no
// key twice; from first to announced. Its JSON checks cover the forms the
// vectors exercise; it is not a complete strict JSON parser (the vms
// parser, judged next to it, is).
func plainRelayVerdict(raws []json.RawMessage, first, announced []byte) bool {
	if len(raws) < 1 || len(raws) > 32 {
		return false
	}
	cur := first
	seen := [][]byte{first}
	for _, raw := range raws {
		var l struct{ Old, New string }
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil || hasDuplicateMember(raw) {
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
		o, ok1 := canonicalB64(l.Old, 32)
		n, ok2 := canonicalB64(l.New, 32)
		so, ok3 := canonicalB64(s.SigOld, 64)
		sn, ok4 := canonicalB64(s.SigNew, 64)
		if !ok1 || !ok2 || !ok3 || !ok4 {
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

// plainFormRefusal classes a form case without vms code: a member named
// twice fails the strict parse of the whole message (§10.1), "malformed";
// anything else refuses the link, "relay_unlinked".
func plainFormRefusal(raws []json.RawMessage) string {
	for _, raw := range raws {
		if hasDuplicateMember(raw) {
			return "malformed"
		}
	}
	return "relay_unlinked"
}

// vmsFormRefusal splices the exact relay_links text into a well-formed
// relay.address.update body and classes vms's refusal: ErrRelayLink inside
// the error is "relay_unlinked", the body's error alone "malformed".
func vmsFormRefusal(t *testing.T, text string, pk []byte) string {
	t.Helper()
	body := `{"relay":{"url":"https://relay.example.org","mailbox":"` + handshake.MailboxID(pk) + `","pk":"` + rr64(pk) +
		`"},"token":"v4.public.dGVzdA","relay_links":` + text + `}`
	_, err := peerwire.ParseAddressUpdate([]byte(body))
	switch {
	case err == nil:
		t.Fatal("vms accepted the form case")
	case errors.Is(err, handshake.ErrRelayLink):
		return "relay_unlinked"
	case !errors.Is(err, peerwire.ErrRelayBody):
		t.Fatalf("vms refused it with %v", err)
	}
	return "malformed"
}

// canonicalB64 decodes standard base64 with padding and zero padding bits
// (re-encoding gives the same text) of exactly n bytes.
func canonicalB64(s string, n int) ([]byte, bool) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != n || base64.StdEncoding.EncodeToString(b) != s {
		return nil, false
	}
	return b, true
}

// hasDuplicateMember reports whether the top-level JSON object raw names a
// member twice (encoding/json keeps the last one silently).
func hasDuplicateMember(raw []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return true
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return true
		}
		k, _ := t.(string)
		if seen[k] {
			return true
		}
		seen[k] = true
		var skip json.RawMessage
		if dec.Decode(&skip) != nil {
			return true
		}
	}
	return false
}
