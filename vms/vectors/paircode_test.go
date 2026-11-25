package vectors

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/vettid/vettid-vault/vms/paircode"
)

// checkPairCodeVectors checks pair-code.json (0.94.1 §6.7.2) as a desktop
// or an agent would: s_r, salt_id, pw, tag, x, k_w, the aad and the
// opened blob recomputed from the spec's formulas with plain SHA-256,
// Argon2id, HKDF and XChaCha20-Poly1305 (no paircode code), then the
// normalization, relay forms and salt lists through the library, each
// against the file's verdict.
func checkPairCodeVectors(t *testing.T, dir string) {
	d := load(t, dir, "pair-code.json")
	code, purpose, r, cid := d.str("code"), d.str("purpose"), d.str("r"), d.str("claim_id")
	epoch := int64(d.num("epoch"))
	nonce, sc := d.b64("nonce_b64"), d.b64("s_c_b64")
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, []byte{0}) }

	var e [8]byte
	binary.BigEndian.PutUint64(e[:], uint64(epoch))
	h := sha256.Sum256(cat([]byte("vettid/pair-code/1/salt"), []byte(r), e[:], nonce))
	sr := h[:16]
	if hex.EncodeToString(sr) != d.str("s_r_hex") || hex.EncodeToString(sr[:4]) != d.str("salt_id") {
		t.Fatal("s_r / salt_id")
	}
	pw := func(l, p string) []byte {
		return cat([]byte("vettid/pair-code/1/"+l), []byte(p), []byte(r), []byte(code))
	}
	if !bytes.Equal(pw("lookup", purpose), d.hex("pw_lookup_hex")) || !bytes.Equal(pw("key", purpose), d.hex("pw_key_hex")) {
		t.Fatal("pw")
	}
	if bytes.Count(d.hex("pw_lookup_hex"), []byte{0}) != 3 {
		t.Fatal("pw has its three 0x00 bytes")
	}
	kdf := func(p, s []byte) []byte { return argon2.IDKey(p, s, 3, 256*1024, 1, 32) }
	if base64.StdEncoding.EncodeToString(kdf(pw("lookup", purpose), sr)) != d.str("tag_b64") {
		t.Fatal("tag")
	}
	if base64.StdEncoding.EncodeToString(kdf(pw("lookup", "d"), sr)) != d.str("tag_desktop_b64") {
		t.Fatal("the desktop tag")
	}
	x := kdf(pw("key", purpose), sc)
	if hex.EncodeToString(x) != d.str("x_hex") {
		t.Fatal("x")
	}
	kw := make([]byte, 32)
	if _, err := hkdf.New(sha256.New, x, nil, []byte("vettid/pair-code/1/key")).Read(kw); err != nil || hex.EncodeToString(kw) != d.str("k_w_hex") {
		t.Fatal("k_w")
	}
	aad := func(p, rr, c string, s []byte) []byte {
		return cat([]byte("vettid/pair-code/1/bundle"), []byte(p), []byte(rr), []byte(c), s)
	}
	if !bytes.Equal(aad(purpose, r, cid, sc), d.hex("aad_hex")) {
		t.Fatal("aad")
	}
	blob := d.b64("blob_b64")
	if !bytes.Equal(blob[:24], d.b64("blob_nonce_b64")) {
		t.Fatal("the blob's nonce")
	}
	a, err := chacha20poly1305.NewX(kw)
	if err != nil {
		t.Fatal(err)
	}
	open := func(p, rr, c string, s []byte) ([]byte, error) {
		return a.Open(nil, blob[:24], blob[24:], aad(p, rr, c, s))
	}
	pt, err := open(purpose, r, cid, sc)
	if err != nil || string(pt) != d.str("bundle_json") {
		t.Fatalf("the blob does not open to the bundle: %v", err)
	}
	var bundle map[string]any
	if json.Unmarshal(pt, &bundle) != nil || bundle["kind"] != "agent" || bundle["remote"] != false {
		t.Fatalf("bundle: %s", pt)
	}
	if _, has := bundle["hint"]; has {
		t.Fatal("a code bundle has no hint")
	}
	put := d.sub("put_body")
	if put.str("salt_id") != d.str("salt_id") || put.str("tag") != d.str("tag_b64") || put.str("salt") != d.str("s_c_b64") || put.str("blob") != d.str("blob_b64") {
		t.Fatal("put_body")
	}

	created, err := time.Parse(time.RFC3339, d.str("created"))
	if err != nil {
		t.Fatal(err)
	}
	if es, ok := bundle["exp"].(string); !ok || func() bool {
		e, err := time.Parse(time.RFC3339, es)
		return err != nil || e.Unix() != created.Unix()+600
	}() {
		t.Fatalf("exp %v, created %s: exp = created + 600", bundle["exp"], created)
	}

	var notOpen []map[string]string
	if json.Unmarshal(d.m["not_open"], &notOpen) != nil || len(notOpen) != 6 {
		t.Fatal("not_open")
	}
	for _, n := range notOpen {
		p, rr, c, s, k, bl := purpose, r, cid, sc, kw, blob
		for key, v := range n {
			switch key {
			case "purpose":
				p = v
			case "r":
				rr = v
			case "claim_id":
				c = v
			case "salt_b64":
				s, _ = base64.StdEncoding.DecodeString(v)
			case "blob_b64":
				bl, _ = base64.StdEncoding.DecodeString(v)
			}
		}
		if other, ok := n["code"]; ok {
			xx := kdf(cat([]byte("vettid/pair-code/1/key"), []byte(p), []byte(rr), []byte(other)), s)
			k = make([]byte, 32)
			if _, err := hkdf.New(sha256.New, xx, nil, []byte("vettid/pair-code/1/key")).Read(k); err != nil {
				t.Fatal(err)
			}
		}
		ak, err := chacha20poly1305.NewX(k)
		if err != nil {
			t.Fatal(err)
		}
		if len(bl) > 24 {
			if _, err := ak.Open(nil, bl[:24], bl[24:], aad(p, rr, c, s)); err == nil {
				t.Fatalf("%s: opened", n["name"])
			}
		}
	}

	// The desktop purpose's blob, and a relay with a port.
	dk := d.sub("desktop")
	xd := kdf(pw("key", "d"), sc)
	kd := make([]byte, 32)
	if _, err := hkdf.New(sha256.New, xd, nil, []byte("vettid/pair-code/1/key")).Read(kd); err != nil || hex.EncodeToString(xd) != dk.str("x_hex") || hex.EncodeToString(kd) != dk.str("k_w_hex") {
		t.Fatal("the desktop x / k_w")
	}
	if !bytes.Equal(aad("d", r, cid, sc), dk.hex("aad_hex")) {
		t.Fatal("the desktop aad")
	}
	adk, _ := chacha20poly1305.NewX(kd)
	bd := dk.b64("blob_b64")
	if pt, err := adk.Open(nil, bd[:24], bd[24:], aad("d", r, cid, sc)); err != nil || string(pt) != dk.str("bundle_json") || !strings.Contains(string(pt), `"kind":"desktop"`) {
		t.Fatal("the desktop blob")
	}
	wp := d.sub("with_port")
	rp := wp.str("r")
	hp := sha256.Sum256(cat([]byte("vettid/pair-code/1/salt"), []byte(rp), e[:], nonce))
	if hex.EncodeToString(hp[:16]) != wp.str("s_r_hex") || hex.EncodeToString(hp[:4]) != wp.str("salt_id") {
		t.Fatal("with_port s_r")
	}
	pwp := cat([]byte("vettid/pair-code/1/lookup"), []byte(purpose), []byte(rp), []byte(code))
	if !bytes.Equal(pwp, wp.hex("pw_lookup_hex")) || base64.StdEncoding.EncodeToString(kdf(pwp, hp[:16])) != wp.str("tag_b64") {
		t.Fatal("with_port tag")
	}

	var norm []map[string]string
	if json.Unmarshal(d.m["normalize"], &norm) != nil || len(norm) == 0 {
		t.Fatal("normalize")
	}
	for _, c := range norm {
		got, err := paircode.Normalize(c["input"])
		want := map[string]error{"": nil, "bad_symbol": paircode.ErrSymbol, "not_a_code": paircode.ErrCode}[c["error"]]
		if string(got) != c["code"] || !errors.Is(err, want) {
			t.Errorf("normalize %q: %q %v", c["input"], got, err)
		}
	}
	// The removed set: every code point listed, and no other (the device's
	// own table must equal it).
	var removed []string
	if json.Unmarshal(d.m["removed"], &removed) != nil || len(removed) != len(paircode.Removed) {
		t.Fatalf("removed: %d listed, %d in the rule", len(removed), len(paircode.Removed))
	}
	prev := rune(-1)
	for _, u := range removed {
		var c rune
		if _, err := fmt.Sscanf(u, "U+%X", &c); err != nil || c <= prev {
			t.Fatalf("removed %s: not a code point in ascending order", u)
		}
		prev = c
		// The rule removes it: inside a code it leaves the code.
		if got, err := paircode.Normalize("K7QM" + string(c) + "4XPZ"); err != nil || string(got) != "K7QM4XPZ" {
			t.Errorf("removed %s: not removed (%q %v)", u, got, err)
		}
	}
	if unicode.Version == "15.0.0" {
		// The set from Unicode 15.0's own tables, not from the rule's.
		others := map[rune]bool{0x09: true, 0x0A: true, 0x0D: true, 0x2212: true, 0xAD: true, 0x200B: true, 0x200E: true,
			0x200F: true, 0x2060: true, 0xFEFF: true}
		n := 0
		for c := rune(0); c <= unicode.MaxRune; c++ {
			if unicode.Is(unicode.Zs, c) || unicode.Is(unicode.Pd, c) || others[c] {
				n++
			}
		}
		if n != len(removed) {
			t.Fatalf("removed lists %d, Unicode 15.0 gives %d", len(removed), n)
		}
	}
	var forms []map[string]any
	if json.Unmarshal(d.m["relay_forms"], &forms) != nil || len(forms) == 0 {
		t.Fatal("relay_forms")
	}
	for _, f := range forms {
		got, err := paircode.CanonicalRelay(f["input"].(string))
		if want, ok := f["r"].(string); ok && (err != nil || got != want) || !ok && err == nil {
			t.Errorf("relay %q: %q %v", f["input"], got, err)
		}
	}

	var fps []struct {
		Name  string `json:"name"`
		Salts []struct {
			SaltID string `json:"salt_id"`
			Epoch  int64  `json:"epoch"`
			Nonce  []byte `json:"nonce"`
		} `json:"salts"`
		Now    time.Time `json:"now"`
		Epochs []int64   `json:"epochs"`
	}
	if err := json.Unmarshal(d.m["for_put"], &fps); err != nil || len(fps) == 0 {
		t.Fatalf("for_put: %v", err)
	}
	for _, f := range fps {
		var in []paircode.Salt
		for _, s := range f.Salts {
			in = append(in, paircode.Salt{SaltID: s.SaltID, Epoch: s.Epoch, Nonce: s.Nonce})
		}
		checked, err := paircode.CheckSalts(r, in, f.Now, nil)
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		var got []int64
		for _, e := range paircode.ForPut(checked, f.Now) {
			got = append(got, e.Epoch)
		}
		if !slices.Equal(got, f.Epochs) {
			t.Errorf("for_put %s: %v, want %v", f.Name, got, f.Epochs)
		}
	}

	var lists []struct {
		Name  string `json:"name"`
		Salts []struct {
			SaltID string `json:"salt_id"`
			Epoch  int64  `json:"epoch"`
			Nonce  []byte `json:"nonce"`
		} `json:"salts"`
		Now  time.Time `json:"now"`
		Seen []struct {
			Epoch int64  `json:"epoch"`
			Nonce []byte `json:"nonce"`
		} `json:"seen"`
		Valid  bool   `json:"valid"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(d.m["salt_lists"], &lists); err != nil || len(lists) == 0 {
		t.Fatalf("salt_lists: %v", err)
	}
	for _, l := range lists {
		var in []paircode.Salt
		for _, s := range l.Salts {
			in = append(in, paircode.Salt{SaltID: s.SaltID, Epoch: s.Epoch, Nonce: s.Nonce})
		}
		seen := map[int64][]byte{}
		for _, s := range l.Seen {
			seen[s.Epoch] = s.Nonce
		}
		_, err := paircode.CheckSalts(r, in, l.Now, seen)
		var re *paircode.RefusedError
		switch {
		case l.Valid && err != nil:
			t.Errorf("%s: refused: %v", l.Name, err)
		case !l.Valid && (!errors.As(err, &re) || re.Reason != l.Reason):
			t.Errorf("%s: %v, want %s", l.Name, err, l.Reason)
		}
	}
}
