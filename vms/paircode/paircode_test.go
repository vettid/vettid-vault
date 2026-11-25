package paircode

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/suite"
)

func TestNormalize(t *testing.T) {
	for _, c := range []struct {
		in, out string
		err     error
	}{
		{"ABCD-EFGH", "ABCDEFGH", nil},
		{" abcd efgh ", "ABCDEFGH", nil},
		{"23456789", "23456789", nil},
		{"a-b-c-d-e-f-g-h", "ABCDEFGH", nil},
		{"ABCD-EFG0", "", ErrSymbol},
		{"ABCD-EFG1", "", ErrSymbol},
		{"abcdefgi", "", ErrSymbol}, // i upper-cases to I
		{"abcdefgl", "", ErrSymbol},
		{"abcdefgo", "", ErrSymbol},
		{"ABCD_EFG", "", ErrSymbol},
		{"ABCDEFG", "", ErrCode},
		{"ABCDEFGHJ", "", ErrCode},
		{"https://relay.vettid.org", "", ErrCode},
		{"ABCDÉFGH", "", ErrSymbol},       // 8 characters (9 bytes): a code, refused
		{"ABCD-EFG\u017f", "", ErrSymbol}, // ſ, which Go upper-cases to S
		{"ABCD-EFG\u00df", "", ErrSymbol}, // ß
		{"ABCD-EFG\u212a", "", ErrSymbol}, // the Kelvin sign
		{"abcd-efgh", "ABCDEFGH", nil},
		{"ABCDÉFG", "", ErrCode}, // 7 characters
		{"0x7f", "", ErrCode},
	} {
		got, err := Normalize(c.in)
		if string(got) != c.out || !errors.Is(err, c.err) {
			t.Errorf("Normalize(%q) = %q, %v; want %q, %v", c.in, got, err, c.out, c.err)
		}
	}
}

func TestNewCode(t *testing.T) {
	for range 200 {
		c, err := NewCode()
		if err != nil || !ValidCode(c) {
			t.Fatalf("valid %v %v", ValidCode(c), err) // never print a code
		}
	}
	if Display([]byte("ABCDEFGH")) != "ABCD-EFGH" {
		t.Fatal(Display([]byte("ABCDEFGH")))
	}
}

func TestCanonicalRelay(t *testing.T) {
	ok := map[string]string{
		"https://relay.vettid.org":       "https://relay.vettid.org",
		"https://Relay.VettID.org":       "https://relay.vettid.org",
		"HTTPS://relay.vettid.org":       "https://relay.vettid.org",
		"https://relay.vettid.org/":      "https://relay.vettid.org",
		"https://relay.vettid.org:443":   "https://relay.vettid.org",
		"https://relay.example.org:8443": "https://relay.example.org:8443",
		"relay.example.org":              "https://relay.example.org",
		"relay.example.org:8443":         "https://relay.example.org:8443",
		"xn--bcher-kva.example":          "https://xn--bcher-kva.example",
		"localhost:8443":                 "https://localhost:8443",
	}
	for in, want := range ok {
		if got, err := CanonicalRelay(in); err != nil || got != want {
			t.Errorf("CanonicalRelay(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", "http://relay.vettid.org", "ftp://relay.vettid.org", "https://relay.vettid.org/v1",
		"https://relay.vettid.org//", "https://relay.vettid.org?x=1", "https://relay.vettid.org?",
		"https://relay.vettid.org#f", "https://u@relay.vettid.org", "https://u:p@relay.vettid.org",
		"https://192.0.2.1", "https://[2001:db8::1]", "https://[::1]:8443", "192.0.2.1:8443", "https://127.1", "https://relay.1", "https://a.0x10",
		"https://0x7f.1", "https://bücher.example", "https://relay.vettid.org:0", "https://relay.vettid.org:65536",
		"https://relay.vettid.org:0443", "https://relay.vettid.org:", "https://0x", "https://1.0x", "https://0x.0x", "https://relay.0X1F",
		"https://relay.99999999999999999999999", "https://a.0x99999999999999999999ffff", "https://relay..org", "https://-relay.org",
		"https://relay.org.", "https://rel ay.org", "https://relay_x.org", "https://relay.vettid.org/%2f",
	} {
		if got, err := CanonicalRelay(in); err == nil {
			t.Errorf("CanonicalRelay(%q) = %q, want refused", in, got)
		}
	}
}

const testR = "https://relay.example.org"

func entry(epoch int64, b byte) Salt {
	n := bytes.Repeat([]byte{b}, NonceSize)
	return Salt{SaltID: SaltID(SaltR(testR, epoch, n)), Epoch: epoch, Nonce: n}
}

func TestCheckSalts(t *testing.T) {
	const e = 493000
	start := time.Unix(e*Hour, 0)
	mid := start.Add(30 * time.Minute)
	refused := func(name string, list []Salt, now time.Time, seen map[int64][]byte, reason string) {
		t.Helper()
		_, err := CheckSalts(testR, list, now, seen)
		var re *RefusedError
		if !errors.As(err, &re) || re.Reason != reason {
			t.Errorf("%s: %v, want %s", name, err, reason)
		}
	}
	got, err := CheckSalts(testR, []Salt{entry(e, 1)}, mid, nil)
	if err != nil || len(got) != 1 || !bytes.Equal(got[0].SR, SaltR(testR, e, bytes.Repeat([]byte{1}, 16))) {
		t.Fatalf("one entry: %v", err)
	}
	if _, err := CheckSalts(testR, []Salt{entry(e, 1), entry(e+1, 2)}, start.Add(59*time.Minute), nil); err != nil {
		t.Fatalf("two entries near the hour: %v", err)
	}
	refused("none", nil, mid, nil, ReasonCount)
	refused("three", []Salt{entry(e-1, 1), entry(e, 2), entry(e+1, 3)}, mid, nil, ReasonCount)
	short := entry(e, 1)
	short.Nonce = short.Nonce[:15]
	refused("short nonce", []Salt{short}, mid, nil, ReasonNonce)
	refused("one epoch twice", []Salt{entry(e, 1), entry(e, 2)}, mid, nil, ReasonEpochDup)
	bad := entry(e, 1)
	bad.SaltID = "00000000"
	refused("salt_id", []Salt{bad}, mid, nil, ReasonSaltID)
	other := entry(e, 1)
	other.SaltID = SaltID(SaltR("https://relay.example.net", e, other.Nonce))
	refused("another relay's salt", []Salt{other}, mid, nil, ReasonSaltID)
	// The window: from start-120-120 to end+600+120 inclusive.
	lo, hi := start.Add(-240*time.Second), start.Add(time.Hour+720*time.Second)
	for _, now := range []time.Time{lo, hi} {
		if _, err := CheckSalts(testR, []Salt{entry(e, 1)}, now, nil); err != nil {
			t.Errorf("edge %v: %v", now, err)
		}
	}
	refused("before the window", []Salt{entry(e, 1)}, lo.Add(-time.Second), nil, ReasonClock)
	refused("after the window", []Salt{entry(e, 1)}, hi.Add(time.Second), nil, ReasonClock)
	refused("one entry out of two outside", []Salt{entry(e, 1), entry(e+5, 2)}, mid, nil, ReasonClock)
	seen := map[int64][]byte{e: bytes.Repeat([]byte{9}, 16)}
	refused("a seen epoch's nonce changed", []Salt{entry(e, 1)}, mid, seen, ReasonChanged)
	seen[e] = bytes.Repeat([]byte{1}, 16)
	if _, err := CheckSalts(testR, []Salt{entry(e, 1)}, mid, seen); err != nil {
		t.Fatalf("the same nonce again: %v", err)
	}
}

func TestForPut(t *testing.T) {
	const e = 493000
	start := time.Unix(e*Hour, 0)
	both := []Salt{entry(e, 1), entry(e+1, 2)}
	if got := ForPut(both, start.Add(59*time.Minute)); len(got) != 2 || got[0].Epoch != e || got[1].Epoch != e+1 {
		t.Fatalf("before the hour: %+v", got)
	}
	if got := ForPut(both, start.Add(time.Hour+time.Second)); len(got) != 2 || got[0].Epoch != e+1 {
		t.Fatalf("after the hour: %+v", got)
	}
	// The relay has not listed the next hour yet; the vault's clock is 60 s ahead.
	if got := ForPut([]Salt{entry(e, 1)}, start.Add(time.Hour+time.Minute)); len(got) != 1 || got[0].Epoch != e {
		t.Fatalf("within the skew: %+v", got)
	}
	if got := ForPut([]Salt{entry(e, 1)}, start.Add(time.Hour+3*time.Minute)); got != nil {
		t.Fatalf("past the skew: %+v", got)
	}
	// Five minutes past the hour, the previous hour's entry (still listed)
	// is not current within the skew: it is not tried.
	if got := ForPut([]Salt{entry(e-1, 1), entry(e, 2)}, start.Add(5*time.Minute)); len(got) != 1 || got[0].Epoch != e {
		t.Fatalf("the previous hour after the skew: %+v", got)
	}
	// 60 s past the hour, it is.
	if got := ForPut([]Salt{entry(e-1, 1), entry(e, 2)}, start.Add(time.Minute)); len(got) != 2 || got[0].Epoch != e || got[1].Epoch != e-1 {
		t.Fatalf("the previous hour within the skew: %+v", got)
	}
}

func TestPWHoldsZeroBytes(t *testing.T) {
	pw := PW("lookup", PurposeAgent, testR, []byte("ABCDEFGH"))
	want := "vettid/pair-code/1/lookup\x00a\x00" + testR + "\x00ABCDEFGH"
	if string(pw) != want || bytes.Count(pw, []byte{0}) != 3 {
		t.Fatalf("%q", pw)
	}
}

func TestSealOpen(t *testing.T) {
	sc := bytes.Repeat([]byte{3}, SaltSize)
	x, err := X(PurposeAgent, testR, []byte("ABCDEFGH"), sc)
	if err != nil {
		t.Fatal(err)
	}
	kw, err := KW(x)
	if err != nil {
		t.Fatal(err)
	}
	const cid = "abcdefghijklmnopqrstuvwxya"
	bundle := []byte(`{"v":1}`)
	blob, err := Seal(kw, PurposeAgent, testR, cid, sc, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := Open(kw, PurposeAgent, testR, cid, sc, blob); err != nil || !bytes.Equal(pt, bundle) {
		t.Fatalf("open: %v", err)
	}
	sc2 := bytes.Clone(sc)
	sc2[0] ^= 1
	for name, open := range map[string]func() error{
		"another purpose": func() error { _, err := Open(kw, PurposeDesktop, testR, cid, sc, blob); return err },
		"another relay":   func() error { _, err := Open(kw, PurposeAgent, testR+":8443", cid, sc, blob); return err },
		"another claim": func() error {
			_, err := Open(kw, PurposeAgent, testR, "bbcdefghijklmnopqrstuvwxya", sc, blob)
			return err
		},
		"a claim id of another form": func() error { _, err := Open(kw, PurposeAgent, testR, "abc", sc, blob); return err },
		"a non-canonical claim id": func() error {
			_, err := Open(kw, PurposeAgent, testR, "abcdefghijklmnopqrstuvwxyb", sc, blob)
			return err
		},
		"a 15-byte salt":        func() error { _, err := Open(kw, PurposeAgent, testR, cid, sc[:15], blob); return err },
		"a relay not canonical": func() error { _, err := Open(kw, PurposeAgent, testR+"/", cid, sc, blob); return err },
		"another salt":          func() error { _, err := Open(kw, PurposeAgent, testR, cid, sc2, blob); return err },
		"a changed blob": func() error {
			b := bytes.Clone(blob)
			b[len(b)-1] ^= 1
			_, err := Open(kw, PurposeAgent, testR, cid, sc, b)
			return err
		},
		"a short blob":         func() error { _, err := Open(kw, PurposeAgent, testR, cid, sc, blob[:24]); return err },
		"another purpose name": func() error { _, err := Open(kw, "x", testR, cid, sc, blob); return err },
	} {
		if err := open(); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The labels keep the derivations apart: the tag under the same salt
	// is not x.
	tag, err := Tag(PurposeAgent, testR, []byte("ABCDEFGH"), sc)
	if err != nil || bytes.Equal(tag, x) {
		t.Fatal("tag equals x")
	}
	if _, err := Tag(PurposeAgent, testR, []byte("ABCDEFG0"), sc); !errors.Is(err, ErrInput) {
		t.Fatal("a bad code derived")
	}
	if _, err := Tag(PurposeAgent, testR+"/", []byte("ABCDEFGH"), sc); !errors.Is(err, ErrInput) {
		t.Fatal("a relay not canonical derived")
	}
	if _, err := Tag("x", testR, []byte("ABCDEFGH"), sc); !errors.Is(err, ErrPurpose) {
		t.Fatal("a bad purpose derived")
	}
}

func TestClaimIDs(t *testing.T) {
	for range 100 {
		id, err := NewClaimID()
		if err != nil || !ValidClaimID(id) {
			t.Fatalf("%q %v", id, err)
		}
	}
	for _, id := range []string{"", "abcdefghijklmnopqrstuvwxyb", "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYA",
		"abcdefghijklmnopqrstuvwxy1", "abcdefghijklmnopqrstuvwxyaa"} {
		if ValidClaimID(id) {
			t.Errorf("%q accepted", id)
		}
	}
	for _, last := range "aeimquy4" {
		if !ValidClaimID("abcdefghijklmnopqrstuvwxy" + string(last)) {
			t.Errorf("%c refused", last)
		}
	}
}

// Seal refuses inputs the aad would bind ambiguously, before sealing.
func TestSealChecksTheBinding(t *testing.T) {
	kw, sc := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{3}, SaltSize)
	const cid = "abcdefghijklmnopqrstuvwxya"
	if _, err := Seal(kw, PurposeAgent, testR, cid, sc, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	for name, seal := range map[string]func() error{
		"a relay not canonical": func() error { _, err := Seal(kw, PurposeAgent, testR+"/", cid, sc, []byte("{}")); return err },
		"a 15-byte salt":        func() error { _, err := Seal(kw, PurposeAgent, testR, cid, sc[:15], []byte("{}")); return err },
		"a claim id of another form": func() error {
			_, err := Seal(kw, PurposeAgent, testR, "abc\x00", sc, []byte("{}"))
			return err
		},
		"another purpose": func() error { _, err := Seal(kw, "x", testR, cid, sc, []byte("{}")); return err },
	} {
		if err := seal(); !errors.Is(err, ErrInput) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The derivations as the vectors fix them, in a plain build: Tag, X, KW
// and Open against testdata/vectors/pair-code.json (its generator runs
// only under -tags vmsvectors).
func TestKnownAnswers(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/vectors/pair-code.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	str := func(k string) string {
		var s string
		if err := json.Unmarshal(m[k], &s); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		return s
	}
	b64 := func(k string) []byte {
		b, err := base64.StdEncoding.DecodeString(str(k))
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		return b
	}
	hx := func(k string) []byte {
		b, err := hex.DecodeString(str(k))
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		return b
	}
	code, purpose, r, cid := []byte(str("code")), str("purpose"), str("r"), str("claim_id")
	sr, sc := hx("s_r_hex"), b64("s_c_b64")
	tag, err := Tag(purpose, r, code, sr)
	if err != nil || !bytes.Equal(tag, b64("tag_b64")) {
		t.Fatal("tag")
	}
	td, err := Tag(PurposeDesktop, r, code, sr)
	if err != nil || !bytes.Equal(td, b64("tag_desktop_b64")) {
		t.Fatal("the desktop tag")
	}
	x, err := X(purpose, r, code, sc)
	if err != nil || !bytes.Equal(x, hx("x_hex")) {
		t.Fatal("x")
	}
	kw, err := KW(x)
	if err != nil || !bytes.Equal(kw, hx("k_w_hex")) {
		t.Fatal("k_w")
	}
	if !bytes.Equal(AAD(purpose, r, cid, sc), hx("aad_hex")) {
		t.Fatal("aad")
	}
	pt, err := Open(kw, purpose, r, cid, sc, b64("blob_b64"))
	if err != nil || string(pt) != str("bundle_json") {
		t.Fatal("the blob")
	}
}

// Open refuses a binding of another form even when the blob would open
// under it: here one sealed directly under a relay that is not canonical.
func TestOpenChecksTheBinding(t *testing.T) {
	kw, sc := bytes.Repeat([]byte{1}, KeySize), bytes.Repeat([]byte{3}, SaltSize)
	nonce := bytes.Repeat([]byte{9}, suite.XNonceSize)
	for name, c := range map[string]struct{ r, cid string }{
		"a relay not canonical":    {testR + "/", "abcdefghijklmnopqrstuvwxya"},
		"a claim id not canonical": {testR, "abcdefghijklmnopqrstuvwxyb"},
	} {
		ct, err := suite.SealX(kw, nonce, AAD(PurposeAgent, c.r, c.cid, sc), []byte("{}"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Open(kw, PurposeAgent, c.r, c.cid, sc, append(bytes.Clone(nonce), ct...)); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDeriveChecks(t *testing.T) {
	sc := bytes.Repeat([]byte{3}, SaltSize)
	for name, f := range map[string]func() error{
		"tag, a 15-byte salt": func() error { _, err := Tag(PurposeAgent, testR, []byte("ABCDEFGH"), sc[:15]); return err },
		"x, a 17-byte salt": func() error {
			_, err := X(PurposeAgent, testR, []byte("ABCDEFGH"), append(bytes.Clone(sc), 0))
			return err
		},
		"k_w, a short x": func() error { _, err := KW(sc); return err },
		"k_w, no x":      func() error { _, err := KW(nil); return err },
	} {
		if err := f(); !errors.Is(err, ErrInput) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCheckSaltsNegativeEpoch(t *testing.T) {
	n := bytes.Repeat([]byte{1}, NonceSize)
	e := Salt{SaltID: SaltID(SaltR(testR, -1, n)), Epoch: -1, Nonce: n}
	_, err := CheckSalts(testR, []Salt{e}, time.Unix(0, 0), nil)
	var re *RefusedError
	if !errors.As(err, &re) || re.Reason != ReasonClock {
		t.Fatalf("%v", err)
	}
}

// ForPut's other entry, exactly at the ±120 s edges of the hour the two
// share.
func TestForPutEdges(t *testing.T) {
	const e = 493000
	h := int64(Hour)
	for _, c := range []struct {
		at   int64
		list []Salt
		n    int
	}{
		{e*h + 119, []Salt{entry(e-1, 1), entry(e, 2)}, 2},     // hh:01:59
		{e*h + 120, []Salt{entry(e-1, 1), entry(e, 2)}, 1},     // hh:02:00
		{(e+1)*h - 120, []Salt{entry(e, 1), entry(e+1, 2)}, 2}, // hh:58:00
		{(e+1)*h - 121, []Salt{entry(e, 1), entry(e+1, 2)}, 1}, // hh:57:59
		{e*h + 119, []Salt{entry(e-1, 1)}, 1},                  // only the previous hour listed: hh:01:59
		{e*h + 120, []Salt{entry(e-1, 1)}, 0},                  // hh:02:00: none current
	} {
		got := ForPut(c.list, time.Unix(c.at, 0))
		if len(got) != c.n || len(got) > 0 && got[0].Epoch != Epoch(time.Unix(c.at, 0)) && c.n == 2 {
			t.Errorf("at %d: %d entries, first %d", c.at%h, len(got), got[0].Epoch)
		}
	}
}

// The sampling on fixed bytes: 248–255 dropped, the rest mod 31, as
// altchan.CodeFromBytes (ENROLLMENT-CODES §3.1).
func TestAppendSymbols(t *testing.T) {
	r := []byte{248, 255, 0, 30, 31, 247, 1, 2, 3, 4, 5, 6, 7}
	want, _, err := altchan.CodeFromBytes(r)
	if err != nil {
		t.Fatal(err)
	}
	if got := appendSymbols(nil, r); string(got) != want {
		t.Fatalf("%q, want %q", got, want)
	}
	if got := appendSymbols(nil, []byte{248, 249, 250, 251, 252, 253, 254, 255}); len(got) != 0 {
		t.Fatal("a byte of 248 or more was used")
	}
	// Stops at 8 symbols, across calls.
	if got := appendSymbols(appendSymbols(nil, r[:4]), r[4:]); string(got) != want {
		t.Fatalf("%q across calls, want %q", got, want)
	}
}
