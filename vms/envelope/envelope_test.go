package envelope

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/suite"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

const specInner = `{"v":1,"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","type":"test.ping","ts":"2026-10-01T12:00:00.000Z","body":{}}`

func testKey(t testing.TB, b byte) *suite.PrivateKey {
	t.Helper()
	k, err := suite.NewPrivateKey(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func key32(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// §5.2 sizes: header 44 / 1,140, overhead 60 / 1,156; §16 lengths.
func TestLayoutSizes(t *testing.T) {
	if HeaderSession != 44 || HeaderSealed != 1140 || OverheadSession != 60 || OverheadSealed != 1156 {
		t.Fatal("layout constants")
	}
	k := testKey(t, 5)
	padded, err := Pad([]byte(specInner))
	if err != nil || len(padded) != 512 {
		t.Fatalf("padded %d %v", len(padded), err)
	}
	env, _, err := SealSealed(k.Public(), suite.Anonymous, padded)
	if err != nil {
		t.Fatal(err)
	}
	if len(env) != 1668 {
		t.Fatalf("sealed envelope %d, want 1668", len(env))
	}
	senv, err := SealSession(key32(8), suite.Kid{2}, suite.Kid{1}, padded)
	if err != nil {
		t.Fatal(err)
	}
	if len(senv) != 572 {
		t.Fatalf("session envelope %d, want 572", len(senv))
	}
	alt, err := PadFixed([]byte(specInner), AltChannelPadded)
	if err != nil {
		t.Fatal(err)
	}
	aenv, _, err := SealSealed(k.Public(), suite.Anonymous, alt)
	if err != nil || len(aenv) != 5252 {
		t.Fatalf("alt envelope %d, want 5252 (%v)", len(aenv), err)
	}
}

func TestSealedRoundTrip(t *testing.T) {
	k := testKey(t, 5)
	padded, _ := Pad([]byte(specInner))
	raw, sexp, err := SealSealed(k.Public(), suite.Kid{7}, padded)
	if err != nil {
		t.Fatal(err)
	}
	e, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if e.Mode() != ModeSealed || !e.SenderKid().Equal(suite.Kid{7}) || !e.RecipientKid().Equal(k.Public().Kid()) {
		t.Fatal("header fields")
	}
	pt, rexp, err := OpenSealed(e, k)
	if err != nil || !bytes.Equal(pt, padded) {
		t.Fatalf("open: %v", err)
	}
	a, _ := sexp.Export(suite.LabelHsKs, 32)
	b, _ := rexp.Export(suite.LabelHsKs, 32)
	if !bytes.Equal(a, b) {
		t.Fatal("exports differ")
	}
	in, err := DecodeInner(pt, ModeSealed)
	if err != nil || in.Type != "test.ping" {
		t.Fatalf("inner: %v", err)
	}
}

// §5.2: the AAD is the whole header; any header or ciphertext change fails.
func TestAADIsWholeHeader(t *testing.T) {
	k := testKey(t, 5)
	padded, _ := Pad([]byte(specInner))
	raw, _, _ := SealSealed(k.Public(), suite.Anonymous, padded)
	for _, off := range []int{4, 11, 20, 600, 1139, 1140, len(raw) - 1} {
		b := bytes.Clone(raw)
		b[off] ^= 1
		e, err := Parse(b)
		if err != nil {
			continue
		}
		if off >= 12 && off < 20 { // recipient_kid: caught by the kid check
			continue
		}
		if _, _, err := OpenSealed(e, k); err == nil {
			t.Fatalf("sealed: tampered byte %d accepted", off)
		}
	}
	key := key32(8)
	sraw, _ := SealSession(key, suite.Kid{2}, suite.Kid{1}, padded)
	for _, off := range []int{4, 12, 20, 43, 44, len(sraw) - 1} {
		b := bytes.Clone(sraw)
		b[off] ^= 1
		e, err := Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenSession(e, key); err == nil {
			t.Fatalf("session: tampered byte %d accepted", off)
		}
	}
}

// §5.2: flags non-zero MUST be rejected; version, suite and mode strict.
func TestParseStrictHeader(t *testing.T) {
	padded, _ := Pad([]byte(specInner))
	raw, _ := SealSession(key32(8), suite.Kid{2}, suite.Kid{1}, padded)
	mut := func(off int, v byte) []byte { b := bytes.Clone(raw); b[off] = v; return b }
	cases := []struct {
		name string
		b    []byte
		want error
	}{
		{"flags", mut(3, 0x01), ErrFlags},
		{"flags high", mut(3, 0x80), ErrFlags},
		{"version 1", mut(0, 0x01), ErrVersion},
		{"version 3", mut(0, 0x03), ErrVersion},
		{"suite 1", mut(1, 0x01), suite.ErrSuite1},
		{"suite 3", mut(1, 0x03), suite.ErrUnsupportedSuite},
		{"suite 0", mut(1, 0x00), suite.ErrUnsupportedSuite},
		{"mode 0", mut(2, 0x00), ErrMode},
		{"mode 3", mut(2, 0x03), ErrMode},
		{"sealed mode on session bytes", mut(2, 0x02), ErrTruncated},
		{"truncated", raw[:19], ErrTruncated},
		{"empty", nil, ErrTruncated},
		{"one byte short", raw[:len(raw)-1], ErrTruncated},
		{"not a bucket", append(bytes.Clone(raw), make([]byte, 100)...), ErrLength},
		{"one byte long", append(bytes.Clone(raw), 0), ErrLength},
	}
	for _, c := range cases {
		if _, err := Parse(c.b); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	if _, err := Parse(raw); err != nil {
		t.Fatal(err)
	}
}

// §5.5: nothing larger than MaxPadded (+ overhead) parses; the largest
// sealed envelope fits the relay default.
func TestSizeLimits(t *testing.T) {
	if MaxPadded+OverheadSealed > DefaultMaxPayload {
		t.Fatal("max envelope exceeds relay default")
	}
	if _, err := PaddedLen(MaxPadded - 1); err != nil {
		t.Fatal("largest JSON rejected")
	}
	if _, err := PaddedLen(MaxPadded); !errors.Is(err, ErrTooLarge) {
		t.Fatal("JSON at MaxPadded accepted (no room for 0x80)")
	}
	big := make([]byte, HeaderSession+MaxPadded+SmallBucketLimit+suite.TagSize)
	big[0], big[1], big[2] = 2, 2, 1
	if _, err := Parse(big); !errors.Is(err, ErrLength) {
		t.Fatalf("oversized: %v", err)
	}
	if DecideBlob(10, 100) != Inline || DecideBlob(BlobThreshold+1, BlobThreshold+200) != BlobRecommended ||
		DecideBlob(MaxPadded, MaxPadded+10) != BlobRequired {
		t.Fatal("DecideBlob")
	}
}

// §5.4 buckets.
func TestPaddingBuckets(t *testing.T) {
	cases := map[int]int{0: 512, 511: 512, 512: 1024, 16383: 16384, 16384: 32768, 32767: 32768, 32768: 49152, 245759: 245760}
	for n, want := range cases {
		got, err := PaddedLen(n)
		if err != nil || got != want {
			t.Errorf("PaddedLen(%d) = %d, %v; want %d", n, got, err, want)
		}
	}
	for _, p := range []int{512, 1024, 16384, 32768, 245760} {
		if !ValidPaddedLen(p) {
			t.Errorf("%d invalid", p)
		}
	}
	for _, p := range []int{0, 511, 513, 16896, 245761, 262144} {
		if ValidPaddedLen(p) {
			t.Errorf("%d valid", p)
		}
	}
}

// §5.4: receivers MUST reject malformed padding.
func TestMustRejectMalformedPadding(t *testing.T) {
	good, _ := Pad([]byte(specInner))
	if j, err := Unpad(good); err != nil || string(j) != specInner {
		t.Fatal("good padding rejected")
	}
	bad := map[string][]byte{}
	b := bytes.Clone(good)
	b[len(specInner)] = 0x81
	bad["wrong marker"] = b
	b = bytes.Clone(good)
	b[len(b)-1] = 1
	bad["non-zero after marker"] = b
	bad["all zero"] = make([]byte, 512)
	bad["no marker, full"] = bytes.Repeat([]byte{'a'}, 512)
	b = bytes.Clone(good)
	b[len(specInner)] = 0
	bad["marker missing"] = b
	bad["not a bucket size"] = good[:511]
	// Over-padding: the JSON would fit in 512, padded to 1024.
	over, _ := PadFixed([]byte(specInner), 1024)
	bad["over-padded"] = over
	for name, p := range bad {
		if _, err := Unpad(p); !errors.Is(err, ErrPadding) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// Fixed padding is exact.
	alt, _ := PadFixed([]byte(specInner), AltChannelPadded)
	if _, err := UnpadFixed(alt, AltChannelPadded); err != nil {
		t.Fatal(err)
	}
	if _, err := UnpadFixed(good, AltChannelPadded); !errors.Is(err, ErrPadding) {
		t.Fatal("wrong fixed size accepted")
	}
}

// §5.3: retransmission reuses the inner id in a new envelope.
func TestRetransmissionNewEnvelopeSameID(t *testing.T) {
	in := &Inner{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Type: "message.send", TS: t0, Seq: 1}
	p1, _ := EncodeInner(in, ModeSession)
	a, _ := SealSession(key32(8), suite.Kid{2}, suite.Kid{1}, p1)
	b, _ := SealSession(key32(8), suite.Kid{2}, suite.Kid{1}, p1)
	if bytes.Equal(a, b) {
		t.Fatal("two envelopes identical (nonce reuse)")
	}
	for _, raw := range [][]byte{a, b} {
		e, _ := Parse(raw)
		pt, err := OpenSession(e, key32(8))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := DecodeInner(pt, ModeSession)
		if got.ID != in.ID {
			t.Fatal("id changed")
		}
	}
}

// §4.2: a fresh random 192-bit nonce per session message.
func TestSessionNonceFreshAndRandom(t *testing.T) {
	padded, _ := Pad([]byte(specInner))
	seen := map[string]bool{}
	for range 64 {
		raw, _ := SealSession(key32(8), suite.Kid{2}, suite.Kid{1}, padded)
		n := string(raw[20:44])
		if seen[n] || n == string(make([]byte, 24)) {
			t.Fatal("nonce repeated")
		}
		seen[n] = true
	}
}

func TestOpenSealedKidMustMatchKey(t *testing.T) {
	k, other := testKey(t, 5), testKey(t, 6)
	padded, _ := Pad([]byte(specInner))
	raw, _, _ := SealSealed(k.Public(), suite.Anonymous, padded)
	e, _ := Parse(raw)
	if _, _, err := OpenSealed(e, other); !errors.Is(err, ErrKid) {
		t.Fatalf("err = %v", err)
	}
	se, _ := Parse(mustSession(t, padded))
	if _, _, err := OpenSealed(se, k); !errors.Is(err, ErrWrongMode) {
		t.Fatal("session envelope opened as sealed")
	}
	if _, err := OpenSession(e, key32(8)); !errors.Is(err, ErrWrongMode) {
		t.Fatal("sealed envelope opened as session")
	}
}

func mustSession(t *testing.T, padded []byte) []byte {
	raw, err := SealSession(key32(8), suite.Kid{2}, suite.Kid{1}, padded)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// §4.3: implementations MUST NOT reuse a context for a second message.
func TestMustNotReuseHPKEContext(t *testing.T) {
	k := testKey(t, 5)
	s, err := NewSealer(k.Public(), suite.Anonymous)
	if err != nil {
		t.Fatal(err)
	}
	padded, _ := Pad([]byte(specInner))
	if _, err := s.Seal(padded); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Seal(padded); !errors.Is(err, suite.ErrContextUsed) {
		t.Fatalf("second Seal: %v", err)
	}
}

func TestBlobRoundTrip(t *testing.T) {
	content := []byte(strings.Repeat("x", 100000))
	blob, key, sum, err := SealBlob(content)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenBlob(blob, key, sum)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatal("blob round trip")
	}
	blob[30] ^= 1
	if _, err := OpenBlob(blob, key, sum); err == nil {
		t.Fatal("tampered blob accepted")
	}
}

func TestULID(t *testing.T) {
	id, err := NewULID(t0)
	if err != nil || !ValidULID(id) {
		t.Fatalf("NewULID %q %v", id, err)
	}
	if encodeULID([16]byte{}) != "00000000000000000000000000" {
		t.Fatal("zero ULID")
	}
	var ff [16]byte
	for i := range ff {
		ff[i] = 0xff
	}
	if encodeULID(ff) != "7ZZZZZZZZZZZZZZZZZZZZZZZZZ" {
		t.Fatalf("max ULID %s", encodeULID(ff))
	}
	for _, s := range []string{"", "8ZZZZZZZZZZZZZZZZZZZZZZZZZ", "01jb2z6v9k3m4n5p6q7r8s9t0v", "01JB2Z6V9K3M4N5P6Q7R8S9T0U", "01JB2Z6V9K3M4N5P6Q7R8S9T0"} {
		if ValidULID(s) {
			t.Errorf("%q valid", s)
		}
	}
}
