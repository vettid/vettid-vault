package strictjson

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Base64 writes the standard encoding straight into the buffer: the same
// member as through a string, and with room reserved it never grows.
func TestBuilderBase64(t *testing.T) {
	for n := 0; n <= 130; n++ {
		v := []byte(strings.Repeat("\xa5", n))
		want := `{"k":"` + base64.StdEncoding.EncodeToString(v) + `","x":1}`
		if got := string(NewBuilder().Base64("k", v).Uint("x", 1).Bytes()); got != want {
			t.Fatalf("%d bytes: %s, want %s", n, got, want)
		}
		b := NewBuilder().Grow(MemberSize("k", Base64Size(v)) + 2)
		c := b.Cap()
		b.Base64("k", v)
		if b.Cap() != c {
			t.Fatalf("%d bytes: grew within its reserve", n)
		}
	}
}

// StringSize bounds MarshalString's output for the strings that expand
// most: control bytes (as \u00XX), invalid UTF-8 (each byte a U+FFFD
// escape), U+2028 and U+2029, quotes and backslashes.
func TestStringSizeBounds(t *testing.T) {
	cases := []string{"", "a", "\x00\x01\x1f", "\xff\xfe\x80", string([]byte{0xe2, 0x80, 0xa8, 0xe2, 0x80, 0xa9}), `"\`,
		strings.Repeat("\x01", 300), strings.Repeat("\xff", 300), strings.Repeat(`"`, 300), "<>&"}
	for b := 0; b < 256; b++ {
		cases = append(cases, string([]byte{byte(b)}), string([]byte{byte(b), byte(b)}))
	}
	for _, s := range cases {
		if n := len(MarshalString(s)); n > StringSize(s) {
			t.Errorf("%q: %d bytes, bound %d", s, n, StringSize(s))
		}
	}
}
