package strictjson

import (
	"bytes"
	"testing"
)

// OptBase64Bytes accepts and refuses exactly what Base64 does, escaped
// spellings included, without a Go string of the text.
func TestOptBase64BytesAgreesWithBase64(t *testing.T) {
	esc := "\\" + "u" // a JSON unicode escape, kept out of this file's own text
	for _, c := range []struct {
		json string
		n    int
	}{
		{`{"k":"AAEC"}`, 3},
		{`{"k":"AAEC"}`, -1},
		{`{"k":"AAEC"}`, 4},                             // wrong length
		{`{"k":"AAE="}`, 2},                             // padded
		{`{"k":"AAF="}`, 2},                             // non-canonical trailing bits
		{`{"k":"AAE"}`, -1},                             // unpadded
		{`{"k":"AA\nEC"}`, -1},                          // an escaped line break
		{`{"k":"AA\\nEC"}`, -1},                         // an escaped backslash, then n
		{`{"k":"` + esc + `0041AEC"}`, 3},               // an escaped A
		{`{"k":"` + esc + `00e9AEC"}`, -1},              // an escaped non-ASCII character
		{`{"k":"AA` + esc + `000aEC"}`, -1},             // an escaped line break, spelled with u
		{`{"k":"` + esc + `002f` + esc + `002f8="}`, 2}, // slashes, spelled with u
		{`{"k":"+\/8="}`, 2},                            // an escaped slash
		{`{"k":""}`, 0},                                 // empty
		{`{"k":1}`, -1},                                 // not a string
		{`{"k":"A\\"}`, -1},                             // an escaped backslash
	} {
		o, err := ParseObject([]byte(c.json))
		if err != nil {
			t.Fatalf("%s: not JSON: %v", c.json, err)
		}
		want, wantErr := o.Base64("k", c.n)
		got, present, err := o.OptBase64Bytes("k", c.n)
		if !present {
			t.Fatalf("%s: not present", c.json)
		}
		if (err == nil) != (wantErr == nil) || !bytes.Equal(got, want) {
			t.Fatalf("%s n=%d: got %x, %v; Base64 gives %x, %v", c.json, c.n, got, err, want, wantErr)
		}
	}
	o, _ := ParseObject([]byte(`{}`))
	if b, present, err := o.OptBase64Bytes("k", -1); b != nil || present || err != nil {
		t.Fatal("an absent member read as present")
	}
}
