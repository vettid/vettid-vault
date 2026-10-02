package cbor

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func h(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// RFC 8949 Appendix A examples within the supported subset.
func TestDecodeRFCExamples(t *testing.T) {
	for _, tc := range []struct {
		in   string
		kind Kind
		u    uint64
	}{
		{"00", KindUint, 0}, {"17", KindUint, 23}, {"1818", KindUint, 24},
		{"1903e8", KindUint, 1000}, {"1b000000e8d4a51000", KindUint, 1000000000000},
		{"20", KindNeg, 0}, {"3863", KindNeg, 99}, {"f4", KindBool, 0}, {"f6", KindNull, 0},
		{"c11a514b67b0", KindTag, 1},
	} {
		v, err := Decode(h(tc.in))
		if err != nil || v.Kind != tc.kind || (tc.kind != KindBool && tc.kind != KindNull && v.Uint != tc.u) {
			t.Errorf("%s: %+v %v", tc.in, v, err)
		}
	}
	v, err := Decode(h("a26161016162820203")) // {"a": 1, "b": [2, 3]}
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := v.UintAt("a"); n != 1 {
		t.Fatal("a")
	}
	b, _ := v.Lookup("b")
	if len(b.Array) != 2 || b.Array[1].Uint != 3 {
		t.Fatal("b")
	}
	v, err = Decode(h("a201020304")) // {1: 2, 3: 4}
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := v.LookupInt(3); !ok || e.Uint != 4 {
		t.Fatal("int key")
	}
}

func TestDecodeRejects(t *testing.T) {
	for name, in := range map[string]string{
		"indefinite bytes":  "5f42010243030405ff",
		"indefinite array":  "9f018202039f0405ffff",
		"indefinite map":    "bf6346756ef563416d7421ff",
		"float":             "f93c00",
		"double":            "fb3ff199999999999a",
		"undefined":         "f7",
		"simple 16":         "f0",
		"simple two-byte":   "f818",
		"false two-byte":    "f814",
		"null two-byte":     "f816",
		"reserved ai":       "1c",
		"duplicate key":     "a2616101616102",
		"duplicate int key": "a201020103",
		"bad utf8":          "62c328",
		"trailing":          "0000",
		"truncated":         "1a0000",
		"truncated string":  "45010203",
		"array too long":    "9a00ffffff",
		"map too long":      "ba00ffffff00",
		"array key":         "a1800001",
		"empty":             "",
	} {
		if _, err := Decode(h(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	deep := bytes.Repeat([]byte{0x81}, MaxDepth+2)
	deep = append(deep, 0)
	if _, err := Decode(deep); !errors.Is(err, ErrDepth) {
		t.Errorf("deep: %v", err)
	}
}

func TestEncodeRoundTrip(t *testing.T) {
	var e Encoder
	e.Map(4).Text("a").Int(-500).Text("b").ByteString([]byte{1, 2}).
		Int(1).Array(2).Bool(true).Null().Text("c").Tag(18).Uint(1 << 40)
	v, err := Decode(e.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := v.Lookup("a"); a.Kind != KindNeg || a.Uint != 499 {
		t.Fatal("neg")
	}
	if b, _ := v.BytesAt("b"); !bytes.Equal(b, []byte{1, 2}) {
		t.Fatal("bytes")
	}
	c, _ := v.Lookup("c")
	if c.Kind != KindTag || c.Uint != 18 || c.Tag.Uint != 1<<40 {
		t.Fatal("tag")
	}
	if !bytes.Equal(v.Raw, e.Bytes()) {
		t.Fatal("raw")
	}
}

func FuzzDecode(f *testing.F) {
	for _, s := range []string{"a26161016162820203", "c11a514b67b0", "84a10126a0f6f6", "9f0000ff"} {
		f.Add(h(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := Decode(b)
		if err != nil {
			return
		}
		if !bytes.Equal(v.Raw, b) {
			t.Fatal("raw differs from input")
		}
	})
}
