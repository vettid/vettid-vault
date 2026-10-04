package der

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func h(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestHighTag(t *testing.T) {
	// [709] EXPLICIT { OCTET STRING 01 02 }: context, constructed, 709 = 0x05 0x45.
	b := h("bf8545" + "04" + "0402" + "0102")
	e, err := NewReader(b).Next()
	if err != nil {
		t.Fatal(err)
	}
	if !e.Is(ClassContext, 709) || !e.Constructed {
		t.Fatalf("%+v", e.Tag)
	}
	r, err := e.Children()
	if err != nil {
		t.Fatal(err)
	}
	in, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	o, err := OctetString(in)
	if err != nil || !bytes.Equal(o, []byte{1, 2}) {
		t.Fatal("octets")
	}
}

func TestRejects(t *testing.T) {
	for name, in := range map[string]string{
		"non-minimal long length": "04810100",
		"leading zero length":     "0482000100",
		"indefinite in DER":       "30800000",
		"truncated":               "0405010203",
		"high tag below 31":       "9f1e00",
		"high tag leading 0x80":   "9f800100",
		"length overflow":         "0485ffffffffff",
	} {
		r := NewReader(h(in))
		if _, err := r.Next(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for name, in := range map[string]string{
		"int non-minimal":     "02020001",
		"int non-minimal neg": "0202ff80",
		"int empty":           "0200",
	} {
		e, err := NewReader(h(in)).Next()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Int(e); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	e, _ := NewReader(h("010101")).Next()
	if _, err := Bool(e); err == nil {
		t.Error("BER boolean accepted")
	}
}

// SEQUENCE and SET are always constructed: a primitive encoding is a
// syntax error in both readers, at any depth.
func TestPrimitiveConstructed(t *testing.T) {
	for _, in := range []string{"1000", "1100", "1003020101", "1101ff", "3003" + "110100", "a103" + "100100"} {
		for _, r := range []*Reader{NewReader(h(in)), NewBERReader(h(in))} {
			e, err := r.Next()
			if err != nil {
				continue
			}
			c, err := e.Children()
			if err != nil {
				t.Fatalf("%s: %v", in, err)
			}
			if _, err := c.Next(); err == nil {
				t.Errorf("%s accepted", in)
			}
		}
	}
	for _, in := range []string{"1000", "1100"} {
		if _, err := NewReader(h(in)).Next(); err != ErrSyntax {
			t.Errorf("%s: %v", in, err)
		}
	}
	// A primitive [16] or [17] in another class is not a SEQUENCE or SET.
	if _, err := NewReader(h("9000")).Next(); err != nil {
		t.Errorf("context [16]: %v", err)
	}
}

func TestChildren(t *testing.T) {
	e, err := NewReader(h("0401aa")).Next()
	if err != nil {
		t.Fatal(err)
	}
	if r, err := e.Children(); err != ErrTag || r != nil {
		t.Fatalf("primitive Children: %v %v", r, err)
	}
	s, err := NewReader(h("3003020101")).Next()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChildrenOf(ClassUniversal, TagSet); err != ErrTag {
		t.Fatalf("SEQUENCE as SET: %v", err)
	}
	r, err := s.ChildrenOf(ClassUniversal, TagSequence)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := r.Next(); err != nil || !v.Is(ClassUniversal, TagInteger) {
		t.Fatalf("%v %+v", err, v)
	}
	// A constructed context tag numbered like SET is not a SET.
	c, err := NewReader(h("b100")).Next()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ChildrenOf(ClassUniversal, TagSet); err != ErrTag {
		t.Fatalf("[17] as SET: %v", err)
	}
	// A BER constructed OCTET STRING outside BER mode is refused.
	o, err := NewReader(h("2403040100")).Next()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OctetString(o); err == nil {
		t.Fatal("constructed OCTET STRING in DER")
	}
}

func TestBERIndefinite(t *testing.T) {
	// SEQUENCE (indefinite) { constructed OCTET STRING (indefinite) { 04 01 aa, 04 02 bb cc } }
	b := h("3080" + "2480" + "0401aa" + "0402bbcc" + "0000" + "0000")
	if _, err := NewReader(b).Next(); err == nil {
		t.Fatal("DER reader accepted indefinite length")
	}
	e, err := NewBERReader(b).Next()
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Children()
	if err != nil {
		t.Fatal(err)
	}
	o, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	got, err := OctetString(o)
	if err != nil || !bytes.Equal(got, h("aabbcc")) {
		t.Fatalf("%x %v", got, err)
	}
	if !r.Empty() {
		t.Fatal("not empty")
	}
}

func TestInt(t *testing.T) {
	for in, want := range map[string]int64{"020100": 0, "02017f": 127, "02020080": 128, "0201ff": -1, "020180": -128} {
		e, _ := NewReader(h(in)).Next()
		if v, err := Int(e); err != nil || v != want {
			t.Errorf("%s: %d %v", in, v, err)
		}
	}
}

func walk(r *Reader, depth int) {
	for !r.Empty() && depth < 40 {
		e, err := r.Next()
		if err != nil {
			return
		}
		_, _ = Int(e)
		_, _ = OctetString(e)
		if c, err := e.Children(); err == nil {
			walk(c, depth+1)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(h("bf854504" + "04020102"))
	f.Add(h("30802480" + "0401aa00000000"))
	f.Add(h("3005" + "a103110102")) // primitive SET inside a SEQUENCE
	f.Add(h("1003" + "020101"))     // primitive SEQUENCE
	f.Fuzz(func(t *testing.T, b []byte) {
		walk(NewReader(b), 0)
		walk(NewBERReader(b), 0)
	})
}
