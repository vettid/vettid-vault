// Package der is a small ASN.1 TLV reader for the structures the vault
// parses by hand: the Android key attestation extension (whose context tags
// go up to [724], beyond what x/crypto/cryptobyte reads) and the CMS
// EnvelopedData that AWS KMS returns for a Nitro recipient.
//
// The default reader is strict DER: definite, minimal lengths only. The BER
// reader additionally accepts indefinite lengths and constructed OCTET
// STRINGs (which CMS producers emit); it is used only for CMS.
//
// Errors never echo input bytes.
package der

import (
	"errors"
)

// MaxDepth bounds nesting.
const MaxDepth = 24

// Errors.
var (
	ErrTruncated = errors.New("der: truncated")
	ErrSyntax    = errors.New("der: malformed encoding")
	ErrDepth     = errors.New("der: nesting too deep")
	ErrTag       = errors.New("der: unexpected tag")
	ErrValue     = errors.New("der: invalid value")
)

// Classes.
const (
	ClassUniversal   = 0
	ClassApplication = 1
	ClassContext     = 2
	ClassPrivate     = 3
)

// Universal tag numbers used here.
const (
	TagBoolean     = 1
	TagInteger     = 2
	TagBitString   = 3
	TagOctetString = 4
	TagNull        = 5
	TagOID         = 6
	TagEnumerated  = 10
	TagSequence    = 16
	TagSet         = 17
)

// Tag identifies an element.
type Tag struct {
	Class       uint8
	Constructed bool
	Number      uint64
}

// Is reports whether t has the given class and number.
func (t Tag) Is(class uint8, number uint64) bool { return t.Class == class && t.Number == number }

// Element is one TLV.
type Element struct {
	Tag
	// Content is the content octets. For an indefinite-length element it
	// is the encoding of the nested elements, without the end-of-contents.
	Content []byte
	// Raw is the complete encoding.
	Raw []byte
	ber bool
}

// Reader reads consecutive elements.
type Reader struct {
	b     []byte
	ber   bool
	depth int
}

// NewReader returns a strict DER reader over b.
func NewReader(b []byte) *Reader { return &Reader{b: b} }

// NewBERReader returns a reader that also accepts indefinite lengths.
func NewBERReader(b []byte) *Reader { return &Reader{b: b, ber: true} }

// Empty reports whether all input was consumed.
func (r *Reader) Empty() bool { return len(r.b) == 0 }

// Next reads the next element.
func (r *Reader) Next() (Element, error) {
	e, rest, err := parse(r.b, r.ber, r.depth)
	if err != nil {
		return Element{}, err
	}
	r.b = rest
	return e, nil
}

// Expect reads the next element and requires the tag.
func (r *Reader) Expect(class uint8, number uint64, constructed bool) (Element, error) {
	e, err := r.Next()
	if err != nil {
		return Element{}, err
	}
	if !e.Is(class, number) || e.Constructed != constructed {
		return Element{}, ErrTag
	}
	return e, nil
}

// Peek returns the tag of the next element without consuming it.
func (r *Reader) Peek() (Tag, bool) {
	e, _, err := parse(r.b, r.ber, r.depth)
	if err != nil {
		return Tag{}, false
	}
	return e.Tag, true
}

// Children returns a reader over a constructed element's content. It
// returns ErrTag (and a nil reader) for a primitive element; callers must
// check the error.
func (e Element) Children() (*Reader, error) {
	if !e.Constructed {
		return nil, ErrTag
	}
	return &Reader{b: e.Content, ber: e.ber}, nil
}

// ChildrenOf requires e to be a constructed element with the given class
// and number and returns a reader over its content.
func (e Element) ChildrenOf(class uint8, number uint64) (*Reader, error) {
	if !e.Is(class, number) || !e.Constructed {
		return nil, ErrTag
	}
	return e.Children()
}

func parse(b []byte, ber bool, depth int) (Element, []byte, error) {
	if depth > MaxDepth {
		return Element{}, nil, ErrDepth
	}
	if len(b) < 2 {
		return Element{}, nil, ErrTruncated
	}
	i := 0
	id := b[i]
	i++
	t := Tag{Class: id >> 6, Constructed: id&0x20 != 0, Number: uint64(id & 0x1f)}
	if t.Number == 0x1f {
		// High-tag-number form (X.690 8.1.2.4): base-128, no leading 0x80,
		// value ≥ 31.
		var n uint64
		for k := 0; ; k++ {
			if i >= len(b) {
				return Element{}, nil, ErrTruncated
			}
			c := b[i]
			i++
			if k == 0 && c == 0x80 {
				return Element{}, nil, ErrSyntax
			}
			if k >= 4 {
				return Element{}, nil, ErrSyntax // tags above 2^28 are not used
			}
			n = n<<7 | uint64(c&0x7f)
			if c&0x80 == 0 {
				break
			}
		}
		if n < 0x1f {
			return Element{}, nil, ErrSyntax
		}
		t.Number = n
	}
	// SEQUENCE and SET are always constructed (X.690 8.9.1, 8.11.1); a
	// primitive encoding of either is malformed in BER and DER alike.
	if t.Class == ClassUniversal && (t.Number == TagSequence || t.Number == TagSet) && !t.Constructed {
		return Element{}, nil, ErrSyntax
	}
	if i >= len(b) {
		return Element{}, nil, ErrTruncated
	}
	lb := b[i]
	i++
	switch {
	case lb < 0x80:
		n := int(lb)
		if len(b)-i < n {
			return Element{}, nil, ErrTruncated
		}
		return Element{Tag: t, Content: b[i : i+n], Raw: b[:i+n], ber: ber}, b[i+n:], nil
	case lb == 0x80:
		if !ber || !t.Constructed {
			return Element{}, nil, ErrSyntax
		}
		// Indefinite length: nested elements up to an end-of-contents.
		start := i
		rest := b[i:]
		for {
			if len(rest) >= 2 && rest[0] == 0 && rest[1] == 0 {
				end := len(b) - len(rest)
				return Element{Tag: t, Content: b[start:end], Raw: b[:end+2], ber: ber}, rest[2:], nil
			}
			_, r2, err := parse(rest, ber, depth+1)
			if err != nil {
				return Element{}, nil, err
			}
			rest = r2
		}
	default:
		k := int(lb & 0x7f)
		if k > 4 || len(b)-i < k {
			return Element{}, nil, ErrSyntax
		}
		var n uint64
		for j := 0; j < k; j++ {
			n = n<<8 | uint64(b[i+j])
		}
		i += k
		// Minimal encoding: no leading zero octet, and long form only for
		// lengths ≥ 128.
		if b[i-k] == 0 || n < 0x80 {
			return Element{}, nil, ErrSyntax
		}
		if n > uint64(len(b)-i) {
			return Element{}, nil, ErrTruncated
		}
		return Element{Tag: t, Content: b[i : i+int(n)], Raw: b[:i+int(n)], ber: ber}, b[i+int(n):], nil
	}
}

// --- typed readers for universal primitives ---

// Int reads an INTEGER that fits in int64.
func Int(e Element) (int64, error) {
	if !e.Is(ClassUniversal, TagInteger) && !e.Is(ClassUniversal, TagEnumerated) {
		return 0, ErrTag
	}
	return intContent(e)
}

func intContent(e Element) (int64, error) {
	c := e.Content
	if e.Constructed || len(c) == 0 || len(c) > 8 {
		return 0, ErrValue
	}
	if len(c) > 1 && (c[0] == 0 && c[1]&0x80 == 0 || c[0] == 0xff && c[1]&0x80 != 0) {
		return 0, ErrValue // non-minimal
	}
	var v int64
	if c[0]&0x80 != 0 {
		v = -1
	}
	for _, x := range c {
		v = v<<8 | int64(x)
	}
	return v, nil
}

// IntContent reads the content of an implicitly tagged INTEGER.
func IntContent(e Element) (int64, error) { return intContent(e) }

// Bool reads a BOOLEAN (DER: 0x00 or 0xff).
func Bool(e Element) (bool, error) {
	if !e.Is(ClassUniversal, TagBoolean) || e.Constructed || len(e.Content) != 1 {
		return false, ErrTag
	}
	switch e.Content[0] {
	case 0:
		return false, nil
	case 0xff:
		return true, nil
	}
	return false, ErrValue
}

// OctetString reads an OCTET STRING. In BER mode a constructed OCTET
// STRING is reassembled from its primitive segments.
func OctetString(e Element) ([]byte, error) {
	if !e.Is(ClassUniversal, TagOctetString) {
		return nil, ErrTag
	}
	return OctetContent(e)
}

// OctetContent returns the octets of a (possibly implicitly tagged) OCTET
// STRING.
func OctetContent(e Element) ([]byte, error) {
	if !e.Constructed {
		return e.Content, nil
	}
	if !e.ber {
		return nil, ErrSyntax
	}
	r, err := e.Children()
	if err != nil {
		return nil, err
	}
	var out []byte
	for !r.Empty() {
		s, err := r.Next()
		if err != nil {
			return nil, err
		}
		if !s.Is(ClassUniversal, TagOctetString) {
			return nil, ErrTag
		}
		p, err := OctetContent(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p...)
	}
	return out, nil
}

// OID reads an OBJECT IDENTIFIER and returns its content octets, for
// comparison with an expected encoding.
func OID(e Element) ([]byte, error) {
	if !e.Is(ClassUniversal, TagOID) || e.Constructed || len(e.Content) == 0 {
		return nil, ErrTag
	}
	return e.Content, nil
}

// Null checks a NULL.
func Null(e Element) error {
	if !e.Is(ClassUniversal, TagNull) || e.Constructed || len(e.Content) != 0 {
		return ErrTag
	}
	return nil
}
