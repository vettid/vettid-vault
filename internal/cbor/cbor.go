// Package cbor is a small, strict CBOR (RFC 8949) decoder and encoder for
// the attestation formats the vault verifies: AWS Nitro attestation
// documents (COSE_Sign1) and Apple App Attest attestation and assertion
// objects.
//
// It is written for the trusted code base rather than taken from a general
// library: it supports only what those formats use (unsigned and negative
// integers, byte and text strings, arrays, maps, tags, false, true and
// null), and rejects indefinite lengths, floats, undefined, other simple
// values, duplicate map keys, invalid UTF-8, nesting deeper than MaxDepth
// and trailing data. Non-minimal integer and length encodings are accepted:
// every caller verifies signatures over the raw bytes it received, so an
// alternative encoding cannot change what a signature covers.
//
// Errors never echo input bytes.
package cbor

import (
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

// MaxDepth bounds array, map and tag nesting.
const MaxDepth = 16

// Errors.
var (
	ErrTruncated = errors.New("cbor: truncated")
	ErrSyntax    = errors.New("cbor: unsupported or malformed item")
	ErrDepth     = errors.New("cbor: nesting too deep")
	ErrDuplicate = errors.New("cbor: duplicate map key")
	ErrTrailing  = errors.New("cbor: trailing data")
	ErrUTF8      = errors.New("cbor: invalid UTF-8 in text string")
	ErrType      = errors.New("cbor: unexpected type")
	ErrMissing   = errors.New("cbor: required map key missing")
)

// Kind is the type of a decoded item.
type Kind uint8

// Kinds.
const (
	KindUint Kind = iota + 1
	KindNeg       // a negative integer: the value is -1 - Uint
	KindBytes
	KindText
	KindArray
	KindMap
	KindTag
	KindBool
	KindNull
)

// Value is one decoded item. Bytes and Text alias the input.
type Value struct {
	Kind  Kind
	Uint  uint64 // KindUint; KindNeg (value -1-Uint); KindTag (tag number)
	Bytes []byte // KindBytes
	Text  string // KindText
	Array []Value
	Map   []Pair
	Tag   *Value // the tagged item (KindTag)
	Bool  bool
	// Raw is the complete encoding of this item within the input.
	Raw []byte
}

// Pair is one map entry.
type Pair struct {
	Key, Value Value
}

// Decode decodes exactly one item from b.
func Decode(b []byte) (*Value, error) {
	d := decoder{b: b}
	v, err := d.item(0)
	if err != nil {
		return nil, err
	}
	if d.off != len(b) {
		return nil, ErrTrailing
	}
	return &v, nil
}

type decoder struct {
	b   []byte
	off int
}

func (d *decoder) head() (major byte, arg uint64, err error) {
	if d.off >= len(d.b) {
		return 0, 0, ErrTruncated
	}
	ib := d.b[d.off]
	d.off++
	major, ai := ib>>5, ib&0x1f
	switch {
	case ai < 24:
		return major, uint64(ai), nil
	case ai <= 27:
		n := 1 << (ai - 24)
		if len(d.b)-d.off < n {
			return 0, 0, ErrTruncated
		}
		var v uint64
		switch n {
		case 1:
			v = uint64(d.b[d.off])
		case 2:
			v = uint64(binary.BigEndian.Uint16(d.b[d.off:]))
		case 4:
			v = uint64(binary.BigEndian.Uint32(d.b[d.off:]))
		case 8:
			v = binary.BigEndian.Uint64(d.b[d.off:])
		}
		d.off += n
		return major, v, nil
	}
	return 0, 0, ErrSyntax // reserved (28-30) or indefinite length (31)
}

func (d *decoder) item(depth int) (Value, error) {
	if depth > MaxDepth {
		return Value{}, ErrDepth
	}
	start := d.off
	major, arg, err := d.head()
	if err != nil {
		return Value{}, err
	}
	var v Value
	switch major {
	case 0:
		v = Value{Kind: KindUint, Uint: arg}
	case 1:
		v = Value{Kind: KindNeg, Uint: arg}
	case 2, 3:
		if arg > uint64(len(d.b)-d.off) {
			return Value{}, ErrTruncated
		}
		s := d.b[d.off : d.off+int(arg)]
		d.off += int(arg)
		if major == 2 {
			v = Value{Kind: KindBytes, Bytes: s}
		} else {
			if !utf8.Valid(s) {
				return Value{}, ErrUTF8
			}
			v = Value{Kind: KindText, Text: string(s)}
		}
	case 4:
		// Every element takes at least one byte.
		if arg > uint64(len(d.b)-d.off) {
			return Value{}, ErrTruncated
		}
		v = Value{Kind: KindArray, Array: make([]Value, 0, int(arg))}
		for i := uint64(0); i < arg; i++ {
			e, err := d.item(depth + 1)
			if err != nil {
				return Value{}, err
			}
			v.Array = append(v.Array, e)
		}
	case 5:
		if arg > uint64(len(d.b)-d.off)/2 {
			return Value{}, ErrTruncated
		}
		v = Value{Kind: KindMap, Map: make([]Pair, 0, int(arg))}
		for i := uint64(0); i < arg; i++ {
			k, err := d.item(depth + 1)
			if err != nil {
				return Value{}, err
			}
			if k.Kind != KindUint && k.Kind != KindNeg && k.Kind != KindText && k.Kind != KindBytes {
				return Value{}, ErrSyntax
			}
			for _, p := range v.Map {
				if sameKey(p.Key, k) {
					return Value{}, ErrDuplicate
				}
			}
			val, err := d.item(depth + 1)
			if err != nil {
				return Value{}, err
			}
			v.Map = append(v.Map, Pair{Key: k, Value: val})
		}
	case 6:
		t, err := d.item(depth + 1)
		if err != nil {
			return Value{}, err
		}
		v = Value{Kind: KindTag, Uint: arg, Tag: &t}
	case 7:
		switch arg {
		case 20, 21, 22:
			if d.off-start != 1 { // simple values below 24 must use the one-byte form
				return Value{}, ErrSyntax
			}
			v = Value{Kind: KindBool, Bool: arg == 21}
			if arg == 22 {
				v = Value{Kind: KindNull}
			}
		default:
			return Value{}, ErrSyntax // undefined, other simple values, floats
		}
	}
	v.Raw = d.b[start:d.off]
	return v, nil
}

func sameKey(a, b Value) bool {
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case KindUint, KindNeg:
		return a.Uint == b.Uint
	case KindText:
		return a.Text == b.Text
	case KindBytes:
		return string(a.Bytes) == string(b.Bytes)
	}
	return false
}

// Lookup returns the map value for a text key.
func (v *Value) Lookup(key string) (*Value, bool) {
	if v.Kind != KindMap {
		return nil, false
	}
	for i := range v.Map {
		if v.Map[i].Key.Kind == KindText && v.Map[i].Key.Text == key {
			return &v.Map[i].Value, true
		}
	}
	return nil, false
}

// LookupInt returns the map value for an integer key (negative keys as
// KindNeg with Uint = -1-key).
func (v *Value) LookupInt(key int64) (*Value, bool) {
	if v.Kind != KindMap {
		return nil, false
	}
	k, kind := uint64(key), KindUint
	if key < 0 {
		k, kind = uint64(-1-key), KindNeg
	}
	for i := range v.Map {
		if v.Map[i].Key.Kind == kind && v.Map[i].Key.Uint == k {
			return &v.Map[i].Value, true
		}
	}
	return nil, false
}

// BytesAt returns the byte string under a text key.
func (v *Value) BytesAt(key string) ([]byte, error) {
	e, ok := v.Lookup(key)
	if !ok {
		return nil, ErrMissing
	}
	if e.Kind != KindBytes {
		return nil, ErrType
	}
	return e.Bytes, nil
}

// TextAt returns the text string under a text key.
func (v *Value) TextAt(key string) (string, error) {
	e, ok := v.Lookup(key)
	if !ok {
		return "", ErrMissing
	}
	if e.Kind != KindText {
		return "", ErrType
	}
	return e.Text, nil
}

// UintAt returns the unsigned integer under a text key.
func (v *Value) UintAt(key string) (uint64, error) {
	e, ok := v.Lookup(key)
	if !ok {
		return 0, ErrMissing
	}
	if e.Kind != KindUint {
		return 0, ErrType
	}
	return e.Uint, nil
}

// Untag removes one tag with the given number, if present.
func (v *Value) Untag(tag uint64) *Value {
	if v.Kind == KindTag && v.Uint == tag {
		return v.Tag
	}
	return v
}
