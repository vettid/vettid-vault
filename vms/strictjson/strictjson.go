// Package strictjson parses the JSON objects of the vault messaging wire
// format strictly: valid UTF-8, exactly one object, no duplicate member
// names at any depth, bounded nesting, and exact (case-sensitive) member
// lookup. encoding/json alone accepts duplicate names (last wins) and
// matches struct fields case-insensitively; both are unacceptable for
// security-relevant parsing.
//
// Errors never echo input bytes.
package strictjson

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"runtime"
	"strconv"
	"unicode/utf8"
)

// MaxDepth bounds object/array nesting.
const MaxDepth = 32

// MaxSafeInteger is the largest integer that every JSON implementation in
// use (including JavaScript) represents exactly: 2^53 - 1.
const MaxSafeInteger = 1<<53 - 1

var (
	ErrSyntax    = errors.New("strictjson: malformed JSON")
	ErrUTF8      = errors.New("strictjson: invalid UTF-8")
	ErrSurrogate = errors.New("strictjson: unpaired surrogate escape")
	ErrNotObject = errors.New("strictjson: not a JSON object")
	ErrDuplicate = errors.New("strictjson: duplicate member name")
	ErrDepth     = errors.New("strictjson: nesting too deep")
	ErrType      = errors.New("strictjson: member has the wrong type")
	ErrMissing   = errors.New("strictjson: required member missing")
	ErrValue     = errors.New("strictjson: member value out of range")
	ErrBase64    = errors.New("strictjson: invalid base64")
)

// Object is a parsed JSON object: member name to raw value.
type Object map[string]json.RawMessage

// ParseObject parses b as exactly one JSON object, rejecting invalid UTF-8,
// an unpaired surrogate \u escape, a leading byte order mark,
// duplicate member names at any depth, nesting deeper than MaxDepth, and
// any non-whitespace data after the object.
func ParseObject(b []byte) (Object, error) {
	if !utf8.Valid(b) {
		return nil, ErrUTF8
	}
	if err := checkSurrogates(b); err != nil {
		return nil, err
	}
	if err := checkTree(b); err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil || m == nil {
		return nil, ErrNotObject
	}
	return Object(m), nil
}

// checkSurrogates scans the raw bytes once, in linear time, and refuses a
// \u escape of a surrogate that is not half of a pair, in any string
// literal (member names included): a high surrogate (D800-DBFF) not
// followed at once by a \u escape of a low one (DC00-DFFF), or a low one not
// preceded at once by a high one (VAULT-MESSAGING 0.83.1 §5.3). encoding/
// json would silently turn it into U+FFFD, so this must look at the raw
// text. Anything else malformed (bad escapes, bad syntax) is left to the
// decoder that follows.
func checkSurrogates(b []byte) error {
	inStr := false
	for i := 0; i < len(b); {
		c := b[i]
		if !inStr {
			inStr = c == '"'
			i++
			continue
		}
		switch c {
		case '"':
			inStr = false
			i++
		case '\\':
			if i+1 >= len(b) {
				return nil
			}
			if b[i+1] != 'u' {
				i += 2 // any other escape is two bytes
				continue
			}
			v, ok := hex4(b, i+2)
			if !ok {
				return nil // the decoder refuses it
			}
			i += 6
			switch {
			case v >= 0xD800 && v <= 0xDBFF:
				if i+1 < len(b) && b[i] == '\\' && b[i+1] == 'u' {
					if lo, ok := hex4(b, i+2); ok && lo >= 0xDC00 && lo <= 0xDFFF {
						i += 6 // a complete pair, consumed once
						continue
					}
				}
				return ErrSurrogate
			case v >= 0xDC00 && v <= 0xDFFF:
				return ErrSurrogate
			}
		default:
			i++
		}
	}
	return nil
}

// hex4 reads four ASCII hex digits at b[i:].
func hex4(b []byte, i int) (rune, bool) {
	if i+4 > len(b) {
		return 0, false
	}
	var v rune
	for _, c := range b[i : i+4] {
		switch {
		case c >= '0' && c <= '9':
			c -= '0'
		case c >= 'a' && c <= 'f':
			c = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			c = c - 'A' + 10
		default:
			return 0, false
		}
		v = v<<4 | rune(c)
	}
	return v, true
}

// checkTree verifies syntax, depth, a single top-level object, and
// member-name uniqueness per object.
//
// It walks b in place and copies no value: member names are decoded (they
// are not secret), but strings, numbers and literals in value position are
// only skipped. A json.Decoder would keep its own copy of the whole input
// and a Go string for every value token, neither of which can be wiped, and
// the plaintext of a message body (a secret value included) would linger
// in them until the garbage collector reused the memory.
//
// The walk reports a duplicate name, too deep a nesting, a top level that is
// not an object and trailing data in input order, as the token stream did;
// json.Valid, which validates in place, then checks the syntax of the rest.
// Where an input is wrong in two ways, the error the walk meets first wins.
func checkTree(b []byte) error {
	var stack []frame
	first := true
	i := 0
	for {
		i = skipSpace(b, i)
		if i >= len(b) {
			break
		}
		if first {
			if b[i] != '{' {
				return ErrNotObject
			}
		} else if len(stack) == 0 {
			return ErrSyntax // trailing data after the top-level object
		}
		first = false
		c := b[i]
		if top := len(stack) - 1; top >= 0 && stack[top].obj && stack[top].key {
			switch c {
			case '}':
				stack = stack[:top]
				markValueDone(stack)
				i++
				continue
			case '"':
				end, ok := stringEnd(b, i)
				if !ok {
					return ErrSyntax
				}
				name, ok := memberName(b[i:end])
				if !ok {
					return ErrSyntax
				}
				if _, dup := stack[top].names[name]; dup {
					return ErrDuplicate
				}
				stack[top].names[name] = struct{}{}
				stack[top].key = false
				i = end
				continue
			case ',':
				i++ // between members; json.Valid checks its place
				continue
			}
			return ErrSyntax
		}
		switch c {
		case '{':
			if len(stack) >= MaxDepth {
				return ErrDepth
			}
			stack = append(stack, frame{obj: true, names: map[string]struct{}{}, key: true})
			i++
		case '[':
			if len(stack) >= MaxDepth {
				return ErrDepth
			}
			stack = append(stack, frame{})
			i++
		case '}', ']':
			top := len(stack) - 1
			if top < 0 || stack[top].obj != (c == '}') {
				return ErrSyntax
			}
			stack = stack[:top]
			markValueDone(stack)
			i++
		case ':', ',':
			i++ // json.Valid checks their places
		case '"':
			end, ok := stringEnd(b, i)
			if !ok {
				return ErrSyntax
			}
			markValueDone(stack)
			i = end
		default:
			// A number or literal: skipped, never decoded.
			end := i
			for end < len(b) && !isDelim(b[end]) {
				end++
			}
			markValueDone(stack)
			i = end
		}
	}
	if first || len(stack) != 0 {
		return ErrSyntax
	}
	if !json.Valid(b) {
		return ErrSyntax
	}
	return nil
}

// skipSpace returns the index of the first byte at or after i that is not
// JSON whitespace.
func skipSpace(b []byte, i int) int {
	for i < len(b) {
		switch b[i] {
		case ' ', '\t', '\n', '\r':
			i++
		default:
			return i
		}
	}
	return i
}

// isDelim reports whether c ends a number or literal.
func isDelim(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', ',', ':', '[', ']', '{', '}', '"':
		return true
	}
	return false
}

// stringEnd returns the index just past the string literal that starts
// with the quote at b[i], or false if it is not closed. An escape skips
// the byte after the backslash; the escapes themselves are left to
// json.Valid.
func stringEnd(b []byte, i int) (int, bool) {
	for j := i + 1; j < len(b); j++ {
		switch b[j] {
		case '\\':
			j++
		case '"':
			return j + 1, true
		}
	}
	return 0, false
}

// memberName decodes a member name's string literal (quotes included).
// Names are compared decoded, so that "a" and its escaped spelling (a
// backslash-u escape of 0061) are the same name. A name that is not valid
// UTF-8 is decoded too, which turns each bad byte into U+FFFD as the
// decoder did, so that checkTree finds the same duplicates even on input
// ParseObject has not checked for UTF-8.
func memberName(lit []byte) (string, bool) {
	if bytes.IndexByte(lit, '\\') < 0 && utf8.Valid(lit) {
		return string(lit[1 : len(lit)-1]), true
	}
	var s string
	if err := json.Unmarshal(lit, &s); err != nil {
		return "", false
	}
	return s, true
}

type frame struct {
	obj   bool
	names map[string]struct{}
	key   bool // next token in an object is a member name
}

func markValueDone(stack []frame) {
	if len(stack) > 0 && stack[len(stack)-1].obj {
		stack[len(stack)-1].key = true
	}
}

// Wipe zeroes every member's raw value. ParseObject copies each value out
// of its input, so a caller that parsed a secret plaintext wipes the copies
// once it has taken what it needs. Strings already returned by String and
// the like are Go strings and cannot be wiped.
func (o Object) Wipe() {
	for _, v := range o {
		clear(v)
		runtime.KeepAlive(v)
	}
}

// IsObjectMember reports whether the member is present and holds an object.
// Unlike Object it makes no copy of the members: o must come from
// ParseObject (or AsObject), which has already checked the whole value.
func (o Object) IsObjectMember(name string) bool {
	raw := o[name]
	return len(raw) > 0 && raw[0] == '{'
}

// Has reports whether the member is present (including as JSON null).
func (o Object) Has(name string) bool { _, ok := o[name]; return ok }

// String returns a required string member.
func (o Object) String(name string) (string, error) {
	raw, ok := o[name]
	if !ok {
		return "", ErrMissing
	}
	return decodeString(raw)
}

// OptString returns an optional string member; present reports presence.
func (o Object) OptString(name string) (s string, present bool, err error) {
	raw, ok := o[name]
	if !ok {
		return "", false, nil
	}
	s, err = decodeString(raw)
	return s, true, err
}

func decodeString(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", ErrType
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", ErrType
	}
	return s, nil
}

// Uint returns a required non-negative integer member in [min, max]. The
// value must be written as a plain JSON integer: no sign, fraction or
// exponent.
func (o Object) Uint(name string, min, max uint64) (uint64, error) {
	raw, ok := o[name]
	if !ok {
		return 0, ErrMissing
	}
	return parseUint(raw, min, max)
}

// OptUint returns an optional integer member.
func (o Object) OptUint(name string, min, max uint64) (v uint64, present bool, err error) {
	raw, ok := o[name]
	if !ok {
		return 0, false, nil
	}
	v, err = parseUint(raw, min, max)
	return v, true, err
}

func parseUint(raw json.RawMessage, min, max uint64) (uint64, error) {
	if len(raw) == 0 || len(raw) > 16 {
		return 0, ErrType
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return 0, ErrType
		}
	}
	if len(raw) > 1 && raw[0] == '0' {
		return 0, ErrType
	}
	v, err := strconv.ParseUint(string(raw), 10, 64)
	if err != nil {
		return 0, ErrType
	}
	if v < min || v > max || v > MaxSafeInteger {
		return 0, ErrValue
	}
	return v, nil
}

// Bool returns a required boolean member.
func (o Object) Bool(name string) (bool, error) {
	raw, ok := o[name]
	if !ok {
		return false, ErrMissing
	}
	switch string(raw) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, ErrType
}

// Object returns a required nested object member.
func (o Object) Object(name string) (Object, error) {
	raw, ok := o[name]
	if !ok {
		return nil, ErrMissing
	}
	return asObject(raw)
}

// OptObjectRaw returns the raw bytes of an optional member that must be an
// object if present.
func (o Object) OptObjectRaw(name string) (json.RawMessage, bool, error) {
	raw, ok := o[name]
	if !ok {
		return nil, false, nil
	}
	if _, err := asObject(raw); err != nil {
		return nil, true, err
	}
	return raw, true, nil
}

func asObject(raw json.RawMessage) (Object, error) {
	if len(raw) == 0 || raw[0] != '{' {
		return nil, ErrType
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, ErrType
	}
	return Object(m), nil
}

// Array returns the elements of a required array member.
func (o Object) Array(name string) ([]json.RawMessage, error) {
	raw, ok := o[name]
	if !ok {
		return nil, ErrMissing
	}
	return asArray(raw)
}

// OptArray returns the elements of an optional array member.
func (o Object) OptArray(name string) ([]json.RawMessage, bool, error) {
	raw, ok := o[name]
	if !ok {
		return nil, false, nil
	}
	a, err := asArray(raw)
	return a, true, err
}

func asArray(raw json.RawMessage) ([]json.RawMessage, error) {
	if len(raw) == 0 || raw[0] != '[' {
		return nil, ErrType
	}
	var a []json.RawMessage
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, ErrType
	}
	return a, nil
}

// AsObject parses a raw array element as an object.
func AsObject(raw json.RawMessage) (Object, error) { return asObject(raw) }

// AsArray parses a raw value as an array.
func AsArray(raw json.RawMessage) ([]json.RawMessage, error) { return asArray(raw) }

// AsString parses a raw array element as a string.
func AsString(raw json.RawMessage) (string, error) { return decodeString(raw) }

// AsUint parses a raw array element as an integer in [min, max].
func AsUint(raw json.RawMessage, min, max uint64) (uint64, error) { return parseUint(raw, min, max) }

// Base64 returns a required member holding standard base64 with padding
// that decodes to exactly n bytes (n < 0: any length).
func (o Object) Base64(name string, n int) ([]byte, error) {
	s, err := o.String(name)
	if err != nil {
		return nil, err
	}
	return DecodeStd(s, n)
}

// DecodeStd decodes canonical standard base64 with padding. Unlike
// encoding/base64 it rejects CR and LF (which the stdlib silently skips)
// and any non-canonical encoding (non-zero trailing bits).
func DecodeStd(s string, n int) ([]byte, error) {
	return decodeCanonical(base64.StdEncoding, s, n)
}

// DecodeRawURL decodes canonical unpadded base64url.
func DecodeRawURL(s string, n int) ([]byte, error) {
	return decodeCanonical(base64.RawURLEncoding, s, n)
}

func decodeCanonical(enc *base64.Encoding, s string, n int) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' || s[i] == '\n' {
			return nil, ErrBase64
		}
	}
	b, err := enc.Strict().DecodeString(s)
	if err != nil {
		return nil, ErrBase64
	}
	if n >= 0 && len(b) != n {
		return nil, ErrBase64
	}
	if enc.EncodeToString(b) != s {
		return nil, ErrBase64
	}
	return b, nil
}

// MarshalString encodes s as a JSON string without HTML escaping, so that
// every implementation produces the same bytes for the same string.
func MarshalString(s string) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a string always encodes
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

// Builder writes a compact JSON object with members in call order.
type Builder struct {
	buf   bytes.Buffer
	first bool
}

// NewBuilder starts an object.
func NewBuilder() *Builder {
	b := &Builder{first: true}
	b.buf.WriteByte('{')
	return b
}

func (b *Builder) name(n string) {
	if !b.first {
		b.buf.WriteByte(',')
	}
	b.first = false
	b.buf.Write(MarshalString(n))
	b.buf.WriteByte(':')
}

// String adds a string member.
func (b *Builder) String(n, v string) *Builder {
	b.name(n)
	b.buf.Write(MarshalString(v))
	return b
}

// Uint adds an integer member.
func (b *Builder) Uint(n string, v uint64) *Builder {
	b.name(n)
	b.buf.WriteString(strconv.FormatUint(v, 10))
	return b
}

// Bool adds a boolean member.
func (b *Builder) Bool(n string, v bool) *Builder {
	b.name(n)
	b.buf.WriteString(strconv.FormatBool(v))
	return b
}

// Base64 adds a standard-base64 member.
func (b *Builder) Base64(n string, v []byte) *Builder {
	return b.String(n, base64.StdEncoding.EncodeToString(v))
}

// Raw adds a member whose value is already-encoded JSON. The caller is
// responsible for its validity.
func (b *Builder) Raw(n string, v []byte) *Builder {
	b.name(n)
	b.buf.Write(v)
	return b
}

// Bytes closes the object and returns it.
func (b *Builder) Bytes() []byte {
	b.buf.WriteByte('}')
	return b.buf.Bytes()
}

// CompactObject validates raw as a strict JSON object (ParseObject rules) and
// returns its compact form.
func CompactObject(raw []byte) ([]byte, error) {
	if _, err := ParseObject(raw); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, ErrSyntax
	}
	return buf.Bytes(), nil
}
