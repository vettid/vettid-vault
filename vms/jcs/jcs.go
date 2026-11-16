// Package jcs writes JSON values in the JSON Canonicalization Scheme (RFC 8785) for the documents VettID signs or
// hashes (BALLOT-PROTOCOL §2, VAULT-MESSAGING §10.4 "Approval documents"). Those documents hold only objects,
// arrays, strings, integers, booleans and null, so RFC 8785's number rule reduces to plain integers within 2^53 - 1;
// each caller parses its documents under its own rules (depth, sign) and hands the values here.
package jcs

import (
	"bytes"
	"errors"
	"sort"
	"strconv"
	"unicode/utf16"
)

// ErrValue is a value of a type the documents do not hold (a float, for one).
var ErrValue = errors.New("jcs: value outside the documents' types")

// Append writes v in its canonical form: v is nil, a bool, an int64, a string, a []any or a map[string]any (of
// those), as a strict parser returns them.
func Append(buf *bytes.Buffer, v any) error { return canonical(buf, v) }

func canonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(x))
	case int64:
		buf.WriteString(strconv.FormatInt(x, 10))
	case string:
		writeString(buf, x)
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := canonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		// RFC 8785 §3.2.3: sort by UTF-16 code units.
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			if err := canonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return ErrValue
	}
	return nil
}

func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

const hexDigits = "0123456789abcdef"

// writeString escapes as RFC 8785 §3.2.2.2 (ECMAScript JSON.stringify): the
// two-character escapes, \u00xx (lower-case hex) for other control
// characters, and everything else as itself.
func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hexDigits[r>>4])
				buf.WriteByte(hexDigits[r&15])
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
