package votewire

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/vettid/vettid-vault/vms/jcs"
)

// JCS (RFC 8785) for the documents (BALLOT-PROTOCOL §2). The documents hold
// only objects, arrays, strings, integers, booleans and null, so the number
// rule reduces to plain integers of at most 2^53 - 1 in magnitude. A
// verifier parses strictly (no duplicate names at any depth), re-serialises
// and refuses the document unless the bytes are identical.

const maxSafeInt = 1<<53 - 1

// maxDepth bounds nesting (the deepest document is the service list at 4).
const maxDepth = 8

// parseStrict parses data as one JSON value with no duplicate member names,
// no fraction or exponent, and nothing after it. Objects come back as
// map[string]any, arrays as []any, integers as int64.
func parseStrict(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, ErrDocument
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, ErrDocument
	}
	return v, nil
}

func parseValue(dec *json.Decoder, depth int) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, ErrDocument
	}
	if d, ok := tok.(json.Delim); ok && (d == '{' || d == '[') && depth >= maxDepth {
		return nil, ErrDocument
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			m := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, ErrDocument
				}
				k, ok := kt.(string)
				if !ok {
					return nil, ErrDocument
				}
				if _, dup := m[k]; dup {
					return nil, ErrDocument
				}
				v, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			if _, err := dec.Token(); err != nil {
				return nil, ErrDocument
			}
			return m, nil
		case '[':
			a := []any{}
			for dec.More() {
				v, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, ErrDocument
			}
			return a, nil
		}
		return nil, ErrDocument
	case json.Number:
		s := string(t)
		if strings.ContainsAny(s, ".eE") || s == "-0" {
			return nil, ErrDocument
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n > maxSafeInt || n < -maxSafeInt {
			return nil, ErrDocument
		}
		return n, nil
	case string, bool, nil:
		return t, nil
	}
	return nil, ErrDocument
}

func canonical(buf *bytes.Buffer, v any) error {
	if err := jcs.Append(buf, v); err != nil {
		return ErrDocument
	}
	return nil
}

// Canonicalize parses data strictly and returns its JCS form.
func Canonicalize(data []byte) ([]byte, error) {
	v, err := parseStrict(data)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := canonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// checkCanonical refuses data unless it is exactly its own JCS form, and
// returns the parsed object.
func checkCanonical(data []byte) (map[string]any, error) {
	v, err := parseStrict(data)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := canonical(&buf, v); err != nil {
		return nil, err
	}
	if !eq(buf.Bytes(), data) {
		return nil, ErrDocument
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, ErrDocument
	}
	return m, nil
}

// encodeCanonical marshals v (a document struct) and returns its JCS form.
func encodeCanonical(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, ErrDocument
	}
	return Canonicalize(b)
}
