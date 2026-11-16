package peerwire

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/vettid/vettid-vault/vms/jcs"
	"github.com/vettid/vettid-vault/vms/strictjson"
)

// Approval documents (VAULT-MESSAGING §10.4 "Approval documents", 0.89.0): an approval challenge from a service
// MAY carry the action's whole canonical document, JCS({"action", "payload", "summary"}), whose SHA-256 is the
// service's action_hash. The member's vault checks it (CheckDocument), keeps it with the ask, and signs the
// document form over its hash.

const (
	// ConnAuthDocumentLabel signs the document form (§10.4 "The document form").
	ConnAuthDocumentLabel = "vettid/vms/2/conn-auth-document"
	// MaxDocument bounds a document's bytes (decoded).
	MaxDocument = 65536
	// MaxDocumentDepth bounds its nesting: the document object is level 1, each object or array inside it one more.
	MaxDocumentDepth = 16
	// MaxDocumentSummary bounds its summary's bytes.
	MaxDocumentSummary = 1024
	// MaxDocumentAction bounds its action's bytes ([a-z0-9_.]).
	MaxDocumentAction = 64
	// maxDocumentB64 is the longest standard base64 of MaxDocument bytes.
	maxDocumentB64 = (MaxDocument + 2) / 3 * 4
	// docRefDigits is how many hex digits of the document's hash end its challenge's context.
	docRefDigits = 16
)

// The reasons a document is dropped (the ref of drop.approval_document is "<connection_id> <reason>").
const (
	DocSize      = "size"
	DocEncoding  = "encoding"
	DocShape     = "shape"
	DocDepth     = "depth"
	DocCanonical = "canonical"
	DocRef       = "ref"
)

// HasDocument reports whether the challenge carries a document member (whatever its value). document_required
// without it is ignored (§10.4).
func (c *ConnAuthChallenge) HasDocument() bool { return c.docRaw != nil }

// CheckDocument makes the four receiver checks on the challenge's document, in their order, and returns the
// document's bytes, its hash d, whether the challenge is document_required, and "" — or the reason of the first
// check that fails. Only for an approval challenge from a service connection that carries a document (the
// caller's to decide: on any other challenge the members are ignored).
func (c *ConnAuthChallenge) CheckDocument() (doc []byte, d [32]byte, required bool, reason string) {
	// 1. A string of standard base64 with padding, decoding to at most MaxDocument bytes.
	var s string
	if json.Unmarshal(c.docRaw, &s) != nil || !strings.HasPrefix(string(bytes.TrimSpace(c.docRaw)), `"`) {
		return nil, d, false, DocEncoding
	}
	if len(s) > maxDocumentB64 {
		return nil, d, false, DocSize
	}
	doc, err := strictjson.DecodeStd(s, -1)
	if err != nil {
		return nil, d, false, DocEncoding
	}
	if len(doc) > MaxDocument {
		return nil, d, false, DocSize
	}
	// 2. Strict (§5.3), at most MaxDocumentDepth levels, exactly action, payload and summary within their bounds;
	// document_required, when present, is true.
	if c.reqRaw != nil {
		if string(c.reqRaw) != "true" {
			return nil, d, false, DocShape
		}
		required = true
	}
	v, reason := parseDocument(doc)
	if reason != "" {
		return nil, d, false, reason
	}
	m, ok := v.(map[string]any)
	if !ok || len(m) != 3 {
		return nil, d, false, DocShape
	}
	action, ok1 := m["action"].(string)
	summary, ok2 := m["summary"].(string)
	_, ok3 := m["payload"].(map[string]any)
	if !ok1 || !ok2 || !ok3 || !validAction(action) || len(summary) > MaxDocumentSummary {
		return nil, d, false, DocShape
	}
	// 3. Canonical: its own RFC 8785 form, byte for byte.
	var buf bytes.Buffer
	if jcs.Append(&buf, v) != nil || subtle.ConstantTimeCompare(buf.Bytes(), doc) != 1 {
		return nil, d, false, DocCanonical
	}
	// 4. The context ends with the first 16 lower-case hex digits of d.
	d = sha256.Sum256(doc)
	if !strings.HasSuffix(c.Context, DocumentRef(d)) {
		return nil, [32]byte{}, false, DocRef
	}
	return doc, d, required, ""
}

// DocumentRef is the 16 lower-case hex digits of d[0:8] a document's challenge's context ends with.
func DocumentRef(d [32]byte) string { return hex.EncodeToString(d[:docRefDigits/2]) }

// validAction: 1 to MaxDocumentAction bytes of [a-z0-9_.].
func validAction(a string) bool {
	if a == "" || len(a) > MaxDocumentAction {
		return false
	}
	for i := 0; i < len(a); i++ {
		c := a[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// parseDocument parses a document under §5.3 (strictjson: UTF-8, no byte order mark, no lone surrogate escape, no
// duplicate names at any depth, nothing after the value) with at most MaxDocumentDepth levels and §5.3's integers
// (no sign, fraction or exponent, at most 2^53 - 1). Objects come back as map[string]any, arrays as []any,
// integers as int64. The reason is DocDepth for the nesting, DocShape for anything else.
func parseDocument(doc []byte) (any, string) {
	// The nesting first, so that a document too deep is told apart from a malformed one.
	if depth, ok := nesting(doc); !ok {
		return nil, DocShape
	} else if depth > MaxDocumentDepth {
		return nil, DocDepth
	}
	if _, err := strictjson.ParseObject(doc); err != nil {
		return nil, DocShape
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	v, err := docValue(dec)
	if err != nil {
		return nil, DocShape
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, DocShape
	}
	return v, ""
}

// nesting returns the deepest nesting of objects and arrays in doc, or false if doc is not one well-formed JSON
// value.
func nesting(doc []byte) (int, bool) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	depth, deepest := 0, 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return deepest, depth == 0 && deepest > 0
		}
		if err != nil {
			return 0, false
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
				deepest = max(deepest, depth)
			default:
				depth--
			}
		}
	}
}

const maxSafeInt = 1<<53 - 1

func docValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			m := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, _ := kt.(string)
				v, err := docValue(dec)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return m, nil
		case '[':
			a := []any{}
			for dec.More() {
				v, err := docValue(dec)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return a, nil
		}
		return nil, ErrBody
	case json.Number:
		// §5.3: a plain integer, no sign, fraction or exponent, at most 2^53 - 1.
		s := string(t)
		if strings.ContainsAny(s, "-+.eE") {
			return nil, ErrBody
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n > maxSafeInt {
			return nil, ErrBody
		}
		return n, nil
	case string, bool, nil:
		return t, nil
	}
	return nil, ErrBody
}

// ConnAuthDocumentMessage returns the bytes signed in the document form (§10.4 "The document form"):
//
//	len(purpose) (1) || purpose || d (32) || m
//
// under ConnAuthDocumentLabel, where m is ConnAuthMessage's.
func ConnAuthDocumentMessage(purpose string, d [32]byte, m []byte) []byte {
	out := make([]byte, 0, 1+len(purpose)+len(d)+len(m))
	out = append(append(append(out, byte(len(purpose))), purpose...), d[:]...)
	return append(out, m...)
}
