package envelope

import (
	"encoding/json"
	"time"

	"github.com/vettid/vettid-vault/vms/strictjson"
)

// InnerVersion is the inner format version `v` (§5.3).
const InnerVersion = 1

// TSLayout is the inner timestamp format: RFC 3339 UTC with exactly three
// fractional digits and a literal Z (§5.3).
const TSLayout = "2006-01-02T15:04:05.000Z"

// Freshness windows (§8.4).
const (
	MaxClockSkewFuture = 5 * time.Minute
	MaxDurableAge      = 16 * 24 * time.Hour
)

// Limits on inner string members. The spec does not bound them; these are
// generous and keep parsers from carrying unbounded strings around.
const (
	MaxTypeLen      = 64
	MaxErrorCodeLen = 64
	MaxErrorMsgLen  = 1024
)

// Status values (§5.3).
const (
	StatusOK    = "ok"
	StatusError = "error"
)

// Error is the `error` member of a response.
type Error struct {
	Code    string
	Message string
}

// Inner is the inner plaintext (§5.3).
type Inner struct {
	ID     string    // ULID; also the idempotency key
	Type   string    // registry name (§10)
	TS     time.Time // sender clock, millisecond precision, UTC
	Seq    uint64    // session mode only, >= 1; 0 means absent
	Re     string    // responses: id of the request answered
	Exp    time.Time // optional; zero means absent
	Status string    // responses: "ok" or "error"
	Error  *Error    // present iff Status == "error"
	// Features (0.86.0, §5.3, §10.8) are the sender's capability names as
	// it advertises them to this recipient: sorted, each once, each
	// [a-z0-9_]{1,32}, never empty (nil: the member is absent). Older
	// receivers ignore it as an unknown member.
	Features []string
	Body     json.RawMessage
}

// MaxFeatures bounds the inner `features` list (as §10.2's device.features
// and §11.10.9's list are bounded).
const MaxFeatures = 32

// ValidFeatures reports whether names is a well-formed `features` list
// (§5.3): 1 to MaxFeatures names, sorted in ascending byte order, each once,
// each [a-z0-9_]{1,32}.
func ValidFeatures(names []string) bool {
	if len(names) == 0 || len(names) > MaxFeatures {
		return false
	}
	for i, n := range names {
		if len(n) == 0 || len(n) > 32 {
			return false
		}
		for j := 0; j < len(n); j++ {
			c := n[j]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
				return false
			}
		}
		if i > 0 && names[i-1] >= n {
			return false
		}
	}
	return true
}

// FormatTS formats t in the inner timestamp format (truncating to ms).
func FormatTS(t time.Time) string { return t.UTC().Truncate(time.Millisecond).Format(TSLayout) }

// ParseTS parses a timestamp strictly: it must be exactly TSLayout and
// round-trip to the same string.
func ParseTS(s string) (time.Time, error) {
	if len(s) != len(TSLayout) {
		return time.Time{}, ErrInner
	}
	t, err := time.Parse(TSLayout, s)
	if err != nil || t.Format(TSLayout) != s {
		return time.Time{}, ErrInner
	}
	return t, nil
}

// ValidType reports whether s is a well-formed registry name: dot-separated
// segments of [a-z][a-z0-9-]*, at most MaxTypeLen bytes.
func ValidType(s string) bool {
	if len(s) == 0 || len(s) > MaxTypeLen {
		return false
	}
	start := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case (c >= '0' && c <= '9') || c == '-':
			if start {
				return false
			}
		case c == '.':
			if start || i == len(s)-1 {
				return false
			}
			start = true
			continue
		default:
			return false
		}
		start = false
	}
	return true
}

func validErrorCode(s string) bool {
	if len(s) == 0 || len(s) > MaxErrorCodeLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c == '_' || (i > 0 && c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// validate checks the semantic rules shared by Marshal and ParseInner.
func (in *Inner) validate(mode Mode) error {
	if !ValidULID(in.ID) || !ValidType(in.Type) || in.TS.IsZero() {
		return ErrInner
	}
	switch mode {
	case ModeSession:
		if in.Seq < 1 || in.Seq > strictjson.MaxSafeInteger {
			return ErrInner
		}
	case ModeSealed:
		if in.Seq != 0 {
			return ErrInner
		}
	default:
		return ErrMode
	}
	if in.Re != "" && !ValidULID(in.Re) {
		return ErrInner
	}
	// A response has both `re` and `status`; a request or event has neither.
	if (in.Re == "") != (in.Status == "") {
		return ErrInner
	}
	switch in.Status {
	case "":
	case StatusOK:
		if in.Error != nil {
			return ErrInner
		}
	case StatusError:
		if in.Error == nil {
			return ErrInner
		}
	default:
		return ErrInner
	}
	if in.Status != StatusError && in.Error != nil {
		return ErrInner
	}
	if in.Error != nil {
		if !validErrorCode(in.Error.Code) || len(in.Error.Message) > MaxErrorMsgLen {
			return ErrInner
		}
	}
	if in.Features != nil && !ValidFeatures(in.Features) {
		return ErrInner
	}
	return nil
}

// Marshal encodes the inner plaintext as compact JSON with members in the
// order v, id, type, ts, seq, re, exp, status, error, features, body. A
// nil Body is encoded as {}. mode selects the `seq` rule: required in session mode,
// absent in sealed mode.
func (in *Inner) Marshal(mode Mode) ([]byte, error) {
	if err := in.validate(mode); err != nil {
		return nil, err
	}
	body := []byte("{}")
	if len(in.Body) > 0 {
		var err error
		if body, err = strictjson.CompactObject(in.Body); err != nil {
			return nil, ErrInner
		}
	}
	b := strictjson.NewBuilder().
		Uint("v", InnerVersion).
		String("id", in.ID).
		String("type", in.Type).
		String("ts", FormatTS(in.TS))
	if mode == ModeSession {
		b.Uint("seq", in.Seq)
	}
	if in.Re != "" {
		b.String("re", in.Re)
	}
	if !in.Exp.IsZero() {
		b.String("exp", FormatTS(in.Exp))
	}
	if in.Status != "" {
		b.String("status", in.Status)
	}
	if in.Error != nil {
		eb := strictjson.NewBuilder().String("code", in.Error.Code)
		if in.Error.Message != "" {
			eb.String("message", in.Error.Message)
		}
		b.Raw("error", eb.Bytes())
	}
	if in.Features != nil {
		arr := []byte{'['}
		for i, n := range in.Features {
			if i > 0 {
				arr = append(arr, ',')
			}
			arr = append(arr, strictjson.MarshalString(n)...)
		}
		b.Raw("features", append(arr, ']'))
	}
	b.Raw("body", body)
	return b.Bytes(), nil
}

// ParseInner parses an (unpadded) inner plaintext strictly. Unknown members
// are ignored (§5.3); known members must have exactly the specified type
// and form; duplicate member names anywhere are rejected.
func ParseInner(b []byte, mode Mode) (*Inner, error) {
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, ErrInner
	}
	if v, err := o.Uint("v", InnerVersion, InnerVersion); err != nil || v != InnerVersion {
		return nil, ErrInner
	}
	in := &Inner{}
	if in.ID, err = o.String("id"); err != nil {
		return nil, ErrInner
	}
	if in.Type, err = o.String("type"); err != nil {
		return nil, ErrInner
	}
	ts, err := o.String("ts")
	if err != nil {
		return nil, ErrInner
	}
	if in.TS, err = ParseTS(ts); err != nil {
		return nil, ErrInner
	}
	seq, hasSeq, err := o.OptUint("seq", 1, strictjson.MaxSafeInteger)
	if err != nil || hasSeq != (mode == ModeSession) {
		return nil, ErrInner
	}
	in.Seq = seq
	if re, ok, err := o.OptString("re"); err != nil || (ok && re == "") {
		return nil, ErrInner
	} else {
		in.Re = re
	}
	if exp, ok, err := o.OptString("exp"); err != nil {
		return nil, ErrInner
	} else if ok {
		if in.Exp, err = ParseTS(exp); err != nil {
			return nil, ErrInner
		}
	}
	if st, ok, err := o.OptString("status"); err != nil || (ok && st == "") {
		return nil, ErrInner
	} else {
		in.Status = st
	}
	if o.Has("error") {
		eo, err := o.Object("error")
		if err != nil {
			return nil, ErrInner
		}
		e := &Error{}
		if e.Code, err = eo.String("code"); err != nil {
			return nil, ErrInner
		}
		if msg, _, err := eo.OptString("message"); err != nil {
			return nil, ErrInner
		} else {
			e.Message = msg
		}
		in.Error = e
	}
	if arr, ok, err := o.OptArray("features"); err != nil {
		return nil, ErrInner
	} else if ok {
		// 0.86.0 (§5.3): a known member, so its form is checked.
		in.Features = make([]string, 0, len(arr))
		for _, raw := range arr {
			n, err := strictjson.AsString(raw)
			if err != nil {
				return nil, ErrInner
			}
			in.Features = append(in.Features, n)
		}
		if !ValidFeatures(in.Features) {
			return nil, ErrInner
		}
	}
	if _, err := o.Object("body"); err != nil {
		return nil, ErrInner
	}
	in.Body = append(json.RawMessage(nil), o["body"]...)
	if err := in.validate(mode); err != nil {
		return nil, err
	}
	return in, nil
}

// CheckTime applies the freshness rules (§8.4, §5.3): reject `ts` more than
// 5 minutes in the future; for durable types also more than 16 days in the
// past; and reject a message whose `exp` has passed.
func (in *Inner) CheckTime(now time.Time, durable bool) error {
	if in.TS.Sub(now) > MaxClockSkewFuture {
		return ErrClockFuture
	}
	if durable && now.Sub(in.TS) > MaxDurableAge {
		return ErrClockPast
	}
	if !in.Exp.IsZero() && now.After(in.Exp) {
		return ErrExpired
	}
	return nil
}

// EncodeInner marshals and bucket-pads an inner plaintext.
func EncodeInner(in *Inner, mode Mode) ([]byte, error) {
	j, err := in.Marshal(mode)
	if err != nil {
		return nil, err
	}
	return Pad(j)
}

// DecodeInner strictly unpads and parses a bucket-padded inner plaintext.
func DecodeInner(padded []byte, mode Mode) (*Inner, error) {
	j, err := Unpad(padded)
	if err != nil {
		return nil, err
	}
	return ParseInner(j, mode)
}
