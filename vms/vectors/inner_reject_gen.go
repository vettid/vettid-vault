//go:build vmsvectors

package vectors

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// The members of the baseline inner plaintext (§5.3, session mode). Each
// case below is the baseline with one change.
const (
	mV    = `"v":1`
	mID   = `"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V"`
	mType = `"type":"test.ping"`
	mTS   = `"ts":"2026-10-01T12:00:00.000Z"`
	mSeq  = `"seq":1`
	mBody = `"body":{}`
	mRe   = `"re":"01JB2Z6V9K3M4N5P6Q7R8S9T0W"`
)

func jo(ms ...string) string { return "{" + strings.Join(ms, ",") + "}" }

// session and sealed build the baseline with the given members replaced
// (by name), removed (empty value) or appended (a name not in the
// baseline).
func session(over ...string) string { return build(true, over...) }
func sealed(over ...string) string  { return build(false, over...) }

func build(withSeq bool, over ...string) string {
	base := []string{mV, mID, mType, mTS}
	if withSeq {
		base = append(base, mSeq)
	}
	base = append(base, mBody)
	name := func(m string) string {
		if strings.HasPrefix(m, dropMark) {
			return `"` + m[len(dropMark):] + `"`
		}
		return m[:strings.Index(m, ":")]
	}
	var out []string
	used := map[string]bool{}
	for _, m := range base {
		repl := m
		for _, o := range over {
			if name(o) == name(m) {
				repl = o
				used[name(o)] = true
			}
		}
		if repl != "" && !strings.HasPrefix(repl, dropMark) {
			out = append(out, repl)
		}
	}
	for _, o := range over {
		if !used[name(o)] {
			out = append(out, o)
		}
	}
	return jo(out...)
}

// dropMark starts a member that removes the named baseline member; it
// cannot occur in JSON.
const dropMark = "\x00"

// drop removes a member from the baseline.
func drop(n string) string { return dropMark + n }

type rejectCase struct {
	name, layer, mode, rule, class string
	inner                          []byte // layer inner, padded, time
	paddedLen                      int    // layer padded
	marker                         *string
	lastByte                       string
	paddedHex                      *string
	env                            []byte // layer envelope, session_open
	key                            []byte
	mutation                       string
	now                            string
	durable                        bool
}

func ptr(s string) *string { return &s }

// classOf names the library's rejection, in the words of the file.
func classOf(err error) string {
	for _, c := range []struct {
		name string
		err  error
	}{
		{"inner", envelope.ErrInner}, {"padding", envelope.ErrPadding}, {"version", envelope.ErrVersion},
		{"suite", suite.ErrSuite1}, {"suite", suite.ErrUnsupportedSuite}, {"mode", envelope.ErrMode},
		{"flags", envelope.ErrFlags}, {"length", envelope.ErrLength}, {"truncated", envelope.ErrTruncated},
		{"decrypt", envelope.ErrDecrypt}, {"clock_future", envelope.ErrClockFuture},
		{"clock_past", envelope.ErrClockPast}, {"expired", envelope.ErrExpired},
	} {
		if errors.Is(err, c.err) {
			return c.name
		}
	}
	return "other: " + err.Error()
}

func modeOf(s string) envelope.Mode {
	if s == "sealed" {
		return envelope.ModeSealed
	}
	return envelope.ModeSession
}

func paddedOf(c rejectCase) ([]byte, error) {
	if c.paddedHex != nil {
		return nil, fmt.Errorf("padded_hex is given directly")
	}
	marker := []byte{0x80}
	if c.marker != nil {
		marker = nil
		if *c.marker != "" {
			if _, err := fmt.Sscanf(*c.marker, "%x", &marker); err != nil {
				return nil, err
			}
		}
	}
	p := make([]byte, c.paddedLen)
	if len(c.inner)+len(marker) > len(p) {
		return nil, errors.New("padded length too small")
	}
	copy(p, c.inner)
	copy(p[len(c.inner):], marker)
	if c.lastByte != "" {
		var b byte
		if _, err := fmt.Sscanf(c.lastByte, "%x", &b); err != nil {
			return nil, err
		}
		p[len(p)-1] = b
	}
	return p, nil
}

// run feeds a case to the real parser and returns its rejection class, or
// an error if the parser accepts it.
func (c rejectCase) run() (string, error) {
	var err error
	switch c.layer {
	case "inner":
		_, err = envelope.ParseInner(c.inner, modeOf(c.mode))
	case "padded":
		var p []byte
		if c.paddedHex != nil {
			p = []byte{}
		} else if p, err = paddedOf(c); err != nil {
			return "", err
		}
		_, err = envelope.DecodeInner(p, modeOf(c.mode))
	case "envelope":
		_, err = envelope.Parse(c.env)
	case "session_open":
		var e *envelope.Envelope
		if e, err = envelope.Parse(c.env); err != nil {
			return "", fmt.Errorf("the envelope must parse: %w", err)
		}
		_, err = envelope.OpenSession(e, c.key)
	case "time":
		var in *envelope.Inner
		if in, err = envelope.ParseInner(c.inner, envelope.ModeSession); err != nil {
			return "", fmt.Errorf("the inner must parse: %w", err)
		}
		now, perr := time.Parse(time.RFC3339, c.now)
		if perr != nil {
			return "", perr
		}
		err = in.CheckTime(now, c.durable)
	default:
		return "", fmt.Errorf("layer %q", c.layer)
	}
	if err == nil {
		return "", fmt.Errorf("case %s is accepted by the parser", c.name)
	}
	return classOf(err), nil
}

func (c rejectCase) obj() obj {
	o := obj{{"case", c.name}, {"layer", c.layer}}
	if c.mode != "" {
		o = append(o, member{"mode", c.mode})
	}
	o = append(o, member{"rule", c.rule}, member{"error", c.class})
	text := func(b []byte) {
		if utf8.Valid(b) && !bytes.HasPrefix(b, []byte("\xef\xbb\xbf")) {
			o = append(o, member{"inner", string(b)})
		} else {
			o = append(o, member{"inner_hex", hx(b)})
		}
	}
	switch c.layer {
	case "inner":
		text(c.inner)
	case "padded":
		if c.paddedHex != nil {
			o = append(o, member{"padded_hex", *c.paddedHex})
			break
		}
		text(c.inner)
		o = append(o, member{"padded_len", c.paddedLen})
		if c.marker != nil {
			o = append(o, member{"marker_hex", *c.marker})
		}
		if c.lastByte != "" {
			o = append(o, member{"last_byte_hex", c.lastByte})
		}
	case "envelope":
		o = append(o, member{"mutation", c.mutation}, member{"envelope_b64", b64(c.env)})
	case "session_open":
		o = append(o, member{"mutation", c.mutation}, member{"key_hex", hx(c.key)}, member{"envelope_b64", b64(c.env)})
	case "time":
		text(c.inner)
		o = append(o, member{"now", c.now}, member{"durable", c.durable})
	}
	return o
}

// genInnerReject builds inner_reject.json (§5.2, §5.3, §5.4): plaintexts and
// envelopes a receiver MUST reject. Every case is fed to the library's
// parser here, and must be rejected with the stated error class; each is the
// baseline with one change, so that a receiver that accepts it is wrong for
// that reason alone. sessEnv is envelope_session.json's envelope.
func genInnerReject(sessEnv []byte) (obj, error) {
	var cs []rejectCase
	inner := func(rule, mode string, named ...string) {
		// named: name, text, name, text, ...
		for i := 0; i < len(named); i += 2 {
			cs = append(cs, rejectCase{name: named[i], layer: "inner", mode: mode, rule: rule, class: "inner", inner: []byte(named[i+1])})
		}
	}
	rawInner := func(rule, name string, b []byte) {
		cs = append(cs, rejectCase{name: name, layer: "inner", mode: "session", rule: rule, class: "inner", inner: b})
	}
	S := session
	long := func(n int) string { return strings.Repeat("a", n) }

	inner("§5.3: v, id, type, ts and body are required; seq in session mode", "session",
		"missing_v", S(drop("v")), "missing_id", S(drop("id")), "missing_type", S(drop("type")),
		"missing_ts", S(drop("ts")), "missing_body", S(drop("body")), "missing_seq_in_session_mode", S(drop("seq")))
	inner("§5.3: seq MUST be absent in sealed mode", "sealed",
		"seq_in_sealed_mode", sealed(mSeq))
	inner("§5.3: v MUST be the integer 1 (plain integer: no fraction, exponent or sign, no leading zero)", "session",
		"v_2", S(`"v":2`), "v_0", S(`"v":0`), "v_string", S(`"v":"1"`), "v_fraction", S(`"v":1.0`),
		"v_exponent", S(`"v":1e0`), "v_true", S(`"v":true`), "v_null", S(`"v":null`), "v_leading_zero", S(`"v":01`))
	inner("§5.3: id MUST be a canonical ULID: 26 upper-case Crockford base32 characters, the first in 0-7", "session",
		"id_lowercase", S(`"id":"01jb2z6v9k3m4n5p6q7r8s9t0v"`),
		"id_25_characters", S(`"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0"`),
		"id_27_characters", S(`"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0VV"`),
		"id_first_character_8", S(`"id":"81JB2Z6V9K3M4N5P6Q7R8S9T0V"`),
		"id_letter_U", S(`"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0U"`),
		"id_letter_I", S(`"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0I"`),
		"id_letter_L", S(`"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0L"`),
		"id_letter_O", S(`"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0O"`),
		"id_empty", S(`"id":""`), "id_number", S(`"id":1`), "id_null", S(`"id":null`))
	inner("§5.3: type MUST match [a-z][a-z0-9-]*(\\.[a-z][a-z0-9-]*)* and be at most 64 bytes", "session",
		"type_uppercase", S(`"type":"Test.ping"`), "type_empty", S(`"type":""`), "type_empty_segment", S(`"type":"a..b"`),
		"type_leading_dot", S(`"type":".a"`), "type_trailing_dot", S(`"type":"a."`),
		"type_segment_starts_with_digit", S(`"type":"a.1b"`), "type_segment_starts_with_hyphen", S(`"type":"a.-b"`),
		"type_underscore", S(`"type":"a_b"`), "type_65_bytes", S(`"type":"`+long(65)+`"`),
		"type_number", S(`"type":1`), "type_null", S(`"type":null`))
	inner("§5.3: ts MUST be YYYY-MM-DDTHH:MM:SS.mmmZ: RFC 3339, UTC, exactly three fractional digits, a literal Z, and a real date and time", "session",
		"ts_no_fraction", S(`"ts":"2026-10-01T12:00:00Z"`), "ts_two_fraction_digits", S(`"ts":"2026-10-01T12:00:00.00Z"`),
		"ts_six_fraction_digits", S(`"ts":"2026-10-01T12:00:00.000000Z"`), "ts_numeric_offset", S(`"ts":"2026-10-01T12:00:00.000+00:00"`),
		"ts_lowercase_z", S(`"ts":"2026-10-01T12:00:00.000z"`), "ts_space_for_T", S(`"ts":"2026-10-01 12:00:00.000Z"`),
		"ts_not_a_date", S(`"ts":"2026-02-30T12:00:00.000Z"`), "ts_hour_24", S(`"ts":"2026-10-01T24:00:00.000Z"`),
		"ts_date_only", S(`"ts":"2026-10-01"`), "ts_unix_number", S(`"ts":1790856000`), "ts_null", S(`"ts":null`))
	inner("§5.3: seq MUST be an integer from 1 to 2^53-1 (plain integer: no sign, fraction or exponent)", "session",
		"seq_zero", S(`"seq":0`), "seq_negative", S(`"seq":-1`), "seq_fraction", S(`"seq":1.5`), "seq_exponent", S(`"seq":1e2`),
		"seq_string", S(`"seq":"1"`), "seq_2_pow_53", S(`"seq":9007199254740992`), "seq_null", S(`"seq":null`))
	inner("§5.3: re and status appear together or not at all; status is ok or error; error is present if and only if status is error", "session",
		"re_without_status", S(mRe), "status_without_re", S(`"status":"ok"`),
		"status_unknown_value", S(mRe, `"status":"done"`), "status_empty", S(mRe, `"status":""`),
		"status_not_a_string", S(mRe, `"status":1`),
		"status_error_without_error", S(mRe, `"status":"error"`),
		"status_ok_with_error", S(mRe, `"status":"ok"`, `"error":{"code":"not_found"}`),
		"error_without_status", S(`"error":{"code":"not_found"}`),
		"error_null", S(mRe, `"status":"error"`, `"error":null`))
	inner("§5.3: re MUST be a canonical ULID", "session",
		"re_lowercase", S(`"re":"01jb2z6v9k3m4n5p6q7r8s9t0w"`, `"status":"ok"`), "re_empty", S(`"re":""`, `"status":"ok"`),
		"re_short", S(`"re":"01JB2Z6V9K3M4N5P6Q7R8S9T0"`, `"status":"ok"`), "re_number", S(`"re":1`, `"status":"ok"`))
	inner("§5.3: error.code MUST match [a-z_][a-z0-9_]* and be at most 64 bytes; error.message, if present, is a string; error is an object", "session",
		"error_code_uppercase", S(mRe, `"status":"error"`, `"error":{"code":"Not_Found"}`),
		"error_code_empty", S(mRe, `"status":"error"`, `"error":{"code":""}`),
		"error_code_leading_digit", S(mRe, `"status":"error"`, `"error":{"code":"1abc"}`),
		"error_code_hyphen", S(mRe, `"status":"error"`, `"error":{"code":"not-found"}`),
		"error_code_65_bytes", S(mRe, `"status":"error"`, `"error":{"code":"`+long(65)+`"}`),
		"error_code_missing", S(mRe, `"status":"error"`, `"error":{"message":"x"}`),
		"error_code_number", S(mRe, `"status":"error"`, `"error":{"code":1}`),
		"error_message_number", S(mRe, `"status":"error"`, `"error":{"code":"a","message":1}`),
		"error_not_an_object", S(mRe, `"status":"error"`, `"error":"not_found"`))
	inner("§5.3: exp, if present, MUST use the same format as ts", "session",
		"exp_no_fraction", S(`"exp":"2026-10-01T13:00:00Z"`), "exp_number", S(`"exp":1790859600`),
		"exp_numeric_offset", S(`"exp":"2026-10-01T13:00:00.000+00:00"`), "exp_null", S(`"exp":null`))
	inner("§5.3: body MUST be a JSON object ({} when empty)", "session",
		"body_array", S(`"body":[]`), "body_string", S(`"body":"x"`), "body_null", S(`"body":null`), "body_number", S(`"body":0`),
		"body_true", S(`"body":true`))
	inner("§5.3: receivers MUST reject duplicate member names at any depth (names are compared after unescaping)", "session",
		"duplicate_v", jo(mV, mV, mID, mType, mTS, mSeq, mBody),
		"duplicate_id_same_value", jo(mV, mID, mID, mType, mTS, mSeq, mBody),
		"duplicate_id_different_value", jo(mV, mID, `"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0W"`, mType, mTS, mSeq, mBody),
		"duplicate_id_escaped_name", jo(mV, mID, `"\u0069d":"01JB2Z6V9K3M4N5P6Q7R8S9T0W"`, mType, mTS, mSeq, mBody),
		"duplicate_body_last", jo(mV, mID, mType, mTS, mSeq, mBody, `"body":{}`),
		"duplicate_in_body", S(`"body":{"a":1,"a":2}`),
		"duplicate_in_nested_body", S(`"body":{"x":{"y":[{"z":1,"z":2}]}}`),
		"duplicate_in_error", S(mRe, `"status":"error"`, `"error":{"code":"a","code":"b"}`),
		"duplicate_unknown_member", S(`"x":1`, `"x":2`))
	inner("§5.3: member names are case-sensitive: a member under another case is not the member", "session",
		"member_name_V", jo(`"V":1`, mID, mType, mTS, mSeq, mBody), "member_name_Id", jo(mV, `"Id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V"`, mType, mTS, mSeq, mBody),
		"member_name_Body", jo(mV, mID, mType, mTS, mSeq, `"Body":{}`), "member_name_SEQ", jo(mV, mID, mType, mTS, `"SEQ":1`, mBody))

	// Nesting depth (§10.19.8, 0.81.6): at most 32 levels, the inner
	// message being level 1 and its body level 2.
	nest := func(levels int) string { // body nested to a total depth of `levels`
		return session(`"body":` + strings.Repeat(`{"a":`, levels-2) + `{}` + strings.Repeat(`}`, levels-2))
	}
	inner("§10.19.8 / 0.81.6: nesting depth at most 32, the inner message is level 1", "session", "depth_33", nest(33))
	if _, err := envelope.ParseInner([]byte(nest(32)), envelope.ModeSession); err != nil {
		return nil, fmt.Errorf("depth 32 must be accepted: %w", err)
	}

	// Not strict JSON, or not a single object.
	ok := session()
	inner("§5.3: the inner plaintext MUST be one JSON object, and nothing may follow it", "session",
		"data_after_object_object", ok+`{}`, "data_after_object_text", ok+`x`, "data_after_object_second_copy", ok+ok,
		"data_after_object_comma", ok+`,`, "data_after_object_null", ok+` null`)
	inner("§5.3: the inner plaintext MUST be a JSON object (strict JSON: RFC 8259)", "session",
		"top_level_array", `[`+ok+`]`, "top_level_string", `"x"`, "top_level_number", `1`, "top_level_null", `null`,
		"empty_input", ``, "whitespace_only", " \n", "truncated_object", ok[:len(ok)-1], "unterminated_string", `{"v":1,"id":"`,
		"trailing_comma", `{"v":1,"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","type":"test.ping","ts":"2026-10-01T12:00:00.000Z","seq":1,"body":{},}`,
		"leading_comma", `{,"v":1,"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","type":"test.ping","ts":"2026-10-01T12:00:00.000Z","seq":1,"body":{}}`,
		"single_quoted_names", `{'v':1,'id':'01JB2Z6V9K3M4N5P6Q7R8S9T0V','type':'test.ping','ts':'2026-10-01T12:00:00.000Z','seq':1,'body':{}}`,
		"unquoted_names", `{v:1,id:"01JB2Z6V9K3M4N5P6Q7R8S9T0V",type:"test.ping",ts:"2026-10-01T12:00:00.000Z",seq:1,body:{}}`,
		"comment_before", `/*x*/`+ok, "comment_inside", S(`"body":{/*x*/}`), "line_comment", ok+"//x",
		"nan_member", S(`"x":NaN`), "infinity_member", S(`"x":Infinity`), "hex_number_member", S(`"x":0x10`),
		"leading_zero_member", S(`"x":01`), "plus_sign_member", S(`"x":+1`), "lone_decimal_point_member", S(`"x":1.`),
		"raw_newline_in_string", S(`"x":"a`+"\n"+`b"`), "raw_tab_in_string", S(`"x":"a`+"\t"+`b"`),
		"invalid_escape", S(`"x":"\q"`), "short_unicode_escape", S(`"x":"\u12"`))
	inner("§5.3 / RFC 8259 §7: the four characters after \\u are ASCII hex digits", "session",
		"unicode_escape_non_ascii_hex_digits", S(`"x":"\u００41"`))
	rawInner("§5.3: the inner plaintext (including its body) MUST be valid UTF-8", "invalid_utf8_in_body_string", []byte(S(`"body":{"a":"`+"\xff"+`"}`)))
	rawInner("§5.3: the inner plaintext (including its body) MUST be valid UTF-8", "invalid_utf8_in_unknown_member", []byte(S(`"x":"`+"\xc3\x28"+`"`)))
	rawInner("§5.3: the inner plaintext (including its body) MUST be valid UTF-8 (overlong encoding of '/')", "overlong_utf8", []byte(S(`"x":"`+"\xc0\xaf"+`"`)))
	rawInner("§5.3: the inner plaintext (including its body) MUST be valid UTF-8 (UTF-16 surrogate encoded in UTF-8)", "utf8_encoded_surrogate", []byte(S(`"x":"`+"\xed\xa0\x80"+`"`)))
	rawInner("§5.3: the inner plaintext (including its body) MUST be valid UTF-8 (truncated sequence)", "truncated_utf8_sequence", []byte(S(`"x":"`+"\xe2\x82"+`"`)))
	rawInner("§5.3: the inner plaintext is a UTF-8 JSON object; these UTF-16 bytes begin with 0xff, which is not valid UTF-8", "utf16_encoding", []byte("\xff\xfe{\x00}\x00"))

	// 0.83.1: a byte order mark, and a \u escape of a surrogate that is not
	// half of a pair (member names included), are refused, never repaired.
	const r831 = "§5.3 (0.83.1): the inner plaintext MUST NOT "
	rawInner(r831+"begin with a byte order mark (EF BB BF); RFC 8259 §8.1 lets a parser ignore one, here it is an error", "bom", []byte("\xef\xbb\xbf"+session()))
	inner(r831+"contain a \\u escape of a surrogate that is not part of a pair: a high one (D800-DBFF) must be followed at once by a \\u escape of a low one (DC00-DFFF)", "session",
		"surrogate_high_then_non_low_escape", S(`"x":"\ud800\u0041"`),
		"surrogate_high_then_ascii", S(`"x":"\ud800A"`),
		"surrogate_high_at_end_of_string", S(`"x":"a\udbff"`),
		"surrogate_high_then_raw_character", S(`"x":"\ud800`+"\u00e9"+`"`),
		"surrogate_high_then_high", S(`"x":"\ud800\udbff"`),
		"surrogate_unpaired_uppercase", S(`"x":"\uD800"`),
		"surrogate_high_in_body", S(`"body":{"a":["\ud83d"]}`))
	inner(r831+"contain a \\u escape of a surrogate that is not part of a pair: a low one (DC00-DFFF) must be preceded at once by a high one", "session",
		"surrogate_lone_low", S(`"x":"\udc00"`),
		"surrogate_low_after_complete_pair", S(`"x":"\ud83d\ude00\udc00"`))
	inner(r831+"contain a \\u escape of an unpaired surrogate in a member name", "session",
		"surrogate_unpaired_in_member_name", S(`"\ud800":1`),
		"surrogate_unpaired_in_body_member_name", S(`"body":{"a\udc00":1}`))

	// Padding (§5.4): DecodeInner on the padded plaintext.
	pad := func(name, rule string, c rejectCase) {
		c.name, c.layer, c.mode, c.rule, c.class = name, "padded", "session", rule, "padding"
		if c.inner == nil && c.paddedHex == nil {
			c.inner = []byte(session())
		}
		cs = append(cs, c)
	}
	r54 := "§5.4: padding is json || 0x80 || 0x00*, to exactly the bucket for len(json)+1: a multiple of 512 up to 16 KiB, then of 16 KiB, at most 245,760 bytes"
	pad("padding_no_marker", r54+"; no marker at all", rejectCase{paddedLen: 512, marker: ptr("")})
	pad("padding_marker_0x81", r54+"; the last non-zero byte MUST be 0x80", rejectCase{paddedLen: 512, marker: ptr("81")})
	pad("padding_non_zero_after_marker", r54+"; only zeros may follow the marker", rejectCase{paddedLen: 512, lastByte: "01"})
	pad("padding_over_padded_1024", r54+"; over-padding to a larger bucket is malformed", rejectCase{paddedLen: 1024})
	pad("padding_over_padded_16384", r54+"; over-padding to a larger bucket is malformed", rejectCase{paddedLen: 16384})
	pad("padding_length_513", r54+"; 513 is not a bucket size", rejectCase{paddedLen: 513})
	pad("padding_length_511", r54+"; 511 is not a bucket size", rejectCase{paddedLen: 511})
	pad("padding_length_16896", r54+"; above 16 KiB the sizes are multiples of 16 KiB", rejectCase{paddedLen: 16896})
	pad("padding_length_0", r54+"; empty", rejectCase{paddedHex: ptr("")})
	pad("padding_unpadded_json", r54+"; the JSON without padding", rejectCase{paddedLen: len(session()), marker: ptr("")})

	// Envelopes (§5.2): Parse; and session-mode decryption.
	env := func(name, rule, mutation string, f func(b []byte) []byte) {
		b := f(bytes.Clone(sessEnv))
		cs = append(cs, rejectCase{name: name, layer: "envelope", rule: rule, mutation: mutation, env: b})
	}
	set := func(i int, v byte) func([]byte) []byte { return func(b []byte) []byte { b[i] = v; return b } }
	r52 := "§5.2: the header and the ciphertext length are checked before anything is decrypted"
	env("envelope_version_3", "§5.2: ver MUST be 0x02", "byte 0 = 0x03", set(0, 3))
	env("envelope_version_1", "§5.2: ver MUST be 0x02", "byte 0 = 0x01", set(0, 1))
	env("envelope_version_0", "§5.2: ver MUST be 0x02", "byte 0 = 0x00", set(0, 0))
	env("envelope_suite_1", "§5.2, §13.4: suite 1 is never accepted", "byte 1 = 0x01", set(1, 1))
	env("envelope_suite_0", "§5.2: suite MUST be 0x02", "byte 1 = 0x00", set(1, 0))
	env("envelope_suite_3", "§5.2: suite MUST be 0x02 (an unknown suite)", "byte 1 = 0x03", set(1, 3))
	env("envelope_mode_0", "§5.2: mode is 0x01 session or 0x02 sealed", "byte 2 = 0x00", set(2, 0))
	env("envelope_mode_3", "§5.2: mode is 0x01 session or 0x02 sealed", "byte 2 = 0x03", set(2, 3))
	env("envelope_flags_1", "§5.2: flags are reserved; non-zero MUST be rejected", "byte 3 = 0x01", set(3, 1))
	env("envelope_flags_0x80", "§5.2: flags are reserved; non-zero MUST be rejected", "byte 3 = 0x80", set(3, 0x80))
	env("envelope_empty", r52, "no bytes", func(b []byte) []byte { return nil })
	env("envelope_19_bytes", r52, "cut to 19 bytes, inside the fixed header", func(b []byte) []byte { return b[:19] })
	env("envelope_header_only", r52, "cut to the 44-byte session header", func(b []byte) []byte { return b[:44] })
	env("envelope_no_room_for_a_bucket", r52, "cut to 44 + 15 bytes: header plus less than the tag", func(b []byte) []byte { return b[:44+15] })
	env("envelope_ciphertext_one_byte_short", r52, "last byte removed: padded length + 16 is not a bucket size", func(b []byte) []byte { return b[:len(b)-1] })
	env("envelope_ciphertext_1025_bytes", r52, "extended to 44 + 16 + 1025 bytes: padded length 1025 is not a bucket size", func(b []byte) []byte { return append(b, make([]byte, 44+16+1025-len(b))...) })
	env("envelope_ciphertext_not_a_multiple_of_512", r52, "cut to 44 + 16 + 513 bytes", func(b []byte) []byte { return append(b[:44+16+512], 0) })
	for i := range cs {
		switch cs[i].name {
		case "envelope_version_3", "envelope_version_1", "envelope_version_0":
			cs[i].class = "version"
		case "envelope_suite_1", "envelope_suite_0", "envelope_suite_3":
			cs[i].class = "suite"
		case "envelope_mode_0", "envelope_mode_3":
			cs[i].class = "mode"
		case "envelope_flags_1", "envelope_flags_0x80":
			cs[i].class = "flags"
		case "envelope_empty", "envelope_19_bytes", "envelope_header_only", "envelope_no_room_for_a_bucket", "envelope_ciphertext_one_byte_short":
			cs[i].class = "truncated"
		default:
			if cs[i].layer == "envelope" {
				cs[i].class = "length"
			}
		}
	}
	open := func(name, mutation string, f func(b []byte)) {
		b := bytes.Clone(sessEnv)
		f(b)
		cs = append(cs, rejectCase{name: name, layer: "session_open", class: "decrypt", mutation: mutation, env: b, key: rep(KeySession, 32),
			rule: "§5.2: the AEAD authenticates the header (aad = bytes[0:44]) and the ciphertext; a receiver MUST reject what does not verify"})
	}
	open("session_ciphertext_bit_flipped", "bit 0 of byte 44 flipped", func(b []byte) { b[44] ^= 1 })
	open("session_tag_bit_flipped", "bit 0 of the last byte flipped", func(b []byte) { b[len(b)-1] ^= 1 })
	open("session_nonce_bit_flipped", "bit 0 of byte 20 flipped", func(b []byte) { b[20] ^= 1 })
	open("session_sender_kid_changed", "bit 0 of byte 4 flipped (the header is the AAD)", func(b []byte) { b[4] ^= 1 })
	open("session_recipient_kid_changed", "bit 0 of byte 12 flipped (the header is the AAD)", func(b []byte) { b[12] ^= 1 })

	// Freshness (§5.3, §8.4): the inner parses; the time check refuses it.
	tm := func(name, rule, class, inner, now string, durable bool) {
		cs = append(cs, rejectCase{name: name, layer: "time", mode: "session", rule: rule, class: class, inner: []byte(inner), now: now, durable: durable})
	}
	tm("ts_more_than_5_minutes_in_the_future", "§8.4: reject a ts more than 5 minutes in the future", "clock_future",
		session(), "2026-10-01T11:54:59.999Z", false)
	tm("ts_more_than_5_minutes_in_the_future_durable", "§8.4: reject a ts more than 5 minutes in the future", "clock_future",
		session(), "2026-10-01T11:54:59.999Z", true)
	tm("ts_more_than_16_days_old_durable", "§8.4: reject a durable message whose ts is more than 16 days in the past", "clock_past",
		session(), "2026-10-17T12:00:00.001Z", true)
	tm("exp_passed", "§5.3: discard a message whose exp has passed", "expired",
		session(`"exp":"2026-10-01T12:30:00.000Z"`), "2026-10-01T12:30:00.001Z", false)
	tm("exp_passed_durable", "§5.3: discard a message whose exp has passed", "expired",
		session(`"exp":"2026-10-01T12:00:00.000Z"`), "2026-10-02T12:00:00.000Z", true)

	var list []any
	distinct := map[string]string{}
	for _, c := range cs {
		key := fmt.Sprintf("%s|%s|%q|%d|%v|%v|%s|%x|%x|%s|%v", c.layer, c.mode, c.inner, c.paddedLen, c.marker, c.paddedHex, c.lastByte, c.env, c.key, c.now, c.durable)
		if prev, dup := distinct[key]; dup {
			return nil, fmt.Errorf("cases %s and %s have the same input", prev, c.name)
		}
		distinct[key] = c.name
		got, err := c.run()
		if err != nil {
			return nil, err
		}
		if got != c.class {
			return nil, fmt.Errorf("case %s: rejected as %q, want %q", c.name, got, c.class)
		}
		list = append(list, c.obj())
	}
	// The baselines are accepted: a case is rejected for its one change.
	for _, b := range []struct {
		mode  envelope.Mode
		inner string
	}{{envelope.ModeSession, session()}, {envelope.ModeSealed, sealed()}} {
		if _, err := envelope.ParseInner([]byte(b.inner), b.mode); err != nil {
			return nil, err
		}
	}
	// A valid escaped pair (U+1F600) and noncharacters (U+FDD0, U+FFFF as
	// escapes) are accepted, in a value and in a member name.
	pairInner := session(`"body":{"\ud83d\ude00":"\ud83d\ude00\ufdd0\ufffe\uffff","decoy":"\\ud800"}`)
	if in, err := envelope.ParseInner([]byte(pairInner), envelope.ModeSession); err != nil {
		return nil, fmt.Errorf("the surrogate pair baseline must be accepted: %w", err)
	} else if !bytes.Contains(in.Body, []byte(`\ud83d\ude00`)) {
		return nil, errors.New("the surrogate pair baseline lost its body")
	}
	return obj{
		{"description", "VAULT-MESSAGING §5.2-§5.4 inner-plaintext and envelope must-reject corpus. Every case is rejected by a receiver, and by the library's parser here. Each is the baseline inner plaintext (accepted) with one change, in the layer named: `inner` = the unpadded JSON handed to the inner parser in `mode`; `padded` = the padded plaintext (inner || marker || zeros to padded_len, marker_hex default 80, last_byte_hex replaces the last byte, or padded_hex given whole) handed to unpad-and-parse; `envelope` = the envelope bytes (envelope_session.json's with the mutation) handed to the envelope parser before any decryption; `session_open` = the envelope parses and is opened with key_hex, which fails; `time` = the inner parses in session mode, and the freshness check at `now` (RFC 3339) fails (durable: also the 16-day limit). `inner` is the UTF-8 text, or `inner_hex` the bytes when they are not valid UTF-8. `rule` names the spec rule. `error` is the class of the rejection and is informative: an implementation MUST reject every case but need not match the class, which follows the Go library's errors: inner (malformed inner plaintext), padding, version, suite, mode, flags, length, truncated, decrypt, clock_future, clock_past, expired; a receiver need only reject, the class says why. The `bom` case is given as `inner_hex`. The baseline_surrogate_pair_inner is the opposite: it is ACCEPTED and carries a valid escaped surrogate pair and escaped noncharacters (including U+FFFE) and an escaped-backslash decoy (the JSON string \\\\ud800 is the literal text \\ud800), which a receiver MUST NOT refuse."},
		{"baseline_session_inner", session()},
		{"baseline_sealed_inner", sealed()},
		{"baseline_depth_32_inner", nest(32)},
		{"baseline_surrogate_pair_inner", pairInner},
		{"cases", list},
	}, nil
}
