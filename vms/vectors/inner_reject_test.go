package vectors

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// rejectClass names the rejection of the library, in the words of
// inner_reject.json.
func rejectClass(err error) string {
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

// checkInnerRejectVectors feeds every case of inner_reject.json to the
// library's parser and requires its rejection, with the stated class. The
// baselines must be accepted.
func checkInnerRejectVectors(t *testing.T, dir string) {
	d := load(t, dir, "inner_reject.json")
	if _, err := envelope.ParseInner([]byte(d.str("baseline_session_inner")), envelope.ModeSession); err != nil {
		t.Fatalf("session baseline: %v", err)
	}
	if _, err := envelope.ParseInner([]byte(d.str("baseline_sealed_inner")), envelope.ModeSealed); err != nil {
		t.Fatalf("sealed baseline: %v", err)
	}
	var cases []map[string]json.RawMessage
	if err := json.Unmarshal(d.m["cases"], &cases); err != nil || len(cases) < 100 {
		t.Fatalf("cases: %v (%d)", err, len(cases))
	}
	seen := map[string]bool{}
	inputs := map[string]string{}
	for _, raw := range cases {
		c := doc{t, raw}
		name := c.str("case")
		if seen[name] {
			t.Errorf("%s: duplicate case name", name)
		}
		seen[name] = true
		// Every case's input is distinct: the case object without its
		// name, rule and error.
		in := map[string]json.RawMessage{}
		for k, v := range raw {
			if k != "case" && k != "rule" && k != "error" && k != "mutation" {
				in[k] = v
			}
		}
		kb, _ := json.Marshal(in) // map keys are sorted
		if prev, dup := inputs[string(kb)]; dup {
			t.Errorf("%s: same input as %s", name, prev)
		}
		inputs[string(kb)] = name
		if c.str("rule") == "" || c.str("error") == "" {
			t.Errorf("%s: no rule or error", name)
		}
		mode := envelope.ModeSession
		if _, ok := raw["mode"]; ok && c.str("mode") == "sealed" {
			mode = envelope.ModeSealed
		}
		// The inner plaintext of the case, as bytes.
		innerBytes := func() []byte {
			if _, ok := raw["inner_hex"]; ok {
				if _, text := raw["inner"]; text {
					t.Errorf("%s: both inner and inner_hex", name)
				}
				return c.hex("inner_hex")
			}
			s := c.str("inner")
			if !utf8.ValidString(s) {
				t.Errorf("%s: inner is not UTF-8", name)
			}
			return []byte(s)
		}
		var err error
		switch layer := c.str("layer"); layer {
		case "inner":
			_, err = envelope.ParseInner(innerBytes(), mode)
		case "padded":
			var p []byte
			if _, ok := raw["padded_hex"]; ok {
				p = c.hex("padded_hex")
			} else {
				marker := []byte{0x80}
				if _, ok := raw["marker_hex"]; ok {
					marker = c.hex("marker_hex")
				}
				in := innerBytes()
				p = make([]byte, c.num("padded_len"))
				if len(in)+len(marker) > len(p) {
					t.Fatalf("%s: padded_len too small", name)
				}
				copy(p, in)
				copy(p[len(in):], marker)
				if _, ok := raw["last_byte_hex"]; ok {
					p[len(p)-1] = c.hex("last_byte_hex")[0]
				}
			}
			_, err = envelope.DecodeInner(p, mode)
		case "envelope":
			_, err = envelope.Parse(c.b64("envelope_b64"))
		case "session_open":
			e, perr := envelope.Parse(c.b64("envelope_b64"))
			if perr != nil {
				t.Errorf("%s: the envelope must parse: %v", name, perr)
				continue
			}
			_, err = envelope.OpenSession(e, c.hex("key_hex"))
		case "time":
			in, perr := envelope.ParseInner(innerBytes(), envelope.ModeSession)
			if perr != nil {
				t.Errorf("%s: the inner must parse: %v", name, perr)
				continue
			}
			var durable bool
			if json.Unmarshal(raw["durable"], &durable) != nil {
				t.Fatalf("%s: durable", name)
			}
			now, terr := time.Parse(time.RFC3339, c.str("now"))
			if terr != nil {
				t.Fatalf("%s: now: %v", name, terr)
			}
			err = in.CheckTime(now, durable)
		default:
			t.Errorf("%s: layer %q", name, layer)
			continue
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if got := rejectClass(err); got != c.str("error") {
			t.Errorf("%s: rejected as %q, want %q", name, got, c.str("error"))
		}
	}
}
