package envelope

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestInnerSpecExactBytes(t *testing.T) {
	in := &Inner{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Type: "test.ping", TS: t0}
	b, err := in.Marshal(ModeSealed)
	if err != nil || string(b) != specInner {
		t.Fatalf("got %s (%v)", b, err)
	}
	out, err := ParseInner(b, ModeSealed)
	if err != nil || out.ID != in.ID || !out.TS.Equal(t0) {
		t.Fatalf("parse: %v", err)
	}
}

func TestInnerResponseRoundTrip(t *testing.T) {
	in := &Inner{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Type: "secret.get", TS: t0, Seq: 42,
		Re: "01JB2Z6V9K3M4N5P6Q7R8S9T0W", Exp: t0.Add(time.Minute), Status: StatusError,
		Error: &Error{Code: "not_found", Message: "no <such> & secret"}, Body: json.RawMessage(`{ "a" : [1, 2] }`)}
	b, err := in.Marshal(ModeSession)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"v":1,"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","type":"secret.get","ts":"2026-10-01T12:00:00.000Z","seq":42,"re":"01JB2Z6V9K3M4N5P6Q7R8S9T0W","exp":"2026-10-01T12:01:00.000Z","status":"error","error":{"code":"not_found","message":"no <such> & secret"},"body":{"a":[1,2]}}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
	if _, err := ParseInner(b, ModeSession); err != nil {
		t.Fatal(err)
	}
}

// §5.3 MUST fields and strict parsing.
func TestInnerMustFields(t *testing.T) {
	sess := `{"v":1,"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","type":"test.ping","ts":"2026-10-01T12:00:00.000Z","seq":1,"body":{}}`
	if _, err := ParseInner([]byte(sess), ModeSession); err != nil {
		t.Fatal(err)
	}
	rep := func(old, new string) string { return strings.Replace(sess, old, new, 1) }
	bad := map[string]string{
		"missing v":                  rep(`"v":1,`, ``),
		"v 2":                        rep(`"v":1`, `"v":2`),
		"v 1.0":                      rep(`"v":1`, `"v":1.0`),
		"v string":                   rep(`"v":1`, `"v":"1"`),
		"missing id":                 rep(`"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V",`, ``),
		"id not ULID":                rep(`01JB2Z6V9K3M4N5P6Q7R8S9T0V`, `not-a-ulid`),
		"id lowercase":               rep(`01JB2Z6V9K3M4N5P6Q7R8S9T0V`, `01jb2z6v9k3m4n5p6q7r8s9t0v`),
		"missing type":               rep(`"type":"test.ping",`, ``),
		"type uppercase":             rep(`test.ping`, `Test.Ping`),
		"type empty segment":         rep(`test.ping`, `test..ping`),
		"missing ts":                 rep(`"ts":"2026-10-01T12:00:00.000Z",`, ``),
		"ts no millis":               rep(`12:00:00.000Z`, `12:00:00Z`),
		"ts offset":                  rep(`12:00:00.000Z`, `12:00:00.000+00:00`),
		"ts micro":                   rep(`12:00:00.000Z`, `12:00:00.000000Z`),
		"ts bad date":                rep(`2026-10-01`, `2026-02-30`),
		"missing seq":                rep(`"seq":1,`, ``),
		"seq 0":                      rep(`"seq":1`, `"seq":0`),
		"seq negative":               rep(`"seq":1`, `"seq":-1`),
		"seq exponent":               rep(`"seq":1`, `"seq":1e0`),
		"seq too big":                rep(`"seq":1`, `"seq":9007199254740992`),
		"missing body":               rep(`,"body":{}`, ``),
		"body array":                 rep(`"body":{}`, `"body":[]`),
		"body null":                  rep(`"body":{}`, `"body":null`),
		"re without status":          rep(`"seq":1,`, `"seq":1,"re":"01JB2Z6V9K3M4N5P6Q7R8S9T0W",`),
		"status without re":          rep(`"seq":1,`, `"seq":1,"status":"ok",`),
		"bad status":                 rep(`"seq":1,`, `"seq":1,"re":"01JB2Z6V9K3M4N5P6Q7R8S9T0W","status":"fine",`),
		"error without status error": rep(`"seq":1,`, `"seq":1,"re":"01JB2Z6V9K3M4N5P6Q7R8S9T0W","status":"ok","error":{"code":"x"},`),
		"status error without error": rep(`"seq":1,`, `"seq":1,"re":"01JB2Z6V9K3M4N5P6Q7R8S9T0W","status":"error",`),
		"duplicate id":               rep(`"type"`, `"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0W","type"`),
		"duplicate nested":           rep(`"body":{}`, `"body":{"a":1,"a":2}`),
		"case variant":               rep(`"type"`, `"Type"`),
		"trailing":                   sess + `{}`,
		"not object":                 `[1]`,
		"invalid utf8":               rep(`test.ping`, "test.p\xffng"),
	}
	for name, s := range bad {
		if _, err := ParseInner([]byte(s), ModeSession); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Unknown fields are ignored.
	if _, err := ParseInner([]byte(rep(`"body"`, `"x-new":{"y":1},"body"`)), ModeSession); err != nil {
		t.Fatalf("unknown field: %v", err)
	}
	// seq is for session mode only.
	if _, err := ParseInner([]byte(sess), ModeSealed); err == nil {
		t.Fatal("seq accepted in sealed mode")
	}
}

// §8.4 freshness.
func TestInnerCheckTime(t *testing.T) {
	in := &Inner{TS: t0}
	if err := in.CheckTime(t0.Add(-4*time.Minute), true); err != nil {
		t.Fatal(err)
	}
	if err := in.CheckTime(t0.Add(-6*time.Minute), true); !errors.Is(err, ErrClockFuture) {
		t.Fatal("future ts accepted")
	}
	if err := in.CheckTime(t0.Add(17*24*time.Hour), true); !errors.Is(err, ErrClockPast) {
		t.Fatal("old durable ts accepted")
	}
	if err := in.CheckTime(t0.Add(17*24*time.Hour), false); err != nil {
		t.Fatal("ephemeral age checked")
	}
	in.Exp = t0.Add(30 * time.Second)
	if err := in.CheckTime(t0.Add(31*time.Second), false); !errors.Is(err, ErrExpired) {
		t.Fatal("expired accepted")
	}
}

func TestValidType(t *testing.T) {
	for _, s := range []string{"hs.init", "critical-secret.use", "wallet.payment.request", "test.ping", "a"} {
		if !ValidType(s) {
			t.Errorf("%q rejected", s)
		}
	}
	for _, s := range []string{"", ".a", "a.", "a..b", "1a", "a.-b", "A", "a b", strings.Repeat("a", 65)} {
		if ValidType(s) {
			t.Errorf("%q accepted", s)
		}
	}
}
