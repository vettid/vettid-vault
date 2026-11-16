package callswire

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
)

var t0 = time.Unix(1_800_000_000, 0).UTC()

func answer(exp int64, extra string) string {
	return `{"stun":["stun:calls.example.org:3478"],"turn":["turn:calls.example.org:3478?transport=udp","turn:calls.example.org:3478?transport=tcp"],` +
		`"credentials":[{"username":"` + strconv.FormatInt(exp, 10) + `:AAAAAAAAAAAAAAAAAAAAAA","credential":"c2VjcmV0","exp":` + strconv.FormatInt(exp, 10) + `}]` + extra + `}`
}

func TestRequestBody(t *testing.T) {
	if got := string(RequestBody(4)); got != `{"count":4}` {
		t.Fatal(got)
	}
}

// VAULT-MESSAGING §10.10: an answer that passes every rule is taken as sent; members the vault does not know are
// ignored.
func TestParseAnswer(t *testing.T) {
	exp := t0.Add(6 * time.Hour).Unix()
	a, err := ParseAnswer([]byte(answer(exp, `,"later":true`)), t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.STUN) != 1 || len(a.TURN) != 2 || len(a.Credentials) != 1 || a.Credentials[0].Exp.Unix() != exp ||
		a.Credentials[0].Credential != "c2VjcmV0" || !strings.HasSuffix(a.Credentials[0].Username, ":AAAAAAAAAAAAAAAAAAAAAA") {
		t.Fatalf("%+v", a)
	}
	if a, err := ParseAnswer([]byte(`{"stun":[],"turn":[],"credentials":[]}`), t0); err != nil || len(a.Credentials) != 0 {
		t.Fatalf("empty: %+v %v", a, err)
	}
}

// Any rule an answer breaks discards the whole answer (a failed attempt).
func TestParseAnswerRefusals(t *testing.T) {
	exp := t0.Add(time.Hour).Unix()
	cred := func(user, c string, e int64) string {
		return `{"username":"` + user + `","credential":"` + c + `","exp":` + strconv.FormatInt(e, 10) + `}`
	}
	ok := cred("u", "c", exp)
	body := func(stun, turn, creds string) string {
		return `{"stun":[` + stun + `],"turn":[` + turn + `],"credentials":[` + creds + `]}`
	}
	s, tu := `"stun:h:3478"`, `"turn:h:3478"`
	for name, b := range map[string]string{
		"not json":              `{`,
		"not an object":         `[]`,
		"no stun":               `{"turn":[],"credentials":[]}`,
		"no turn":               `{"stun":[],"credentials":[]}`,
		"no credentials":        `{"stun":[],"turn":[]}`,
		"turn in stun":          body(tu, tu, ok),
		"stun in turn":          body(s, s, ok),
		"http url":              body(`"https://h"`, tu, ok),
		"space in url":          body(`"stun:h 1"`, tu, ok),
		"empty scheme rest":     body(`"stun:"`, tu, ok),
		"long url":              body(`"stun:`+strings.Repeat("a", 512)+`"`, tu, ok),
		"five stun":             body(strings.Repeat(s+",", 4)+s, tu, ok),
		"five turn":             body(s, strings.Repeat(tu+",", 4)+tu, ok),
		"five credentials":      body(s, tu, strings.Repeat(ok+",", 4)+ok),
		"empty username":        body(s, tu, cred("", "c", exp)),
		"empty credential":      body(s, tu, cred("u", "", exp)),
		"long username":         body(s, tu, cred(strings.Repeat("u", 513), "c", exp)),
		"control in username":   body(s, tu, cred(`u\u0001`, "c", exp)),
		"long credential":       body(s, tu, cred("u", strings.Repeat("c", 513), exp)),
		"control in credential": body(s, tu, cred("u", `c\u007f`, exp)),
		"expired":               body(s, tu, cred("u", "c", t0.Unix())),
		"too far ahead":         body(s, tu, cred("u", "c", t0.Add(6*time.Hour+time.Second).Unix())),
		"exp not a number":      body(s, tu, `{"username":"u","credential":"c","exp":"1"}`),
		"exp fraction":          body(s, tu, `{"username":"u","credential":"c","exp":1.5}`),
		"no exp":                body(s, tu, `{"username":"u","credential":"c"}`),
		"url not a string":      body(`1`, tu, ok),
		"too large":             body(s, tu, ok) + strings.Repeat(" ", MaxAnswer),
	} {
		if _, err := ParseAnswer([]byte(b), t0); !errors.Is(err, ErrResponse) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The bounds themselves pass: 4 of each kind, 512-byte fields, exp exactly 6 h ahead.
	long := strings.Repeat("u", 512)
	b := body(strings.Repeat(s+",", 3)+s, strings.Repeat(tu+",", 3)+tu, strings.Repeat(cred(long, long, t0.Add(6*time.Hour).Unix())+",", 3)+ok)
	if _, err := ParseAnswer([]byte(b), t0); err != nil {
		t.Fatalf("bounds: %v", err)
	}
}

func TestParseError(t *testing.T) {
	e := ParseError(429, []byte(`{"code":"rate_limited","retry_after":99999}`))
	if e.Code != CodeRateLimited || e.RetryAfter != MaxRetryAfter || e.Status != 429 {
		t.Fatalf("%+v", e)
	}
	if e := ParseError(502, []byte(`<html>`)); e.Code != "http_502" {
		t.Fatalf("%+v", e)
	}
}

// The client signs each request with a key of its own (never the same twice), attests that key over the
// request's digest, and checks the answer against its clock.
func TestClient(t *testing.T) {
	var mu sync.Mutex
	var keys []string
	var status = http.StatusOK
	srvNow := t0
	exp := t0.Add(5 * time.Hour).Unix()
	is := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := new(bytes.Buffer)
		_, _ = b.ReadFrom(r.Body)
		sr, err := relayauth.ParseHeaders(r.Header)
		if err != nil || r.URL.Path != PathCredentials || sr.Verify(http.MethodPost, PathCredentials, relayauth.BodyHash(b.Bytes()), srvNow) != nil {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"code":"signature_invalid"}`))
			return
		}
		doc, _ := base64.StdEncoding.DecodeString(r.Header.Get(HeaderAttestation))
		d := relayauth.Digest(http.MethodPost, PathCredentials, sr.Timestamp, relayauth.BodyHash(b.Bytes()))
		if !bytes.Equal(doc, append(append([]byte{}, sr.Key...), d[:]...)) || b.String() != `{"count":2}` {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"code":"attestation_invalid"}`))
			return
		}
		mu.Lock()
		keys = append(keys, string(sr.Key))
		st := status
		mu.Unlock()
		w.WriteHeader(st)
		if st == http.StatusOK {
			_, _ = w.Write([]byte(answer(exp, "")))
		} else {
			_, _ = w.Write([]byte(`{"code":"internal","retry_after":30}`))
		}
	}))
	defer is.Close()
	c := &Client{BaseURL: is.URL, HTTP: is.Client(), Now: func() time.Time { return t0 },
		Attest: func(pub ed25519.PublicKey, d [32]byte) ([]byte, error) {
			return append(append([]byte{}, pub...), d[:]...), nil
		}}
	for range 2 {
		a, err := c.Credentials(context.Background(), 2)
		if err != nil || len(a.Credentials) != 1 {
			t.Fatalf("%+v %v", a, err)
		}
	}
	if len(keys) != 2 || keys[0] == keys[1] {
		t.Fatal("the two requests did not each have a key of their own")
	}
	status = http.StatusServiceUnavailable
	var ie *Error
	if _, err := c.Credentials(context.Background(), 2); !errors.As(err, &ie) || ie.Status != 503 || ie.RetryAfter != 30 {
		t.Fatalf("error answer: %v", err)
	}
	for _, n := range []int{0, 5} {
		if _, err := c.Credentials(context.Background(), n); !errors.Is(err, ErrResponse) {
			t.Fatalf("count %d: %v", n, err)
		}
	}
	// A clock past the credential's exp makes the same answer one the vault refuses.
	late := &Client{BaseURL: is.URL, HTTP: is.Client(), Now: func() time.Time { return time.Unix(exp, 0) }, Attest: c.Attest}
	status = http.StatusOK
	srvNow = time.Unix(exp, 0)
	if _, err := late.Credentials(context.Background(), 2); !errors.Is(err, ErrResponse) {
		t.Fatalf("an expired credential: %v", err)
	}
	is.Close()
	if _, err := c.Credentials(context.Background(), 2); !errors.Is(err, ErrTransport) {
		t.Fatalf("closed: %v", err)
	}
}

// An answer longer than MaxAnswer is refused like any other answer that fails the checks (a failed attempt).
func TestOversizedAnswerIsRefused(t *testing.T) {
	is := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte(" "), MaxAnswer+1))
	}))
	defer is.Close()
	c := &Client{BaseURL: is.URL, HTTP: is.Client()}
	if _, err := c.Credentials(context.Background(), 1); !errors.Is(err, ErrOversized) || !errors.Is(err, ErrResponse) {
		t.Fatalf("oversized: %v", err)
	}
}

// Error codes are taken only when they read as Relay Protocol §7.1 codes: lower-case letters, digits and _, 1-64.
func TestParseErrorCodes(t *testing.T) {
	for _, c := range []string{"Bad", "a-b", "", strings.Repeat("a", 65), "a b"} {
		if e := ParseError(400, []byte(`{"code":"`+c+`"}`)); e.Code != "http_400" {
			t.Errorf("%q taken: %s", c, e.Code)
		}
	}
	if e := ParseError(400, []byte(`{"code":"bad_request_2"}`)); e.Code != "bad_request_2" {
		t.Fatal(e.Code)
	}
}

// Neither an answer nor a credential prints a username or credential, however it is formatted.
func TestAnswerPrintsNoSecret(t *testing.T) {
	a := Answer{STUN: []string{"stun:h"}, Credentials: []Credential{{Username: "user-x", Credential: "secret-y", Exp: time.Unix(1, 0)}}}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, v := range []any{a, &a, a.Credentials[0], a.Credentials} {
			if s := fmt.Sprintf(f, v); strings.Contains(s, "user-x") || strings.Contains(s, "secret-y") {
				t.Fatalf("%s: %s", f, s)
			}
		}
	}
}
