package pushwire

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// VAULT-MESSAGING 0.24.1 §14.1 check 5 (owner decision 2026-10-10): every
// answer the gateway gave over HTTP counts toward push_registrations, an
// unparsable or oversized one included; a timeout or no connection does
// not.
func TestClientAnswered(t *testing.T) {
	var mu sync.Mutex
	var status int
	var body string
	var delay time.Duration
	set := func(s int, b string, d time.Duration) {
		mu.Lock()
		status, body, delay = s, b, d
		mu.Unlock()
	}
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		status, body, delay := status, body, delay
		mu.Unlock()
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
			}
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer gw.Close()
	_, key, _ := ed25519.GenerateKey(nil)
	reg := Registration{Platform: PlatformFCM, Token: "t", AppID: "a"}
	c := &Client{BaseURL: gw.URL, HTTP: gw.Client()}
	for _, x := range []struct {
		name     string
		status   int
		body     string
		want     error
		answered bool
	}{
		{"202", 202, `{"pending":"UEVORA"}`, nil, true},
		{"unparsable 202", 202, `{"pending":`, ErrResponse, true},
		{"oversized 202", 202, `{"pending":"` + strings.Repeat("A", MaxAnswer) + `"}`, ErrOversized, true},
		// PUSH-GATEWAY 0.5.0: a one-step 201 is no longer a registration.
		{"201", 201, `{"wake_blob":"QUJD"}`, nil, true},
		{"oversized 403", 403, strings.Repeat(" ", MaxAnswer+1), ErrOversized, true},
		{"oversized 502", 502, strings.Repeat(" ", MaxAnswer+1), ErrOversized, true},
		{"403", 403, `{"code":"attestation_invalid"}`, nil, true},
		{"401", 401, `{"code":"signature_invalid"}`, nil, true},
	} {
		set(x.status, x.body, 0)
		_, err := c.Register(context.Background(), key, reg)
		var ge *Error
		if x.want != nil && !errors.Is(err, x.want) || x.want == nil && x.status != 202 && !errors.As(err, &ge) || x.status == 202 && x.want == nil && err != nil {
			t.Errorf("%s: %v", x.name, err)
		}
		if Answered(err) != x.answered {
			t.Errorf("%s: answered %v", x.name, !x.answered)
		}
	}
	// A timeout: not answered.
	set(202, `{"pending":"UEVORA"}`, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	_, err := c.Register(ctx, key, reg)
	cancel()
	if !errors.Is(err, ErrTransport) || Answered(err) {
		t.Fatalf("timeout: %v", err)
	}
	// No connection: not answered.
	gw.Close()
	if _, err := c.Register(context.Background(), key, reg); !errors.Is(err, ErrTransport) || Answered(err) {
		t.Fatalf("closed: %v", err)
	}
	if Answered(context.DeadlineExceeded) || Answered(errors.New("x")) {
		t.Fatal("other errors answered")
	}
}

// PUSH-GATEWAY 0.5.0 §5.1: the registration answers 202 {pending}; the
// confirmation is POST /v1/confirm {pending, code}, signed by the same
// key, without an attestation, answered 201 {wake_blob}.
func TestClientRegisterConfirm(t *testing.T) {
	var mu sync.Mutex
	var reqs []*http.Request
	var bodies []string
	confirmStatus, confirmBody := 201, `{"wake_blob":"QkxPQg"}`
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 4096)
		n, _ := r.Body.Read(b)
		mu.Lock()
		defer mu.Unlock()
		reqs = append(reqs, r.Clone(context.Background()))
		bodies = append(bodies, string(b[:n]))
		switch r.URL.Path {
		case PathRegister:
			w.WriteHeader(202)
			_, _ = w.Write([]byte(`{"pending":"UEVORElORw"}`))
		case PathConfirm:
			w.WriteHeader(confirmStatus)
			_, _ = w.Write([]byte(confirmBody))
		}
	}))
	defer gw.Close()
	_, key, _ := ed25519.GenerateKey(nil)
	attested := 0
	c := &Client{BaseURL: gw.URL, HTTP: gw.Client(), Attest: func(ed25519.PublicKey, [32]byte) ([]byte, error) {
		attested++
		return []byte("doc"), nil
	}}
	p, err := c.Register(context.Background(), key, Registration{Platform: PlatformFCM, Token: "t", AppID: "a"})
	if err != nil || p != "UEVORElORw" || attested != 1 {
		t.Fatalf("register: %q %v (attested %d)", p, err, attested)
	}
	b, err := c.Confirm(context.Background(), key, p, "Y29kZQ")
	if err != nil || b != "QkxPQg" || attested != 1 {
		t.Fatalf("confirm: %q %v (attested %d)", b, err, attested)
	}
	mu.Lock()
	cr, cb := reqs[1], bodies[1]
	mu.Unlock()
	if cr.URL.Path != PathConfirm || cr.Header.Get(HeaderAttestation) != "" || cb != `{"pending":"UEVORElORw","code":"Y29kZQ"}` ||
		cr.Header.Get("X-VettID-Key") != reqs[0].Header.Get("X-VettID-Key") {
		t.Fatalf("confirm request %s %v %s", cr.URL.Path, cr.Header, cb)
	}
	confirmStatus, confirmBody = 403, `{"code":"challenge_invalid"}`
	var ge *Error
	if _, err := c.Confirm(context.Background(), key, p, "Y29kZQ"); !errors.As(err, &ge) || ge.Status != 403 || ge.Code != CodeChallengeInvalid || !Answered(err) {
		t.Fatalf("challenge_invalid: %v", err)
	}
	confirmStatus, confirmBody = 201, `{"wake_blob":"a b"}`
	if _, err := c.Confirm(context.Background(), key, p, "Y29kZQ"); !errors.Is(err, ErrResponse) {
		t.Fatalf("bad blob: %v", err)
	}
}

func TestPendingAndCodes(t *testing.T) {
	if p, err := ParsePending([]byte(`{"pending":"AQID"}`)); err != nil || p != "AQID" {
		t.Fatal(p, err)
	}
	for _, b := range []string{`{"pending":"a b"}`, `{"pending":""}`, `{"wake_blob":"AQID"}`, `[]`} {
		if _, err := ParsePending([]byte(b)); err == nil {
			t.Fatalf("%s accepted", b)
		}
	}
	if !ValidChallengeCode("Y29kZQ_-") || !ValidChallengeCode(strings.Repeat("a", 64)) || ValidChallengeCode("") ||
		ValidChallengeCode(strings.Repeat("a", 65)) || ValidChallengeCode("a=") || ValidChallengeCode("a b") {
		t.Fatal("ValidChallengeCode")
	}
	if p, c, err := ParseConfirm(ConfirmBody("UA", "Yw")); err != nil || p != "UA" || c != "Yw" {
		t.Fatal(p, c, err)
	}
	for _, b := range []string{`{"pending":"UA"}`, `{"pending":"UA","code":"Yw","x":1}`, `{"pending":"UA","code":""}`, `{"pending":1,"code":"Yw"}`} {
		if _, _, err := ParseConfirm([]byte(b)); err == nil {
			t.Fatalf("%s accepted", b)
		}
	}
}
