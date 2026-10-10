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
		{"201", 201, `{"wake_blob":"QUJD"}`, nil, true},
		{"unparsable 201", 201, `{"wake_blob":`, ErrResponse, true},
		{"oversized 201", 201, `{"wake_blob":"` + strings.Repeat("A", MaxAnswer) + `"}`, ErrOversized, true},
		{"oversized 403", 403, strings.Repeat(" ", MaxAnswer+1), ErrOversized, true},
		{"oversized 502", 502, strings.Repeat(" ", MaxAnswer+1), ErrOversized, true},
		{"403", 403, `{"code":"attestation_invalid"}`, nil, true},
		{"401", 401, `{"code":"signature_invalid"}`, nil, true},
	} {
		set(x.status, x.body, 0)
		_, err := c.Register(context.Background(), key, reg)
		var ge *Error
		if x.want != nil && !errors.Is(err, x.want) || x.want == nil && x.status != 201 && !errors.As(err, &ge) || x.status == 201 && x.want == nil && err != nil {
			t.Errorf("%s: %v", x.name, err)
		}
		if Answered(err) != x.answered {
			t.Errorf("%s: answered %v", x.name, !x.answered)
		}
	}
	// A timeout: not answered.
	set(201, `{"wake_blob":"QUJD"}`, time.Second)
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
