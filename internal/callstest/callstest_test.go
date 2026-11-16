package callstest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/callswire"
)

type attestFn = func(pub ed25519.PublicKey, d [32]byte) ([]byte, error)

func setup(t *testing.T) (*Server, *httptest.Server, *enclavetest.FakeNSM) {
	spec := enclavetest.Spec(3, "")
	nsm := enclavetest.NewFakeNSM(spec.PCR0, spec.PCR1, spec.PCR2, time.Now)
	s := New(Config{Roots: enclavetest.TestNitroCA().Roots(), PCR0s: []string{spec.PCR0Hex()}})
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return s, srv, nsm
}

func client(srv *httptest.Server, attest attestFn) *callswire.Client {
	return &callswire.Client{BaseURL: srv.URL, HTTP: srv.Client(), Attest: attest}
}

func code(err error) string {
	var e *callswire.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// The vault's own client gets an answer that passes its checks: count credentials of the TURN REST form, the
// stand-in's STUN and TURN URLs.
func TestClientGetsValidAnswer(t *testing.T) {
	s, srv, nsm := setup(t)
	c := client(srv, func(pub ed25519.PublicKey, d [32]byte) ([]byte, error) { return nsm.Attest(d[:], nil, pub) })
	before := time.Now()
	a, err := c.Credentials(context.Background(), 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.STUN) != 1 || a.STUN[0] != "stun:calls.vettid.test:3478" || len(a.TURN) != 2 || len(a.Credentials) != 3 {
		t.Fatalf("%+v %v %v", a, a.STUN, a.TURN)
	}
	seen := map[string]bool{}
	for _, cr := range a.Credentials {
		exp, rnd, ok := strings.Cut(cr.Username, ":")
		if !ok || exp != strconv.FormatInt(cr.Exp.Unix(), 10) || len(rnd) != 22 || seen[cr.Username] ||
			cr.Exp.Sub(before) > Lifetime || cr.Exp.Sub(before) < Lifetime-time.Minute {
			t.Fatalf("credential %q exp %v", cr.Username, cr.Exp)
		}
		seen[cr.Username] = true
		if b, err := base64.StdEncoding.Strict().DecodeString(cr.Credential); err != nil || len(b) != 20 {
			t.Fatalf("credential %q", cr.Credential)
		}
	}
	rs := s.Requests()
	if len(rs) != 1 || rs[0].Status != 200 || !rs[0].Attested || rs[0].Count != 3 || len(rs[0].Usernames) != 3 || rs[0].Key == "" {
		t.Fatalf("%+v", rs)
	}
	// Each request has its own key.
	if _, err := c.Credentials(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if rs := s.Requests(); len(rs) != 2 || rs[1].Key == rs[0].Key {
		t.Fatalf("%+v", rs)
	}
}

// Every check the issuer makes refuses a request that fails it (CALLING-SERVICE §5.2), with its code.
func TestRefusals(t *testing.T) {
	s, srv, nsm := setup(t)
	other := enclavetest.Spec(4, "")
	otherNSM := enclavetest.NewFakeNSM(other.PCR0, other.PCR1, other.PCR2, time.Now)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	for name, tc := range map[string]struct {
		attest attestFn
		code   string
	}{
		"no attestation": {nil, callswire.CodeAttestationInvalid},
		"another key": {func(_ ed25519.PublicKey, d [32]byte) ([]byte, error) {
			return nsm.Attest(d[:], nil, otherKey.Public().(ed25519.PublicKey))
		}, callswire.CodeAttestationInvalid},
		"another digest": {func(pub ed25519.PublicKey, d [32]byte) ([]byte, error) {
			d[0] ^= 1
			return nsm.Attest(d[:], nil, pub)
		}, callswire.CodeAttestationInvalid},
		"another release": {func(pub ed25519.PublicKey, d [32]byte) ([]byte, error) { return otherNSM.Attest(d[:], nil, pub) },
			callswire.CodeAttestationInvalid},
		"not a document": {func(ed25519.PublicKey, [32]byte) ([]byte, error) { return []byte("x"), nil }, callswire.CodeAttestationInvalid},
	} {
		if _, err := client(srv, tc.attest).Credentials(context.Background(), 1); code(err) != tc.code {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A signature over another body, with an attestation of the body sent: signature_invalid.
	attestSent := func(k ed25519.PrivateKey, ts string, body []byte) string {
		d := relayauth.Digest(http.MethodPost, callswire.PathCredentials, ts, relayauth.BodyHash(body))
		doc, err := nsm.Attest(d[:], nil, k.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(doc)
	}
	post := func(signed, sent []byte, at time.Time) (int, string) {
		t.Helper()
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+callswire.PathCredentials, bytes.NewReader(sent))
		relayauth.SetHeaders(req.Header, k, http.MethodPost, callswire.PathCredentials, at, relayauth.BodyHash(signed))
		req.Header.Set(callswire.HeaderAttestation, attestSent(k, req.Header.Get(relayauth.HeaderTimestamp), sent))
		r, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var b bytes.Buffer
		_, _ = b.ReadFrom(r.Body)
		return r.StatusCode, callswire.ParseError(r.StatusCode, b.Bytes()).Code
	}
	if st, c := post([]byte(`{"count":1}`), []byte(`{"count":2}`), time.Now()); st != 401 || c != callswire.CodeSignatureInvalid {
		t.Errorf("another body: %d %s", st, c)
	}
	if st, c := post([]byte(`{"count":1}`), []byte(`{"count":1}`), time.Now().Add(-2*time.Minute)); st != 401 || c != callswire.CodeTimestampStale {
		t.Errorf("stale: %d %s", st, c)
	}
	for _, b := range []string{`{"count":0}`, `{"count":5}`, `{"count":1,"x":1}`, `{}`, `[]`, `{"count":"1"}`, `{"count":1}` + strings.Repeat(" ", 1024)} {
		if st, c := post([]byte(b), []byte(b), time.Now()); st != 400 || c != callswire.CodeBadRequest {
			t.Errorf("body %.20q: %d %s", b, st, c)
		}
	}
	if st, c := post([]byte(`{"count":1}`), []byte(`{"count":1}`), time.Now()); st != 200 {
		t.Errorf("the same request, well formed: %d %s", st, c)
	}
	rs := s.Requests()
	if len(rs) != 5+2+7+1 {
		t.Fatalf("%d requests", len(rs))
	}
	for _, r := range rs[:5] {
		if r.Attested || r.Status != 403 || r.Usernames != nil {
			t.Fatalf("%+v", r)
		}
	}
}

// Injected failures answer the next requests that pass the checks; Reset forgets them and the record.
func TestFailNextAndReset(t *testing.T) {
	s, srv, nsm := setup(t)
	c := client(srv, func(pub ed25519.PublicKey, d [32]byte) ([]byte, error) { return nsm.Attest(d[:], nil, pub) })
	ctx := context.Background()
	s.FailNext(Failure{Status: 429, Code: callswire.CodeRateLimited, RetryAfter: 30, Count: 2})
	for range 2 {
		var e *callswire.Error
		if _, err := c.Credentials(ctx, 1); !errors.As(err, &e) || e.Status != 429 || e.Code != callswire.CodeRateLimited || e.RetryAfter != 30 {
			t.Fatal(err)
		}
	}
	if _, err := c.Credentials(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if rs := s.Requests(); len(rs) != 3 || rs[0].Code != callswire.CodeRateLimited || rs[2].Status != 200 {
		t.Fatalf("%+v", rs)
	}
	s.FailNext(Failure{Status: 503, Code: callswire.CodeInternal})
	s.Reset()
	if _, err := c.Credentials(ctx, 1); err != nil || len(s.Requests()) != 1 {
		t.Fatal(err, s.Requests())
	}
	r, err := srv.Client().Get(srv.URL + callswire.PathHealth)
	if err != nil || r.StatusCode != 200 {
		t.Fatal(err)
	}
	r.Body.Close()
}
