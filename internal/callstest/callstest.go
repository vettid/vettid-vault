// Package callstest is a TEST-ONLY stand-in for the calling service's credential issuer (CALLING-SERVICE §5.2;
// VAULT-MESSAGING §10.10 "Servers and credentials"): POST /v1/credentials with the issuer's signature,
// attestation and body rules, but it accepts the dev enclave's TEST attestation (the test Nitro root and the test
// releases' PCR0s). It answers with credentials of the TURN REST form (§5.3) under a random secret of its own and
// records each request. Failures can be injected for the next requests. It never links into a release package
// (make check-tcb).
package callstest

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/callswire"
	"github.com/vettid/vettid-vault/vms/nitro"
	"github.com/vettid/vettid-vault/vms/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Config configures a stand-in.
type Config struct {
	// Roots verify the requests' attestation documents (the TEST Nitro root, enclavetest.TestNitroCA().Roots()).
	Roots *x509.CertPool
	// PCR0s are the accepted releases (hex); empty accepts none.
	PCR0s []string
	// Host names the STUN and TURN URLs of the answers (default "calls.vettid.test").
	Host string
	Now  func() time.Time
}

// Lifetime is a credential's lifetime (CALLING-SERVICE §5.3: 6 hours).
const Lifetime = 6 * time.Hour

// maxBody bounds a request's body (CALLING-SERVICE §5.2: 1 KiB).
const maxBody = 1 << 10

// Request is one recorded request to POST /v1/credentials, refused or answered.
type Request struct {
	At time.Time `json:"at"`
	// Key is the request's signing key (X-VettID-Key, standard base64); "" when the headers did not parse.
	Key string `json:"key,omitempty"`
	// Attested: the request carried an attestation that verified.
	Attested bool `json:"attested"`
	Count    int  `json:"count,omitempty"`
	Status   int  `json:"status"`
	// Code is the error code of a refused request.
	Code string `json:"code,omitempty"`
	// Usernames are the answered credentials' usernames (never the credentials).
	Usernames []string `json:"usernames,omitempty"`
}

// Failure is an injected answer for the next request(s) that pass the checks.
type Failure struct {
	Status     int    `json:"status"`
	Code       string `json:"code"`
	RetryAfter int    `json:"retry_after,omitempty"`
	// Count is how many requests it answers (default 1).
	Count int `json:"count,omitempty"`
}

// Server is the stand-in (an http.Handler).
type Server struct {
	cfg    Config
	secret [32]byte

	mu       sync.Mutex
	requests []Request
	failures []Failure
}

// New returns a stand-in with a fresh random secret.
func New(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Host == "" {
		cfg.Host = "calls.vettid.test"
	}
	s := &Server{cfg: cfg}
	if _, err := rand.Read(s.secret[:]); err != nil {
		panic(err)
	}
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == callswire.PathHealth && r.Method == http.MethodGet:
		writeJSON(w, 200, []byte(`{}`))
	case r.URL.Path == callswire.PathCredentials && r.Method == http.MethodPost:
		s.credentials(w, r)
	default:
		writeJSON(w, 404, errorBody("not_found", 0))
	}
}

func writeJSON(w http.ResponseWriter, status int, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// credentials is CALLING-SERVICE §5.2 with the TEST trust anchors, in the issuer's order: the signature and its
// timestamp, the attestation, the body; then count credentials.
func (s *Server) credentials(w http.ResponseWriter, r *http.Request) {
	rec := Request{At: s.cfg.Now().UTC()}
	answer := func(status int, code string, retryAfter int, b []byte) {
		rec.Status, rec.Code = status, code
		if b == nil {
			b = errorBody(code, retryAfter)
		}
		s.mu.Lock()
		s.requests = append(s.requests, rec)
		s.mu.Unlock()
		writeJSON(w, status, b)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		answer(400, callswire.CodeBadRequest, 0, nil)
		return
	}
	sr, err := relayauth.ParseHeaders(r.Header)
	if err != nil {
		answer(401, callswire.CodeSignatureInvalid, 0, nil)
		return
	}
	rec.Key = base64.StdEncoding.EncodeToString(sr.Key)
	if err := sr.Verify(http.MethodPost, r.URL.Path, relayauth.BodyHash(body), s.cfg.Now()); err != nil {
		code := callswire.CodeSignatureInvalid
		if errors.Is(err, relayauth.ErrTimestampStale) {
			code = callswire.CodeTimestampStale
		}
		answer(401, code, 0, nil)
		return
	}
	if !s.attested(r, sr, body) {
		answer(403, callswire.CodeAttestationInvalid, 0, nil)
		return
	}
	rec.Attested = true
	n, ok := count(body)
	if !ok {
		answer(400, callswire.CodeBadRequest, 0, nil)
		return
	}
	rec.Count = n
	s.mu.Lock()
	if len(s.failures) > 0 {
		f := &s.failures[0]
		st, code, ra := f.Status, f.Code, f.RetryAfter
		if f.Count--; f.Count <= 0 {
			s.failures = s.failures[1:]
		}
		s.mu.Unlock()
		answer(st, code, ra, nil)
		return
	}
	s.mu.Unlock()
	b, users := s.make(n)
	rec.Usernames = users
	answer(200, "", 0, b)
}

// attested checks X-VettID-Attestation (CALLING-SERVICE §5.2 step 2, PUSH-GATEWAY §5.1 step 2): the chain to the
// configured root, a timestamp within 300 s, public_key = the signing key, user_data = the request's digest, PCR0
// of an accepted release.
func (s *Server) attested(r *http.Request, sr relayauth.SignedRequest, body []byte) bool {
	v := r.Header.Values(callswire.HeaderAttestation)
	if len(v) != 1 || s.cfg.Roots == nil {
		return false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(v[0])
	if err != nil {
		return false
	}
	doc, err := nitro.Verify(raw, s.cfg.Roots)
	if err != nil || doc.CheckFresh(s.cfg.Now(), 300*time.Second, 300*time.Second) != nil {
		return false
	}
	if !suite.EqualPublic(doc.PublicKey, sr.Key) {
		return false
	}
	d := relayauth.Digest(http.MethodPost, r.URL.Path, sr.Timestamp, relayauth.BodyHash(body))
	if doc.CheckUserData(d[:]) != nil {
		return false
	}
	pcr0 := doc.PCRHex(0)
	for _, p := range s.cfg.PCR0s {
		if p == pcr0 {
			return true
		}
	}
	return false
}

// count reads a request's body: {"count": 1..MaxCount} and nothing else.
func count(body []byte) (int, bool) {
	o, err := strictjson.ParseObject(body)
	if err != nil || len(o) != 1 {
		return 0, false
	}
	n, err := o.Uint("count", 1, callswire.MaxCount)
	return int(n), err == nil
}

// make returns an answer with n credentials of the TURN REST form (§5.3): username = <expiry>:<16 random bytes,
// base64url>, credential = base64(HMAC-SHA-1(secret, username)), exp = the expiry, Lifetime ahead in whole seconds.
func (s *Server) make(n int) ([]byte, []string) {
	exp := s.cfg.Now().Add(Lifetime).Unix()
	type cred struct {
		Username   string `json:"username"`
		Credential string `json:"credential"`
		Exp        int64  `json:"exp"`
	}
	creds := make([]cred, 0, n)
	users := make([]string, 0, n)
	for range n {
		var rb [16]byte
		if _, err := rand.Read(rb[:]); err != nil {
			panic(err)
		}
		user := strconv.FormatInt(exp, 10) + ":" + base64.RawURLEncoding.EncodeToString(rb[:])
		m := hmac.New(sha1.New, s.secret[:])
		m.Write([]byte(user))
		creds = append(creds, cred{Username: user, Credential: base64.StdEncoding.EncodeToString(m.Sum(nil)), Exp: exp})
		users = append(users, user)
	}
	stun, _ := json.Marshal([]string{"stun:" + s.cfg.Host + ":3478"})
	turn, _ := json.Marshal([]string{"turn:" + s.cfg.Host + ":3478?transport=udp", "turn:" + s.cfg.Host + ":3478?transport=tcp"})
	cb, _ := json.Marshal(creds)
	return strictjson.NewBuilder().Raw("stun", stun).Raw("turn", turn).Raw("credentials", cb).Bytes(), users
}

// --- control (tests, the dev stack) ---

// Requests returns the recorded requests, oldest first.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// FailNext answers the next requests that pass the checks with f instead of credentials.
func (s *Server) FailNext(f Failure) {
	if f.Count <= 0 {
		f.Count = 1
	}
	s.mu.Lock()
	s.failures = append(s.failures, f)
	s.mu.Unlock()
}

// Reset forgets the recorded requests and the injected answers (the secret stays).
func (s *Server) Reset() {
	s.mu.Lock()
	s.requests, s.failures = nil, nil
	s.mu.Unlock()
}

// errorBody is an error body (Relay Protocol §7.1).
func errorBody(code string, retryAfter int) []byte {
	b := strictjson.NewBuilder().String("code", code)
	if retryAfter > 0 {
		b.Uint("retry_after", uint64(retryAfter))
	}
	return b.Bytes()
}
