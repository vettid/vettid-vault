// Package pushtest is a TEST-ONLY stand-in for the VettID push gateway
// (PUSH-GATEWAY 0.5.0, VAULT-MESSAGING 0.24.0 §14; N3): POST /v1/register,
// POST /v1/confirm and POST /v1/wake with the gateway's signature,
// attestation, body, challenge and blob rules, but it accepts the dev
// enclave's TEST attestation (the test Nitro root and the test releases'
// PCR0s), and it records registration challenges (with their codes, so
// that a test or the dev stack can play the app) and wakes instead of
// sending them to FCM or APNs. Failures can be injected for the next
// wakes. It never links into a release package (make check-tcb).
package pushtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/nitro"
	"github.com/vettid/vettid-vault/vms/pushwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Config configures a stand-in.
type Config struct {
	// Roots verify registrations' attestation documents (the TEST Nitro
	// root, enclavetest.TestNitroCA().Roots()).
	Roots *x509.CertPool
	// PCR0s are the accepted releases (hex); empty accepts none.
	PCR0s []string
	// AppIDs, if set, are the accepted app ids per platform (app_invalid
	// otherwise); nil accepts every well-formed one.
	AppIDs map[string][]string
	// Channel is sealed into blobs' associated data (default "dev").
	Channel string
	Now     func() time.Time
}

// Wake is one recorded wake: what the gateway would have sent to the
// platform. The token itself is kept as its SHA-256 (hex).
type Wake struct {
	At          time.Time `json:"at"`
	Platform    string    `json:"platform"`
	Environment string    `json:"environment,omitempty"`
	AppID       string    `json:"app_id"`
	TokenSHA256 string    `json:"token_sha256"`
	Class       string    `json:"class"`
}

// Challenge is one recorded registration challenge: what the gateway
// would have sent to the token by push (PUSH-GATEWAY 0.5.0 §6), with its
// code. The token is kept as its SHA-256 (hex).
type Challenge struct {
	At          time.Time `json:"at"`
	Platform    string    `json:"platform"`
	Environment string    `json:"environment,omitempty"`
	AppID       string    `json:"app_id"`
	TokenSHA256 string    `json:"token_sha256"`
	Code        string    `json:"code"`
}

// ChallengeLife is how long a pending registration can be confirmed
// (PUSH-GATEWAY 0.5.0 §5.1).
const ChallengeLife = 10 * time.Minute

// Failure is an injected answer for the next wake(s).
type Failure struct {
	Status     int    `json:"status"`
	Code       string `json:"code"`
	RetryAfter int    `json:"retry_after,omitempty"`
	// Count is how many wakes it answers (default 1).
	Count int `json:"count,omitempty"`
}

// Server is the stand-in (an http.Handler).
type Server struct {
	cfg    Config
	key    [32]byte
	keyID  [4]byte
	replay *relayauth.ReplayCache

	mu         sync.Mutex
	wakes      []Wake
	challenges []Challenge
	regs       int
	failures   []Failure
	reseal     int
	refusals   map[string]int
	changed    chan struct{}
	lastBlobs  []string
}

// New returns a stand-in with a fresh random blob key.
func New(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Channel == "" {
		cfg.Channel = "dev"
	}
	s := &Server{cfg: cfg, replay: relayauth.NewReplayCache(1 << 16), refusals: map[string]int{}, changed: make(chan struct{})}
	if _, err := rand.Read(s.key[:]); err != nil {
		panic(err)
	}
	if _, err := rand.Read(s.keyID[:]); err != nil {
		panic(err)
	}
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == pushwire.PathHealth && r.Method == http.MethodGet:
		writeJSON(w, 200, []byte(`{}`))
	case r.URL.Path == pushwire.PathRegister && r.Method == http.MethodPost:
		s.register(w, r)
	case r.URL.Path == pushwire.PathConfirm && r.Method == http.MethodPost:
		s.confirm(w, r)
	case r.URL.Path == pushwire.PathWake && r.Method == http.MethodPost:
		s.wake(w, r)
	default:
		s.fail(w, 404, "not_found", "", 0)
	}
}

func writeJSON(w http.ResponseWriter, status int, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func (s *Server) fail(w http.ResponseWriter, status int, code, op string, retryAfter int) {
	if op != "" {
		s.mu.Lock()
		s.refusals[op+":"+code]++
		s.bump()
		s.mu.Unlock()
	}
	writeJSON(w, status, pushwire.ErrorBody(code, retryAfter))
}

// bump wakes waiters; s.mu held.
func (s *Server) bump() {
	close(s.changed)
	s.changed = make(chan struct{})
}

// auth reads the body and checks the signature, freshness and replay
// cache (Relay Protocol §4.1).
func (s *Server) auth(w http.ResponseWriter, r *http.Request, op string) (relayauth.SignedRequest, []byte, bool) {
	sr, body, ok := s.signed(w, r, op)
	if !ok || !s.fresh(w, sr, op) {
		return sr, nil, false
	}
	return sr, body, true
}

// fresh checks and records the replay cache.
func (s *Server) fresh(w http.ResponseWriter, sr relayauth.SignedRequest, op string) bool {
	if err := s.replay.Check(sr, s.cfg.Now()); err != nil {
		s.fail(w, 401, pushwire.CodeReplayDetected, op, 0)
		return false
	}
	return true
}

// signed reads the body and checks the signature and freshness.
func (s *Server) signed(w http.ResponseWriter, r *http.Request, op string) (relayauth.SignedRequest, []byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10+1))
	if err != nil || len(body) > 16<<10 {
		s.fail(w, 400, pushwire.CodeBadRequest, op, 0)
		return relayauth.SignedRequest{}, nil, false
	}
	sr, err := relayauth.ParseHeaders(r.Header)
	if err != nil {
		s.fail(w, 401, pushwire.CodeSignatureInvalid, op, 0)
		return sr, nil, false
	}
	now := s.cfg.Now()
	if err := sr.Verify(http.MethodPost, r.URL.Path, relayauth.BodyHash(body), now); err != nil {
		code := pushwire.CodeSignatureInvalid
		if errors.Is(err, relayauth.ErrTimestampStale) {
			code = pushwire.CodeTimestampStale
		}
		s.fail(w, 401, code, op, 0)
		return sr, nil, false
	}
	return sr, body, true
}

// register is PUSH-GATEWAY 0.5.0 §5.1 with the TEST trust anchors: it
// records the challenge it would send to the token and answers 202
// {pending}.
func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	sr, body, ok := s.auth(w, r, "register")
	if !ok {
		return
	}
	if !s.attested(r, sr, body) {
		s.fail(w, 403, pushwire.CodeAttestationInvalid, "register", 0)
		return
	}
	reg, code := classify(body)
	if code == "" && s.cfg.AppIDs != nil && !contains(s.cfg.AppIDs[reg.Platform], reg.AppID) {
		code = pushwire.CodeAppInvalid
	}
	if code != "" {
		s.fail(w, 400, code, "register", 0)
		return
	}
	var c [16]byte
	if _, err := rand.Read(c[:]); err != nil {
		panic(err)
	}
	code = base64.RawURLEncoding.EncodeToString(c[:])
	pending := s.sealRecord(newRecord(reg, sr.Key, s.cfg.Now(), code), pendingLabel)
	th := sha256.Sum256([]byte(reg.Token))
	s.mu.Lock()
	s.challenges = append(s.challenges, Challenge{At: s.cfg.Now().UTC(), Platform: reg.Platform, Environment: reg.Environment,
		AppID: reg.AppID, TokenSHA256: hex.EncodeToString(th[:]), Code: code})
	s.bump()
	s.mu.Unlock()
	writeJSON(w, 202, strictjson.NewBuilder().String("pending", pending).Bytes())
}

// confirm is PUSH-GATEWAY 0.5.0 §5.1's second step: the pending
// registration must open, be the signer's, be at most 10 minutes old and
// carry the code; every failure is the same 403 challenge_invalid and
// leaves no replay record. Then the wake blob, issued now.
func (s *Server) confirm(w http.ResponseWriter, r *http.Request) {
	sr, body, ok := s.signed(w, r, "confirm")
	if !ok {
		return
	}
	pending, code, err := pushwire.ParseConfirm(body)
	if err != nil {
		s.fail(w, 400, pushwire.CodeBadRequest, "confirm", 0)
		return
	}
	rec, ok := s.openRecord(pending, pendingLabel)
	now := s.cfg.Now()
	if !ok || rec.K != base64.StdEncoding.EncodeToString(sr.Key) || now.Unix()-rec.I < 0 ||
		now.Unix()-rec.I > int64(ChallengeLife/time.Second) || subtle.ConstantTimeCompare([]byte(rec.C), []byte(code)) != 1 ||
		s.cfg.AppIDs != nil && !contains(s.cfg.AppIDs[rec.P], rec.A) {
		s.fail(w, 403, pushwire.CodeChallengeInvalid, "confirm", 0)
		return
	}
	if !s.fresh(w, sr, "confirm") {
		return
	}
	rec.C, rec.I = "", now.Unix()
	blob := s.sealRecord(*rec, aadLabel)
	s.mu.Lock()
	s.regs++
	s.bump()
	s.mu.Unlock()
	writeJSON(w, 201, strictjson.NewBuilder().String("wake_blob", blob).Bytes())
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// attested checks X-VettID-Attestation (§5.1 step 2): the chain to the
// configured root, a timestamp within 300 s, public_key = the signing
// key, user_data = the request's digest, PCR0 of an accepted release.
func (s *Server) attested(r *http.Request, sr relayauth.SignedRequest, body []byte) bool {
	v := r.Header.Values(pushwire.HeaderAttestation)
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
	return contains(s.cfg.PCR0s, doc.PCRHex(0))
}

// classify parses a register body and names the gateway's code for a bad
// one (§7: platform_invalid, token_invalid, app_invalid, bad_request).
func classify(body []byte) (pushwire.Registration, string) {
	if r, err := pushwire.ParseRegistration(body); err == nil {
		return r, ""
	}
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return pushwire.Registration{}, pushwire.CodeBadRequest
	}
	pl, _ := o.String("platform")
	if pl != pushwire.PlatformFCM && pl != pushwire.PlatformAPNs {
		return pushwire.Registration{}, pushwire.CodePlatformInvalid
	}
	app, err := o.String("app_id")
	if err != nil || (pushwire.Registration{Platform: pushwire.PlatformFCM, Token: "x", AppID: app}).Validate() != nil {
		return pushwire.Registration{}, pushwire.CodeAppInvalid
	}
	return pushwire.Registration{}, pushwire.CodeTokenInvalid
}

// The associated data's labels: a wake blob, and (0.5.0) a pending
// registration, which never opens as the other.
const (
	aadLabel     = "vettid/push/1/blob"
	pendingLabel = "vettid/push/1/pending"
)

type record struct {
	P string `json:"p"`
	E string `json:"e,omitempty"`
	A string `json:"a"`
	T string `json:"t"`
	K string `json:"k"`
	I int64  `json:"i"`
	C string `json:"c,omitempty"` // a pending registration's challenge code
}

func newRecord(r pushwire.Registration, key ed25519.PublicKey, at time.Time, code string) record {
	return record{P: r.Platform, E: r.Environment, A: r.AppID, T: r.Token,
		K: base64.StdEncoding.EncodeToString(key), I: at.Unix(), C: code}
}

// seal makes a wake blob (PUSH-GATEWAY §4), issued now.
func (s *Server) seal(r pushwire.Registration, key ed25519.PublicKey) string {
	return s.sealRecord(newRecord(r, key, s.cfg.Now(), ""), aadLabel)
}

// sealRecord seals rec under label (§4).
func (s *Server) sealRecord(rec record, label string) string {
	pt, _ := json.Marshal(rec)
	aead, _ := chacha20poly1305.NewX(s.key[:])
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	out := append([]byte{0x01}, s.keyID[:]...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, pt, []byte(label+"\x00"+s.cfg.Channel))
	return base64.RawURLEncoding.EncodeToString(out)
}

func (s *Server) open(blob string) (*record, bool) { return s.openRecord(blob, aadLabel) }

func (s *Server) openRecord(blob, label string) (*record, bool) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(blob)
	if err != nil || len(blob) > pushwire.MaxBlob || len(b) < 1+4+chacha20poly1305.NonceSizeX+16 || b[0] != 0x01 ||
		binary.BigEndian.Uint32(b[1:5]) != binary.BigEndian.Uint32(s.keyID[:]) {
		return nil, false
	}
	aead, _ := chacha20poly1305.NewX(s.key[:])
	n := b[5 : 5+chacha20poly1305.NonceSizeX]
	pt, err := aead.Open(nil, n, b[5+chacha20poly1305.NonceSizeX:], []byte(label+"\x00"+s.cfg.Channel))
	if err != nil {
		return nil, false
	}
	var rec record
	if json.Unmarshal(pt, &rec) != nil || (label == pendingLabel) != (rec.C != "") {
		return nil, false
	}
	return &rec, true
}

// wake is PUSH-GATEWAY §5.2, recording instead of sending.
func (s *Server) wake(w http.ResponseWriter, r *http.Request) {
	sr, body, ok := s.auth(w, r, "wake")
	if !ok {
		return
	}
	blob, class, err := pushwire.ParseWake(body)
	if err != nil || class != pushwire.ClassNotify {
		s.fail(w, 400, pushwire.CodeBadRequest, "wake", 0)
		return
	}
	rec, ok := s.open(blob)
	if !ok || rec.K != base64.StdEncoding.EncodeToString(sr.Key) {
		s.fail(w, 410, pushwire.CodeBlobInvalid, "wake", 0)
		return
	}
	s.mu.Lock()
	if len(s.failures) > 0 {
		f := &s.failures[0]
		st, code, ra := f.Status, f.Code, f.RetryAfter
		if f.Count--; f.Count <= 0 {
			s.failures = s.failures[1:]
		}
		s.mu.Unlock()
		s.fail(w, st, code, "wake", ra)
		return
	}
	th := sha256.Sum256([]byte(rec.T))
	s.wakes = append(s.wakes, Wake{At: s.cfg.Now().UTC(), Platform: rec.P, Environment: rec.E, AppID: rec.A,
		TokenSHA256: hex.EncodeToString(th[:]), Class: class})
	ans := []byte(`{}`)
	if s.reseal > 0 {
		s.reseal--
		nb := s.seal(pushwire.Registration{Platform: rec.P, Environment: rec.E, AppID: rec.A, Token: rec.T}, sr.Key)
		s.lastBlobs = append(s.lastBlobs, nb)
		ans = strictjson.NewBuilder().String("reseal", nb).Bytes()
	}
	s.bump()
	s.mu.Unlock()
	writeJSON(w, 202, ans)
}

// --- control (tests, the dev stack) ---

// Wakes returns the recorded wakes.
func (s *Server) Wakes() []Wake {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Wake(nil), s.wakes...)
}

// Challenges returns the recorded registration challenges, oldest first.
func (s *Server) Challenges() []Challenge {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Challenge(nil), s.challenges...)
}

// LastCode returns the latest challenge's code ("" without one): what
// the app would pass to its vault in push.confirm.
func (s *Server) LastCode() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.challenges) == 0 {
		return ""
	}
	return s.challenges[len(s.challenges)-1].Code
}

// Registrations returns how many registrations completed (a wake blob
// issued by a confirmation).
func (s *Server) Registrations() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.regs
}

// Refusals returns how many requests were refused, by "op:code".
func (s *Server) Refusals() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for k, v := range s.refusals {
		out[k] = v
	}
	return out
}

// FailNext answers the next wakes with f instead of recording them.
func (s *Server) FailNext(f Failure) {
	if f.Count <= 0 {
		f.Count = 1
	}
	s.mu.Lock()
	s.failures = append(s.failures, f)
	s.mu.Unlock()
}

// ResealNext answers the next n recorded wakes with a reseal.
func (s *Server) ResealNext(n int) {
	s.mu.Lock()
	s.reseal += n
	s.mu.Unlock()
}

// Resealed returns the blobs handed out as reseals.
func (s *Server) Resealed() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lastBlobs...)
}

// Reset forgets the recorded challenges, wakes, counts and injected answers (the
// blob key stays, so registered vaults keep working).
func (s *Server) Reset() {
	s.mu.Lock()
	s.wakes, s.challenges, s.regs, s.failures, s.reseal, s.lastBlobs = nil, nil, 0, nil, 0, nil
	s.refusals = map[string]int{}
	s.bump()
	s.mu.Unlock()
}

// Wait blocks until cond holds (checked at every change) or the timeout.
func (s *Server) Wait(timeout time.Duration, cond func(*Server) bool) bool {
	deadline := time.After(timeout)
	for {
		s.mu.Lock()
		ch := s.changed
		s.mu.Unlock()
		if cond(s) {
			return true
		}
		select {
		case <-ch:
		case <-deadline:
			return cond(s)
		}
	}
}
