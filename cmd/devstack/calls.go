//go:build devenclave

package main

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/vettid/vettid-vault/internal/callstest"
	"github.com/vettid/vettid-vault/internal/enclavetest"
)

// The calling service's issuer stand-in (VAULT-MESSAGING §10.10 "Servers and credentials", CALLING-SERVICE §5;
// TEST-ONLY): served on calls.vettid.test behind a TLS front with the test root, which the dev enclave's egress and
// the parent allow. The release constant calls_url is not involved: the dev enclave takes the URL from -calls-url.
const (
	callsHost = "calls.vettid.test"
	callsURL  = "https://" + callsHost
)

// startCalls starts the stand-in: it accepts the dev enclave's TEST attestation of the stack's release and records
// the credential requests.
func (s *stack) startCalls() {
	s.calls = callstest.New(callstest.Config{Roots: enclavetest.TestNitroCA().Roots(),
		PCR0s: []string{enclavetest.Spec(release, "").PCR0Hex()}, Host: callsHost})
	s.callsTLS = s.tlsFront(logged("calls", s.calls), true, callsHost)
}

// callsControl adds the stand-in's control routes (TEST-ONLY):
//
//	GET  /dev/calls        {requests: [{at, key?, attested, count?, status, code?, usernames?}]}: every
//	                       credentials request, oldest first; key is the request's signing key
//	                       (X-VettID-Key), usernames those of the credentials answered (never the
//	                       credentials themselves)
//	POST /dev/calls/fail   {status, code, retry_after?, count?}: the next count requests that pass the
//	                       checks (default 1) are answered with that error (429 rate_limited, 503 internal)
//	POST /dev/calls/reset  forgets the requests and injected answers
func (s *stack) callsControl(mux *http.ServeMux) {
	mux.HandleFunc("GET /dev/calls", func(w http.ResponseWriter, r *http.Request) {
		rs := s.calls.Requests()
		if rs == nil {
			rs = []callstest.Request{}
		}
		writeJSON(w, 200, map[string]any{"requests": rs})
	})
	mux.HandleFunc("POST /dev/calls/fail", func(w http.ResponseWriter, r *http.Request) {
		var f callstest.Failure
		if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&f) != nil || f.Status < 400 || f.Status > 599 || !validType(f.Code) ||
			f.Count < 0 || f.Count > 1000 || f.RetryAfter < 0 || f.RetryAfter > 3600 {
			writeJSON(w, 400, map[string]any{"error": "bad_request"})
			return
		}
		s.calls.FailNext(f)
		writeJSON(w, 200, map[string]any{})
	})
	mux.HandleFunc("POST /dev/calls/reset", func(w http.ResponseWriter, r *http.Request) {
		s.calls.Reset()
		writeJSON(w, 200, map[string]any{})
	})
}
