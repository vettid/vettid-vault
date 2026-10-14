//go:build devenclave

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/internal/pushtest"
)

// The push gateway stand-in (VAULT-MESSAGING 0.24.0 §14, PUSH-GATEWAY
// 0.5.0 §10.4; TEST-ONLY): served on push.vettid.test behind a TLS front with
// the test root, which the dev enclave's egress and the parent allow.
const (
	pushHost = "push.vettid.test"
	pushURL  = "https://" + pushHost
)

// startPush starts the stand-in: it accepts the dev enclave's TEST
// attestation of the stack's release and records registration challenges
// and wakes.
func (s *stack) startPush() {
	s.push = pushtest.New(pushtest.Config{Roots: enclavetest.TestNitroCA().Roots(),
		PCR0s: []string{enclavetest.Spec(release, "").PCR0Hex()}})
	s.pushTLS = s.tlsFront(logged("push", s.push), true, pushHost)
}

// pushControl adds the stand-in's control routes (TEST-ONLY):
//
//	GET  /dev/push        {registrations, challenges: [{at, platform, environment?, app_id,
//	                      token_sha256, code}], wakes: [{at, platform, environment?, app_id,
//	                      token_sha256, class}], refusals: {"op:code": n}}; registrations
//	                      counts completed (confirmed) ones; the latest challenge's code is
//	                      what the app returns in push.confirm (PUSH-GATEWAY 0.5.0)
//	POST /dev/push/fail   {status, code, retry_after?, count?}: the next count wakes
//	                      (default 1) are answered with that error instead of recorded
//	                      (410 token_gone, 400 token_invalid, 410 blob_invalid, 429, 502)
//	POST /dev/push/reseal {count?}: the next count wakes answer with a reseal
//	POST /dev/push/reset  forgets challenges, wakes, counts and injected answers
//	POST /dev/push/wait   {wakes: N, timeout_s}: waits (default 30 s, at most 300) until
//	                      N wakes are recorded; 404 {"error": "timeout"} otherwise
func (s *stack) pushControl(mux *http.ServeMux) {
	state := func() map[string]any {
		ch := s.push.Challenges()
		if ch == nil {
			ch = []pushtest.Challenge{}
		}
		return map[string]any{"registrations": s.push.Registrations(), "challenges": ch, "wakes": nonNil(s.push.Wakes()), "refusals": s.push.Refusals()}
	}
	mux.HandleFunc("GET /dev/push", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, state()) })
	mux.HandleFunc("POST /dev/push/fail", func(w http.ResponseWriter, r *http.Request) {
		var f pushtest.Failure
		if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&f) != nil || f.Status < 400 || f.Status > 599 || !validType(f.Code) ||
			f.Count < 0 || f.Count > 1000 || f.RetryAfter < 0 || f.RetryAfter > 3600 {
			writeJSON(w, 400, map[string]any{"error": "bad_request"})
			return
		}
		s.push.FailNext(f)
		writeJSON(w, 200, map[string]any{})
	})
	mux.HandleFunc("POST /dev/push/reseal", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Count int `json:"count"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in)
		if in.Count <= 0 || in.Count > 1000 {
			in.Count = 1
		}
		s.push.ResealNext(in.Count)
		writeJSON(w, 200, map[string]any{})
	})
	mux.HandleFunc("POST /dev/push/reset", func(w http.ResponseWriter, r *http.Request) {
		s.push.Reset()
		writeJSON(w, 200, map[string]any{})
	})
	mux.HandleFunc("POST /dev/push/wait", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Wakes    int `json:"wakes"`
			TimeoutS int `json:"timeout_s"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in) != nil || in.Wakes < 1 {
			writeJSON(w, 400, map[string]any{"error": "bad_request"})
			return
		}
		if in.TimeoutS <= 0 || in.TimeoutS > 300 {
			in.TimeoutS = 30
		}
		if !s.push.Wait(time.Duration(in.TimeoutS)*time.Second, func(p *pushtest.Server) bool { return len(p.Wakes()) >= in.Wakes }) {
			writeJSON(w, 404, map[string]any{"error": "timeout"})
			return
		}
		writeJSON(w, 200, state())
	})
}

func nonNil(w []pushtest.Wake) []pushtest.Wake {
	if w == nil {
		return []pushtest.Wake{}
	}
	return w
}
