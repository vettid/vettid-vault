//go:build devenclave

package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/internal/enclavetest"
)

// control serves the dev control API (TEST-ONLY):
//
//	GET  /dev/health         {"ok": true}
//	GET  /dev/info           what ready.json holds
//	GET  /dev/trust          the stack's TEST trust anchors: the test Nitro root (DER, base64)
//	                         and manifest keys (SPKI DER, base64), the relay URL, and the
//	                         dev device policy in force (null: the TEST policy only)
//	POST /dev/peer/request   {"type": T, "body": {...}}: `vaultctl request T BODY` on the
//	                         peer vault; answers the vault's response object
//	POST /dev/peer/event     {"type": T, "match": {k: v}, "timeout_s": N}: waits (default
//	                         90 s, at most 300) for a peer event of type T whose body
//	                         matches; events that do not match are kept for later calls
func (s *stack) control() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /dev/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("GET /dev/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, s.info())
	})
	mux.HandleFunc("GET /dev/trust", func(w http.ResponseWriter, r *http.Request) {
		spki, err := x509.MarshalPKIXPublicKey(&enclavetest.ManifestKey().PublicKey)
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		var dp any
		if s.policy != nil {
			dp = s.policy.Summary()
		}
		writeJSON(w, 200, map[string]any{
			"nitro_root":    base64.StdEncoding.EncodeToString(enclavetest.TestNitroCA().Root.Cert.Raw),
			"manifest_keys": []string{base64.StdEncoding.EncodeToString(spki)},
			"relay_url":     relayURL,
			"device_policy": dp,
		})
	})
	mux.HandleFunc("POST /dev/peer/request", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Type string          `json:"type"`
			Body json.RawMessage `json:"body"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in) != nil || !validType(in.Type) {
			writeJSON(w, 400, map[string]any{"error": "bad_request"})
			return
		}
		body := strings.TrimSpace(string(in.Body))
		if body == "" || body == "null" {
			body = "{}"
		}
		if body[0] != '{' {
			writeJSON(w, 400, map[string]any{"error": "bad_request", "message": "body must be a JSON object"})
			return
		}
		s.peerMu.Lock()
		out, err := s.vaultctlFn("request", in.Type, body)
		s.peerMu.Unlock()
		vs := jsonValues(out)
		if err != nil || len(vs) == 0 {
			writeJSON(w, 502, map[string]any{"error": "vaultctl", "output": out})
			return
		}
		writeJSON(w, 200, vs[0])
	})
	mux.HandleFunc("POST /dev/peer/event", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Type     string            `json:"type"`
			Match    map[string]string `json:"match"`
			TimeoutS int               `json:"timeout_s"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in) != nil || !validType(in.Type) {
			writeJSON(w, 400, map[string]any{"error": "bad_request"})
			return
		}
		if in.TimeoutS <= 0 || in.TimeoutS > 300 {
			in.TimeoutS = 90
		}
		deadline := time.Now().Add(time.Duration(in.TimeoutS) * time.Second)
		for {
			s.peerMu.Lock()
			if ev, ok := s.takeEvent(in.Type, in.Match); ok {
				s.peerMu.Unlock()
				writeJSON(w, 200, ev)
				return
			}
			if time.Now().After(deadline) || r.Context().Err() != nil {
				s.peerMu.Unlock()
				writeJSON(w, 404, map[string]any{"error": "timeout"})
				return
			}
			out, _ := s.vaultctlFn("events", "-wait", "3s")
			s.peerEvents = append(s.peerEvents, jsonValues(out)...)
			if len(s.peerEvents) > 1000 {
				s.peerEvents = s.peerEvents[len(s.peerEvents)-1000:]
			}
			s.peerMu.Unlock()
		}
	})
	return mux
}

// takeEvent removes and returns the first kept event of type typ whose
// body matches (peerMu held).
func (s *stack) takeEvent(typ string, match map[string]string) (map[string]any, bool) {
	for i, ev := range s.peerEvents {
		b, _ := ev["body"].(map[string]any)
		if ev["type"] == typ && matches(b, match) {
			s.peerEvents = append(s.peerEvents[:i:i], s.peerEvents[i+1:]...)
			return ev, true
		}
	}
	return nil, false
}

// validType accepts a request or event type: dotted words, no
// leading dash (it becomes a vaultctl argument).
func validType(t string) bool {
	if t == "" || len(t) > 64 || t[0] == '-' {
		return false
	}
	for _, c := range t {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// jsonValues decodes the JSON objects vaultctl printed.
func jsonValues(out string) []map[string]any {
	var vs []map[string]any
	i := strings.IndexByte(out, '{')
	if i < 0 {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(out[i:]))
	for {
		var v map[string]any
		if dec.Decode(&v) != nil {
			return vs
		}
		vs = append(vs, v)
	}
}

func matches(body map[string]any, want map[string]string) bool {
	for k, v := range want {
		if fmt.Sprint(body[k]) != v {
			return false
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
