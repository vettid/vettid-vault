//go:build devenclave

package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// recoveryCode serves POST /dev/recovery/code {"guid": G, "timeout_s": N}:
// the account portal's side of a recovery (VAULT-MESSAGING §11.11) for
// member G, through the member API stand-in, with the recovery clock moved
// past the 24 h delay (-recovery-skew). It answers
//
//	200 {"vault_id", "recovery_id", "code", "qr", "not_before", "expires_at", "available_at"}
//
// where qr is the QR payload the portal would show (§11.11.2); the app
// registers with it through POST /api/vault/recovery/register. A vault
// without a credential answers 422 {"error": "no_credential"} and the
// recovery is cancelled. Member API refusals (404 no vault, 409
// recovery_active, ...) are passed on with their status.
func (s *stack) recoveryCode(w http.ResponseWriter, r *http.Request) {
	var in struct {
		GUID     string `json:"guid"`
		TimeoutS int    `json:"timeout_s"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in) != nil || in.GUID == "" || len(in.GUID) > 128 {
		writeJSON(w, 400, map[string]any{"error": "bad_request", "message": `body must be {"guid": "..."}`})
		return
	}
	if s.opts.recoverySkew <= 0 {
		writeJSON(w, 409, map[string]any{"error": "no_recovery_skew",
			"message": "the code would only be available in 24 h; start devstack with -recovery-skew 24h"})
		return
	}
	if in.TimeoutS <= 0 || in.TimeoutS > 600 {
		in.TimeoutS = 120
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(in.TimeoutS)*time.Second)
	defer cancel()
	// One recovery at a time: each moves the shared clock.
	s.recMu.Lock()
	defer s.recMu.Unlock()
	status, out := s.playPortal(ctx, in.GUID)
	writeJSON(w, status, out)
}

func (s *stack) playPortal(ctx context.Context, guid string) (int, map[string]any) {
	bk, err := ecdh.P256().GenerateKey(nil)
	if err != nil {
		return 500, map[string]any{"error": err.Error()}
	}
	code, req, err := s.apiCall(ctx, guid, "POST", "/api/vault/recovery", map[string]any{"browser_key": base64.StdEncoding.EncodeToString(bk.PublicKey().Bytes())})
	if err != nil {
		return 502, map[string]any{"error": "member_api", "message": err.Error()}
	}
	if code != 202 {
		return code, req
	}
	rid, _ := req["recovery_id"].(string)
	// The enclave answers the request: the code is minted under the
	// current recovery clock.
	for {
		code, st, err := s.apiCall(ctx, guid, "GET", "/api/vault/requests/"+rid, nil)
		if err != nil {
			return 502, map[string]any{"error": "member_api", "message": err.Error()}
		}
		if code == 200 && st["status"] == "done" {
			break
		}
		if code != 200 || st["status"] != "queued" {
			return 502, map[string]any{"error": "recovery_not_answered", "recovery_id": rid, "request": st}
		}
		if !sleepCtx(ctx, 500*time.Millisecond) {
			return 504, map[string]any{"error": "timeout", "recovery_id": rid, "step": "minting"}
		}
	}
	// Past the delay, for the member API and the enclave.
	if err := s.setRecoveryOffset(time.Duration(s.recOff.Load()) + s.opts.recoverySkew); err != nil {
		return 500, map[string]any{"error": err.Error()}
	}
	s.logf("recovery %s: recovery clock moved forward %s (now +%s)", rid, s.opts.recoverySkew, time.Duration(s.recOff.Load()))
	var rec map[string]any
	for {
		code, st, err := s.apiCall(ctx, guid, "GET", "/api/vault/recovery", nil)
		if err != nil {
			return 502, map[string]any{"error": "member_api", "message": err.Error()}
		}
		rec, _ = st["recovery"].(map[string]any)
		if code != 200 || rec == nil || rec["recovery_id"] != rid {
			return 502, map[string]any{"error": "recovery_lost", "recovery_id": rid, "status": st}
		}
		if rec["state"] == "available" && rec["sealed_code"] != nil {
			break
		}
		if rec["state"] != "pending" && rec["state"] != "available" {
			return 409, map[string]any{"error": "recovery_ended", "recovery": rec}
		}
		if !sleepCtx(ctx, time.Second) {
			return 504, map[string]any{"error": "timeout", "recovery": rec, "step": "availability"}
		}
	}
	sealed, err := base64.StdEncoding.DecodeString(fmt.Sprint(rec["sealed_code"]))
	if err != nil {
		return 502, map[string]any{"error": "sealed_code", "message": err.Error()}
	}
	vid := fmt.Sprint(rec["vault_id"])
	c, err := altchan.OpenRecoveryCode(bk, sealed, vid, rid)
	if err != nil {
		// Random bytes: the enclave could not answer (§11.11.2).
		return 502, map[string]any{"error": "sealed_code_unreadable", "recovery_id": rid}
	}
	if c.Error != "" {
		// What the portal shows; the member can request again only once
		// this one is cancelled.
		_, _, _ = s.apiCall(ctx, guid, "POST", "/api/vault/recovery/cancel", map[string]any{"recovery_id": rid})
		return 422, map[string]any{"error": c.Error, "vault_id": vid, "recovery_id": rid}
	}
	c.API = strings.TrimRight(s.apiURL(), "/") // the QR names its member API (0.15.0, §11.11.2)
	return 200, map[string]any{"vault_id": c.VaultID, "recovery_id": c.RecoveryID, "code": c.Code, "qr": string(altchan.RecoveryQR(c)),
		"not_before": envelope.FormatTS(c.NotBefore), "expires_at": envelope.FormatTS(c.Expires), "available_at": rec["available_at"]}
}

// apiCall calls the member API stand-in as member guid.
func (s *stack) apiCall(ctx context.Context, guid, method, path string, body any) (int, map[string]any, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.apiURL()+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+guid)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m); err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, m, nil
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
