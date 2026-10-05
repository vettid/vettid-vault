package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/manifest"
)

// MemberAPI is a client for the member API's vault routes
// (MEMBER-API.md "Vault", VAULT-MESSAGING §11.1): it fetches the instance
// to seal to, posts sealed requests and polls their response slots. The
// API only ever sees opaque envelopes.
type MemberAPI struct {
	// Base is the API origin, e.g. https://vettid.org.
	Base string
	HTTP *http.Client
	// Authorize adds the member session to a request.
	Authorize func(*http.Request)
	// PollInterval is the slot polling interval (default 600 ms; the API
	// allows 2 polls per second).
	PollInterval time.Duration
}

// APIError is a member API error (§11.9): Code is the spec's code.
type APIError struct {
	Status     int
	Code       string
	Message    string
	Release    string
	RetryAfter int
}

func (e *APIError) Error() string { return fmt.Sprintf("member API %d %s", e.Status, e.Code) }

// EnclaveInfo is GET /api/vault/enclave.
type EnclaveInfo struct {
	InstanceID  string
	Release     string
	Descriptor  []byte
	Attestation []byte
}

// Slot is a response slot (§11.5).
type Slot struct {
	Status   string
	Envelope []byte
	Code     string
}

func (a *MemberAPI) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(a.Base, "/")+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.Authorize != nil {
		a.Authorize(req)
	}
	hc := a.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error      string `json:"error"`
			Code       string `json:"code"`
			Message    string `json:"message"`
			Release    string `json:"release"`
			RetryAfter int    `json:"retry_after"`
		}
		_ = json.Unmarshal(b, &e)
		if e.Code == "" {
			e.Code = e.Error
		}
		return &APIError{Status: resp.StatusCode, Code: e.Code, Message: e.Message, Release: e.Release, RetryAfter: e.RetryAfter}
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// Enclave fetches the instance to seal to (release "" = routed by the
// API; a PCR0 only to abandon an unconfirmed move, §11.10.5).
func (a *MemberAPI) Enclave(ctx context.Context, release string) (*EnclaveInfo, error) {
	p := "/api/vault/enclave"
	if release != "" {
		p += "?release=" + url.QueryEscape(release)
	}
	var r struct {
		InstanceID  string `json:"instance_id"`
		Release     string `json:"release"`
		Descriptor  string `json:"descriptor"`
		Attestation string `json:"attestation"`
	}
	if err := a.do(ctx, http.MethodGet, p, nil, &r); err != nil {
		return nil, err
	}
	d, err1 := base64.StdEncoding.DecodeString(r.Descriptor)
	at, err2 := base64.StdEncoding.DecodeString(r.Attestation)
	if err1 != nil || err2 != nil {
		return nil, errors.New("client: malformed enclave answer")
	}
	return &EnclaveInfo{InstanceID: r.InstanceID, Release: r.Release, Descriptor: d, Attestation: at}, nil
}

// EnclaveWait is Enclave retried while the release is starting (503
// release_starting, §11.10.5).
func (a *MemberAPI) EnclaveWait(ctx context.Context, release string) (*EnclaveInfo, error) {
	for {
		e, err := a.Enclave(ctx, release)
		var ae *APIError
		if !errors.As(err, &ae) || ae.Code != "release_starting" {
			return e, err
		}
		wait := time.Duration(max(ae.RetryAfter, 1)) * time.Second
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(min(wait, 2*time.Second)):
		}
	}
}

type posted struct {
	VaultID   string `json:"vault_id"`
	RequestID string `json:"request_id"`
}

// Enroll posts a sealed vault.enroll and returns the vault id the API
// assigned.
func (a *MemberAPI) Enroll(ctx context.Context, instanceID string, r *Request) (string, error) {
	var out posted
	err := a.do(ctx, http.MethodPost, "/api/vault/enroll", map[string]string{"request_id": r.RequestID, "instance_id": instanceID,
		"etk_kid": r.ETKKid, "envelope": base64.StdEncoding.EncodeToString(r.Envelope), "manifest_sha256": r.ManifestSHA256}, &out)
	return out.VaultID, err
}

// Unlock posts a sealed vault.unlock.
func (a *MemberAPI) Unlock(ctx context.Context, vaultID, instanceID string, r *Request) error {
	return a.do(ctx, http.MethodPost, "/api/vault/unlock", map[string]string{"vault_id": vaultID, "request_id": r.RequestID,
		"instance_id": instanceID, "etk_kid": r.ETKKid, "envelope": base64.StdEncoding.EncodeToString(r.Envelope),
		"manifest_sha256": r.ManifestSHA256}, nil)
}

// Lock posts a lock request (no envelope).
func (a *MemberAPI) Lock(ctx context.Context, vaultID, requestID string) error {
	return a.do(ctx, http.MethodPost, "/api/vault/lock", map[string]string{"vault_id": vaultID, "request_id": requestID}, nil)
}

// Poll polls a response slot until it is no longer queued.
func (a *MemberAPI) Poll(ctx context.Context, requestID string) (*Slot, error) {
	iv := a.PollInterval
	if iv == 0 {
		iv = 600 * time.Millisecond
	}
	for {
		var r struct {
			Status   string `json:"status"`
			Envelope string `json:"envelope"`
			Code     string `json:"code"`
		}
		if err := a.do(ctx, http.MethodGet, "/api/vault/requests/"+url.PathEscape(requestID), nil, &r); err != nil {
			return nil, err
		}
		if r.Status != "queued" {
			s := &Slot{Status: r.Status, Code: r.Code}
			if r.Envelope != "" {
				b, err := base64.StdEncoding.DecodeString(r.Envelope)
				if err != nil {
					return nil, errors.New("client: malformed slot envelope")
				}
				s.Envelope = b
			}
			return s, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(iv):
		}
	}
}

// Manifest fetches the served release manifest
// (/.well-known/vettid/pcr-manifest.json).
func (a *MemberAPI) Manifest(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(a.Base, "/")+"/.well-known/vettid/pcr-manifest.json", nil)
	if err != nil {
		return nil, err
	}
	hc := a.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{Status: resp.StatusCode, Code: "manifest_unavailable"}
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// ErrInstanceMismatch is an enclave answer whose descriptor names another
// instance than the API routed to.
var ErrInstanceMismatch = errors.New("client: descriptor names another instance")

// retryable reports whether an alternate-channel attempt should be
// repeated with a fresh descriptor (§11.9).
func retryable(err error, s *Slot) bool {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Code == "instance_moved"
	}
	return err == nil && s != nil && (s.Status == "expired" || s.Code == "etk_unknown")
}

// refetchManifest fetches and verifies the served manifest again.
func (a *MemberAPI) refetchManifest(ctx context.Context, d *Device, t Trust) (*manifest.Manifest, error) {
	raw, err := a.Manifest(ctx)
	if err != nil {
		return nil, err
	}
	_, m, err := d.VerifyManifest(raw, t)
	return m, err
}

// maxAttempts bounds re-seals after instance_moved, etk_unknown or expiry.
const maxAttempts = 4

func (a *MemberAPI) enclaveFor(ctx context.Context, release string, m *manifest.Manifest, enroll bool, t Trust) (*EnclaveInfo, *Enclave, error) {
	info, err := a.EnclaveWait(ctx, release)
	if err != nil {
		return nil, nil, err
	}
	e, err := VerifyEnclave(info.Descriptor, info.Attestation, m, enroll, t, time.Now())
	if err != nil {
		return nil, nil, err
	}
	if e.Descriptor.InstanceID != info.InstanceID {
		return nil, nil, ErrInstanceMismatch
	}
	return info, e, nil
}

// EnrollVia enrolls this app through the member API (§11.3): verify the
// manifest and the routed enclave, seal vault.enroll, post it, poll the
// slot and open the result. It returns the vault id the API assigned.
func (d *Device) EnrollVia(ctx context.Context, api *MemberAPI, userGUID, pin string, t Trust, att Attester) (string, *EnrollOutcome, error) {
	raw, err := api.Manifest(ctx)
	if err != nil {
		return "", nil, err
	}
	_, m, err := d.VerifyManifest(raw, t)
	if err != nil {
		return "", nil, err
	}
	refetched := false
	for attempt := 1; ; attempt++ {
		info, e, err := api.enclaveFor(ctx, "", m, true, t)
		if err != nil {
			return "", nil, err
		}
		req, err := d.BuildEnroll(userGUID, pin, e, m, att)
		if err != nil {
			return "", nil, err
		}
		vid, err := api.Enroll(ctx, info.InstanceID, req)
		var slot *Slot
		if err == nil {
			slot, err = api.Poll(ctx, req.RequestID)
		}
		if retryable(err, slot) && attempt < maxAttempts {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		if slot.Status != "done" || len(slot.Envelope) == 0 {
			return "", nil, fmt.Errorf("client: enrollment not answered (%s %s)", slot.Status, slot.Code)
		}
		r, err := d.OpenEnrollResult(slot.Envelope, req.RequestID)
		if err != nil {
			return "", nil, err
		}
		if !r.OK && r.Code == "manifest" && !refetched {
			// The host had no document for this manifest (or a stale
			// one): refetch it and retry once (§11.5, 0.10.0).
			refetched = true
			if m, err = api.refetchManifest(ctx, d, t); err != nil {
				return "", nil, err
			}
			continue
		}
		return vid, &EnrollOutcome{OK: r.OK, Code: r.Code, InstanceID: info.InstanceID}, nil
	}
}

// EnrollOutcome is the opened vault.enroll.result.
type EnrollOutcome struct {
	OK         bool
	Code       string
	InstanceID string
}

// UnlockOutcome is the opened vault.unlock.result and where it ran.
type UnlockOutcome struct {
	OK             bool
	Code           string
	StateSeq       uint64
	HeaderSeq      uint64
	ReleaseNumber  uint64
	ReleaseStatus  string
	Update         string // moved, abandoned, refused, ""
	UpdateCode     string
	InstanceID     string
	ReleaseChanged bool
	// CredentialBackup: the recovered app's unlock carries the vault's
	// credential.backup setting (§11.11.5 step 1, 0.10.6); nil otherwise.
	CredentialBackup *bool
}

// UnlockVia unlocks the vault through the member API (§11.4). release is
// "" (routed by the API) or a PCR0 (abandoning an unconfirmed move).
func (d *Device) UnlockVia(ctx context.Context, api *MemberAPI, userGUID, pin string, t Trust, att Attester, o UnlockOptions, release string) (*UnlockOutcome, error) {
	raw, err := api.Manifest(ctx)
	if err != nil {
		return nil, err
	}
	_, m, err := d.VerifyManifest(raw, t)
	if err != nil {
		return nil, err
	}
	refetched := false
	for attempt := 1; ; attempt++ {
		info, e, err := api.enclaveFor(ctx, release, m, false, t)
		if err != nil {
			return nil, err
		}
		req, err := d.BuildUnlock(userGUID, pin, e, m, att, o)
		if err != nil {
			return nil, err
		}
		err = api.Unlock(ctx, d.VaultID(), info.InstanceID, req)
		var slot *Slot
		if err == nil {
			slot, err = api.Poll(ctx, req.RequestID)
		}
		if retryable(err, slot) && attempt < maxAttempts {
			continue
		}
		if err != nil {
			return nil, err
		}
		if slot.Status != "done" || len(slot.Envelope) == 0 {
			return nil, fmt.Errorf("client: unlock not answered (%s %s)", slot.Status, slot.Code)
		}
		r, err := d.OpenUnlockResult(slot.Envelope)
		if err != nil {
			return nil, err
		}
		if !r.OK && r.Code == "manifest" && !refetched {
			refetched = true // as in EnrollVia: refetch and retry once
			if m, err = api.refetchManifest(ctx, d, t); err != nil {
				return nil, err
			}
			continue
		}
		out := &UnlockOutcome{OK: r.OK, Code: r.Code, StateSeq: r.StateSeq, HeaderSeq: r.HeaderSeq, ReleaseNumber: r.ReleaseNumber,
			ReleaseStatus: r.ReleaseStatus, InstanceID: info.InstanceID, ReleaseChanged: req.ReleaseChanged, CredentialBackup: r.CredentialBackup}
		if r.Update != nil {
			out.Update, out.UpdateCode = r.Update.Result, r.Update.Code
		}
		return out, nil
	}
}

// RecoveryRegister posts a sealed vault.recovery.register (§11.11.3,
// MEMBER-API "Vault recovery").
func (a *MemberAPI) RecoveryRegister(ctx context.Context, vaultID, instanceID string, r *Request) error {
	return a.do(ctx, http.MethodPost, "/api/vault/recovery/register", map[string]string{"vault_id": vaultID, "request_id": r.RequestID,
		"instance_id": instanceID, "etk_kid": r.ETKKid, "envelope": base64.StdEncoding.EncodeToString(r.Envelope)}, nil)
}

// RecoveryRegisterVia registers this new app with the recovery code from
// the portal's QR through the member API (§11.11.3): verify the manifest
// and the routed enclave, seal the request, post it, poll the slot and
// open the result. The slot is returned too: its code is
// recovery_registered when the enclave said so in the clear (0.10.6),
// which the app ignores (it reads the sealed result).
func (d *Device) RecoveryRegisterVia(ctx context.Context, api *MemberAPI, userGUID string, qr *altchan.RecoveryCode, t Trust, att Attester) (*altchan.RecoveryResult, *Slot, error) {
	raw, err := api.Manifest(ctx)
	if err != nil {
		return nil, nil, err
	}
	_, m, err := d.VerifyManifest(raw, t)
	if err != nil {
		return nil, nil, err
	}
	for attempt := 1; ; attempt++ {
		info, e, err := api.enclaveFor(ctx, "", m, false, t)
		if err != nil {
			return nil, nil, err
		}
		req, err := d.BuildRecoveryRegister(userGUID, qr, e, att)
		if err != nil {
			return nil, nil, err
		}
		err = api.RecoveryRegister(ctx, qr.VaultID, info.InstanceID, req)
		var slot *Slot
		if err == nil {
			slot, err = api.Poll(ctx, req.RequestID)
		}
		if retryable(err, slot) && attempt < maxAttempts {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		if slot.Status != "done" || len(slot.Envelope) == 0 {
			return nil, slot, fmt.Errorf("client: recovery register not answered (%s %s)", slot.Status, slot.Code)
		}
		r, err := d.OpenRecoveryResult(slot.Envelope)
		return r, slot, err
	}
}

// LockVia asks the member API to lock the vault and waits for the slot.
func (d *Device) LockVia(ctx context.Context, api *MemberAPI) (*Slot, error) {
	rid, err := envelope.NewULID(time.Now())
	if err != nil {
		return nil, err
	}
	if err := api.Lock(ctx, d.VaultID(), rid); err != nil {
		return nil, err
	}
	return api.Poll(ctx, rid)
}
