package client

import (
	"context"
	"encoding/json"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/pushwire"
)

// VAULT-MESSAGING 0.24.0 §14 from the app's side: push.register,
// push.confirm (PUSH-GATEWAY 0.5.0), push.unregister, the push state in
// device.list and push.token-needed.

// EventPushTokenNeeded asks the app for a fresh push.register (§14.2;
// the grammar's form of the spec's push.token_needed).
const EventPushTokenNeeded = "push.token-needed"

// PushState is the push state of §14.1.
type PushState struct {
	Platform     string    `json:"platform"`
	Environment  string    `json:"environment,omitempty"`
	AppID        string    `json:"app_id"`
	State        string    `json:"state"`
	RegisteredAt time.Time `json:"registered_at"`
	LastWakeAt   time.Time `json:"last_wake_at,omitzero"`
	LastResult   string    `json:"last_result,omitempty"`
}

// ParsePushState parses a push state strictly.
func ParsePushState(raw json.RawMessage) (*PushState, error) {
	o, err := strictjson.AsObject(raw)
	if err != nil {
		return nil, ErrProtocol
	}
	s := &PushState{}
	for k, p := range map[string]*string{"platform": &s.Platform, "app_id": &s.AppID, "state": &s.State} {
		if *p, err = o.String(k); err != nil {
			return nil, ErrProtocol
		}
	}
	for k, p := range map[string]*string{"environment": &s.Environment, "last_result": &s.LastResult} {
		if *p, _, err = o.OptString(k); err != nil {
			return nil, ErrProtocol
		}
	}
	ts, err := o.String("registered_at")
	if err != nil {
		return nil, ErrProtocol
	}
	if s.RegisteredAt, err = envelope.ParseTS(ts); err != nil {
		return nil, ErrProtocol
	}
	if ts, ok, err := o.OptString("last_wake_at"); err != nil {
		return nil, ErrProtocol
	} else if ok {
		if s.LastWakeAt, err = envelope.ParseTS(ts); err != nil {
			return nil, ErrProtocol
		}
	}
	return s, nil
}

// PushRegister registers the app's platform token (§14.1); the vault
// answers its push state: pending while the gateway's challenge code is
// on its way to the token by push (send it with PushConfirm within 10
// minutes), active when the token's registration is current. Errors are
// *OpError (bad_request, forbidden, unavailable, gateway_error
// {retry_after?}, limit).
func (d *Device) PushRegister(ctx context.Context, r pushwire.Registration) (*PushState, error) {
	body := map[string]any{"platform": r.Platform, "token": r.Token, "app_id": r.AppID}
	if r.Environment != "" {
		body["environment"] = r.Environment
	}
	o, err := d.Op(ctx, "push.register", body)
	if err != nil {
		return nil, err
	}
	raw, ok := o["push"]
	if !ok {
		return nil, ErrProtocol
	}
	return ParsePushState(raw)
}

// PushConfirm returns the challenge code the app received by push for
// the vault's pending registration (PUSH-GATEWAY 0.5.0); the vault answers
// its push state, active. Errors are *OpError: bad_request (a malformed
// code, or no_pending_registration), gateway_error (challenge_invalid,
// challenge_expired, or the gateway unreachable; register again),
// forbidden, unavailable.
func (d *Device) PushConfirm(ctx context.Context, code string) (*PushState, error) {
	o, err := d.Op(ctx, "push.confirm", map[string]any{"code": code})
	if err != nil {
		return nil, err
	}
	raw, ok := o["push"]
	if !ok {
		return nil, ErrProtocol
	}
	return ParsePushState(raw)
}

// PushUnregister drops the app's registration (§14.1).
func (d *Device) PushUnregister(ctx context.Context) error {
	_, err := d.Op(ctx, "push.unregister", nil)
	return err
}

// PushStatus returns this device's push state from device.list (nil
// without a registration).
func (d *Device) PushStatus(ctx context.Context) (*PushState, error) {
	o, err := d.Op(ctx, "device.list", nil)
	if err != nil {
		return nil, err
	}
	arr, err := o.Array("devices")
	if err != nil {
		return nil, ErrProtocol
	}
	for _, raw := range arr {
		e, err := strictjson.AsObject(raw)
		if err != nil {
			return nil, ErrProtocol
		}
		if p, ok := e["push"]; ok {
			return ParsePushState(p)
		}
	}
	return nil, nil
}
