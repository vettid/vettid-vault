package client

import (
	"context"
	"encoding/json"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

// Shared actions (VAULT-MESSAGING §10.14): the built-in catalog and its
// permission modes, invocations of a connection's actions, and the
// member's decisions.

// ActionConfig configures one built-in action (action.configure).
type ActionConfig struct {
	ActionID    string   `json:"action_id"`
	Mode        string   `json:"mode"` // default-deny, allowlist, prompt-each-time, default-allow
	Version     *uint64  `json:"version,omitempty"`
	Connections []string `json:"connections,omitempty"`
	Fields      []string `json:"fields,omitempty"`
	Secrets     []string `json:"secrets,omitempty"`
}

// ActionConfigure sets an action's permission mode and returns the
// configuration's version.
func (d *Device) ActionConfigure(ctx context.Context, c ActionConfig) (uint64, error) {
	o, err := d.Op(ctx, "action.configure", c)
	if err != nil {
		return 0, err
	}
	v, err := o.Uint("version", 1, strictjson.MaxSafeInteger)
	if err != nil {
		return 0, ErrProtocol
	}
	return v, nil
}

// ActionList lists the catalog with its configuration (connectionID "")
// or the actions a connection offers.
func (d *Device) ActionList(ctx context.Context, connectionID string) (strictjson.Object, error) {
	body := map[string]any{}
	if connectionID != "" {
		body["connection_id"] = connectionID
	}
	return d.Op(ctx, "action.list", body)
}

// ActionInvoke invokes an action a connection offers and returns the
// invocation id; the answer arrives as an action.result event.
func (d *Device) ActionInvoke(ctx context.Context, connectionID, actionID string, params json.RawMessage) (string, error) {
	if params == nil {
		params = json.RawMessage(`{}`)
	}
	o, err := d.Op(ctx, "action.invoke", map[string]any{"connection_id": connectionID, "action_id": actionID, "params": params})
	if err != nil {
		return "", err
	}
	return o.String("invocation_id")
}

// ActionRespond approves or denies an invocation waiting for the member
// and returns the status sent. A critical action is approved only by an
// app within the credential's unlock window (credential_locked).
func (d *Device) ActionRespond(ctx context.Context, invocationID string, approve bool) (string, error) {
	o, err := d.Op(ctx, "action.respond", map[string]any{"invocation_id": invocationID, "approve": approve})
	if err != nil {
		return "", err
	}
	return o.String("status")
}

// ActionResult waits for the result of an invocation.
func (d *Device) ActionResult(ctx context.Context, invocationID string) (strictjson.Object, error) {
	in, err := d.WaitEvent(ctx, "action.result", func(b json.RawMessage) bool {
		o, err := strictjson.ParseObject(b)
		if err != nil {
			return false
		}
		id, _ := o.String("invocation_id")
		return id == invocationID
	})
	if err != nil {
		return nil, err
	}
	return strictjson.ParseObject(in.Body)
}
