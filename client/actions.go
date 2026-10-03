package client

import (
	"context"
	"encoding/json"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

// Shared actions (VAULT-MESSAGING §10.14): actions the member offers to
// chosen connections, invocations of a connection's actions, and answers.

// ActionDef is an action definition for ActionDefine.
type ActionDef struct {
	ActionID    string          `json:"action_id,omitempty"` // "" creates
	Version     uint64          `json:"version,omitempty"`   // required when replacing
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Kind        string          `json:"kind"`           // "respond" or "fixed"
	Mode        string          `json:"mode,omitempty"` // "ask" (default) or "auto"
	Result      json.RawMessage `json:"result,omitempty"`
	Connections []string        `json:"connections"`
}

// ActionDefine creates or replaces an action and returns its id and
// version.
func (d *Device) ActionDefine(ctx context.Context, def ActionDef) (string, uint64, error) {
	if def.Connections == nil {
		def.Connections = []string{}
	}
	o, err := d.Op(ctx, "action.define", def)
	if err != nil {
		return "", 0, err
	}
	id, err := o.String("action_id")
	if err != nil {
		return "", 0, ErrProtocol
	}
	v, err := o.Uint("version", 1, strictjson.MaxSafeInteger)
	if err != nil {
		return "", 0, ErrProtocol
	}
	return id, v, nil
}

// ActionDelete deletes an action.
func (d *Device) ActionDelete(ctx context.Context, actionID string) error {
	_, err := d.Op(ctx, "action.delete", map[string]any{"action_id": actionID})
	return err
}

// ActionList lists the member's actions (connectionID "") or the actions a
// connection offers.
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
	body := map[string]any{"connection_id": connectionID, "action_id": actionID}
	if params != nil {
		body["params"] = params
	}
	o, err := d.Op(ctx, "action.invoke", body)
	if err != nil {
		return "", err
	}
	return o.String("invocation_id")
}

// ActionRespond answers an invocation waiting for the member (result only
// when approving a `respond` action).
func (d *Device) ActionRespond(ctx context.Context, invocationID string, approve bool, result json.RawMessage) error {
	body := map[string]any{"invocation_id": invocationID, "approve": approve}
	if result != nil {
		body["result"] = result
	}
	_, err := d.Op(ctx, "action.respond", body)
	return err
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
