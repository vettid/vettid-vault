package client

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/sharewire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Grants between connections (VAULT-MESSAGING §10.12) from a device's
// side: ask a connection, decide on a connection's request, fetch a
// granted value (sealed to a one-time key of this device), revoke, list,
// read a connection's catalog.

// GrantItem is one requested item: kind "field" (a profile key) or
// "secret" (a secret id), with an optional label.
type GrantItem struct {
	Kind  string `json:"kind"`
	Ref   string `json:"ref"`
	Label string `json:"label,omitempty"`
}

// GrantRequest asks a connection for items; uses and expiresIn are
// optional (0: the defaults). It returns the request id.
func (d *Device) GrantRequest(ctx context.Context, connectionID string, items []GrantItem, uses, expiresIn int, reason string) (string, error) {
	body := map[string]any{"connection_id": connectionID, "items": items}
	if uses > 0 {
		body["uses"] = uses
	}
	if expiresIn > 0 {
		body["expires_in"] = expiresIn
	}
	if reason != "" {
		body["reason"] = reason
	}
	o, err := d.Op(ctx, "grant.request", body)
	if err != nil {
		return "", err
	}
	return o.String("request_id")
}

// GrantDecide approves or denies a connection's request. items (indices)
// may be nil for all; uses and expiresIn 0 keep the request's. It returns
// the grants made.
func (d *Device) GrantDecide(ctx context.Context, requestID string, approve bool, items []int, uses, expiresIn int) (json.RawMessage, error) {
	body := map[string]any{"request_id": requestID, "approve": approve}
	if items != nil {
		body["items"] = items
	}
	if uses > 0 {
		body["uses"] = uses
	}
	if expiresIn > 0 {
		body["expires_in"] = expiresIn
	}
	o, err := d.Op(ctx, "grant.decide", body)
	if err != nil {
		return nil, err
	}
	return o["grants"], nil
}

// GrantResult is the outcome of a fetch: the value, or the member's vault's
// refusal (revoked, expired, exhausted, unavailable, not_found).
type GrantResult struct {
	Value    []byte
	UsesLeft uint64
	Error    string
}

// GrantFetch fetches a received grant's current value: a one-time
// MLKEM768X25519 reply key is generated for it, the value arrives in
// grant.value sealed to it, and the key is destroyed afterwards.
func (d *Device) GrantFetch(ctx context.Context, grantID string) (*GrantResult, error) {
	k, err := suite.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	defer k.Destroy()
	o, err := d.Op(ctx, "grant.fetch", map[string]any{"grant_id": grantID,
		"reply_key": base64.StdEncoding.EncodeToString(k.Public().Bytes())})
	if err != nil {
		return nil, err
	}
	fid, err := o.String("fetch_id")
	if err != nil {
		return nil, ErrProtocol
	}
	ev, err := d.WaitEvent(ctx, "grant.value", func(b json.RawMessage) bool {
		v, err := strictjson.ParseObject(b)
		if err != nil {
			return false
		}
		id, _ := v.String("fetch_id")
		return id == fid
	})
	if err != nil {
		return nil, err
	}
	v, err := strictjson.ParseObject(ev.Body)
	if err != nil {
		return nil, ErrProtocol
	}
	if e, ok, _ := v.OptString("error"); ok {
		return &GrantResult{Error: e}, nil
	}
	sealed, err := v.Base64("value_sealed", -1)
	if err != nil {
		return nil, ErrProtocol
	}
	left, err := v.Uint("uses_left", 0, 100)
	if err != nil {
		return nil, ErrProtocol
	}
	pt, err := sharewire.OpenValue(k, grantID, fid, sealed)
	if err != nil {
		return nil, ErrProtocol
	}
	return &GrantResult{Value: pt, UsesLeft: left}, nil
}

// GrantRevoke revokes a grant given or gives up one received.
func (d *Device) GrantRevoke(ctx context.Context, grantID string) error {
	_, err := d.Op(ctx, "grant.revoke", map[string]any{"grant_id": grantID})
	return err
}

// GrantList lists grants given and received and requests pending and made.
func (d *Device) GrantList(ctx context.Context) (strictjson.Object, error) {
	return d.Op(ctx, "grant.list", nil)
}

// GrantCatalog asks a connection for its catalog and waits for it; it
// returns the `secrets` array (metadata only).
func (d *Device) GrantCatalog(ctx context.Context, connectionID string) (json.RawMessage, error) {
	o, err := d.Op(ctx, "grant.catalog", map[string]any{"connection_id": connectionID})
	if err != nil {
		return nil, err
	}
	rid, err := o.String("request_id")
	if err != nil {
		return nil, ErrProtocol
	}
	ev, err := d.WaitEvent(ctx, "grant.catalog.result", func(b json.RawMessage) bool {
		v, err := strictjson.ParseObject(b)
		if err != nil {
			return false
		}
		id, _ := v.String("request_id")
		return id == rid
	})
	if err != nil {
		return nil, err
	}
	v, err := strictjson.ParseObject(ev.Body)
	if err != nil {
		return nil, ErrProtocol
	}
	return v["secrets"], nil
}
