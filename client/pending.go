package client

import (
	"context"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

// PendingList returns one page of the open asks that arrive only as
// events (VAULT-MESSAGING §10.4.2, 0.70.0): `{asks: [{kind, body}], next?}`.
// after is the previous page's next cursor ("" for the first page); limit
// 0 means the vault's default.
func (d *Device) PendingList(ctx context.Context, after string, limit int) (strictjson.Object, error) {
	body := map[string]any{}
	if after != "" {
		body["after"] = after
	}
	if limit > 0 {
		body["limit"] = limit
	}
	return d.Op(ctx, "pending.list", body)
}
