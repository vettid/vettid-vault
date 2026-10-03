package client

import (
	"context"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

// Presence (VAULT-MESSAGING §9.2, §10.17): on-demand pings; a connection
// that does not share its presence with this member stays silent.

// PresenceGet returns the member's presence policy.
func (d *Device) PresenceGet(ctx context.Context) (strictjson.Object, error) {
	return d.Op(ctx, "presence.get", nil)
}

// PresenceSet changes the presence policy (members left nil are kept)
// and returns its new version.
func (d *Device) PresenceSet(ctx context.Context, version uint64, state, share string, except []string) (uint64, error) {
	body := map[string]any{"version": version}
	if state != "" {
		body["state"] = state
	}
	if share != "" {
		body["share"] = share
	}
	if except != nil {
		body["except"] = except
	}
	o, err := d.Op(ctx, "presence.set", body)
	if err != nil {
		return 0, err
	}
	v, err := o.Uint("version", 1, strictjson.MaxSafeInteger)
	if err != nil {
		return 0, ErrProtocol
	}
	return v, nil
}

// PresenceQuery pings a connection and returns the ping id; the answer,
// if any, arrives as presence.result before the ping's exp.
func (d *Device) PresenceQuery(ctx context.Context, connectionID string) (string, error) {
	o, err := d.Op(ctx, "presence.query", map[string]any{"connection_id": connectionID})
	if err != nil {
		return "", err
	}
	return o.String("ping_id")
}

// PresenceResult waits for the answer to a ping.
func (d *Device) PresenceResult(ctx context.Context, pingID string) (strictjson.Object, error) {
	return d.waitObj(ctx, "presence.result", func(o strictjson.Object) bool {
		id, _ := o.String("ping_id")
		return id == pingID
	})
}
