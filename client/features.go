package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

// Feature operations of VAULT-MESSAGING §10.6–§10.9. Each is a request to
// the vault; errors carry the response's error code.

// OpError is an error response.
type OpError struct {
	Type string
	Code string
}

func (e *OpError) Error() string { return fmt.Sprintf("client: %s: %s", e.Type, e.Code) }

// Code returns the error code of err if it is an *OpError.
func Code(err error) string {
	var oe *OpError
	if errors.As(err, &oe) {
		return oe.Code
	}
	return ""
}

// Op sends a request whose body is v marshalled as JSON and returns the
// parsed response body.
func (d *Device) Op(ctx context.Context, typ string, v any) (strictjson.Object, error) {
	body := json.RawMessage(`{}`)
	if v != nil {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		if string(b) != "null" { // a nil map
			body = b
		}
	}
	r, err := d.Request(ctx, typ, body)
	if err != nil {
		return nil, err
	}
	if !r.OK() {
		return nil, &OpError{Type: typ, Code: r.ErrorCode()}
	}
	b := r.Body()
	if len(b) == 0 {
		b = json.RawMessage(`{}`)
	}
	return strictjson.ParseObject(b)
}

// ProfileGet returns the owner's profile object: the display name and
// photo (§10.8; what connections see also includes the @profile items).
func (d *Device) ProfileGet(ctx context.Context) (strictjson.Object, error) {
	return d.Op(ctx, "profile.get", nil)
}

// ProfileSet applies a profile.set body (which must name the version) and
// returns the new version.
func (d *Device) ProfileSet(ctx context.Context, body map[string]any) (uint64, error) {
	o, err := d.Op(ctx, "profile.set", body)
	if err != nil {
		return 0, err
	}
	return o.Uint("version", 1, strictjson.MaxSafeInteger)
}

// SettingsGet returns the settings.
func (d *Device) SettingsGet(ctx context.Context) (strictjson.Object, error) {
	return d.Op(ctx, "settings.get", nil)
}

// SettingsSet sets keys at a version and returns the new version.
func (d *Device) SettingsSet(ctx context.Context, version uint64, set map[string]any) (uint64, error) {
	o, err := d.Op(ctx, "settings.set", map[string]any{"version": version, "set": set})
	if err != nil {
		return 0, err
	}
	return o.Uint("version", 1, strictjson.MaxSafeInteger)
}

// AuditList returns audit.list (or connection.audit.list when q names a
// connection_id and perConnection is set).
func (d *Device) AuditList(ctx context.Context, q map[string]any, perConnection bool) (strictjson.Object, error) {
	typ := "audit.list"
	if perConnection {
		typ = "connection.audit.list"
	}
	return d.Op(ctx, typ, q)
}

// FeedList returns feed.list.
func (d *Device) FeedList(ctx context.Context, q map[string]any) (strictjson.Object, error) {
	return d.Op(ctx, "feed.list", q)
}

// FeedGet returns one feed item.
func (d *Device) FeedGet(ctx context.Context, id string) (strictjson.Object, error) {
	return d.Op(ctx, "feed.get", map[string]any{"item_id": id})
}

// FeedUpdate sets an item's status and/or priority ("" to leave as is).
func (d *Device) FeedUpdate(ctx context.Context, id, status, priority string) (strictjson.Object, error) {
	body := map[string]any{"item_id": id}
	if status != "" {
		body["status"] = status
	}
	if priority != "" {
		body["priority"] = priority
	}
	return d.Op(ctx, "feed.update", body)
}

// FeedDelete deletes a feed item.
func (d *Device) FeedDelete(ctx context.Context, id string) error {
	_, err := d.Op(ctx, "feed.delete", map[string]any{"item_id": id})
	return err
}

// GuideSync sends the app's guide catalog.
func (d *Device) GuideSync(ctx context.Context, guides []map[string]any) (strictjson.Object, error) {
	return d.Op(ctx, "guide.sync", map[string]any{"guides": guides})
}
