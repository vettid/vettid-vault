package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
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
// connection_id and perConnection is set). q holds the request's members
// as §10.9 names them (connection_id, kinds, q, since, until, before_seq
// or after_seq, limit); AuditQuery builds it.
func (d *Device) AuditList(ctx context.Context, q map[string]any, perConnection bool) (strictjson.Object, error) {
	typ := "audit.list"
	if perConnection {
		typ = "connection.audit.list"
	}
	return d.Op(ctx, typ, q)
}

// AuditQuery is an audit.list request (§10.9). Zero members are left out.
// Q, Since and Until (0.20.0) search the log in the vault: Q is a
// case-insensitive substring of an entry's kind and the current names of
// its connection, device and item (1–128 bytes, sent in NFC); Since is
// inclusive and Until exclusive. With Q the vault evaluates at most 2,000
// entries per request: a page it cut short has partial, and the app
// continues with its cursor.
type AuditQuery struct {
	ConnectionID string
	Kinds        []string
	Q            string
	Since, Until time.Time
	BeforeSeq    uint64
	// After lists oldest first from AfterSeq (exclusive).
	After    bool
	AfterSeq uint64
	Limit    int
}

// Body returns the request body.
func (q AuditQuery) Body() map[string]any {
	b := map[string]any{}
	if q.ConnectionID != "" {
		b["connection_id"] = q.ConnectionID
	}
	if len(q.Kinds) > 0 {
		b["kinds"] = q.Kinds
	}
	if q.Q != "" {
		b["q"] = q.Q
	}
	if !q.Since.IsZero() {
		b["since"] = envelope.FormatTS(q.Since)
	}
	if !q.Until.IsZero() {
		b["until"] = envelope.FormatTS(q.Until)
	}
	if q.BeforeSeq != 0 {
		b["before_seq"] = q.BeforeSeq
	}
	if q.After {
		b["after_seq"] = q.AfterSeq
	}
	if q.Limit != 0 {
		b["limit"] = q.Limit
	}
	return b
}

// AuditPage is one audit.list answer: the entries as sent, the cursor
// (Next, 0 at the end of the results) and Partial (0.20.0: the search
// budget ran out before limit matches).
type AuditPage struct {
	Entries []json.RawMessage
	Head    string
	Seq     uint64
	Next    uint64
	Partial bool
}

// AuditSearch sends q (connection.audit.list when perConnection) and
// parses the page.
func (d *Device) AuditSearch(ctx context.Context, q AuditQuery, perConnection bool) (*AuditPage, error) {
	o, err := d.AuditList(ctx, q.Body(), perConnection)
	if err != nil {
		return nil, err
	}
	p := &AuditPage{}
	if err := json.Unmarshal(o["entries"], &p.Entries); err != nil {
		return nil, ErrProtocol
	}
	if p.Head, err = o.String("head"); err != nil {
		return nil, ErrProtocol
	}
	if p.Seq, err = o.Uint("seq", 0, strictjson.MaxSafeInteger); err != nil {
		return nil, ErrProtocol
	}
	for _, k := range []string{"next_before_seq", "next_after_seq"} {
		if v, present, err := o.OptUint(k, 0, strictjson.MaxSafeInteger); err != nil {
			return nil, ErrProtocol
		} else if present {
			p.Next = v
		}
	}
	if o.Has("partial") {
		if p.Partial, err = o.Bool("partial"); err != nil {
			return nil, ErrProtocol
		}
	}
	return p, nil
}

// AuditSearchAll follows the cursors of q until the end of the results
// or max entries (0: no bound), across partial pages, and returns the
// entries in the vault's order.
func (d *Device) AuditSearchAll(ctx context.Context, q AuditQuery, perConnection bool, max int) ([]json.RawMessage, error) {
	var out []json.RawMessage
	for {
		p, err := d.AuditSearch(ctx, q, perConnection)
		if err != nil {
			return out, err
		}
		out = append(out, p.Entries...)
		if max > 0 && len(out) >= max {
			return out[:max], nil
		}
		if p.Next == 0 { // a cursor is an entry's seq, never 0
			return out, nil
		}
		if q.After {
			q.AfterSeq = p.Next
		} else {
			q.BeforeSeq = p.Next
		}
	}
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
