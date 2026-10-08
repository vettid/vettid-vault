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

// OpError is an error response. Body is the error's body, if any
// (limit's {limit, max, size?} since 0.21.0, backoff's {retry_after}).
type OpError struct {
	Type string
	Code string
	Body json.RawMessage
}

// Limit is a `limit` error's body (§10.1, 0.21.0): the limit's name, its
// bound and, for a size limit, the size the refused request reached.
type Limit struct {
	Name    string
	Max     uint64
	Size    uint64
	HasSize bool
}

// LimitOf returns the limit a `limit` error names; ok is false for any
// other error, or a limit error without the body.
func LimitOf(err error) (Limit, bool) {
	var oe *OpError
	if !errors.As(err, &oe) || oe.Code != "limit" {
		return Limit{}, false
	}
	o, perr := strictjson.ParseObject(oe.Body)
	if perr != nil {
		return Limit{}, false
	}
	var l Limit
	var e1, e2 error
	l.Name, e1 = o.String("limit")
	l.Max, e2 = o.Uint("max", 0, strictjson.MaxSafeInteger)
	if e1 != nil || e2 != nil {
		return Limit{}, false
	}
	if v, present, err := o.OptUint("size", 0, strictjson.MaxSafeInteger); err != nil {
		return Limit{}, false
	} else if present {
		l.Size, l.HasSize = v, true
	}
	return l, true
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
		return nil, &OpError{Type: typ, Code: r.ErrorCode(), Body: r.Body()}
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

// AuditExportResult is audit.export's answer (§10.9, 0.22.0): the count
// (at most 10,000, newest first), More when more entries match, the bound
// UptoSeq and its UptoHash (the log head of the export file), the range
// when Count > 0, and, for an export (not a preview), EntrySeq, the seq
// of its audit.exported entry.
type AuditExportResult struct {
	Count     uint64    `json:"count"`
	More      bool      `json:"more"`
	UptoSeq   uint64    `json:"upto_seq"`
	UptoHash  []byte    `json:"upto_hash"`
	OldestSeq uint64    `json:"oldest_seq,omitempty"`
	NewestSeq uint64    `json:"newest_seq,omitempty"`
	OldestAt  time.Time `json:"oldest_at,omitzero"`
	NewestAt  time.Time `json:"newest_at,omitzero"`
	EntrySeq  uint64    `json:"entry_seq,omitempty"`
}

func parseAuditExport(o strictjson.Object) (*AuditExportResult, error) {
	r := &AuditExportResult{}
	var err error
	if r.Count, err = o.Uint("count", 0, 10000); err != nil {
		return nil, ErrProtocol
	}
	if r.More, err = o.Bool("more"); err != nil {
		return nil, ErrProtocol
	}
	if r.UptoSeq, err = o.Uint("upto_seq", 0, strictjson.MaxSafeInteger); err != nil {
		return nil, ErrProtocol
	}
	if r.UptoHash, err = o.Base64("upto_hash", 32); err != nil {
		return nil, ErrProtocol
	}
	if r.Count > 0 {
		if r.OldestSeq, err = o.Uint("oldest_seq", 1, strictjson.MaxSafeInteger); err != nil {
			return nil, ErrProtocol
		}
		if r.NewestSeq, err = o.Uint("newest_seq", 1, strictjson.MaxSafeInteger); err != nil {
			return nil, ErrProtocol
		}
		for _, t := range []struct {
			k   string
			dst *time.Time
		}{{"oldest_at", &r.OldestAt}, {"newest_at", &r.NewestAt}} {
			s, err := o.String(t.k)
			if err != nil {
				return nil, ErrProtocol
			}
			if *t.dst, err = envelope.ParseTS(s); err != nil {
				return nil, ErrProtocol
			}
		}
	}
	if v, present, err := o.OptUint("entry_seq", 1, strictjson.MaxSafeInteger); err != nil {
		return nil, ErrProtocol
	} else if present {
		r.EntrySeq = v
	}
	return r, nil
}

// exportFilters is q's filters as audit.export takes them (no cursor or
// limit).
func exportFilters(q AuditQuery) map[string]any {
	q.BeforeSeq, q.After, q.AfterSeq, q.Limit = 0, false, 0, 0
	return q.Body()
}

// AuditExportPreview sends audit.export's dry run (§10.9, 0.22.0): it
// counts the entries q's filters match (q's cursor and limit are ignored)
// without the PIN; format ("csv", "json" or "" for none) is only checked.
// Only the holder's app may send it.
func (d *Device) AuditExportPreview(ctx context.Context, q AuditQuery, format string) (*AuditExportResult, error) {
	b := exportFilters(q)
	b["dry_run"] = true
	if format != "" {
		b["format"] = format
	}
	o, err := d.Op(ctx, "audit.export", b)
	if err != nil {
		return nil, err
	}
	return parseAuditExport(o)
}

// AuditExport sends the export (§10.9, 0.22.0): the same filters, format
// ("csv" or "json"), the preview's uptoSeq and the vault PIN alone sealed
// to a UTK, as the enrolling app's vault.delete carries it. A wrong PIN
// is bad_pin and counts in the PIN backoff (backoff with retry_after);
// it is not a failed owner check. The answer authorises writing the
// file; AuditExportEntries reads the entries.
func (d *Device) AuditExport(ctx context.Context, q AuditQuery, format string, uptoSeq uint64, pin string) (*AuditExportResult, error) {
	extra := exportFilters(q)
	extra["format"], extra["upto_seq"] = format, uptoSeq
	u, err := d.takeUTK(ctx)
	if err != nil {
		return nil, err
	}
	o, _, _, err := d.sealedWith(ctx, "audit.export", u, nil, false, map[string]any{"pin": pin}, false, extra)
	if err != nil {
		return nil, err
	}
	return parseAuditExport(o)
}

// AuditExportEntries reads an export's entries with audit.list (§10.9,
// 0.22.0): q's filters, from before_seq = r.UptoSeq + 1, limit 100,
// following the cursors (also across partial pages), and keeps the first
// r.Count. Fewer come back when the retention dropped entries meanwhile.
func (d *Device) AuditExportEntries(ctx context.Context, q AuditQuery, r *AuditExportResult) ([]json.RawMessage, error) {
	if r == nil || r.Count == 0 {
		return nil, nil
	}
	q.After, q.AfterSeq, q.BeforeSeq, q.Limit = false, 0, r.UptoSeq+1, 100
	return d.AuditSearchAll(ctx, q, false, int(r.Count))
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
