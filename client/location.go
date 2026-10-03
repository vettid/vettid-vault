package client

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Location sharing (VAULT-MESSAGING §10.16): 1:1 shares to a connection,
// once or continuous until an expiry, at a precision; samples go from
// this device to its vault and on to the connection's, from memory only.

// LocationShare is a location.share.start body.
type LocationShare struct {
	ConnectionID string `json:"connection_id"`
	Mode         string `json:"mode"`                // once, continuous
	Precision    string `json:"precision,omitempty"` // exact, approximate, city
	Duration     int    `json:"duration_seconds,omitempty"`
	Interval     int    `json:"interval_seconds,omitempty"`
	History      bool   `json:"history,omitempty"`
	RequestID    string `json:"request_id,omitempty"`
}

// LocationShareStart starts a share and returns its id and expiry.
func (d *Device) LocationShareStart(ctx context.Context, s LocationShare) (string, time.Time, error) {
	o, err := d.Op(ctx, "location.share.start", s)
	if err != nil {
		return "", time.Time{}, err
	}
	id, err := o.String("share_id")
	if err != nil {
		return "", time.Time{}, ErrProtocol
	}
	e, err := o.String("expires_at")
	if err != nil {
		return "", time.Time{}, ErrProtocol
	}
	exp, err := envelope.ParseTS(e)
	if err != nil {
		return "", time.Time{}, ErrProtocol
	}
	return id, exp, nil
}

// LocationShareStop stops an outgoing share, or asks the sharer of an
// incoming one to stop (and forgets it).
func (d *Device) LocationShareStop(ctx context.Context, shareID string) error {
	_, err := d.Op(ctx, "location.share.stop", map[string]any{"share_id": shareID})
	return err
}

// LocationShareList lists the active shares, outgoing and incoming.
func (d *Device) LocationShareList(ctx context.Context) (strictjson.Object, error) {
	return d.Op(ctx, "location.share.list", nil)
}

// LocationGet returns a connection's latest shared sample (and its trail
// if the share allows it and history is set).
func (d *Device) LocationGet(ctx context.Context, connectionID string, history bool) (strictjson.Object, error) {
	body := map[string]any{"connection_id": connectionID}
	if history {
		body["history"] = true
	}
	return d.Op(ctx, "location.get", body)
}

// LocationRequest asks a connection to share its location.
func (d *Device) LocationRequest(ctx context.Context, connectionID, note string) (string, error) {
	body := map[string]any{"connection_id": connectionID}
	if note != "" {
		body["note"] = note
	}
	o, err := d.Op(ctx, "location.request", body)
	if err != nil {
		return "", err
	}
	return o.String("request_id")
}

// LocationSample is one fix this device sends to its vault.
type LocationSample struct {
	Lat, Lon float64
	Accuracy float64
	Altitude *float64
	Speed    *float64
	Heading  *float64
	At       time.Time
}

func num(v float64) json.RawMessage { return json.RawMessage(strconv.FormatFloat(v, 'f', -1, 64)) }

// LocationUpdate sends a sample to the vault (ephemeral, exp 60 s), which
// forwards it to the shares this device started.
func (d *Device) LocationUpdate(ctx context.Context, s LocationSample) error {
	b := strictjson.NewBuilder().Raw("lat", num(s.Lat)).Raw("lon", num(s.Lon)).Raw("accuracy_m", num(s.Accuracy))
	if s.Altitude != nil {
		b.Raw("altitude_m", num(*s.Altitude))
	}
	if s.Speed != nil {
		b.Raw("speed_mps", num(*s.Speed))
	}
	if s.Heading != nil {
		b.Raw("heading_deg", num(*s.Heading))
	}
	at := s.At
	if at.IsZero() {
		at = d.cfg.Now()
	}
	b.String("at", envelope.FormatTS(at))
	_, err := d.SendExp(ctx, "location.update", b.Bytes(), d.cfg.Now().Add(time.Minute))
	return err
}

// LocationEvent waits for a location.event (started or stopped) about a
// connection.
func (d *Device) LocationEvent(ctx context.Context, connectionID, event string) (strictjson.Object, error) {
	return d.waitObj(ctx, "location.event", func(o strictjson.Object) bool {
		c, _ := o.String("connection_id")
		e, _ := o.String("event")
		return c == connectionID && e == event
	})
}

// LocationUpdateFrom waits for a sample shared by a connection.
func (d *Device) LocationUpdateFrom(ctx context.Context, connectionID string) (strictjson.Object, error) {
	return d.waitObj(ctx, "location.update", func(o strictjson.Object) bool {
		c, _ := o.String("connection_id")
		return c == connectionID
	})
}

// LocationRequestPending waits for a connection's request to share.
func (d *Device) LocationRequestPending(ctx context.Context, connectionID string) (strictjson.Object, error) {
	return d.waitObj(ctx, "location.request.pending", func(o strictjson.Object) bool {
		c, _ := o.String("connection_id")
		return c == connectionID
	})
}

// waitObj waits for an event of typ whose body matches pred.
func (d *Device) waitObj(ctx context.Context, typ string, pred func(strictjson.Object) bool) (strictjson.Object, error) {
	in, err := d.WaitEvent(ctx, typ, func(b json.RawMessage) bool {
		o, err := strictjson.ParseObject(b)
		return err == nil && pred(o)
	})
	if err != nil {
		return nil, err
	}
	return strictjson.ParseObject(in.Body)
}

// LocationHistoryList returns the member's own location log (§10.16), a
// time range (zero: open) and a page (`after` = the previous `next`).
func (d *Device) LocationHistoryList(ctx context.Context, from, to time.Time, after string, limit int) (strictjson.Object, error) {
	return d.Op(ctx, "location.history.list", historyRange(from, to, after, limit, ""))
}

// LocationHistoryDelete deletes the log's positions in a range (zero
// bounds: open; both zero: everything) and returns how many.
func (d *Device) LocationHistoryDelete(ctx context.Context, from, to time.Time) (uint64, error) {
	o, err := d.Op(ctx, "location.history.delete", historyRange(from, to, "", 0, ""))
	if err != nil {
		return 0, err
	}
	return o.Uint("deleted", 0, 1<<53)
}

// LocationHistoryShare sends the connection of an active outgoing share a
// snapshot of the log between from and to, at the share's precision.
func (d *Device) LocationHistoryShare(ctx context.Context, shareID string, from, to time.Time) (uint64, error) {
	o, err := d.Op(ctx, "location.history.share", historyRange(from, to, "", 0, shareID))
	if err != nil {
		return 0, err
	}
	return o.Uint("sent", 0, 1<<53)
}

func historyRange(from, to time.Time, after string, limit int, shareID string) map[string]any {
	b := map[string]any{}
	if !from.IsZero() {
		b["from"] = envelope.FormatTS(from)
	}
	if !to.IsZero() {
		b["to"] = envelope.FormatTS(to)
	}
	if after != "" {
		b["after"] = after
	}
	if limit > 0 {
		b["limit"] = limit
	}
	if shareID != "" {
		b["share_id"] = shareID
	}
	return b
}
