package main

import (
	"context"
	"errors"
	"flag"
	"time"

	"github.com/vettid/vettid-vault/client"
)

// Location sharing (VAULT-MESSAGING §10.16).

func init() {
	commands["location"] = command{"location start -conn ID -mode once|continuous [-precision exact|approximate|city] [-duration S] [-interval S] [-history] [-request ID]" +
		" | stop -id ID | list | get -conn ID [-history] | request -conn ID [-note T] | update -lat F -lon F [-accuracy M] | history [-from TS] [-to TS] [-after TS] [-limit N] | " +
		"history-delete [-from TS] [-to TS] | history-share -id SHARE -from TS -to TS", cmdLocation}
}

func cmdLocation(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["location"].usage)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("location "+op, flag.ExitOnError)
	conn := fs.String("conn", "", "connection id")
	mode := fs.String("mode", "", "once or continuous")
	precision := fs.String("precision", "", "exact, approximate or city")
	duration := fs.Int("duration", 0, "share duration in seconds (continuous)")
	interval := fs.Int("interval", 0, "update interval in seconds (continuous)")
	history := fs.Bool("history", false, "let the connection keep the trail (start); return it (get)")
	request := fs.String("request", "", "the location request this share answers")
	id := fs.String("id", "", "share id")
	note := fs.String("note", "", "a note shown with the request")
	lat := fs.Float64("lat", 0, "latitude")
	lon := fs.Float64("lon", 0, "longitude")
	acc := fs.Float64("accuracy", 0, "accuracy in metres")
	from := fs.String("from", "", "range start (RFC 3339)")
	to := fs.String("to", "", "range end (RFC 3339)")
	after := fs.String("after", "", "page after (history)")
	limit := fs.Int("limit", 0, "page size (history)")
	_ = fs.Parse(rest)
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "start":
			sid, exp, err := d.LocationShareStart(ctx, client.LocationShare{ConnectionID: *conn, Mode: *mode, Precision: *precision,
				Duration: *duration, Interval: *interval, History: *history, RequestID: *request})
			return map[string]string{"share_id": sid, "expires_at": exp.Format(time.RFC3339)}, err
		case "stop":
			return nil, d.LocationShareStop(ctx, *id)
		case "list":
			return d.LocationShareList(ctx)
		case "get":
			return d.LocationGet(ctx, *conn, *history)
		case "request":
			rid, err := d.LocationRequest(ctx, *conn, *note)
			return map[string]string{"request_id": rid}, err
		case "history", "history-delete", "history-share":
			var f, t time.Time
			var err error
			if *from != "" {
				if f, err = time.Parse(time.RFC3339Nano, *from); err != nil {
					return nil, errors.New("-from: RFC 3339")
				}
			}
			if *to != "" {
				if t, err = time.Parse(time.RFC3339Nano, *to); err != nil {
					return nil, errors.New("-to: RFC 3339")
				}
			}
			switch op {
			case "history":
				return d.LocationHistoryList(ctx, f, t, *after, *limit)
			case "history-delete":
				n, err := d.LocationHistoryDelete(ctx, f, t)
				return map[string]uint64{"deleted": n}, err
			}
			n, err := d.LocationHistoryShare(ctx, *id, f, t)
			return map[string]uint64{"sent": n}, err
		case "update":
			return nil, d.LocationUpdate(ctx, client.LocationSample{Lat: *lat, Lon: *lon, Accuracy: *acc})
		}
		return nil, errors.New(commands["location"].usage)
	})
}
