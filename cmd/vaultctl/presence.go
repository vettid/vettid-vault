package main

import (
	"context"
	"errors"
	"flag"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/client"
)

// Presence (VAULT-MESSAGING §9.2, §10.17).

func init() {
	commands["presence"] = command{"presence get | set -version N [-state available|busy|away|invisible] [-share all|none] [-except ID,ID] | query -conn ID [-wait S]", cmdPresence}
}

func cmdPresence(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["presence"].usage)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("presence "+op, flag.ExitOnError)
	version := fs.Uint64("version", 0, "the policy version the change is based on")
	state := fs.String("state", "", "available, busy, away or invisible")
	share := fs.String("share", "", "all or none")
	except := fs.String("except", "-", "comma-separated connection ids that invert share (\"\" for none)")
	conn := fs.String("conn", "", "connection id")
	wait := fs.Int("wait", 30, "seconds to wait for the answer")
	_ = fs.Parse(rest)
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "get":
			return d.PresenceGet(ctx)
		case "set":
			var ex []string
			if *except != "-" {
				ex = []string{}
				for _, c := range strings.Split(*except, ",") {
					if c != "" {
						ex = append(ex, c)
					}
				}
			}
			v, err := d.PresenceSet(ctx, *version, *state, *share, ex)
			return map[string]uint64{"version": v}, err
		case "query":
			pid, err := d.PresenceQuery(ctx, *conn)
			if err != nil {
				return nil, err
			}
			wctx, cancel := context.WithTimeout(ctx, time.Duration(*wait)*time.Second)
			defer cancel()
			res, err := d.PresenceResult(wctx, pid)
			if err != nil {
				return map[string]string{"ping_id": pid, "state": "unknown"}, nil // no answer before exp (§9.2)
			}
			return res, nil
		}
		return nil, errors.New(commands["presence"].usage)
	})
}
