package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/client"
)

// Shared actions: the built-in catalog (VAULT-MESSAGING §10.14).

func init() {
	commands["action"] = command{"action list [-connection ID] | configure -id ACTION -mode default-deny|allowlist|prompt-each-time|default-allow " +
		"[-connections a,b] [-fields k,k] [-secrets id,id] | invoke -connection ID -id ACTION [-params JSON] [-wait 60s] | " +
		"respond -invocation ID -approve=true|false | pending [-wait 30s]", cmdAction}
}

func commaList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func cmdAction(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["action"].usage)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("action "+op, flag.ExitOnError)
	id := fs.String("id", "", "action id (catalog)")
	mode := fs.String("mode", "", "permission mode")
	connsFlag := fs.String("connections", "", "comma-separated connection ids")
	fields := fs.String("fields", "", "comma-separated profile keys (profile.fields.read)")
	secretsFlag := fs.String("secrets", "", "comma-separated secret ids (secrets.share)")
	conn := fs.String("connection", "", "connection id")
	params := fs.String("params", "{}", "params JSON object")
	inv := fs.String("invocation", "", "invocation id")
	approve := fs.Bool("approve", false, "approve (false: deny)")
	wait := fs.Duration("wait", 0, "wait for the result or a pending invocation")
	_ = fs.Parse(rest)
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "list":
			return d.ActionList(ctx, *conn)
		case "configure":
			v, err := d.ActionConfigure(ctx, client.ActionConfig{ActionID: *id, Mode: *mode, Connections: commaList(*connsFlag),
				Fields: commaList(*fields), Secrets: commaList(*secretsFlag)})
			return map[string]any{"version": v}, err
		case "invoke":
			iid, err := d.ActionInvoke(ctx, *conn, *id, json.RawMessage(*params))
			if err != nil || *wait == 0 {
				return map[string]string{"invocation_id": iid}, err
			}
			wctx, cancel := context.WithTimeout(ctx, *wait)
			defer cancel()
			return d.ActionResult(wctx, iid)
		case "respond":
			st, err := d.ActionRespond(ctx, *inv, *approve)
			return map[string]string{"status": st}, err
		case "pending":
			w := *wait
			if w == 0 {
				w = 30 * time.Second
			}
			wctx, cancel := context.WithTimeout(ctx, w)
			defer cancel()
			ev, err := d.WaitEvent(wctx, "action.pending", nil)
			if err != nil {
				return nil, err
			}
			return ev.Body, nil
		}
		return nil, errors.New(commands["action"].usage)
	})
}
