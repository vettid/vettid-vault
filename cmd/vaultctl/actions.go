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

// Shared actions (VAULT-MESSAGING §10.14).

func init() {
	commands["action"] = command{"action define -name N -kind respond|fixed [-mode ask|auto] [-result JSON] [-connections a,b] [-id ID -version N] [-description D] | delete -id ID | list [-connection ID] | invoke -connection ID -id ACTION [-params JSON] [-wait 60s] | respond -invocation ID -approve=true|false [-result JSON] | pending [-wait 60s]", cmdAction}
}

func cmdAction(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["action"].usage)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("action "+op, flag.ExitOnError)
	id := fs.String("id", "", "action id")
	version := fs.Uint64("version", 0, "version the replacement is based on")
	name := fs.String("name", "", "name")
	desc := fs.String("description", "", "description")
	kind := fs.String("kind", "", "respond|fixed")
	mode := fs.String("mode", "", "ask|auto")
	result := fs.String("result", "", "result JSON object")
	connsFlag := fs.String("connections", "", "comma-separated connection ids (the allowlist)")
	conn := fs.String("connection", "", "connection id")
	params := fs.String("params", "", "params JSON object")
	inv := fs.String("invocation", "", "invocation id")
	approve := fs.Bool("approve", false, "approve (false: deny)")
	wait := fs.Duration("wait", 0, "wait for the result or a pending invocation")
	_ = fs.Parse(rest)
	raw := func(s string) json.RawMessage {
		if s == "" {
			return nil
		}
		return json.RawMessage(s)
	}
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "define":
			cs := []string{}
			if *connsFlag != "" {
				cs = strings.Split(*connsFlag, ",")
			}
			aid, v, err := d.ActionDefine(ctx, client.ActionDef{ActionID: *id, Version: *version, Name: *name, Description: *desc,
				Kind: *kind, Mode: *mode, Result: raw(*result), Connections: cs})
			return map[string]any{"action_id": aid, "version": v}, err
		case "delete":
			return nil, d.ActionDelete(ctx, *id)
		case "list":
			return d.ActionList(ctx, *conn)
		case "invoke":
			iid, err := d.ActionInvoke(ctx, *conn, *id, raw(*params))
			if err != nil || *wait == 0 {
				return map[string]string{"invocation_id": iid}, err
			}
			wctx, cancel := context.WithTimeout(ctx, *wait)
			defer cancel()
			return d.ActionResult(wctx, iid)
		case "respond":
			return nil, d.ActionRespond(ctx, *inv, *approve, raw(*result))
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
