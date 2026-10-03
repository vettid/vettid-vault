package main

import (
	"context"
	"errors"
	"flag"
	"strconv"
	"strings"

	"github.com/vettid/vettid-vault/client"
)

// V4 batch 3: grants between connections (VAULT-MESSAGING §10.12).

func init() {
	commands["grant"] = command{"grant request -connection ID -field KEY[,KEY] -secret ID[,ID] [-uses N] [-expires-in S] [-reason R] | " +
		"decide -id REQUEST -approve=true|false [-items 0,2] [-uses N] [-expires-in S] | fetch -id GRANT | revoke -id GRANT | " +
		"list | catalog -connection ID", cmdGrant}
}

func grantList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func cmdGrant(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["grant"].usage)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("grant "+op, flag.ExitOnError)
	conn := fs.String("connection", "", "connection id")
	fields := fs.String("field", "", "profile field keys (comma-separated)")
	secrets := fs.String("secret", "", "secret ids (comma-separated)")
	uses := fs.Int("uses", 0, "fetches allowed (1–100)")
	expIn := fs.Int("expires-in", 0, "grant lifetime in seconds")
	reason := fs.String("reason", "", "reason shown to the member")
	id := fs.String("id", "", "request or grant id")
	approve := fs.Bool("approve", false, "approve (false: deny)")
	items := fs.String("items", "", "item indices to grant (comma-separated; default all)")
	_ = fs.Parse(rest)
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "request":
			var it []client.GrantItem
			for _, k := range grantList(*fields) {
				it = append(it, client.GrantItem{Kind: "field", Ref: k})
			}
			for _, s := range grantList(*secrets) {
				it = append(it, client.GrantItem{Kind: "secret", Ref: s})
			}
			rid, err := d.GrantRequest(ctx, *conn, it, *uses, *expIn, *reason)
			return map[string]string{"request_id": rid}, err
		case "decide":
			var idx []int
			for _, s := range grantList(*items) {
				n, err := strconv.Atoi(s)
				if err != nil {
					return nil, errors.New("bad -items")
				}
				idx = append(idx, n)
			}
			gs, err := d.GrantDecide(ctx, *id, *approve, idx, *uses, *expIn)
			return map[string]any{"grants": gs}, err
		case "fetch":
			r, err := d.GrantFetch(ctx, *id)
			if err != nil {
				return nil, err
			}
			if r.Error != "" {
				return map[string]string{"error": r.Error}, nil
			}
			return map[string]any{"value": string(r.Value), "uses_left": r.UsesLeft}, nil
		case "revoke":
			return nil, d.GrantRevoke(ctx, *id)
		case "list":
			return d.GrantList(ctx)
		case "catalog":
			c, err := d.GrantCatalog(ctx, *conn)
			return map[string]any{"secrets": c}, err
		}
		return nil, errors.New(commands["grant"].usage)
	})
}
