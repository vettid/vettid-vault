package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"strconv"
	"strings"

	"github.com/vettid/vettid-vault/client"
)

// V4 batch 3: grants between connections (VAULT-MESSAGING §10.12).

func init() {
	commands["grant"] = command{"grant request -connection ID [-item ID[,ID]] [-fields F,F] [-category C[,C]] [-uses N] [-expires-in S] [-reason R] | " +
		"decide -id REQUEST -approve=true|false [-items 0,2] [-answer INDEX:ITEM_ID[,...]] [-uses N] [-expires-in S] | fetch -id GRANT | revoke -id GRANT | " +
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
	itemIDs := fs.String("item", "", "item ids (comma-separated)")
	fields := fs.String("fields", "", "field ids to ask for, of each -item (comma-separated; default all)")
	cats := fs.String("category", "", "categories for the member to answer (comma-separated)")
	answers := fs.String("answer", "", "answers to category entries: INDEX:ITEM_ID (comma-separated)")
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
			for _, k := range grantList(*itemIDs) {
				it = append(it, client.GrantItem{Kind: "item", Ref: k, Fields: grantList(*fields)})
			}
			for _, c := range grantList(*cats) {
				it = append(it, client.GrantItem{Kind: "category", Ref: c})
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
			var ans []client.GrantAnswer
			for _, a := range grantList(*answers) {
				i, item, ok := strings.Cut(a, ":")
				n, err := strconv.Atoi(i)
				if !ok || err != nil {
					return nil, errors.New("bad -answer")
				}
				ans = append(ans, client.GrantAnswer{Index: n, ItemID: item})
			}
			gs, err := d.GrantDecideAnswers(ctx, *id, *approve, idx, ans, *uses, *expIn)
			return map[string]any{"grants": gs}, err
		case "fetch":
			r, err := d.GrantFetch(ctx, *id)
			if err != nil {
				return nil, err
			}
			if r.Error != "" {
				out := map[string]any{"error": r.Error}
				if r.RetryAfter > 0 {
					out["retry_after"] = r.RetryAfter // rate_limited (0.23.0)
				}
				return out, nil
			}
			out := map[string]any{"content": json.RawMessage(r.Value)}
			if r.Counted {
				out["uses_left"] = r.UsesLeft
			}
			return out, nil
		case "revoke":
			return nil, d.GrantRevoke(ctx, *id)
		case "list":
			return d.GrantList(ctx)
		case "catalog":
			c, err := d.GrantCatalog(ctx, *conn)
			return map[string]any{"items": c}, err
		}
		return nil, errors.New(commands["grant"].usage)
	})
}
