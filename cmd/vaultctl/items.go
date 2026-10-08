package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"strings"

	"github.com/vettid/vettid-vault/client"
)

// Items, tags and share rules (VAULT-MESSAGING §10.7, §10.8, §10.12).
// Critical items are credential operations: the password comes from
// VAULTCTL_PASSWORD. Item content is JSON, {name, category?, template?,
// fields?: [{field_id?, label, kind, value?}], notes?, keep_notes?}, from
// -content or a file (-content-file) so that values stay off the command
// line; a replacement's field with its field_id and no value keeps the
// stored value, and keep_notes the notes (0.21.0, §10.7 Kept values), so
// that a secret item is edited without a reveal and a critical one with
// one password entry.

func init() {
	commands["item"] = command{"item put [-id ID -version N] [-sensitivity data|secret|critical] [-tags a,b] (-content JSON | -content-file F) | " +
		"get -id ID | reveal -id ID [-fields f1,f2] | list [-tags a,b] [-match any|all] [-category C] [-sensitivity S] [-after ID] [-limit N] | " +
		"tag -id ID -version N -tags a,b [-dry-run] | sensitivity -id ID -version N -to S | delete -id ID   " +
		"(put -dry-run [-id ID -version N] [-sensitivity S] [-tags a,b]: the sharing effect, without content or password)", cmdItem}
	commands["tag"] = command{"tag list | set -version N -tag T [-color #rrggbb] [-icon I] [-description D] | " +
		"delete -version N -tag T [-dry-run] | merge -version N -from a,b -into c [-dry-run]", cmdTag}
	commands["share"] = command{"share set [-rule ID -version N] (-connection ID | -agent ID) -tags a,b [-match any|all] [-mode ask|auto] [-uses N] " +
		"[-expires TS] [-include-existing=false] [-per-hour N] [-per-day N] [-status-ttl S] [-dry-run] | list [-connection ID | -agent ID] | " +
		"delete -rule ID | decide -rule ID (-items a,b [-decline] | [-include a,b] [-decline-items c,d]) | " +
		"pending [-rule ID | -connection ID | -agent ID] [-after C] [-limit N] [-all]   (an agent rule needs the credential unlock window)", cmdShare}
}

func readContent(inline, file string) (client.ItemContent, error) {
	var c client.ItemContent
	b := []byte(inline)
	if file != "" {
		var err error
		if b, err = os.ReadFile(file); err != nil {
			return c, err
		}
	}
	if len(b) == 0 {
		return c, errors.New("-content or -content-file")
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, errors.New("bad content JSON")
	}
	return c, nil
}

// sensitivityOf returns an item's sensitivity (to pick the credential
// form of an operation).
func sensitivityOf(ctx context.Context, d *client.Device, id string) (string, error) {
	o, err := d.ItemGet(ctx, id)
	if err != nil {
		return "", err
	}
	return o.String("sensitivity")
}

func cmdItem(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["item"].usage)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("item "+op, flag.ExitOnError)
	id := fs.String("id", "", "item id")
	version := fs.Uint64("version", 0, "version being changed")
	sens := fs.String("sensitivity", "", "data, secret or critical")
	to := fs.String("to", "", "sensitivity: the new sensitivity")
	tags := fs.String("tags", "", "comma-separated tags")
	match := fs.String("match", "", "list: any (default) or all")
	category := fs.String("category", "", "list: category")
	after := fs.String("after", "", "list: continue after this item id")
	limit := fs.Int("limit", 0, "list: at most this many items")
	fields := fs.String("fields", "", "reveal: field ids (comma-separated)")
	content := fs.String("content", "", "item content JSON")
	contentFile := fs.String("content-file", "", "file holding the item content JSON")
	dry := fs.Bool("dry-run", false, "put, tag: only show what the change would do to sharing")
	_ = fs.Parse(rest)
	tagList := func() []string {
		if *tags == "" {
			return nil
		}
		return strings.Split(*tags, ",")
	}
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "put":
			if *dry {
				return d.ItemPutDryRun(ctx, *id, *version, *sens, tagList())
			}
			c, err := readContent(*content, *contentFile)
			if err != nil {
				return nil, err
			}
			var iid string
			var v uint64
			if *sens == "critical" {
				pw, err := password("VAULTCTL_PASSWORD")
				if err != nil {
					return nil, err
				}
				iid, v, err = d.ItemPutCritical(ctx, pw, *id, *version, tagList(), c)
				if err != nil {
					return nil, err
				}
			} else if iid, v, err = d.ItemPut(ctx, *id, *version, *sens, tagList(), c); err != nil {
				return nil, err
			}
			return map[string]any{"item_id": iid, "version": v}, nil
		case "get":
			return d.ItemGet(ctx, *id)
		case "reveal":
			s, err := sensitivityOf(ctx, d, *id)
			if err != nil {
				return nil, err
			}
			if s == "critical" {
				pw, err := password("VAULTCTL_PASSWORD")
				if err != nil {
					return nil, err
				}
				v, err := d.ItemRevealCritical(ctx, pw, *id)
				if err != nil {
					return nil, err
				}
				return map[string]any{"item_id": *id, "values": v}, nil
			}
			return d.ItemReveal(ctx, *id, splitList(*fields))
		case "list":
			f := map[string]any{}
			if l := tagList(); l != nil {
				f["tags"] = l
			}
			for k, v := range map[string]string{"match": *match, "category": *category, "sensitivity": *sens, "after": *after} {
				if v != "" {
					f[k] = v
				}
			}
			if *limit > 0 {
				f["limit"] = *limit
			}
			return d.ItemList(ctx, f)
		case "tag":
			if *dry {
				return d.ItemTagDryRun(ctx, *id, *version, tagList())
			}
			v, err := d.ItemTag(ctx, *id, *version, tagList())
			return map[string]any{"version": v}, err
		case "sensitivity":
			s, err := sensitivityOf(ctx, d, *id)
			if err != nil {
				return nil, err
			}
			pw := ""
			if s == "critical" || *to == "critical" {
				if pw, err = password("VAULTCTL_PASSWORD"); err != nil {
					return nil, err
				}
			}
			v, err := d.ItemSensitivity(ctx, *id, *version, *to, pw)
			return map[string]any{"version": v}, err
		case "delete":
			s, err := sensitivityOf(ctx, d, *id)
			if err != nil {
				return nil, err
			}
			pw := ""
			if s == "critical" {
				if pw, err = password("VAULTCTL_PASSWORD"); err != nil {
					return nil, err
				}
			}
			return nil, d.ItemDelete(ctx, *id, pw)
		}
		return nil, errors.New(commands["item"].usage)
	})
}

func cmdTag(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["tag"].usage)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("tag "+op, flag.ExitOnError)
	version := fs.Uint64("version", 0, "the registry's version")
	tag := fs.String("tag", "", "tag")
	color := fs.String("color", "", "#rrggbb")
	icon := fs.String("icon", "", "app icon name")
	desc := fs.String("description", "", "description")
	from := fs.String("from", "", "merge: comma-separated tags")
	into := fs.String("into", "", "merge: the tag they become")
	dry := fs.Bool("dry-run", false, "only show what would change")
	_ = fs.Parse(rest)
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		body := map[string]any{"version": *version}
		if *dry {
			body["dry_run"] = true
		}
		switch op {
		case "list":
			return d.TagList(ctx)
		case "set":
			body["tag"] = *tag
			for k, v := range map[string]string{"color": *color, "icon": *icon, "description": *desc} {
				if v != "" {
					body[k] = v
				}
			}
			delete(body, "dry_run")
			return d.TagOp(ctx, "tag.set", body)
		case "delete":
			body["tag"] = *tag
			return d.TagOp(ctx, "tag.delete", body)
		case "merge":
			body["from"], body["into"] = splitList(*from), *into
			return d.TagOp(ctx, "tag.merge", body)
		}
		return nil, errors.New(commands["tag"].usage)
	})
}

func cmdShare(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["share"].usage)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("share "+op, flag.ExitOnError)
	rule := fs.String("rule", "", "rule id")
	version := fs.Uint64("version", 0, "version of the rule replaced")
	conn := fs.String("connection", "", "subject: a connection id")
	agent := fs.String("agent", "", "subject: an agent device id")
	tags := fs.String("tags", "", "comma-separated tags")
	match := fs.String("match", "", "any (default) or all")
	mode := fs.String("mode", "", "ask (default) or auto")
	uses := fs.Int("uses", 0, "fetches of each included item (default: not counted)")
	expires := fs.String("expires", "", "expiry (YYYY-MM-DDTHH:MM:SS.mmmZ)")
	incl := fs.Bool("include-existing", true, "apply the rule to the items that already match")
	perHour := fs.Int("per-hour", 0, "agent rules: reads per hour")
	perDay := fs.Int("per-day", 0, "agent rules: reads per day")
	ttl := fs.Int("status-ttl", 0, "agent rules: status statement lifetime in seconds")
	dry := fs.Bool("dry-run", false, "list the items the rule would match")
	items := fs.String("items", "", "decide: comma-separated item ids")
	decline := fs.Bool("decline", false, "decide: decline (default: approve)")
	include := fs.String("include", "", "decide: comma-separated item ids to include (with -decline-items, one change)")
	declineItems := fs.String("decline-items", "", "decide: comma-separated item ids to decline")
	after := fs.String("after", "", "pending: the previous page's next")
	limit := fs.Int("limit", 0, "pending: page size")
	all := fs.Bool("all", false, "pending: every page")
	_ = fs.Parse(rest)
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "set":
			body := map[string]any{"tags": splitList(*tags), "include_existing": *incl}
			if *conn != "" {
				body["subject"] = map[string]string{"connection_id": *conn}
			} else {
				body["subject"] = map[string]string{"agent_id": *agent}
			}
			if *rule != "" {
				body["rule_id"], body["version"] = *rule, *version
			}
			for k, v := range map[string]string{"match": *match, "mode": *mode, "expires_at": *expires} {
				if v != "" {
					body[k] = v
				}
			}
			for k, v := range map[string]int{"uses": *uses, "per_hour": *perHour, "per_day": *perDay, "status_ttl": *ttl} {
				if v > 0 {
					body[k] = v
				}
			}
			if *dry {
				body["dry_run"] = true
			}
			return d.ShareRuleSet(ctx, body)
		case "list":
			f := map[string]any{}
			if *conn != "" {
				f["connection_id"] = *conn
			}
			if *agent != "" {
				f["agent_id"] = *agent
			}
			return d.ShareRuleList(ctx, f)
		case "delete":
			return nil, d.ShareRuleDelete(ctx, *rule)
		case "decide":
			if *include != "" || *declineItems != "" {
				return d.ShareDecideBoth(ctx, *rule, splitList(*include), splitList(*declineItems))
			}
			return d.ShareDecide(ctx, *rule, splitList(*items), !*decline)
		case "pending":
			f := map[string]any{}
			for k, v := range map[string]string{"rule_id": *rule, "connection_id": *conn, "agent_id": *agent} {
				if v != "" {
					f[k] = v
				}
			}
			if *limit > 0 {
				f["limit"] = *limit
			}
			if *all {
				return d.SharePendingAll(ctx, f)
			}
			if *after != "" {
				f["after"] = *after
			}
			return d.SharePendingList(ctx, f)
		}
		return nil, errors.New(commands["share"].usage)
	})
}
