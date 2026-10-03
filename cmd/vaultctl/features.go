package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/strictjson"
)

// Feature commands (VAULT-MESSAGING §10.6–§10.9). Passwords come from the
// environment, never from the command line: VAULTCTL_PASSWORD and, for a
// change, VAULTCTL_NEW_PASSWORD.

func init() {
	commands["credential"] = command{"credential create|fetch|version|unlock|lock|rotate|password|delete|secret-add|secret-get|secret-list|secret-delete [flags]", cmdCredential}
	commands["secret"] = command{"secret put|get|list|delete [flags]   vault-held secrets", cmdSecret}
	commands["profile"] = command{"profile get | profile set JSON", cmdProfile}
	commands["settings"] = command{"settings get | settings set VERSION JSON", cmdSettings}
	commands["audit"] = command{"audit [-connection ID] [-kinds a,b] [-before N] [-limit N]", cmdAudit}
	commands["feed"] = command{"feed list|get|update|delete|guides [flags]", cmdFeed}
}

func password(env string) (string, error) {
	p := os.Getenv(env)
	if p == "" {
		return "", fmt.Errorf("set %s", env)
	}
	return p, nil
}

// withDevice loads the device, runs fn, prints its result and saves.
func withDevice(ctx context.Context, g *globals, fn func(d *client.Device) (any, error)) error {
	d, err := load(g)
	if err != nil {
		return err
	}
	out, err := fn(d)
	if err != nil {
		if c := client.Code(err); c != "" {
			_ = save(g, d)
			return fmt.Errorf("error %s", c)
		}
		return err
	}
	switch v := out.(type) {
	case nil:
		fmt.Println("ok")
	case strictjson.Object:
		printJSON(map[string]json.RawMessage(v))
	default:
		printJSON(v)
	}
	return save(g, d)
}

func sub(args []string, usage string) (string, []string, error) {
	if len(args) < 1 {
		return "", nil, errors.New(usage)
	}
	return args[0], args[1:], nil
}

func cmdCredential(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["credential"].usage)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("credential "+op, flag.ExitOnError)
	id := fs.String("id", "", "secret id")
	name := fs.String("name", "", "secret name")
	category := fs.String("category", "other", "seed_phrase|private_key|signing_key|master_password|recovery_key|other")
	desc := fs.String("description", "", "description")
	valueFile := fs.String("value-file", "", "file holding the secret value")
	_ = fs.Parse(rest)
	needPW := map[string]bool{"create": true, "unlock": true, "rotate": true, "password": true, "delete": true,
		"secret-add": true, "secret-get": true, "secret-delete": true}
	var pw string
	if needPW[op] {
		if pw, err = password("VAULTCTL_PASSWORD"); err != nil {
			return err
		}
	}
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "create":
			return nil, d.CredentialCreate(ctx, pw)
		case "fetch":
			return nil, d.CredentialFetch(ctx)
		case "version":
			return d.CredentialVersion(ctx)
		case "unlock":
			exp, err := d.CredentialUnlock(ctx, pw)
			return map[string]string{"expires_at": exp}, err
		case "lock":
			return nil, d.CredentialLock(ctx)
		case "rotate":
			return nil, d.CredentialRotate(ctx, pw)
		case "password":
			np, err := password("VAULTCTL_NEW_PASSWORD")
			if err != nil {
				return nil, err
			}
			return nil, d.CredentialChangePassword(ctx, pw, np)
		case "delete":
			return nil, d.CredentialDelete(ctx, pw)
		case "secret-add":
			v, err := os.ReadFile(*valueFile)
			if err != nil {
				return nil, err
			}
			sid, err := d.CriticalSecretAdd(ctx, pw, *name, *category, *desc, v)
			return map[string]string{"secret_id": sid}, err
		case "secret-get":
			v, err := d.CriticalSecretGet(ctx, pw, *id)
			if err != nil {
				return nil, err
			}
			os.Stdout.Write(v)
			fmt.Println()
			return map[string]string{"secret_id": *id}, nil
		case "secret-list":
			return d.CriticalSecretList(ctx)
		case "secret-delete":
			return nil, d.CriticalSecretDelete(ctx, pw, *id)
		}
		return nil, errors.New(commands["credential"].usage)
	})
}

func cmdSecret(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["secret"].usage)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("secret "+op, flag.ExitOnError)
	id := fs.String("id", "", "secret id (put: replace this secret)")
	version := fs.Uint64("version", 0, "version being replaced")
	name := fs.String("name", "", "name")
	valueFile := fs.String("value-file", "", "file holding the value")
	category := fs.String("category", "", "category")
	_ = fs.Parse(rest)
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "put":
			v, err := os.ReadFile(*valueFile)
			if err != nil {
				return nil, err
			}
			extra := map[string]any{}
			if *category != "" {
				extra["category"] = *category
			}
			sid, ver, err := d.SecretPut(ctx, *id, *version, *name, strings.TrimRight(string(v), "\n"), extra)
			return map[string]any{"secret_id": sid, "version": ver}, err
		case "get":
			return d.SecretGet(ctx, *id)
		case "list":
			return d.SecretList(ctx)
		case "delete":
			return nil, d.SecretDelete(ctx, *id)
		}
		return nil, errors.New(commands["secret"].usage)
	})
}

func jsonArg(s string) (map[string]any, error) {
	var m map[string]any
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	if err := d.Decode(&m); err != nil {
		return nil, fmt.Errorf("bad JSON: %w", err)
	}
	return m, nil
}

func cmdProfile(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["profile"].usage)
	if err != nil {
		return err
	}
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "get":
			return d.ProfileGet(ctx)
		case "set":
			if len(rest) != 1 {
				return nil, errors.New(commands["profile"].usage)
			}
			body, err := jsonArg(rest[0])
			if err != nil {
				return nil, err
			}
			v, err := d.ProfileSet(ctx, body)
			return map[string]uint64{"version": v}, err
		}
		return nil, errors.New(commands["profile"].usage)
	})
}

func cmdSettings(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["settings"].usage)
	if err != nil {
		return err
	}
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "get":
			return d.SettingsGet(ctx)
		case "set":
			var v uint64
			if len(rest) != 2 {
				return nil, errors.New(commands["settings"].usage)
			}
			if _, err := fmt.Sscan(rest[0], &v); err != nil {
				return nil, err
			}
			set, err := jsonArg(rest[1])
			if err != nil {
				return nil, err
			}
			nv, err := d.SettingsSet(ctx, v, set)
			return map[string]uint64{"version": nv}, err
		}
		return nil, errors.New(commands["settings"].usage)
	})
}

func cmdAudit(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	conn := fs.String("connection", "", "connection id (connection.audit.list)")
	kinds := fs.String("kinds", "", "comma-separated kind prefixes")
	before := fs.Uint64("before", 0, "before_seq")
	limit := fs.Uint64("limit", 0, "limit")
	_ = fs.Parse(args)
	q := map[string]any{}
	if *conn != "" {
		q["connection_id"] = *conn
	}
	if *kinds != "" {
		q["kinds"] = strings.Split(*kinds, ",")
	}
	if *before != 0 {
		q["before_seq"] = *before
	}
	if *limit != 0 {
		q["limit"] = *limit
	}
	return withDevice(ctx, g, func(d *client.Device) (any, error) { return d.AuditList(ctx, q, *conn != "") })
}

func cmdFeed(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["feed"].usage)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("feed "+op, flag.ExitOnError)
	id := fs.String("id", "", "item id")
	status := fs.String("status", "", "status")
	priority := fs.String("priority", "", "priority")
	after := fs.Int64("after", -1, "after_seq")
	guides := fs.String("guides", "", "guide.sync: JSON array of guides")
	_ = fs.Parse(rest)
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "list":
			q := map[string]any{}
			if *status != "" {
				q["status"] = *status
			}
			if *after >= 0 {
				q["after_seq"] = *after
			}
			return d.FeedList(ctx, q)
		case "get":
			return d.FeedGet(ctx, *id)
		case "update":
			return d.FeedUpdate(ctx, *id, *status, *priority)
		case "delete":
			return nil, d.FeedDelete(ctx, *id)
		case "guides":
			var gs []map[string]any
			if err := json.Unmarshal([]byte(*guides), &gs); err != nil {
				return nil, err
			}
			return d.GuideSync(ctx, gs)
		}
		return nil, errors.New(commands["feed"].usage)
	})
}
