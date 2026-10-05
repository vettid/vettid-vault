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

// Feature commands (VAULT-MESSAGING §10.6, §10.8, §10.9). Passwords come from the
// environment, never from the command line: VAULTCTL_PASSWORD and, for a
// change, VAULTCTL_NEW_PASSWORD.

func init() {
	commands["credential"] = command{"credential create|fetch|version|unlock|lock|rotate|password|delete|recover|reset | credential confirm ALARM_ID mine|not-mine", cmdCredential}
	commands["delete-vault"] = command{"delete-vault CONFIRMATION   (CONFIRMATION must be \"delete my vault\"; reads VAULTCTL_PIN and VAULTCTL_PASSWORD, the password empty when the credential is lost)", cmdDeleteVault}
	commands["transfer"] = command{"transfer create | transfer approve ID | transfer reject ID   (move the app to a new phone; approve reads VAULTCTL_PIN and VAULTCTL_PASSWORD)", cmdTransfer}
	commands["profile"] = command{"profile get | profile set JSON   (the display name and photo; @profile items are items)", cmdProfile}
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

func cmdDeleteVault(ctx context.Context, g *globals, args []string) error {
	if len(args) != 1 || args[0] != "delete my vault" {
		return errors.New(commands["delete-vault"].usage)
	}
	pin, err := password("VAULTCTL_PIN")
	if err != nil {
		return err
	}
	pw := os.Getenv("VAULTCTL_PASSWORD")
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		return nil, d.VaultDelete(ctx, pin, pw)
	})
}

func cmdTransfer(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["transfer"].usage)
	if err != nil {
		return err
	}
	var pin, pw string
	if op == "approve" {
		if pin, err = password("VAULTCTL_PIN"); err != nil {
			return err
		}
		if pw, err = password("VAULTCTL_PASSWORD"); err != nil {
			return err
		}
	}
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch {
		case op == "create" && len(rest) == 0:
			id, link, err := d.TransferCreate(ctx)
			return map[string]string{"transfer_id": id, "link": link}, err
		case op == "approve" && len(rest) == 1:
			return nil, d.TransferApprove(ctx, rest[0], pin, pw)
		case op == "reject" && len(rest) == 1:
			return nil, d.TransferReject(ctx, rest[0])
		}
		return nil, errors.New(commands["transfer"].usage)
	})
}

func cmdCredential(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["credential"].usage)
	if err != nil {
		return err
	}
	needPW := map[string]bool{"create": true, "unlock": true, "rotate": true, "password": true, "delete": true, "recover": true, "reset": true}
	if op == "recover" {
		// §11.11.5 step 1 (0.10.6): the recovered app's unlock said whether
		// the vault keeps a copy; without one there is nothing to recover,
		// so do not ask for the password.
		d, err := load(g)
		if err != nil {
			return err
		}
		if on, known := d.RecoveryCredentialBackup(); known && !on {
			return errors.New("the vault keeps no copy of the credential (credential.backup off): use `credential reset` with a new password, or `delete-vault`")
		}
	}
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
		case "recover":
			return nil, d.CredentialRecover(ctx, pw)
		case "reset":
			// The credential is lost (backup off, §11.11.5): a new one.
			return nil, d.CredentialReset(ctx, pw)
		case "confirm":
			if len(rest) != 2 || rest[1] != "mine" && rest[1] != "not-mine" {
				return nil, errors.New(commands["credential"].usage)
			}
			st, err := d.CredentialAlarmConfirm(ctx, rest[0], rest[1] == "mine")
			return map[string]string{"state": st}, err
		}
		return nil, errors.New(commands["credential"].usage)
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
