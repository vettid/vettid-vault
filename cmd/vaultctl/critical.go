package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"

	"github.com/vettid/vettid-vault/client"
)

// V4 batch 3: critical-secret use by a connection (VAULT-MESSAGING §10.13).

func init() {
	commands["critical"] = command{"critical catalog -id SECRET [-off] | request -connection ID -id SECRET -op sign|auth -payload B64 [-context C] | " +
		"approve -id REQUEST -payload-sha256 B64 (password in VAULTCTL_PASSWORD) | deny -id REQUEST | list", cmdCritical}
}

func cmdCritical(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["critical"].usage)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("critical "+op, flag.ExitOnError)
	id := fs.String("id", "", "secret id (catalog, request) or request id")
	off := fs.Bool("off", false, "take the secret out of the catalog")
	conn := fs.String("connection", "", "connection id")
	operation := fs.String("op", "sign", "sign|auth")
	payload := fs.String("payload", "", "payload, standard base64")
	hash := fs.String("payload-sha256", "", "SHA-256 of the pending payload, standard base64 (from critical-secret-use.pending)")
	note := fs.String("context", "", "context shown to the member")
	_ = fs.Parse(rest)
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "catalog":
			return nil, d.CriticalSecretCatalog(ctx, *id, !*off)
		case "request":
			p, err := base64.StdEncoding.DecodeString(*payload)
			if err != nil {
				return nil, errors.New("-payload: standard base64")
			}
			rid, err := d.CriticalUseRequest(ctx, *conn, *id, *operation, p, *note)
			return map[string]string{"request_id": rid}, err
		case "approve":
			h, err := base64.StdEncoding.DecodeString(*hash)
			if err != nil || len(h) != 32 {
				return nil, errors.New("-payload-sha256: 32 bytes, standard base64")
			}
			pw, err := password("VAULTCTL_PASSWORD")
			if err != nil {
				return nil, err
			}
			st, err := d.CriticalUseApproveHash(ctx, pw, *id, h)
			return map[string]string{"status": st}, err
		case "deny":
			return nil, d.CriticalUseDeny(ctx, *id)
		case "list":
			return d.CriticalUseList(ctx)
		}
		return nil, errors.New(commands["critical"].usage)
	})
}
