package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/leashwire"
)

// V4 batch 3, LEASH (VAULT-MESSAGING §10.11).

func init() {
	commands["leash"] = command{"leash issue -agent ID -scope S [-approval ask|auto] [-connections a,b] [-per-hour N] [-per-day N] [-expires TS] [-status-ttl S] [-grant ID -version N] | revoke -id ID | list [-agent ID] | resume -agent ID   (issue needs the credential unlock window; an agent's items are share rules: vaultctl share set -agent)", cmdLeash}
	commands["agent"] = command{"agent request -op catalog|item.get|item.use [-item ID] [-fields F,F] [-field F] [-data TEXT] | grants | present -grant ID [-member-key B64]   (an agent: LEASH requests, its grants, a delegation with a fresh status statement, verified under iss)", cmdAgent}
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func cmdLeash(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["leash"].usage)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("leash "+op, flag.ExitOnError)
	agent := fs.String("agent", "", "agent device id")
	scope := fs.String("scope", "", "grant scope (§10.11)")
	approval := fs.String("approval", "", "ask (default) or auto")
	conns := fs.String("connections", "", "comma-separated connection ids")
	perHour := fs.Int("per-hour", 0, "auto grants: requests per hour")
	perDay := fs.Int("per-day", 0, "auto grants: requests per day")
	expires := fs.String("expires", "", "expiry (YYYY-MM-DDTHH:MM:SS.mmmZ)")
	statusTTL := fs.Int("status-ttl", 0, "lifetime of the grant's status statements, 60-3600 s (default 900)")
	grant := fs.String("grant", "", "grant id to replace")
	version := fs.Int("version", 0, "version of the grant replaced")
	id := fs.String("id", "", "grant id")
	_ = fs.Parse(rest)
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "issue":
			spec := map[string]any{"scope": *scope}
			if *approval != "" {
				spec["approval"] = *approval
			}
			if l := splitList(*conns); l != nil {
				spec["connections"] = l
			}
			if *perHour > 0 {
				spec["per_hour"] = *perHour
			}
			if *perDay > 0 {
				spec["per_day"] = *perDay
			}
			if *expires != "" {
				spec["expires_at"] = *expires
			}
			if *statusTTL > 0 {
				spec["status_ttl"] = *statusTTL
			}
			if *grant != "" {
				spec["grant_id"], spec["version"] = *grant, *version
			}
			return d.LeashGrantIssue(ctx, *agent, spec)
		case "revoke":
			return nil, d.LeashGrantRevoke(ctx, *id)
		case "list":
			gs, err := d.LeashGrantList(ctx, *agent)
			return map[string][]json.RawMessage{"grants": gs}, err
		case "resume":
			_, err := d.Op(ctx, "leash.agent.resume", map[string]any{"agent_id": *agent})
			return nil, err
		}
		return nil, errors.New(commands["leash"].usage)
	})
}

func cmdAgent(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["agent"].usage)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("agent "+op, flag.ExitOnError)
	rop := fs.String("op", "", "catalog, item.get or item.use")
	item := fs.String("item", "", "item id")
	fields := fs.String("fields", "", "item.get: field ids (comma-separated; default all)")
	field := fs.String("field", "", "item.use: field id")
	data := fs.String("data", "", "data for item.use (hmac-sha256)")
	grant := fs.String("grant", "", "present: grant id")
	memberKey := fs.String("member-key", "", "present: the member's credential key as pinned (standard base64); default: the delegation's iss, unpinned")
	_ = fs.Parse(rest)
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "request":
			m := map[string]any{}
			if *item != "" {
				m["item_id"] = *item
			}
			if l := splitList(*fields); l != nil && *rop == "item.get" {
				m["fields"] = l
			}
			if *rop == "item.use" {
				m["field_id"] = *field
				m["action"] = "hmac-sha256"
				m["data"] = base64.StdEncoding.EncodeToString([]byte(*data))
			}
			r, err := d.AgentRequest(ctx, *rop, m)
			if err != nil {
				return nil, err
			}
			if !r.OK() {
				return nil, &client.OpError{Type: "agent.request", Code: r.ErrorCode()}
			}
			return strictjson.ParseObject(r.Body())
		case "grants":
			gs, err := d.LeashGrantList(ctx, "")
			return map[string][]json.RawMessage{"grants": gs}, err
		case "present":
			return leashPresent(ctx, d, *grant, *memberKey)
		}
		return nil, errors.New(commands["agent"].usage)
	})
}

// leashPresent is what the agent shows a relying party for one grant
// (§10.11): the delegation and its sig, a fresh status statement and its
// status_sig, and the vault's rotation chain if any, checked with the
// reference verifier (steps 1-5) under iss. Without -member-key, iss is
// taken from the delegation itself, which shows the bundle is well formed
// but not that iss is the member's key.
func leashPresent(ctx context.Context, d *client.Device, grantID, memberKey string) (any, error) {
	if grantID == "" {
		return nil, errors.New("agent present: -grant is required")
	}
	p, err := d.LeashPresent(ctx, grantID)
	if err != nil {
		return nil, err
	}
	del, err := leashwire.Parse(p.Delegation)
	if err != nil {
		return nil, err
	}
	key, pinned := del.Iss, false
	if memberKey != "" {
		if key, err = strictjson.DecodeStd(memberKey, ed25519.PublicKeySize); err != nil {
			return nil, errors.New("agent present: -member-key is not a standard base64 Ed25519 key")
		}
		pinned = true
	}
	if _, err := leashwire.VerifyPresented(key, p, time.Now()); err != nil {
		return nil, err
	}
	enc := base64.StdEncoding.EncodeToString
	out := map[string]any{"grant_id": grantID, "delegation": enc(p.Delegation), "sig": enc(p.Sig),
		"status": enc(p.Status), "status_sig": enc(p.StatusSig), "iss": enc(del.Iss), "member_key_pinned": pinned, "verified": true}
	if len(p.Rotations) > 0 {
		var rs []json.RawMessage
		for _, r := range p.Rotations {
			rs = append(rs, r.Marshal())
		}
		out["rotations"] = rs
	}
	return out, nil
}
