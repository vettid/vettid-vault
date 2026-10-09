package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// V4 batch 2 commands (VAULT-MESSAGING §6.8, §10.3, §10.4, §10.10).

func init() {
	commands["session"] = command{"session request [-seconds N] | approve -id ID [-seconds N] | deny -id ID | end [-device ID]", cmdSession}
	commands["approval"] = command{"approval decide -id ID -approve=true|false   held desktop/agent requests", cmdApproval}
	commands["block"] = command{"block add -connection ID|-pending ID [-note N] | remove -id ID | list", cmdBlock}
	commands["connection"] = command{"connection update -connection ID -version N [-alias A] [-note N] [-tags a,b] [-favorite=bool] [-archived=bool] | auth -connection ID [-context C] | auth-approve -id ID | auth-deny -id ID | auth-list | " +
		"asks -connection ID | asks-mute -connection ID [-unmute] | asks-resume -connection ID   (a connection's asks, §10.4.1)", cmdConnection}
	commands["call"] = command{"call dial -connection ID [-media audio|video] [-hold 2s] | answer [-wait 60s] | end -id ID [-reason hangup] | list", cmdCall}
}

func cmdSession(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["session"].usage)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("session "+op, flag.ExitOnError)
	id := fs.String("id", "", "request id")
	secs := fs.Int("seconds", 0, "session length (60–86400; default 3600)")
	dev := fs.String("device", "", "device id (apps)")
	_ = fs.Parse(rest)
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "request":
			rid, err := d.SessionRequest(ctx, *secs)
			return map[string]string{"request_id": rid}, err
		case "approve":
			exp, err := d.SessionApprove(ctx, *id, *secs)
			return map[string]string{"expires_at": envelope.FormatTS(exp)}, err
		case "deny":
			return nil, d.SessionDeny(ctx, *id)
		case "end":
			return nil, d.SessionEnd(ctx, *dev)
		}
		return nil, errors.New(commands["session"].usage)
	})
}

func cmdApproval(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["approval"].usage)
	if err != nil || op != "decide" {
		return errors.New(commands["approval"].usage)
	}
	fs := flag.NewFlagSet("approval decide", flag.ExitOnError)
	id := fs.String("id", "", "approval id")
	approve := fs.Bool("approve", false, "approve (false: deny)")
	_ = fs.Parse(rest)
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		res, err := d.ApprovalDecide(ctx, *id, *approve)
		return map[string]string{"result": res}, err
	})
}

func cmdBlock(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["block"].usage)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("block "+op, flag.ExitOnError)
	conn := fs.String("connection", "", "connection id")
	pend := fs.String("pending", "", "pending connection request id")
	note := fs.String("note", "", "local note")
	id := fs.String("id", "", "block id")
	_ = fs.Parse(rest)
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "add":
			var bid string
			var err error
			if *pend != "" {
				bid, err = d.BlockPending(ctx, *pend, *note)
			} else {
				bid, err = d.BlockConnection(ctx, *conn, *note)
			}
			return map[string]string{"block_id": bid}, err
		case "remove":
			return nil, d.BlockRemove(ctx, *id)
		case "list":
			return d.BlockList(ctx)
		}
		return nil, errors.New(commands["block"].usage)
	})
}

func cmdConnection(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["connection"].usage)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("connection "+op, flag.ExitOnError)
	conn := fs.String("connection", "", "connection id")
	version := fs.Uint64("version", 0, "metadata version the change is based on")
	alias := fs.String("alias", "", "local name")
	note := fs.String("note", "", "local note")
	tags := fs.String("tags", "", "comma-separated tags")
	fav := fs.String("favorite", "", "true|false")
	arch := fs.String("archived", "", "true|false")
	ctxt := fs.String("context", "", "authentication context shown to the peer")
	id := fs.String("id", "", "authentication request id")
	unmute := fs.Bool("unmute", false, "asks-mute: unmute instead")
	_ = fs.Parse(rest)
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "update":
			set := map[string]any{}
			fs.Visit(func(f *flag.Flag) {
				switch f.Name {
				case "alias":
					set["alias"] = *alias
				case "note":
					set["note"] = *note
				case "tags":
					t := []string{}
					if *tags != "" {
						t = strings.Split(*tags, ",")
					}
					set["tags"] = t
				case "favorite":
					set["favorite"] = *fav == "true"
				case "archived":
					set["archived"] = *arch == "true"
				}
			})
			v, err := d.ConnectionUpdate(ctx, *conn, *version, set)
			return map[string]uint64{"version": v}, err
		case "auth":
			rid, err := d.AuthRequest(ctx, *conn, *ctxt)
			return map[string]string{"request_id": rid}, err
		case "auth-approve":
			return nil, d.AuthApprove(ctx, *id)
		case "auth-deny":
			return nil, d.AuthDeny(ctx, *id)
		case "auth-list":
			return d.Op(ctx, "connection.authenticate.list", nil)
		case "asks":
			a, err := d.ConnectionAsks(ctx, *conn)
			if err != nil {
				return nil, err
			}
			out := map[string]any{"muted": a.Muted, "paused": a.Paused, "cooldowns": a.Cooldowns}
			if a.Paused {
				out["paused_at"] = a.PausedAt
			}
			return out, nil
		case "asks-mute":
			return nil, d.ConnectionAsksMute(ctx, *conn, !*unmute)
		case "asks-resume":
			return nil, d.ConnectionAsksResume(ctx, *conn)
		}
		return nil, errors.New(commands["connection"].usage)
	})
}

// fingerprint prints a media key's hash, never the key.
func fingerprint(k []byte) string {
	h := sha256.Sum256(k)
	return hex.EncodeToString(h[:8])
}

// cmdCall drives call signalling. dial and answer run a whole call in one
// invocation (the caller's ephemeral KEM key lives only in memory); they
// print the media key's fingerprint so two devices can compare it.
func cmdCall(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["call"].usage)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("call "+op, flag.ExitOnError)
	conn := fs.String("connection", "", "connection id")
	media := fs.String("media", "audio", "audio|video")
	hold := fs.Duration("hold", 2*time.Second, "how long to stay in the call before hanging up (dial)")
	wait := fs.Duration("wait", 60*time.Second, "how long to wait for an offer (answer) or its end")
	id := fs.String("id", "", "call id")
	reason := fs.String("reason", "hangup", "hangup|decline|busy|timeout")
	_ = fs.Parse(rest)
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "dial":
			c, err := d.CallStart(ctx, *conn, *media, "v=0 vaultctl")
			if err != nil {
				return nil, err
			}
			defer c.Destroy()
			ans, err := d.WaitEvent(ctx, "call.answer", func(b json.RawMessage) bool { return strings.Contains(string(b), c.ID) })
			if err != nil {
				return nil, fmt.Errorf("no answer: %w", err)
			}
			if _, err := d.CallAccept(c, ans); err != nil {
				return nil, err
			}
			time.Sleep(*hold)
			if err := d.CallEnd(ctx, c.ID, "hangup"); err != nil {
				return nil, err
			}
			return map[string]string{"call_id": c.ID, "key_fingerprint": fingerprint(c.Key)}, nil
		case "answer":
			wctx, cancel := context.WithTimeout(ctx, *wait)
			defer cancel()
			ev, err := d.WaitEvent(wctx, "call.offer", nil)
			if err != nil {
				return nil, fmt.Errorf("no call: %w", err)
			}
			c, err := d.IncomingCall(ev)
			if err != nil {
				return nil, err
			}
			defer c.Destroy()
			_ = d.CallRinging(ctx, c.ID)
			if err := d.CallAnswer(ctx, c, "v=0 vaultctl"); err != nil {
				return nil, err
			}
			end, err := d.WaitEvent(wctx, "call.end", func(b json.RawMessage) bool { return strings.Contains(string(b), c.ID) })
			if err != nil {
				return nil, fmt.Errorf("call did not end: %w", err)
			}
			return map[string]string{"call_id": c.ID, "connection_id": c.Conn, "key_fingerprint": fingerprint(c.Key),
				"ended": string(end.Body)}, nil
		case "end":
			return nil, d.CallEnd(ctx, *id, *reason)
		case "list":
			return d.Op(ctx, "call.list", nil)
		}
		return nil, errors.New(commands["call"].usage)
	})
}
