// Command vaultctl is the VettID vault test driver (VAULT-PLAN V2): it acts
// as an owner device (app, desktop or agent) through package client, and in
// dev builds (-tags devenclave) it can also create and run a vault, which is
// how a peer vault is played.
//
//	vaultctl -state app.json init -role app -name phone -relay http://localhost:8080
//	vaultctl -state app.json request vault.status '{}'
//	vaultctl -state app.json events -wait 5s
//
// Device state files hold private keys; they are written with mode 0600.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/client"
)

type command struct {
	usage string
	run   func(ctx context.Context, g *globals, args []string) error
}

type globals struct {
	state   string
	timeout time.Duration
}

var commands = map[string]command{
	"init":        {"init -role app|desktop|agent -name NAME -relay URL", cmdInit},
	"open-token":  {"open-token            print a 10-minute open token for this device's mailbox", cmdOpenToken},
	"enroll-wait": {"enroll-wait           wait for vault.enrolled, then run the first-app handshake", cmdEnrollWait},
	"pair":        {"pair -link LINK       pair from a QR/link; prints the SAS, waits for approval", cmdPair},
	"request":     {"request TYPE [JSON]   send a request and print the response", cmdRequest},
	"send":        {"send TYPE [JSON]      send a message without waiting", cmdSend},
	"events":      {"events [-wait 5s]     collect and print events", cmdEvents},
	"whoami":      {"whoami                print the device's public identity", cmdWhoami},
}

func main() {
	g := &globals{}
	flag.StringVar(&g.state, "state", "vaultctl.json", "device state file (contains private keys)")
	flag.DurationVar(&g.timeout, "timeout", 60*time.Second, "overall timeout")
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() < 1 {
		usage()
		os.Exit(2)
	}
	cmd, ok := commands[flag.Arg(0)]
	if !ok {
		usage()
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	defer cancel()
	if err := cmd.run(ctx, g, flag.Args()[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "vaultctl:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: vaultctl [-state FILE] [-timeout D] COMMAND ...")
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintln(os.Stderr, "  "+commands[n].usage)
	}
}

func load(g *globals) (*client.Device, error) {
	b, err := os.ReadFile(g.state)
	if err != nil {
		return nil, err
	}
	return client.Load(client.Config{}, b)
}

func save(g *globals, d *client.Device) error {
	b, err := d.Save()
	if err != nil {
		return err
	}
	tmp := g.state + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, g.state)
}

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func cmdInit(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	role := fs.String("role", "app", "app, desktop or agent")
	name := fs.String("name", "", "device name")
	relay := fs.String("relay", "", "relay base URL")
	_ = fs.Parse(args)
	if *relay == "" {
		return errors.New("-relay is required")
	}
	if _, err := os.Stat(g.state); err == nil {
		return fmt.Errorf("%s exists", g.state)
	}
	if err := os.MkdirAll(filepath.Dir(g.state), 0o700); err != nil {
		return err
	}
	d, err := client.New(ctx, client.Config{Role: *role, Name: *name, RelayURL: *relay})
	if err != nil {
		return err
	}
	return save(g, d)
}

func cmdOpenToken(_ context.Context, g *globals, _ []string) error {
	d, err := load(g)
	if err != nil {
		return err
	}
	t, err := d.OpenToken()
	if err != nil {
		return err
	}
	fmt.Println(t)
	return nil
}

func cmdWhoami(_ context.Context, g *globals, _ []string) error {
	d, err := load(g)
	if err != nil {
		return err
	}
	a := d.RelayAddr()
	printJSON(map[string]any{"ik": d.IdentityKey(), "kem": d.KEMKey().Bytes(), "relay": map[string]any{"url": a.URL, "mailbox": a.Mailbox, "pk": a.PK},
		"vault_id": d.VaultID(), "device_id": d.DeviceID()})
	return nil
}

func cmdEnrollWait(ctx context.Context, g *globals, _ []string) error {
	d, err := load(g)
	if err != nil {
		return err
	}
	if err := d.AwaitEnrolled(ctx); err != nil {
		return err
	}
	if err := save(g, d); err != nil {
		return err
	}
	if err := d.CompleteEnrollment(ctx); err != nil {
		return err
	}
	fmt.Println("enrolled; vault", d.VaultID(), "device", d.DeviceID())
	return save(g, d)
}

func cmdPair(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	link := fs.String("link", "", "pairing link")
	_ = fs.Parse(args)
	d, err := load(g)
	if err != nil {
		return err
	}
	sas, err := d.Pair(ctx, *link)
	if err != nil {
		return err
	}
	fmt.Println("SAS:", sas, "(compare with the approving app)")
	if err := save(g, d); err != nil {
		return err
	}
	if err := d.AwaitPaired(ctx); err != nil {
		return err
	}
	fmt.Println("paired; device", d.DeviceID())
	return save(g, d)
}

func body(args []string) json.RawMessage {
	if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
		return json.RawMessage(`{}`)
	}
	return json.RawMessage(args[1])
}

func cmdRequest(ctx context.Context, g *globals, args []string) error {
	if len(args) < 1 {
		return errors.New("request TYPE [JSON]")
	}
	d, err := load(g)
	if err != nil {
		return err
	}
	r, err := d.Request(ctx, args[0], body(args))
	if err != nil {
		return err
	}
	out := map[string]any{"status": r.Inner.Status, "body": r.Body()}
	if !r.OK() {
		out["error"] = r.ErrorCode()
	}
	printJSON(out)
	printEvents(d)
	return save(g, d)
}

func cmdSend(ctx context.Context, g *globals, args []string) error {
	if len(args) < 1 {
		return errors.New("send TYPE [JSON]")
	}
	d, err := load(g)
	if err != nil {
		return err
	}
	id, err := d.Send(ctx, args[0], body(args))
	if err != nil {
		return err
	}
	fmt.Println(id)
	return save(g, d)
}

func cmdEvents(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("events", flag.ExitOnError)
	wait := fs.Duration("wait", 2*time.Second, "how long to collect")
	_ = fs.Parse(args)
	d, err := load(g)
	if err != nil {
		return err
	}
	end := time.Now().Add(*wait)
	for time.Now().Before(end) {
		if err := d.Poll(ctx); err != nil {
			return err
		}
	}
	printEvents(d)
	return save(g, d)
}

func printEvents(d *client.Device) {
	for _, ev := range d.Events() {
		printJSON(map[string]any{"type": ev.Type, "id": ev.ID, "ts": ev.TS, "re": ev.Re, "body": json.RawMessage(ev.Body)})
	}
}
