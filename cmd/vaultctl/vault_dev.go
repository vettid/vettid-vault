//go:build devenclave

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/devenclave"
	"github.com/vettid/vettid-vault/features/messaging"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vault/store"
)

// Dev builds add the vault commands: a vault with a dev sealer whose key is
// kept next to the store. Never use these for anything but development.
func init() {
	commands["vault-create"] = command{"vault-create -store DIR -relay URL -pin PIN -app STATEFILE   (dev) create a vault, enrolling the app", cmdVaultCreate}
	commands["vault-run"] = command{"vault-run -store DIR -vault-id ID -pin PIN [-ws]   (dev) unlock and run a vault", cmdVaultRun}
}

func devSealer(dir string, create bool) (*devenclave.Sealer, error) {
	p := filepath.Join(dir, "dev-sealer.key")
	key, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) && create {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(p, key, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return devenclave.NewSealer(key)
}

func cmdVaultCreate(ctx context.Context, _ *globals, args []string) error {
	fs := flag.NewFlagSet("vault-create", flag.ExitOnError)
	dir := fs.String("store", "", "store directory")
	relay := fs.String("relay", "", "relay base URL")
	pin := fs.String("pin", "", "PIN")
	appState := fs.String("app", "", "state file of the app to enroll")
	_ = fs.Parse(args)
	if *dir == "" || *relay == "" || *pin == "" || *appState == "" {
		return errors.New("-store, -relay, -pin and -app are required")
	}
	sealer, err := devSealer(*dir, true)
	if err != nil {
		return err
	}
	st, err := store.NewDir(*dir)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(*appState)
	if err != nil {
		return err
	}
	app, err := client.Load(client.Config{}, b)
	if err != nil {
		return err
	}
	open, err := app.OpenToken()
	if err != nil {
		return err
	}
	ra := app.RelayAddr()
	m, err := devenclave.Create(ctx, vault.CreateParams{
		Options: vault.Options{Store: st, Sealer: sealer, Features: []vault.Feature{messaging.New()}},
		PIN:     *pin, RelayURL: *relay, Provisional: true,
		App: &vault.EnrollApp{Name: "app", IK: app.IdentityKey(), KEM: app.KEMKey(),
			Relay: vault.PeerRelay{URL: ra.URL, Mailbox: ra.Mailbox, PK: ra.PK}, OpenToken: open},
	})
	if err != nil {
		return err
	}
	fmt.Println(m.VaultID())
	return m.Lock(ctx)
}

func cmdVaultRun(_ context.Context, _ *globals, args []string) error {
	fs := flag.NewFlagSet("vault-run", flag.ExitOnError)
	dir := fs.String("store", "", "store directory")
	id := fs.String("vault-id", "", "vault id")
	pin := fs.String("pin", "", "PIN")
	ws := fs.Bool("ws", false, "collect over WebSocket")
	_ = fs.Parse(args)
	sealer, err := devSealer(*dir, false)
	if err != nil {
		return err
	}
	st, err := store.NewDir(*dir)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	m, res, err := devenclave.Unlock(ctx, vault.UnlockParams{
		Options: vault.Options{Store: st, Sealer: sealer, WebSocket: *ws, Features: []vault.Feature{messaging.New()}},
		VaultID: *id, PIN: *pin,
	})
	if err != nil {
		return err
	}
	fmt.Printf("unlocked %s (state_seq %d, header_seq %d); running until interrupted\n", *id, res.StateSeq, res.HeaderSeq)
	err = m.Run(ctx)
	if ctx.Err() != nil {
		return m.Lock(context.Background())
	}
	return err
}
