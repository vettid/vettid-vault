package main

import (
	"context"
	"errors"
	"flag"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/vms/pushwire"
)

// Push (VAULT-MESSAGING 0.24.0 §14): the app's registration and its state.

func init() {
	commands["push"] = command{"push register -platform fcm|apns -token T -app-id ID [-environment production|sandbox] | unregister | status   " +
		"(the holder app only; status is device.list's push state, null without one)", cmdPush}
}

func cmdPush(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["push"].usage)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("push "+op, flag.ExitOnError)
	platform := fs.String("platform", "fcm", "fcm or apns")
	token := fs.String("token", "", "the platform push token")
	appID := fs.String("app-id", "com.vettid.app", "Android package or iOS bundle id")
	env := fs.String("environment", "", "apns only: production or sandbox")
	_ = fs.Parse(rest)
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "register":
			return d.PushRegister(ctx, pushwire.Registration{Platform: *platform, Token: *token, AppID: *appID, Environment: *env})
		case "unregister":
			return nil, d.PushUnregister(ctx)
		case "status":
			return d.PushStatus(ctx)
		}
		return nil, errors.New(commands["push"].usage)
	})
}
