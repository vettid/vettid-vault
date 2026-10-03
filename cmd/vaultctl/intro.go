package main

import (
	"context"
	"errors"
	"flag"

	"github.com/vettid/vettid-vault/client"
)

// Introductions (VAULT-MESSAGING §10.15).

func init() {
	commands["intro"] = command{"intro create -a ID -c ID -name-a N -name-c N [-note-a T] [-note-c T] | cancel -id ID | list | accept -id ID | decline -id ID", cmdIntro}
}

func cmdIntro(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["intro"].usage)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("intro "+op, flag.ExitOnError)
	a := fs.String("a", "", "connection id of A")
	c := fs.String("c", "", "connection id of C")
	nameA := fs.String("name-a", "", "the name shown to A for C")
	nameC := fs.String("name-c", "", "the name shown to C for A")
	noteA := fs.String("note-a", "", "a note shown to A")
	noteC := fs.String("note-c", "", "a note shown to C")
	id := fs.String("id", "", "introduction id")
	_ = fs.Parse(rest)
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "create":
			iid, err := d.IntroCreate(ctx, *a, *c, client.IntroPeer{Name: *nameA, Note: *noteA}, client.IntroPeer{Name: *nameC, Note: *noteC})
			return map[string]string{"intro_id": iid}, err
		case "cancel":
			return nil, d.IntroCancel(ctx, *id)
		case "list":
			return d.IntroList(ctx)
		case "accept":
			return nil, d.IntroAccept(ctx, *id)
		case "decline":
			return nil, d.IntroDecline(ctx, *id)
		}
		return nil, errors.New(commands["intro"].usage)
	})
}
