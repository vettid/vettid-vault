package client

import (
	"context"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

// Introductions (VAULT-MESSAGING §10.15): the member introduces two of
// their connections; each is asked and accepts or declines.

// IntroPeer is what the introducer shows one party about the other.
type IntroPeer struct {
	Name string `json:"name"`
	Note string `json:"note,omitempty"`
}

// IntroCreate introduces connections a and c: toA is shown to A about C,
// toC to C about A. It returns the introduction's id.
func (d *Device) IntroCreate(ctx context.Context, a, c string, toA, toC IntroPeer) (string, error) {
	o, err := d.Op(ctx, "intro.create", map[string]any{"a": a, "c": c, "to_a": toA, "to_c": toC})
	if err != nil {
		return "", err
	}
	return o.String("intro_id")
}

// IntroCancel cancels an introduction this member made.
func (d *Device) IntroCancel(ctx context.Context, id string) error {
	_, err := d.Op(ctx, "intro.cancel", map[string]any{"intro_id": id})
	return err
}

// IntroList lists introductions made and received.
func (d *Device) IntroList(ctx context.Context) (strictjson.Object, error) {
	return d.Op(ctx, "intro.list", nil)
}

// IntroAccept accepts an introduction offered to this member.
func (d *Device) IntroAccept(ctx context.Context, id string) error {
	_, err := d.Op(ctx, "intro.accept", map[string]any{"intro_id": id})
	return err
}

// IntroDecline declines an introduction offered to this member.
func (d *Device) IntroDecline(ctx context.Context, id string) error {
	_, err := d.Op(ctx, "intro.decline", map[string]any{"intro_id": id})
	return err
}
