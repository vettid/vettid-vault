// Package actions is shared actions between connections (VAULT-MESSAGING
// §10.14). STUB: being implemented.
package actions

import (
	"context"
	"encoding/json"

	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Feature implements vault.Feature.
type Feature struct{}

// New returns the feature.
func New() *Feature { return &Feature{} }

// Name implements vault.Feature.
func (f *Feature) Name() string { return "actions" }

// Types implements vault.Feature.
func (f *Feature) Types() []vault.TypeSpec { return nil }

// Load implements vault.Feature.
func (f *Feature) Load(json.RawMessage) error { return nil }

// Save implements vault.Feature.
func (f *Feature) Save() (json.RawMessage, error) { return json.RawMessage(`{}`), nil }

// Handle implements vault.Handler.
func (f *Feature) Handle(context.Context, *vault.Session, *envelope.Inner) (json.RawMessage, error) {
	return nil, vault.NewError("unsupported_type", "")
}
