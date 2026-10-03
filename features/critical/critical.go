// Package critical is critical-secret use by a connection
// (VAULT-MESSAGING §10.13). STUB: being implemented.
package critical

import (
	"context"
	"encoding/json"

	"github.com/vettid/vettid-vault/features/credential"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Feature implements vault.Feature.
type Feature struct {
	cred *credential.Feature
}

// New returns the feature; cred performs the uses (credential.UseSecret).
func New(cred *credential.Feature) *Feature { return &Feature{cred: cred} }

// Name implements vault.Feature.
func (f *Feature) Name() string { return "critical" }

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
