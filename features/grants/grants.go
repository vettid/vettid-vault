// Package grants is 1:1 sharing between connections (VAULT-MESSAGING
// §10.12). STUB: being implemented.
package grants

import (
	"context"
	"encoding/json"

	"github.com/vettid/vettid-vault/features/credential"
	"github.com/vettid/vettid-vault/features/secrets"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// FieldSource is the profile (§10.8).
type FieldSource interface {
	FieldValue(key string) (string, bool)
}

// SecretSource is the vault-held secrets (§10.7).
type SecretSource interface {
	Catalog() []secrets.CatalogEntry
	CatalogedValue(id string) (name, value string, ok bool)
}

// CriticalCatalog is the credential's catalog of critical secrets (§10.13).
type CriticalCatalog interface {
	CatalogedSecrets() []credential.Meta
}

// Feature implements vault.Feature.
type Feature struct {
	fields  FieldSource
	secrets SecretSource
	crit    CriticalCatalog
}

// New returns the feature.
func New(fields FieldSource, src SecretSource, crit CriticalCatalog) *Feature {
	return &Feature{fields: fields, secrets: src, crit: crit}
}

// Name implements vault.Feature.
func (f *Feature) Name() string { return "grants" }

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
