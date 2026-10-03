// Package all assembles the vault's feature set (VAULT-MESSAGING §10).
// Every call returns fresh, per-vault instances: feature code keeps no
// package-level mutable state.
package all

import (
	"github.com/vettid/vettid-vault/features/audit"
	"github.com/vettid/vettid-vault/features/calls"
	"github.com/vettid/vettid-vault/features/connauth"
	"github.com/vettid/vettid-vault/features/credential"
	"github.com/vettid/vettid-vault/features/feed"
	"github.com/vettid/vettid-vault/features/messaging"
	"github.com/vettid/vettid-vault/features/profile"
	"github.com/vettid/vettid-vault/features/secrets"
	"github.com/vettid/vettid-vault/vault"
)

// Options configure the feature set.
type Options struct {
	// CredentialKDF is the Protean Credential's password KDF; zero means
	// credential.DefaultKDF (tests and development use credential.MinKDF).
	CredentialKDF credential.KDF
	// ICE issues call ICE servers and credentials (CALLING-SERVICE §5);
	// nil means none (no calling service yet).
	ICE calls.ICEIssuer
}

// Set is one vault's features, with typed access for tests and tools.
type Set struct {
	Messaging  *messaging.Feature
	Credential *credential.Feature
	Secrets    *secrets.Feature
	Profile    *profile.Feature
	Audit      *audit.Feature
	Feed       *feed.Feature
	Calls      *calls.Feature
	ConnAuth   *connauth.Feature
}

// NewSet returns fresh instances of every feature.
func NewSet(o Options) *Set {
	cred := credential.New(credential.Options{KDF: o.CredentialKDF})
	return &Set{
		Messaging:  messaging.New(),
		Credential: cred,
		Secrets:    secrets.New(),
		Profile:    profile.New(),
		Audit:      audit.New(),
		Feed:       feed.New(),
		Calls:      calls.New(calls.Options{ICE: o.ICE}),
		ConnAuth:   connauth.New(cred), // signs with the credential key in its unlock window
	}
}

// List returns the features in registration order. The audit log and the
// feed come first so that they see activity recorded while the others load.
func (s *Set) List() []vault.Feature {
	return []vault.Feature{s.Audit, s.Feed, s.Messaging, s.Credential, s.Secrets, s.Profile, s.Calls, s.ConnAuth}
}

// New returns a fresh feature list.
func New(o Options) []vault.Feature { return NewSet(o).List() }

// Dev returns a fresh feature list with test-strength KDF parameters
// (development builds and tests only).
func Dev() []vault.Feature { return New(Options{CredentialKDF: credential.MinKDF}) }
