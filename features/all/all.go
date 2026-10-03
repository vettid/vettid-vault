// Package all assembles the vault's feature set (VAULT-MESSAGING §10).
// Every call returns fresh, per-vault instances: feature code keeps no
// package-level mutable state.
package all

import (
	"github.com/vettid/vettid-vault/features/actions"
	"github.com/vettid/vettid-vault/features/audit"
	"github.com/vettid/vettid-vault/features/calls"
	"github.com/vettid/vettid-vault/features/connauth"
	"github.com/vettid/vettid-vault/features/credential"
	"github.com/vettid/vettid-vault/features/critical"
	"github.com/vettid/vettid-vault/features/feed"
	"github.com/vettid/vettid-vault/features/grants"
	"github.com/vettid/vettid-vault/features/intro"
	"github.com/vettid/vettid-vault/features/items"
	"github.com/vettid/vettid-vault/features/leash"
	"github.com/vettid/vettid-vault/features/messaging"
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
	Items      *items.Feature
	Audit      *audit.Feature
	Feed       *feed.Feature
	Calls      *calls.Feature
	ConnAuth   *connauth.Feature
	Leash      *leash.Feature
	Grants     *grants.Feature
	Critical   *critical.Feature
	Actions    *actions.Feature
	Intro      *intro.Feature
}

// NewSet returns fresh instances of every feature.
func NewSet(o Options) *Set {
	cred := credential.New(credential.Options{KDF: o.CredentialKDF})
	auth := connauth.New(cred)        // signs with the credential key in its unlock window
	cred.AddKeyRotationObserver(auth) // and follows its rotations (§10.4)
	// Items: critical items are credential operations; their readable
	// inclusions are grants; agent rules are LEASH grants (§10.7, §10.11,
	// §10.12).
	it := items.New(cred)
	cred.AddDeleteObserver(it)
	cred.SetItemRekeyer(it) // credential.rotate and .recover re-key every critical item
	gr := grants.New(it)
	ls := leash.New(cred, it) // signs delegations in the unlock window; reads the items agents' rules include
	it.SetGrants(gr)
	it.SetAgents(ls)
	aud := audit.New()
	return &Set{
		Messaging:  messaging.New(),
		Credential: cred,
		Items:      it,
		Audit:      aud,
		Feed:       feed.New(),
		Calls:      calls.New(calls.Options{ICE: o.ICE}),
		ConnAuth:   auth,
		Leash:      ls,
		Grants:     gr,
		Critical:   critical.New(cred, it), // each use is a credential operation (§3.5.3) on a usable item
		// Built-in actions run through grants, the audit log and the
		// credential's unlock window (§10.14).
		Actions: actions.New(actions.Deps{Grants: gr, Audit: aud, Keys: cred}),
		Intro:   intro.New(),
	}
}

// List returns the features in registration order. The audit log and the
// feed come first so that they see activity recorded while the others load.
func (s *Set) List() []vault.Feature {
	return []vault.Feature{s.Audit, s.Feed, s.Messaging, s.Credential, s.Items, s.Calls, s.ConnAuth, s.Leash, s.Grants, s.Critical, s.Actions, s.Intro}
}

// New returns a fresh feature list.
func New(o Options) []vault.Feature { return NewSet(o).List() }

// Dev returns a fresh feature list with test-strength KDF parameters
// (development builds and tests only).
func Dev() []vault.Feature { return New(Options{CredentialKDF: credential.MinKDF}) }
