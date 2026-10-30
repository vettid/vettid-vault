// Package all assembles the vault's feature set (VAULT-MESSAGING §10).
// Every call returns fresh, per-vault instances: feature code keeps no
// package-level mutable state.
//
// Eight features are always registered: audit, feed, messaging,
// credential, items, grants, critical and connauth. The other eight are
// optional (0.26.0, §11.10.8 "Feature allowlist"): an image registers
// exactly those its release configuration lists. An optional feature that
// is not listed is not constructed: its types are unknown types
// (unsupported_type, §5.3), it has no state entry and nothing is migrated
// for it, none of its hooks run and it sends nothing. A features.<name>
// entry that a vault's state already holds for it is carried unchanged by
// the vault core, which reads and writes only the entries of the features
// it was given.
package all

import (
	"fmt"
	"sort"

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
	"github.com/vettid/vettid-vault/features/location"
	"github.com/vettid/vettid-vault/features/messaging"
	"github.com/vettid/vettid-vault/features/presence"
	"github.com/vettid/vettid-vault/features/vote"
	"github.com/vettid/vettid-vault/features/wallet"
	"github.com/vettid/vettid-vault/vault"
)

// Optional feature names (0.26.0, §11.10.8): the feature packages' own
// names. A feature added to the code later belongs here, and is off in
// every channel until a channel file names it.
const (
	Actions  = "actions"
	Calls    = "calls"
	Intro    = "intro"
	Leash    = "leash"
	Location = "location"
	Presence = "presence"
	Vote     = "vote"
	Wallet   = "wallet"
)

// Optional returns the names of the optional features in ascending byte
// order: what a release configuration's "features" may list
// (enclave/releasecfg keeps the same list; a test holds them together).
func Optional() []string {
	return []string{Actions, Calls, Intro, Leash, Location, Presence, Vote, Wallet}
}

// CheckOptional reports a name that is not an optional feature's (an
// always-registered feature's included) or that is repeated.
func CheckOptional(names []string) error {
	known := map[string]bool{}
	for _, n := range Optional() {
		known[n] = true
	}
	seen := map[string]bool{}
	for _, n := range names {
		if !known[n] {
			return fmt.Errorf("features: %q is not an optional feature", n)
		}
		if seen[n] {
			return fmt.Errorf("features: %q is listed twice", n)
		}
		seen[n] = true
	}
	return nil
}

// Options configure the feature set.
type Options struct {
	// CredentialKDF is the Protean Credential's password KDF; zero means
	// credential.DefaultKDF (tests and development use credential.MinKDF).
	CredentialKDF credential.KDF
	// ICE issues call ICE servers and credentials (CALLING-SERVICE §5);
	// nil means none (no calling service yet).
	ICE calls.ICEIssuer
	// WalletNetworks are the Bitcoin networks new wallets may use; nil
	// means mainnet, testnet, testnet4 and signet (§10.18, 0.35.0).
	WalletNetworks []string
	// Optional names the optional features to register (0.26.0,
	// §11.10.8): a release passes its channel file's list. Empty: none,
	// so a configuration that names nothing registers nothing optional.
	// A name that is not an optional feature's registers nothing.
	Optional []string
	// Vote are the release constants the vote feature checks against
	// (0.81.0, §11.10.8): present when the channel lists `vote`. In a
	// development build without a channel file they are empty, so no
	// service list verifies and every proposal stays `checking`.
	Vote vote.Options
}

// Set is one vault's features, with typed access for tests and tools.
// The eight optional features are nil when not registered.
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
	Wallet     *wallet.Feature
	Location   *location.Feature
	Presence   *presence.Feature
	Vote       *vote.Feature
}

// NewSet returns fresh instances of the always-registered features and of
// the optional features o.Optional names.
func NewSet(o Options) *Set {
	on := map[string]bool{}
	for _, n := range o.Optional {
		on[n] = true
	}
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
	it.SetGrants(gr)
	aud := audit.New()
	aud.SetItems(it)        // the search reads the items' current names (§10.9, 0.20.0)
	aud.SetCredential(cred) // History export: the holder's UTK-sealed PIN (§10.9, 0.22.0)
	s := &Set{
		Messaging:  messaging.New(),
		Credential: cred,
		Items:      it,
		Audit:      aud,
		Feed:       feed.New(),
		ConnAuth:   auth,
		Grants:     gr,
		Critical:   critical.New(cred, it), // each use is a credential operation (§3.5.3) on a usable item
	}
	if on[Leash] {
		// Signs delegations in the unlock window; reads the items agents'
		// rules include. Without it no feature keeps agent rules, and a
		// share rule for an agent is answered not_found (§11.10.8).
		s.Leash = leash.New(cred, it)
		it.SetAgents(s.Leash)
	}
	if on[Wallet] {
		// The wallet's recovery phrases are critical items; it owns them
		// (item.put and item.sensitivity refused) and spends through the
		// credential (§10.18). No chain source: the app is the chain source.
		s.Wallet = wallet.New(cred, it, wallet.Options{Networks: o.WalletNetworks})
		it.SetGuard(s.Wallet)
	}
	if on[Actions] {
		// Built-in actions run through grants, the audit log and the
		// credential's unlock window (§10.14). Without the wallet its
		// actions answer unavailable, so actions may be listed without
		// wallet (§11.10.8).
		deps := actions.Deps{Grants: gr, Audit: aud, Keys: cred}
		if s.Wallet != nil {
			deps.Wallet = s.Wallet // never a typed nil
		}
		s.Actions = actions.New(deps)
	}
	if on[Calls] {
		s.Calls = calls.New(calls.Options{ICE: o.ICE})
	}
	if on[Intro] {
		s.Intro = intro.New()
	}
	if on[Location] {
		s.Location = location.New()
	}
	if on[Presence] {
		s.Presence = presence.New()
	}
	if on[Vote] {
		s.Vote = vote.New(o.Vote)
		// The profile.update to a service says so (§10.19.1).
		it.SetPeerFeatures([]string{vote.Name})
	}
	return s
}

// List returns the registered features in registration order. The audit
// log and the feed come first so that they see activity recorded while
// the others load. An optional feature that is not registered is absent.
func (s *Set) List() []vault.Feature {
	out := []vault.Feature{s.Audit, s.Feed, s.Messaging, s.Credential, s.Items}
	if s.Calls != nil {
		out = append(out, s.Calls)
	}
	out = append(out, s.ConnAuth)
	if s.Leash != nil {
		out = append(out, s.Leash)
	}
	out = append(out, s.Grants, s.Critical)
	if s.Actions != nil {
		out = append(out, s.Actions)
	}
	if s.Intro != nil {
		out = append(out, s.Intro)
	}
	if s.Wallet != nil {
		out = append(out, s.Wallet)
	}
	if s.Location != nil {
		out = append(out, s.Location)
	}
	if s.Presence != nil {
		out = append(out, s.Presence)
	}
	if s.Vote != nil {
		out = append(out, s.Vote)
	}
	return out
}

// Names returns the registered features' names, ascending.
func (s *Set) Names() []string {
	var out []string
	for _, f := range s.List() {
		out = append(out, f.Name())
	}
	sort.Strings(out)
	return out
}

// New returns a fresh feature list.
func New(o Options) []vault.Feature { return NewSet(o).List() }

// Dev returns a fresh feature list with test-strength KDF parameters and
// every optional feature (development builds and tests only).
func Dev() []vault.Feature { return New(DevOptions()) }

// DevOptions are the development and test options: test-strength KDF
// parameters, regtest wallets besides the release networks, and every
// optional feature (the development build has no channel file, §11.10.8).
func DevOptions() Options {
	return Options{CredentialKDF: credential.MinKDF, WalletNetworks: []string{"mainnet", "testnet", "testnet4", "signet", "regtest"}, Optional: Optional()}
}

// DevOptionsWith are DevOptions with exactly the named optional features:
// the development enclave's test configuration, so that the app is run
// against production's list before a production release (§11.10.8).
func DevOptionsWith(optional []string) Options {
	o := DevOptions()
	o.Optional = append([]string{}, optional...)
	return o
}
