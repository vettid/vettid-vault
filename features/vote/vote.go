// Package vote is the member side of the ballot protocol (VAULT-MESSAGING
// 0.81.0 §10.19; BALLOT-PROTOCOL 0.12): a service puts a proposal to its
// members over the service connection, and this vault checks it
// (signature, tag, public anchor), keeps it, and later casts one ballot,
// verifies the receipt and checks the results.
//
// This file is the feature itself: its types, state and bookkeeping. The
// checks of §10.19.4 are in intake.go, the limits of §10.19.2 in store.go,
// and the service list and site comparison in site.go. Casting, receipts,
// restore and the results check (PR 3) and the app's API (PR 4) build on
// the records kept here.
//
// The feature is optional (§11.10.8): an image registers it only if its
// channel file lists `vote`.
package vote

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// Name is the feature's name in a channel file's `features`.
const Name = "vote"

// Options are the release constants the feature checks against (§11.10.8):
// the Ed25519 key votes.vettid.org signs its service list with, and the
// pinned Sigstore trusted roots, newest last. Without them nothing can be
// verified: a service list never verifies, and every proposal stays
// `checking`.
type Options struct {
	SiteKey ed25519.PublicKey
	Roots   []*votewire.TrustRoot
}

// Keys gives access to the credential key during the unlock window
// (credential.Feature.UseKey, §3.5.3).
type Keys interface {
	UseKey(now time.Time, ttl time.Duration) (ed25519.PrivateKey, bool)
}

// Auth is what the vote feature asks of member authentication (§10.4):
// the credential key a connection pinned (from a signed response the vault
// sent it), and the rotation statement still owed to it.
type Auth interface {
	SignedInKey(conn string) []byte
	RotatedBody(conn string) []byte
}

// Deps are the features the vote feature works with. Without Keys nothing
// can be cast.
type Deps struct {
	Keys Keys
	Auth Auth
	// Cred is the credential feature, for vote.release (the holder, the PIN).
	Cred Credential
}

// Feature implements vault.Feature.
type Feature struct {
	mu    sync.Mutex
	dep   Deps
	pend  map[string]pendRef // our outstanding requests by inner id (memory only)
	asked map[string]int64   // the last RequestProposal by connection|id, ms (memory only)
	opt   Options
	st    state
	last  int64      // unix ms of the last recheck (memory only)
	idx   *listIndex // the held list, parsed (memory only)
}

// New returns the feature.
func New(o Options, d ...Deps) *Feature {
	f := &Feature{opt: o, pend: map[string]pendRef{}, asked: map[string]int64{}}
	if len(d) > 0 {
		f.dep = d[0]
	}
	f.st.init()
	return f
}

// Name implements vault.Feature.
func (f *Feature) Name() string { return Name }

var conns = []string{vault.KindConnection}

// Types implements vault.Feature: the three requests a service sends
// (§6.4 "Votes"), from service connections only. The app's requests and
// the two the vault sends (vote.cast, vote.status) come with the next PRs.
func (f *Feature) Types() []vault.TypeSpec {
	return append(appTypes(), []vault.TypeSpec{
		{Type: "vote.proposal", Request: true, From: conns, Connections: vault.PeersService},
		{Type: "vote.extended", Request: true, From: conns, Connections: vault.PeersService},
		{Type: "vote.closed", Request: true, From: conns, Connections: vault.PeersService},
	}...)
}

// Load implements vault.Feature.
func (f *Feature) Load(raw json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var st state
	if err := json.Unmarshal(raw, &st); err != nil {
		return err
	}
	st.init()
	f.st = st
	return nil
}

// Save implements vault.Feature.
func (f *Feature) Save() (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return json.Marshal(&f.st)
}

// Handle implements vault.Handler.
func (f *Feature) Handle(_ context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	if s.From().Kind == vault.KindApp {
		f.mu.Lock()
		f.prune(s)
		f.mu.Unlock()
		return f.handleApp(s, in) // each locks for itself
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !s.From().IsService() {
		// The runtime's gate (§6.4) never lets another kind here; this is
		// the second lock on the door.
		return nil, vault.NewError("unsupported_type", "")
	}
	f.prune(s)
	switch in.Type {
	case "vote.proposal":
		return f.onProposal(s, in)
	case "vote.extended":
		return f.onExtended(s, in)
	case "vote.closed":
		return f.onClosed(s, in)
	}
	return nil, vault.NewError("unsupported_type", "")
}

var (
	errBad      = vault.NewError("bad_request", "")
	errNotFound = vault.NewError("not_found", "")
)

var _ vault.UnlockObserver = (*Feature)(nil)
