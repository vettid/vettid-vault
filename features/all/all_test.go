package all_test

import (
	"reflect"
	"sort"
	"testing"

	"github.com/vettid/vettid-vault/features/all"
	"github.com/vettid/vettid-vault/features/connauth"
	"github.com/vettid/vettid-vault/features/credential"
	"github.com/vettid/vettid-vault/features/vote"
	"github.com/vettid/vettid-vault/vault"
)

var always = []string{"audit", "connauth", "credential", "critical", "feed", "grants", "items", "messaging"}

func typesOf(fs []vault.Feature) map[string]string {
	out := map[string]string{}
	for _, f := range fs {
		for _, ts := range f.Types() {
			out[ts.Type] = f.Name()
		}
	}
	return out
}

// VAULT-MESSAGING 0.26.0 §11.10.8: the set is built from the list. With
// no list the eight always-registered features are there and nothing
// else; a name of the list registers exactly that feature; a feature not
// listed is not constructed, so none of its types is registered (each is
// then an unknown type to the vault, vault.TestUnregisteredTypeIsUnknown)
// and none of its hooks exists to run.
func TestSetFollowsTheList(t *testing.T) {
	if got := all.Optional(); !reflect.DeepEqual(got, []string{"actions", "calls", "intro", "leash", "location", "presence", "vote", "wallet"}) || !sort.StringsAreSorted(got) {
		t.Fatalf("optional %v", got)
	}
	// The zero options register nothing optional (fail closed).
	for _, o := range []all.Options{{}, all.DevOptionsWith(nil), all.DevOptionsWith([]string{})} {
		s := all.NewSet(o)
		if got := s.Names(); !reflect.DeepEqual(got, always) {
			t.Fatalf("no list: %v", got)
		}
		if s.Actions != nil || s.Calls != nil || s.Intro != nil || s.Leash != nil || s.Location != nil || s.Presence != nil || s.Vote != nil || s.Wallet != nil {
			t.Fatal("an optional feature was constructed without being listed")
		}
		for _, f := range s.List() {
			if f == nil {
				t.Fatal("nil feature in the list")
			}
		}
	}
	full := all.NewSet(all.DevOptions())
	if got := full.Names(); len(got) != len(always)+8 {
		t.Fatalf("development set: %v", got)
	}
	fullTypes := typesOf(full.List())
	baseTypes := typesOf(all.New(all.DevOptionsWith(nil)))
	for typ, owner := range baseTypes {
		for _, n := range all.Optional() {
			if owner == n {
				t.Fatalf("%s of %s registered without a list", typ, n)
			}
		}
	}
	for _, name := range all.Optional() {
		// Listed alone: the feature and its types beside the base.
		one := typesOf(all.New(all.DevOptionsWith([]string{name})))
		n := 0
		for typ, owner := range fullTypes {
			_, has := one[typ]
			switch {
			case owner == name:
				n++
				if !has {
					t.Errorf("%s listed: its type %s is not registered", name, typ)
				}
			case has != (baseTypes[typ] != ""):
				t.Errorf("%s listed: type %s of %s registered=%v", name, typ, owner, has)
			}
		}
		if n == 0 {
			t.Errorf("%s declares no type", name)
		}
		// Left out of the full list: every other type stays, none of its.
		var rest []string
		for _, o := range all.Optional() {
			if o != name {
				rest = append(rest, o)
			}
		}
		without := typesOf(all.New(all.DevOptionsWith(rest)))
		for typ, owner := range fullTypes {
			if _, has := without[typ]; has == (owner == name) {
				t.Errorf("without %s: type %s of %s registered=%v", name, typ, owner, has)
			}
		}
	}
	// The table of §11.10.8: which type prefixes belong to which name.
	for typ, owner := range fullTypes {
		want := map[string]string{"action.": "actions", "call.": "calls", "intro.": "intro", "leash.": "leash", "agent.": "leash",
			"location.": "location", "presence.": "presence", "wallet.": "wallet"}
		for prefix, name := range want {
			if len(typ) > len(prefix) && typ[:len(prefix)] == prefix && owner != name {
				t.Errorf("type %s is registered by %s, the list's table says %s", typ, owner, name)
			}
		}
	}
	// A name that is no optional feature's registers nothing, and is
	// reported by CheckOptional (so is an always-registered name, and a
	// repeated one).
	if got := all.NewSet(all.DevOptionsWith([]string{"audit", "teleport", ""})).Names(); !reflect.DeepEqual(got, always) {
		t.Fatalf("unknown names registered something: %v", got)
	}
	for _, bad := range [][]string{{"audit"}, {"teleport"}, {""}, {"calls", "calls"}} {
		if all.CheckOptional(bad) == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if err := all.CheckOptional(all.Optional()); err != nil {
		t.Fatal(err)
	}
	if err := all.CheckOptional(nil); err != nil {
		t.Fatal(err)
	}
}

// The vote feature (0.81.0, 0.81.1) is wired to the features it works with:
// the credential's rotation (both keys open), member authentication's signed
// responses, and the vault's hooks for responses, ticks and restores.
func TestVoteFeatureHooks(t *testing.T) {
	s := all.NewSet(all.DevOptionsWith([]string{"vote"}))
	if s.Vote == nil {
		t.Fatal("vote not registered")
	}
	var f any = s.Vote
	for name, ok := range map[string]bool{
		"credential.KeyRotationObserver":  func() bool { _, ok := f.(credential.KeyRotationObserver); return ok }(),
		"credential.KeyRotationSigner":    func() bool { _, ok := f.(credential.KeyRotationSigner); return ok }(),
		"connauth.ResponseObserver":       func() bool { _, ok := f.(connauth.ResponseObserver); return ok }(),
		"vault.ResponseObserver":          func() bool { _, ok := f.(vault.ResponseObserver); return ok }(),
		"vault.TickObserver":              func() bool { _, ok := f.(vault.TickObserver); return ok }(),
		"vault.TransferObserver":          func() bool { _, ok := f.(vault.TransferObserver); return ok }(),
		"vault.RecoveryObserver":          func() bool { _, ok := f.(vault.RecoveryObserver); return ok }(),
		"vault.ConnectionRemovedObserver": func() bool { _, ok := f.(vault.ConnectionRemovedObserver); return ok }(),
		"vote.Auth":                       func() bool { _, ok := any(s.ConnAuth).(vote.Auth); return ok }(),
		"vote.Keys":                       func() bool { _, ok := any(s.Credential).(vote.Keys); return ok }(),
	} {
		if !ok {
			t.Errorf("%s", name)
		}
	}
}
