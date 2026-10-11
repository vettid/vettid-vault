//go:build devenclave && e2e

package e2e

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/features/all"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
)

// The feature allowlist (VAULT-MESSAGING 0.26.0 §11.10.8) with the real
// features, through the real relay: what a vault does when its image does
// not register an optional feature. The core's rules with stand-in
// features (a connection's message, a response, the carried state entry)
// are in vault/v026_test.go; the release configuration's in
// enclave/releasecfg.

// alwaysOn are the features every image registers.
var alwaysOn = []string{"audit", "connauth", "credential", "critical", "feed", "grants", "items", "messaging"}

func without(name string) []string {
	out := []string{}
	for _, n := range all.Optional() {
		if n != name {
			out = append(out, n)
		}
	}
	return out
}

// relock locks the vault (a flush) and unlocks it again from the store.
func (tv *testVault) relock(t *testing.T) {
	t.Helper()
	tv.stop()
	if err := tv.manager().Lock(ctxT(t, 30*time.Second)); err != nil {
		t.Fatalf("lock: %v", err)
	}
	m, f, err := tv.unlock(ctxT(t, 30*time.Second), nil)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	tv.mu.Lock()
	tv.msg = f
	tv.mu.Unlock()
	tv.start(m)
}

// Per optional feature, in an image without it: every one of its types
// is answered unsupported_type, exactly as a type no vault knows; the
// vault's state has no features.<name> entry after enrollment, after
// requests (each flushes) and after a lock and an unlock; and the same
// vault with the feature answers the type and has the entry.
func TestOptionalFeatureNotRegistered(t *testing.T) {
	r := relaytest.Start(t, nil)
	full := newSet()
	for _, name := range all.Optional() {
		name := name
		t.Run(name, func(t *testing.T) {
			// Its types, and one an app may send as a plain request (for
			// the image that registers it, below).
			var types []string
			appRequest := ""
			for _, f := range full.List() {
				if f.Name() == name {
					for _, ts := range f.Types() {
						types = append(types, ts.Type)
						if appRequest == "" && ts.Request && !ts.Ephemeral && ts.Allows(vault.KindApp) {
							appRequest = ts.Type
						}
					}
				}
			}
			if len(types) == 0 || appRequest == "" {
				t.Fatalf("feature %s: types %v, app request %q", name, types, appRequest)
			}
			tv := newTestVaultWith(t, r.URL, "no"+name, without(name), nil)
			if got := tv.fs.Names(); slices.Contains(got, name) || len(got) != len(alwaysOn)+len(all.Optional())-1 {
				t.Fatalf("registered %v", got)
			}
			unknown := tv.request(tv.app, "nosuch.type", `{}`)
			if unknown.ErrorCode() != "unsupported_type" {
				t.Fatalf("an unknown type: %q", unknown.ErrorCode())
			}
			check := func(when string) {
				t.Helper()
				if got := tv.manager().FeatureEntries(); slices.Contains(got, name) {
					t.Fatalf("%s: the state has a features.%s entry: %v", when, name, got)
				}
			}
			check("after enrollment")
			for _, typ := range types {
				rr := tv.request(tv.app, typ, `{}`)
				if rr.OK() || rr.ErrorCode() != "unsupported_type" {
					t.Fatalf("%s without %s: %q, want unsupported_type", typ, name, rr.ErrorCode())
				}
			}
			check("after requests")
			tv.relock(t)
			check("after a lock and an unlock")
			if rr := tv.request(tv.app, types[0], `{}`); rr.ErrorCode() != "unsupported_type" {
				t.Fatalf("%s after the unlock: %q", types[0], rr.ErrorCode())
			}
			// The always-registered features are there and keep state.
			for _, n := range []string{"audit", "credential", "items"} {
				if !slices.Contains(tv.manager().FeatureEntries(), n) {
					t.Fatalf("no features.%s entry: %v", n, tv.manager().FeatureEntries())
				}
			}
			// A later image that lists the feature: the vault has no entry
			// for it, so it starts empty; a request of its is answered
			// (with whatever the feature says to an empty body, never
			// unsupported_type), and its entry is written with a flush.
			tv.mu.Lock()
			tv.optional = all.Optional()
			tv.mu.Unlock()
			tv.relock(t)
			if rr := tv.request(tv.app, appRequest, `{}`); rr.ErrorCode() == "unsupported_type" {
				t.Fatalf("%s with %s registered: unsupported_type", appRequest, name)
			}
			tv.relock(t)
			if got := tv.manager().FeatureEntries(); !slices.Contains(got, name) {
				t.Fatalf("with %s registered the state has no entry for it: %v", name, got)
			}
		})
	}
}

// Production release 1's list: no optional feature at all. The flows the
// v1 app uses pass (enrollment and the credential in the harness, a
// connection, messages both ways, items, the credential's unlock, History
// and the Notifications feed, settings, a desktop pairing), the state
// holds entries of the always-registered features only, and what needs an
// optional feature is refused as §11.10.8 says.
func TestNoOptionalFeatures(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVaultWith(t, r.URL, "a", []string{}, nil)
	b := newTestVaultWith(t, r.URL, "b", []string{}, nil)
	ctx := ctxT(t, 180*time.Second)
	if got := a.fs.Names(); !slices.Equal(got, alwaysOn) {
		t.Fatalf("registered %v, want %v", got, alwaysOn)
	}
	if a.fs.Calls != nil || a.fs.Leash != nil || a.fs.Wallet != nil || a.fs.Location != nil || a.fs.Presence != nil || a.fs.Actions != nil || a.fs.Intro != nil {
		t.Fatal("an optional feature was constructed")
	}
	aConn, bConn := connect(t, a, b, 600)
	sendText(t, a, a.app, aConn, "hello from a")
	waitEvent(t, b.app, "message.new", nil)
	sendText(t, b, b.app, bConn, "hello from b")
	waitEvent(t, a.app, "message.new", nil)
	if _, _, err := a.app.ItemPut(ctx, "", 0, "", nil, client.ItemContent{Name: "Phone", Category: "contact",
		Fields: []client.ItemField{{Label: "Mobile", Kind: "phone", Value: "555-0100"}}}); err != nil {
		t.Fatalf("item.put: %v", err)
	}
	if l, err := a.app.ItemList(ctx, nil); err != nil || !strings.Contains(string(l["items"]), "Phone") {
		t.Fatalf("item.list: %v", err)
	}
	if _, err := a.app.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatalf("credential.unlock: %v", err)
	}
	if _, _, err := a.app.ItemPutCritical(ctx, credPW, "", 0, nil, client.ItemContent{Name: "seed",
		Fields: []client.ItemField{{Label: "Words", Kind: "multiline", Value: "legal winner thank year"}}}); err != nil {
		t.Fatalf("critical item: %v", err)
	}
	if au, err := a.app.AuditList(ctx, nil, false); err != nil || !strings.Contains(string(au["entries"]), "connection.") {
		t.Fatalf("audit.list: %v", err)
	}
	if _, err := a.app.FeedList(ctx, nil); err != nil {
		t.Fatalf("feed.list: %v", err)
	}
	mustOK(t, a.request(a.app, "vault.status", `{}`))
	mustOK(t, a.request(a.app, "device.list", `{}`))
	mustOK(t, a.request(a.app, "connection.list", `{}`))
	if _, err := a.app.SettingsSet(ctx, 0, map[string]any{"app.theme": "dark", "feed.retention_days": 30}); err != nil {
		t.Fatalf("settings.set: %v", err)
	}
	// Desktop pairing and its access session are core and stay answered.
	desk := pairDesktop(t, a, r.URL)
	if rr, err := desk.Request(ctx, "vault.status", json.RawMessage(`{}`)); err != nil || !rr.OK() {
		t.Fatalf("desktop: %v", err)
	}

	// Without leash: an agent pairing is an unknown role, and a share
	// rule for an agent is not_found.
	if rr := a.request(a.app, "device.pair.create", `{"role":"agent"}`); rr.ErrorCode() != "bad_request" {
		t.Fatalf("agent pairing without leash: %q", rr.ErrorCode())
	}
	if _, err := a.app.ShareRuleSet(ctx, map[string]any{"subject": map[string]any{"agent_id": "01JB2Z6V9K3M4N5P6Q7R8S9T0V"},
		"tags": []string{"agent ok"}, "mode": "auto"}); client.Code(err) != "not_found" {
		t.Fatalf("agent share rule without leash: %v", err)
	}
	for _, typ := range []string{"leash.grant.list", "agent.request"} {
		if rr := a.request(a.app, typ, `{}`); rr.ErrorCode() != "unsupported_type" {
			t.Fatalf("%s: %q", typ, rr.ErrorCode())
		}
	}
	// Without location: the location log's settings are refused;
	// settings.get is unchanged.
	if _, err := a.app.SettingsSet(ctx, 1, map[string]any{"location.history.enabled": true}); client.Code(err) != "bad_request" {
		t.Fatalf("location.history.enabled without location: %v", err)
	}
	st, err := a.app.SettingsGet(ctx)
	if err != nil || !strings.Contains(string(st["settings"]), `"location.history.enabled":false`) || !strings.Contains(string(st["settings"]), `"app.theme":"dark"`) {
		t.Fatalf("settings.get: %v %s", err, st["settings"])
	}
	// A connection's message of an optional feature's type: B's vault
	// (which has none either) cannot even send one, and what A's app
	// tries is an unknown type.
	for _, typ := range []string{"call.offer", "presence.ping", "intro.request", "action.invoke", "location.share.start", "wallet.list"} {
		if rr := a.request(a.app, typ, `{"connection_id":"`+aConn+`"}`); rr.ErrorCode() != "unsupported_type" {
			t.Fatalf("%s: %q", typ, rr.ErrorCode())
		}
	}
	a.relock(t)
	for _, tv := range []*testVault{a, b} {
		for _, n := range tv.manager().FeatureEntries() {
			if !slices.Contains(alwaysOn, n) {
				t.Fatalf("%s: features.%s entry in a vault without optional features", tv.name, n)
			}
		}
	}
	// Still working after the unlock.
	sendText(t, a, a.app, aConn, "after the unlock")
	waitEvent(t, b.app, "message.new", nil)
}

// A vault whose image registers every optional feature sends one of their
// messages to a connection whose image registers none: the peer's vault
// answers as to any unknown type and nothing reaches its app; the sender
// keeps working. (The answer itself, error code unsupported_type to a
// connection, is asserted in vault.TestUnregisteredTypeIsUnknown.)
func TestConnectionSendsUnregisteredType(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVaultWith(t, r.URL, "b", []string{}, nil)
	ctx := ctxT(t, 120*time.Second)
	aConn, bConn := connect(t, a, b, 600)
	// A asks for B's presence: presence.ping travels to B's vault, which
	// does not know the type. No pong comes back, as from a connection
	// that does not share its presence.
	pid, err := a.app.PresenceQuery(ctx, aConn)
	if err != nil {
		t.Fatalf("presence.query: %v", err)
	}
	quiet, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if res, err := a.app.PresenceResult(quiet, pid); err == nil {
		t.Fatalf("a vault without presence answered a ping: %v", res)
	}
	if got := b.manager().FeatureEntries(); slices.Contains(got, "presence") {
		t.Fatalf("B gained a presence entry: %v", got)
	}
	// Both vaults keep working with each other.
	sendText(t, b, b.app, bConn, "still here")
	waitEvent(t, a.app, "message.new", nil)
	sendText(t, a, a.app, aConn, "and here")
	waitEvent(t, b.app, "message.new", nil)
}

// actions may be listed without wallet (§11.10.8): the wallet actions of
// §10.14 are still offered and answer unavailable, as they do when no
// wallet is configured.
func TestActionsWithoutWallet(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVaultWith(t, r.URL, "a", []string{all.Actions}, nil)
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 180*time.Second)
	if a.fs.Actions == nil || a.fs.Wallet != nil {
		t.Fatal("feature set")
	}
	_, bConn := connect(t, a, b, 600)
	status := func(o strictjson.Object) string { s, _ := o.String("status"); return s }
	if _, err := a.app.ActionConfigure(ctx, client.ActionConfig{ActionID: "wallet.request-address", Mode: "default-allow"}); err != nil {
		t.Fatalf("configure: %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		l, err := b.app.ActionList(ctx, bConn)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(l["actions"]), "wallet.request-address") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("wallet.request-address not offered: %s", l["actions"])
		}
		time.Sleep(200 * time.Millisecond)
	}
	id, err := b.app.ActionInvoke(ctx, bConn, "wallet.request-address", json.RawMessage(`{"asset":"BTC"}`))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	res, err := b.app.ActionResult(ctx, id)
	if err != nil || status(res) != "unavailable" {
		t.Fatalf("wallet action without the wallet: %v %v", err, res)
	}
	// The wallet's own types are unknown to A.
	if rr := a.request(a.app, "wallet.list", `{}`); rr.ErrorCode() != "unsupported_type" {
		t.Fatalf("wallet.list: %q", rr.ErrorCode())
	}
	if got := a.manager().FeatureEntries(); slices.Contains(got, "wallet") {
		t.Fatalf("a wallet entry without the wallet: %v", got)
	}
}

// The development enclave given production's list (-dev-features none,
// §11.10.8 "The development build"), as real processes: parent,
// supervisor and one vault process. A vault enrolls, unlocks and answers
// the core's requests; an optional feature's type is an unknown type, an
// agent pairing an unknown role and the location log's settings refused,
// before and after a lock and an unlock.
func TestHostStackProductionFeatures(t *testing.T) {
	hs := newHostStack(t)
	hs.features = []string{}
	a := hs.start("i-a", 3, 0)
	const vid = "33333333333333333333333333333333"
	m := hs.newApp("member-prod-list", 0x67)
	m.enroll(a, vid)
	if !m.status() {
		t.Fatal("vault.status")
	}
	ctx := ctxT(t, 60*time.Second)
	req := func(typ, body string) *client.Response {
		t.Helper()
		r, err := m.dev.Request(ctx, typ, json.RawMessage(body))
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		return r
	}
	for _, typ := range []string{"presence.get", "wallet.list", "leash.grant.list", "location.share.list", "intro.list", "action.list", "call.offer"} {
		if r := req(typ, `{}`); r.ErrorCode() != "unsupported_type" {
			t.Fatalf("%s on production's list: %q", typ, r.ErrorCode())
		}
	}
	if r := req("device.pair.create", `{"role":"agent"}`); r.ErrorCode() != "bad_request" {
		t.Fatalf("agent pairing: %q", r.ErrorCode())
	}
	if r := req("settings.set", `{"version":0,"set":{"location.history.enabled":true}}`); r.ErrorCode() != "bad_request" {
		t.Fatalf("location.history.enabled: %q", r.ErrorCode())
	}
	for _, typ := range []string{"device.list", "connection.list", "settings.get", "item.list", "feed.list", "audit.list"} {
		if r := req(typ, `{}`); !r.OK() {
			t.Fatalf("%s on production's list: %q", typ, r.ErrorCode())
		}
	}
	m.lock(a)
	waitUntil(t, "lock", func() bool { return len(a.p.RunningVaults()) == 0 })
	if u, _ := m.unlock(a); !u.OK {
		t.Fatalf("unlock: %+v", u)
	}
	if r := req("presence.get", `{}`); r.ErrorCode() != "unsupported_type" {
		t.Fatalf("presence.get after the unlock: %q", r.ErrorCode())
	}
}
