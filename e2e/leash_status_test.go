//go:build devenclave && e2e

package e2e

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/leashwire"
)

// §10.11 status statements through the real relay: the agent presents its
// delegation with a status statement that a relying party verifies
// offline with only the member's key; the client refreshes it before it
// expires; after a revocation no new statement is issued and the old one
// lapses; a locked vault issues none.
func TestLeashStatus(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	ctx := ctxT(t, 120*time.Second)
	agent, err := client.New(ctx, client.Config{Role: vault.KindAgent, Name: "a-agent", RelayURL: r.URL, PollWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	pc := mustOK(t, a.request(a.app, "device.pair.create", `{"role":"agent"}`))
	link, _ := pc.String("link")
	pid, _ := pc.String("pairing_id")
	if _, err := agent.Pair(ctx, link); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, a.app, "device.pair.pending", has("pairing_id", pid))
	if _, err := a.app.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	mustOK(t, a.request(a.app, "device.pair.approve", `{"pairing_id":"`+pid+`","session_seconds":3600,"grants":[{"scope":"connection.list","approval":"auto"}]}`))
	if err := agent.AwaitPaired(ctx); err != nil {
		t.Fatal(err)
	}
	up := waitEvent(t, agent, "leash.grant.updated", nil)
	if !strings.Contains(string(up.Body), `"status_sig"`) {
		t.Fatalf("no status statement with the grants: %s", up.Body)
	}
	if len(agent.LeashGrants()) == 0 {
		t.Fatalf("grants: %s", up.Body)
	}
	gid := field(t, agent.LeashGrants()[0], "grant_id")
	cv, err := a.app.CredentialVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	memberKey, _ := cv.Base64("key", 32)

	// Offline verification with only the member's key.
	p1, err := agent.LeashPresent(ctx, gid)
	if err != nil {
		t.Fatal(err)
	}
	d1, err := leashwire.VerifyPresented(memberKey, p1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// 0.12.0 (LEASH §3.5): iss is the member's credential key, sub the
	// agent's ik, status_issuer the vault's ik; an auto grant carries its
	// limits; a fresh 16-byte nonce; JCS bytes.
	if string(d1.Iss) != string(memberKey) || string(d1.Sub) != string(agent.IdentityKey()) || d1.Scope.Op != "connection.list" ||
		d1.Approval != "auto" || d1.Limits == nil || d1.Limits.PerHour != 60 || d1.Limits.PerDay != 1000 || len(d1.Nonce) != leashwire.NonceSize {
		t.Fatalf("presented delegation: %+v", d1)
	}
	if _, err := leashwire.ParseCanonical(p1.Delegation); err != nil {
		t.Fatal("delegation not in JCS")
	}
	if _, err := leashwire.VerifyPresented(memberKey, &leashwire.Presented{Delegation: p1.Delegation, Sig: p1.Sig}, time.Now()); err == nil {
		t.Fatal("accepted without a status statement")
	}
	// Fresh enough: the cached statement is reused.
	p2, err := agent.LeashPresent(ctx, gid)
	if err != nil || string(p2.Status) != string(p1.Status) {
		t.Fatalf("cached statement: %v", err)
	}
	if _, err := leashwire.VerifyPresented(memberKey, p2, time.Now().Add(16*time.Minute)); err == nil {
		t.Fatal("statement outlived its ttl")
	}
	// An agent share rule (items.read) is presented the same way: the
	// delegation carries the rule's tags (§10.11).
	ro, err := a.app.ShareRuleSet(ctx, map[string]any{"subject": map[string]any{"agent_id": agent.DeviceID()}, "tags": []string{"travel"}})
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := ro.String("rule_id")
	waitEvent(t, agent, "leash.grant.updated", func(b json.RawMessage) bool { return strings.Contains(string(b), rid) })
	pr, err := agent.LeashPresent(ctx, rid)
	if err != nil {
		t.Fatal(err)
	}
	if d, err := leashwire.VerifyPresented(memberKey, pr, time.Now()); err != nil || d.Scope.Op != "items.read" || d.Scope.Tags[0] != "travel" ||
		d.Limits == nil {
		t.Fatalf("items.read presented: %+v %v", d, err)
	}
	// Revoked: no new statement. A 60 s statement is always within the
	// client's refresh margin, so it asks again and gets none; the old
	// statement lapses within its ttl.
	g1, err := a.app.LeashGrantIssue(ctx, agent.DeviceID(), map[string]any{"scope": "connection.list", "status_ttl": 60})
	if err != nil {
		t.Fatal(err)
	}
	short1, _ := g1.String("grant_id")
	waitEvent(t, agent, "leash.grant.updated", func(b json.RawMessage) bool { return strings.Contains(string(b), short1) })
	old, err := agent.LeashPresent(ctx, short1)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.app.LeashGrantRevoke(ctx, short1); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.LeashPresent(ctx, short1); client.Code(err) != "not_found" {
		t.Fatalf("refresh after revocation: %v", err)
	}
	if _, err := leashwire.VerifyPresented(memberKey, old, time.Now().Add(3*time.Minute)); err == nil {
		t.Fatal("revoked grant's statement still valid past its ttl")
	}

	// A locked vault issues nothing (fail closed).
	g, err := a.app.LeashGrantIssue(ctx, agent.DeviceID(), map[string]any{"scope": "connection.list"})
	if err != nil {
		t.Fatal(err)
	}
	gid2, _ := g.String("grant_id")
	if _, _, _, err := agent.LeashStatus(ctx, gid2); err != nil {
		t.Fatal(err)
	}
	if err := a.manager().Lock(ctx); err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, _, _, err := agent.LeashStatus(short, gid2); err == nil {
		t.Fatal("a locked vault issued a statement")
	}
}
