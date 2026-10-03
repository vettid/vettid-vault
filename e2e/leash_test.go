//go:build devenclave && e2e

package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/vault"
)

// V4 batch 3, LEASH (§6.7, §6.8, §10.11) through the real relay: an
// agent paired with initial grants reads the catalog and a named secret
// without approval (auto), has a profile read referred to the app and
// approved, and is refused what no grant covers; revoking a grant stops it
// at once; a grant signed with the credential key verifies under the
// member's key; unlinking the agent revokes everything.
func TestLeashAgent(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	ctx := ctxT(t, 180*time.Second)

	wifi, _, err := a.app.SecretPut(ctx, "", 0, "wifi", "hunter22", map[string]any{"discoverability": "cataloged"})
	if err != nil {
		t.Fatal(err)
	}
	bank, _, err := a.app.SecretPut(ctx, "", 0, "bank", "s3cret", nil) // private
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.app.ProfileSet(ctx, map[string]any{"version": 0, "name": "Ada"}); err != nil {
		t.Fatal(err)
	}

	// Pairing with initial grants and a first access session (§6.7).
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
	grants := `[{"scope":"secrets.catalog","approval":"auto"},` +
		`{"scope":"secrets.get","approval":"auto","secrets":["` + wifi + `","` + bank + `"]},` +
		`{"scope":"profile.get"}]`
	approve := `{"pairing_id":"` + pid + `","session_seconds":600,"grants":` + grants + `}`
	// Every grant is a delegation signed by the member's credential key:
	// the app must open the unlock window first (§10.11).
	if rr := a.request(a.app, "device.pair.approve", approve); rr.ErrorCode() != "credential_locked" {
		t.Fatalf("pairing grants outside the unlock window: %q", rr.ErrorCode())
	}
	if _, err := a.app.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	mustOK(t, a.request(a.app, "device.pair.approve", approve))
	if err := agent.AwaitPaired(ctx); err != nil {
		t.Fatal(err)
	}
	up := waitEvent(t, agent, "leash.grant.updated", nil)
	if n := strings.Count(string(up.Body), `"grant_id"`); n != 3 {
		t.Fatalf("initial grants: %s", up.Body)
	}
	// The agent holds each grant as a delegation it can present: signed by
	// the member's credential key, for its own identity key.
	cv, err := a.app.CredentialVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	memberKey, _ := cv.Base64("key", 32)
	for _, g := range agent.LeashGrants() {
		d, err := client.VerifyDelegation(g, memberKey, time.Now())
		if err != nil || string(d.AgentIK) != string(agent.IdentityKey()) {
			t.Fatalf("delegation: %v", err)
		}
	}
	waitEvent(t, a.app, "sync.event", syncKind("leash.grant.changed"))

	// Allowed without approval (auto grants).
	cat, err := agent.AgentRequest(ctx, "catalog", nil)
	if err != nil || !cat.OK() || !strings.Contains(string(cat.Body()), wifi) || strings.Contains(string(cat.Body()), bank) {
		t.Fatalf("catalog: %v %s", err, cat.Body())
	}
	get, err := agent.AgentRequest(ctx, "secret.get", map[string]any{"secret_id": wifi})
	if err != nil || !get.OK() || !strings.Contains(string(get.Body()), `"value":"hunter22"`) {
		t.Fatalf("secret.get: %v %+v", err, get)
	}
	// A private secret is not found, even when the grant names it.
	if pr, err := agent.AgentRequest(ctx, "secret.get", map[string]any{"secret_id": bank}); err != nil || pr.ErrorCode() != "not_found" {
		t.Fatalf("private secret: %v %q", err, pr.ErrorCode())
	}

	// Referred to the app (an ask grant), approved, then answered.
	type res struct {
		r   *client.Response
		err error
	}
	done := make(chan res, 1)
	go func() {
		rr, err := agent.Request(ctxT(t, 60*time.Second), "profile.get", json.RawMessage(`{}`))
		done <- res{rr, err}
	}()
	ap := waitEvent(t, a.app, "approval.pending", has("type", "profile.get"))
	if field(t, ap.Body, "role") != vault.KindAgent || field(t, ap.Body, "device_id") != agent.DeviceID() {
		t.Fatalf("approval.pending: %s", ap.Body)
	}
	if result, err := a.app.ApprovalDecide(ctx, field(t, ap.Body, "approval_id"), true); err != nil || result != "ok" {
		t.Fatalf("decide: %q %v", result, err)
	}
	got := <-done
	if got.err != nil || !got.r.OK() || !strings.Contains(string(got.r.Body()), `"name":"Ada"`) {
		t.Fatalf("referred profile.get: %v %+v", got.err, got.r)
	}

	// Refused: no grant covers these.
	if rr := a.request(agent, "settings.get", `{}`); rr.ErrorCode() != "forbidden" {
		t.Fatalf("settings.get: %q", rr.ErrorCode())
	}
	if rr, err := agent.AgentRequest(ctx, "secret.use", map[string]any{"secret_id": wifi, "action": "hmac-sha256", "data": "aGk="}); err != nil || rr.ErrorCode() != "forbidden" {
		t.Fatalf("secret.use without a grant: %v %q", err, rr.ErrorCode())
	}
	if rr := a.request(agent, "leash.grant.issue", `{"agent_id":"`+agent.DeviceID()+`","scope":"secrets.use"}`); rr.ErrorCode() != "forbidden" {
		t.Fatalf("agent issued itself a grant: %q", rr.ErrorCode())
	}

	// Revoking the secrets.get grant stops it at once.
	list, err := a.app.LeashGrantList(ctx, agent.DeviceID())
	if err != nil {
		t.Fatal(err)
	}
	var getGrant string
	for _, g := range list {
		if strings.Contains(string(g), `"scope":"secrets.get"`) {
			getGrant = field(t, g, "grant_id")
		}
	}
	if err := a.app.LeashGrantRevoke(ctx, getGrant); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, agent, "leash.grant.updated", func(b json.RawMessage) bool { return !strings.Contains(string(b), getGrant) })
	if rr, err := agent.AgentRequest(ctx, "secret.get", map[string]any{"secret_id": wifi}); err != nil || rr.ErrorCode() != "forbidden" {
		t.Fatalf("after revoke: %v %q", err, rr.ErrorCode())
	}

	// Issuing needs the credential's unlock window (the phone present).
	if err := a.app.CredentialLock(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := a.app.LeashGrantIssue(ctx, agent.DeviceID(), map[string]any{"scope": "secrets.use", "approval": "auto"}); client.Code(err) != "credential_locked" {
		t.Fatalf("issued outside the window: %v", err)
	}
	if _, err := a.app.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	g, err := a.app.LeashGrantIssue(ctx, agent.DeviceID(), map[string]any{"scope": "secrets.use", "approval": "auto"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]json.RawMessage(g))
	d, err := client.VerifyDelegation(raw, memberKey, time.Now())
	if err != nil || d.Scope != "secrets.use" || string(d.AgentIK) != string(agent.IdentityKey()) {
		t.Fatalf("delegation: %v %+v", err, d)
	}
	waitEvent(t, agent, "leash.grant.updated", func(b json.RawMessage) bool { return strings.Contains(string(b), `"delegation"`) })
	use, err := agent.AgentRequest(ctx, "secret.use", map[string]any{"secret_id": wifi, "action": "hmac-sha256", "data": "aGk="})
	if err != nil || !use.OK() || strings.Contains(string(use.Body()), "hunter22") {
		t.Fatalf("secret.use: %v %+v", err, use)
	}

	// Spam after refusals: the agent hammers a type no grant covers; it
	// is throttled and, past the limit, suspended until an app resumes it.
	for i := 0; i < 40; i++ {
		if rr := a.request(agent, "settings.get", `{}`); rr.ErrorCode() != "forbidden" {
			t.Fatalf("hammer %d: %q", i, rr.ErrorCode())
		}
	}
	waitEvent(t, agent, "leash.grant.updated", func(b json.RawMessage) bool { return strings.Contains(string(b), `"suspended":true`) })
	waitEvent(t, a.app, "sync.event", syncKind("leash.agent.suspended"))
	if rr, err := agent.AgentRequest(ctx, "secret.use", map[string]any{"secret_id": wifi, "action": "hmac-sha256", "data": "aGk="}); err != nil || rr.ErrorCode() != "forbidden" {
		t.Fatalf("suspended agent: %v %q", err, rr.ErrorCode())
	}
	mustOK(t, a.request(a.app, "leash.agent.resume", `{"agent_id":"`+agent.DeviceID()+`"}`))
	waitEvent(t, agent, "leash.grant.updated", func(b json.RawMessage) bool { return strings.Contains(string(b), `"suspended":false`) })
	if rr, err := agent.AgentRequest(ctx, "secret.use", map[string]any{"secret_id": wifi, "action": "hmac-sha256", "data": "aGk="}); err != nil || !rr.OK() {
		t.Fatalf("after resume: %v %+v", err, rr)
	}

	// Audit (§10.9): refusals and throttling summarised, not one entry each.
	au, err := a.app.AuditList(ctx, map[string]any{"kinds": []string{"leash", "approval"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(au["entries"]), `"kind":"leash.refused"`); n > 3 {
		t.Errorf("%d single refusal entries", n)
	}
	for _, k := range []string{"leash.grant.issued", "leash.allowed", "leash.secret.read", "leash.secret.used", "leash.grant.revoked",
		"leash.refused", "leash.agent.suspended", "leash.agent.resumed", "leash.throttled.summary", "approval.granted"} {
		if !strings.Contains(string(au["entries"]), `"`+k+`"`) {
			t.Errorf("audit lacks %s", k)
		}
	}

	// Unlinking revokes every grant (§7.4).
	mustOK(t, a.request(a.app, "device.unlink", `{"device_id":"`+agent.DeviceID()+`"}`))
	o := mustOK(t, a.request(a.app, "leash.grant.list", `{}`))
	if gs, _ := o.Array("grants"); len(gs) != 0 {
		t.Fatalf("grants after unlink: %d", len(gs))
	}
}
