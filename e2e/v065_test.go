//go:build devenclave && e2e

package e2e

import (
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/relaytest"
)

// VAULT-MESSAGING 0.65.0 end to end (§10.4, §10.4.1): A challenges B's
// member to sign in; B's member says "Not me". A's next sign-in challenge
// is suppressed in B's vault (cooled for an hour, audited
// drop.ask_cooldown) and B's connection is not paused, while A's approval
// challenge still reaches B's member, who approves it: the result names
// the purpose the signature commits to.
func TestConnectionAuthenticatePurposeE2E(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 120*time.Second)
	aConn, bConn := connect(t, a, b, 600)

	rid, err := a.app.AuthRequestFor(ctx, aConn, "example.org, Firefox on Linux", "signin")
	if err != nil {
		t.Fatal(err)
	}
	pend := waitEvent(t, b.app, "connection.authenticate.pending", has("request_id", rid))
	if field(t, pend.Body, "purpose") != "signin" {
		t.Fatalf("pending: %s", pend.Body)
	}
	if err := b.app.AuthDeny(ctx, rid); err != nil {
		t.Fatal(err)
	}
	if res := waitEvent(t, a.app, "connection.authenticate.result", has("request_id", rid)); field(t, res.Body, "reason") != "denied" {
		t.Fatalf("result: %s", res.Body)
	}
	st, err := b.app.ConnectionAsks(ctx, bConn)
	if err != nil || st.Paused || st.Cooldowns != 1 {
		t.Fatalf("asks after a sign-in decline: %+v %v", st, err)
	}

	// Another sign-in: suppressed. Then an approval: it reaches the member
	// (it arrives after the sign-in, so the sign-in has been gated by then).
	rid2, err := a.app.AuthRequestFor(ctx, aConn, "example.org, Firefox on Linux", "signin")
	if err != nil {
		t.Fatal(err)
	}
	rid3, err := a.app.AuthRequestFor(ctx, aConn, "Open the vote on proposal 7", "approval")
	if err != nil {
		t.Fatal(err)
	}
	pend = waitEvent(t, b.app, "connection.authenticate.pending", has("request_id", rid3))
	if field(t, pend.Body, "purpose") != "approval" {
		t.Fatalf("pending: %s", pend.Body)
	}
	au, err := b.app.AuditList(ctx, map[string]any{"kinds": []string{"drop"}}, false)
	if err != nil || !strings.Contains(string(au["entries"]), `"drop.ask_cooldown"`) || !strings.Contains(string(au["entries"]), rid2) {
		t.Fatalf("the second sign-in was not suppressed: %s %v", au["entries"], err)
	}
	if _, err := b.app.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	if err := b.app.AuthApprove(ctx, rid3); err != nil {
		t.Fatal(err)
	}
	res := waitEvent(t, a.app, "connection.authenticate.result", has("request_id", rid3))
	if field(t, res.Body, "purpose") != "approval" || !strings.Contains(string(res.Body), `"authenticated":true`) {
		t.Fatalf("result: %s", res.Body)
	}
}
