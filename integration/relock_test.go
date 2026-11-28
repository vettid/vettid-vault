//go:build devenclave && integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/parent"
	"github.com/vettid/vettid-vault/vault"
)

// The staging case of a vault that ended itself 1.5 s after an unlock
// (VAULT-MESSAGING §11.5, §12.3): an agent with an access session, the
// app's bound lock, requests from the agent while locked, then the app's
// unlock, which starts a second vault process in the same enclave. The
// vault must stay up and answer.
func TestUnlockAfterAnAgentsRequestsWhileLocked(t *testing.T) {
	s := newStack(t)
	a := s.start("a", 3)
	ctx := ctxT(t, 8*time.Minute)
	app, err := client.New(ctx, client.Config{Role: vault.KindApp, Name: "phone", RelayURL: relayURL, HTTP: s.appHTTP, PollWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	portal := &client.MemberAPI{Base: s.api.URL, Authorize: bearer("member-r")}
	code, err := portal.IssueEnrollCode(ctx)
	if err != nil {
		t.Fatal(err)
	}
	api, err := app.APIFor(s.api.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	red, err := app.RedeemVia(ctx, api, "", "member-r@example.org", code.Code)
	if err != nil {
		t.Fatal(err)
	}
	att := enclavetest.NewAndroidAttester(0x63, enclavetest.AndroidOptions{})
	trust := s.w.Trust()
	vid, er, err := app.EnrollVia(ctx, api, red.UserGUID, "246802", trust, att)
	if err != nil || !er.OK {
		t.Fatalf("enroll: %v %+v", err, er)
	}
	if err := app.AwaitEnrolled(ctx); err != nil {
		t.Fatal(err)
	}
	if err := app.CompleteEnrollment(ctx); err != nil {
		t.Fatal(err)
	}
	if err := app.CredentialCreate(ctx, "246802", "member r password"); err != nil {
		t.Fatal(err)
	}
	mustOK(t, req(t, app, "vault.enroll.confirm", `{}`))

	// An agent, paired with no access, then given a session in Approvals.
	agent, err := client.New(ctx, client.Config{Role: vault.KindAgent, Name: "agent", RelayURL: relayURL, HTTP: s.appHTTP, PollWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	pc := mustOK(t, req(t, app, "device.pair.create", `{"role":"agent"}`))
	link, _ := pc.String("link")
	pid, _ := pc.String("pairing_id")
	if _, err := agent.Pair(ctx, link); err != nil {
		t.Fatal(err)
	}
	if _, err := app.WaitEvent(ctx, "device.pair.pending", nil); err != nil {
		t.Fatal(err)
	}
	mustOK(t, req(t, app, "device.pair.approve", `{"pairing_id":"`+pid+`"}`))
	if err := agent.AwaitPaired(ctx); err != nil {
		t.Fatal(err)
	}
	rid, err := agent.SessionRequest(ctx, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.WaitEvent(ctx, "device.session.pending", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := app.SessionApprove(ctx, rid, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.AgentRequest(ctxT(t, 30*time.Second), "catalog", nil); err != nil {
		t.Fatalf("before the lock: %v", err)
	}

	// The app's lock, bound to its unlock; the agent asks while locked.
	if sl, err := app.LockVia(ctx, api); err != nil || sl.Status != "done" {
		t.Fatalf("lock: %v %+v", err, sl)
	}
	a.waitHealth(func(h parent.Health) bool { return h.Vaults == 0 }, "with the vault locked")
	for range 2 {
		go func() {
			short, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			_, _ = agent.AgentRequest(short, "catalog", nil)
		}()
	}
	time.Sleep(6 * time.Second)

	if u, err := app.UnlockVia(ctx, api, red.UserGUID, "246802", trust, att, client.UnlockOptions{}, ""); err != nil || !u.OK {
		t.Fatalf("unlock: %v %+v", err, u)
	}
	time.Sleep(5 * time.Second)
	if r := s.vaultRow(vid); r.State != "unlocked" {
		t.Fatalf("the vault ended itself after the unlock: %+v", r)
	}
	if _, err := agent.AgentRequest(ctxT(t, 30*time.Second), "catalog", nil); err != nil {
		t.Fatalf("after the unlock: %v", err)
	}
	mustOK(t, req(t, app, "vault.status", `{}`))
}
