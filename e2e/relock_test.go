//go:build devenclave && e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/vault"
)

// TestUnlockAfterAgentRequestsWhileLocked is the staging case of a vault
// that ended itself 1.5 s after an unlock: an agent with an access session
// sent requests while the vault was locked; the vault is unlocked with the
// PIN only and must stay up and answer them.
func TestUnlockAfterAgentRequestsWhileLocked(t *testing.T) {
	// The check ok, held, and past the idle lock's time (staging's scale).
	for _, c := range []struct {
		scale uint64
		ahead time.Duration
	}{{1, 0}, {24, 36 * time.Hour}, {24, 9 * 24 * time.Hour}} {
		t.Run(fmt.Sprintf("scale%d/%s", c.scale, c.ahead), func(t *testing.T) { unlockAfterAgentRequests(t, c.scale, c.ahead) })
	}
}

// unlockAfterAgentRequests runs the case with the owner check's clock moved
// ahead by ahead before the lock: past the deadline (held), past the idle
// lock's time.
func unlockAfterAgentRequests(t *testing.T, scale uint64, ahead time.Duration) {
	rl := relaytest.Start(t, nil)
	r := rl.URL
	var off atomic.Int64
	a := newTestVault(t, r, "a", func(o *vault.Options) {
		o.OwnerCheckClock = func() time.Time { return time.Now().Add(time.Duration(off.Load())) }
		o.TimeScale = scale
	})
	ctx := ctxT(t, 120*time.Second)
	agent, err := client.New(ctx, client.Config{Role: vault.KindAgent, Name: "a-agent", RelayURL: r, PollWait: time.Second})
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
	// As on the phone: paired with no access, then the agent's own request
	// for an access session, approved in Approvals.
	mustOK(t, a.request(a.app, "device.pair.approve", `{"pairing_id":"`+pid+`"}`))
	if err := agent.AwaitPaired(ctx); err != nil {
		t.Fatal(err)
	}
	reqID, err := agent.SessionRequest(ctx, 3600)
	if err != nil {
		t.Fatal(err)
	}
	waitEvent(t, a.app, "device.session.pending", has("request_id", reqID))
	if _, err := a.app.SessionApprove(ctx, reqID, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.AgentRequest(ctxT(t, 20*time.Second), "catalog", nil); err != nil {
		t.Fatalf("before the lock: %v", err)
	}

	off.Store(int64(ahead))
	if err := a.manager().Lock(ctx); err != nil {
		t.Fatal(err)
	}
	a.stop()
	// While locked: a request the vault will find when it opens, sent
	// again with the same inner id (an application retry, §8.6), as the
	// connector does.
	body := json.RawMessage(`{"op":"catalog"}`)
	id, err := agent.Send(ctx, "agent.request", body)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	if _, err := agent.SendWithID(ctx, id, "agent.request", body); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)

	m, f, err := a.unlock(ctx, nil)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	a.mu.Lock()
	a.msg = f
	a.mu.Unlock()
	a.start(m)
	time.Sleep(5 * time.Second)
	if m.Locked() {
		t.Fatal("the vault locked itself after the unlock")
	}
	if _, err := agent.AgentRequest(ctxT(t, 30*time.Second), "catalog", nil); err != nil {
		t.Fatalf("after the unlock: %v", err)
	}
	if r := a.request(a.app, "vault.status", `{}`); !r.OK() && r.ErrorCode() != "owner_check_required" {
		t.Fatalf("vault.status: %s", r.ErrorCode())
	}
}
