//go:build devenclave && e2e

package e2e

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/vault"
)

// ocClock is the owner check's injectable clock (vault.Options
// .OwnerCheckClock): moved forward while messages keep the real time.
type ocClock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *ocClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.off)
}

func (c *ocClock) add(d time.Duration) {
	c.mu.Lock()
	c.off += d
	c.mu.Unlock()
}

// §3.6 (0.13.0) through the real relay: past the deadline the vault is
// held: it still receives a connection's message (counted in vault.held,
// not delivered), refuses the app's other requests and the agent's
// (owner_check_required) and issues no status statement; a wrong PIN is a
// failed check; the check (PIN and password) ends the hold, the agent gets
// fresh status statements and the app reads the message.
func TestOwnerCheckHeldVault(t *testing.T) {
	r := relaytest.Start(t, nil)
	clk := &ocClock{}
	a := newTestVault(t, r.URL, "a", func(o *vault.Options) { o.OwnerCheckClock = clk.Now })
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 300*time.Second)
	aConn, bConn := connect(t, a, b, 600)

	// An agent with a session and a grant.
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
	waitEvent(t, agent, "leash.grant.updated", nil)
	gid := field(t, agent.LeashGrants()[0], "grant_id")
	st, err := a.app.OwnerCheckState(ctx)
	if err != nil || st.State != vault.OwnerCheckOK || st.Deadline.Before(time.Now().Add(23*time.Hour)) {
		t.Fatalf("before the deadline: %+v %v", st, err)
	}

	// Past the deadline: held from the next collect cycle on.
	clk.add(25 * time.Hour)
	held := waitEvent(t, a.app, "vault.held", nil)
	if !strings.Contains(string(held.Body), `"waiting":{"messages":0`) {
		t.Fatalf("vault.held %s", held.Body)
	}
	if r := a.request(a.app, "connection.list", `{}`); r.ErrorCode() != "owner_check_required" {
		t.Fatalf("app request while held: %q", r.ErrorCode())
	}
	if r := a.request(agent, "leash.status.get", `{"grant_id":"`+gid+`"}`); r.ErrorCode() != "owner_check_required" {
		t.Fatalf("agent while held: %q", r.ErrorCode())
	}
	if st, _ := a.app.OwnerCheckState(ctx); st == nil || st.State != vault.OwnerCheckHeld {
		t.Fatalf("status %+v", st)
	}
	// A connection's message is received and counted, not delivered.
	msgID := sendText(t, b, b.app, bConn, "while you were away")
	clk.add(11 * time.Minute) // vault.held at most every 10 minutes
	waitEvent(t, a.app, "vault.held", func(b json.RawMessage) bool {
		return strings.Contains(string(b), `"messages":1`)
	})
	for _, ev := range a.app.Events() {
		if ev.Type == "message.new" {
			t.Fatal("message delivered while held")
		}
	}
	// A wrong PIN is a failed check.
	if _, err := a.app.OwnerCheck(ctx, "111111", credPW, nil, nil); client.Code(err) != "bad_pin" {
		t.Fatalf("wrong PIN: %v", err)
	}
	if st, _ := a.app.OwnerCheckState(ctx); st == nil || st.Failures != 1 {
		t.Fatalf("failures %+v", st)
	}
	// The check ends the hold.
	res, err := a.app.OwnerCheck(ctx, pin, credPW, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Hold || res.Deadline.Before(clk.Now().Add(23*time.Hour)) || res.Interval != 24*time.Hour {
		t.Fatalf("check result %+v", res)
	}
	up := waitEvent(t, agent, "leash.grant.updated", nil)
	if !strings.Contains(string(up.Body), `"status_sig"`) {
		t.Fatalf("agent not resumed: %s", up.Body)
	}
	if r := a.request(agent, "leash.status.get", `{"grant_id":"`+gid+`"}`); !r.OK() {
		t.Fatalf("agent after the check: %q", r.ErrorCode())
	}
	list := mustOK(t, a.request(a.app, "message.list", `{"connection_id":"`+aConn+`"}`))
	if raw, _ := json.Marshal(list); !strings.Contains(string(raw), msgID) {
		t.Fatalf("message not kept while held: %s", raw)
	}
	if st, _ := a.app.OwnerCheckState(ctx); st == nil || st.State != vault.OwnerCheckOK || st.Failures != 0 {
		t.Fatalf("after the check %+v", st)
	}
}

// 0.35.0 (§3.6.3, §10.16): while the vault is held the member can still
// end a location share (as they can lock): location.share.stop is on the
// hold's allow list, starting a share is not, and the connection learns
// that the share stopped.
func TestOwnerCheckHeldStopsLocationShare(t *testing.T) {
	r := relaytest.Start(t, nil)
	clk := &ocClock{}
	a := newTestVault(t, r.URL, "a", func(o *vault.Options) { o.OwnerCheckClock = clk.Now })
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 180*time.Second)
	aConn, bConn := connect(t, a, b, 600)

	sid, _, err := a.app.LocationShareStart(ctx, client.LocationShare{ConnectionID: aConn, Mode: "continuous", Precision: "approximate",
		Duration: 3600, Interval: 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.app.LocationEvent(ctx, bConn, "started"); err != nil {
		t.Fatal(err)
	}
	clk.add(25 * time.Hour)
	waitEvent(t, a.app, "vault.held", nil)
	if _, _, err := a.app.LocationShareStart(ctx, client.LocationShare{ConnectionID: aConn, Mode: "once", Precision: "approximate", Duration: 600}); client.Code(err) != "owner_check_required" {
		t.Fatalf("share start while held: %v", err)
	}
	if err := a.app.LocationShareStop(ctx, sid); err != nil {
		t.Fatalf("share stop while held: %v", err)
	}
	if _, err := b.app.LocationEvent(ctx, bConn, "stopped"); err != nil {
		t.Fatal(err)
	}
}

// §3.6.3, §10.16 (0.35.0) through the real relay: while the vault is
// held, the location feature's sync events are withheld from the owner's
// other devices. The app stops a share (allowed while held); the
// connection learns of it, the paired desktop gets no
// sync.event{location.share.changed} for it. Before the hold the same
// event reaches the desktop.
func TestOwnerCheckHeldWithholdsLocationSyncEvents(t *testing.T) {
	r := relaytest.Start(t, nil)
	clk := &ocClock{}
	a := newTestVault(t, r.URL, "a", func(o *vault.Options) { o.OwnerCheckClock = clk.Now })
	b := newTestVault(t, r.URL, "b", nil)
	desk := pairDesktop(t, a, r.URL)
	ctx := ctxT(t, 180*time.Second)
	aConn, bConn := connect(t, a, b, 600)

	start := func() string {
		t.Helper()
		sid, _, err := a.app.LocationShareStart(ctx, client.LocationShare{ConnectionID: aConn, Mode: "continuous", Precision: "approximate",
			Duration: 3600, Interval: 10})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.app.LocationEvent(ctx, bConn, "started"); err != nil {
			t.Fatal(err)
		}
		return sid
	}
	changed := func(sid, state string) func(json.RawMessage) bool {
		return func(body json.RawMessage) bool {
			return syncKind("location.share.changed")(body) && has("share_id", sid)(body) && has("state", state)(body)
		}
	}
	// Before the hold the desktop sees the share start.
	sid := start()
	waitEvent(t, desk, "sync.event", changed(sid, "active"))

	clk.add(25 * time.Hour)
	waitEvent(t, a.app, "vault.held", nil)
	if err := a.app.LocationShareStop(ctx, sid); err != nil {
		t.Fatalf("stop while held: %v", err)
	}
	if _, err := b.app.LocationEvent(ctx, bConn, "stopped"); err != nil {
		t.Fatal(err)
	}
	// The desktop collects for a while past the stop and must not see it.
	if _, err := desk.WaitEvent(ctxT(t, 5*time.Second), "sync.event", changed(sid, "ended")); err == nil {
		t.Fatal("location.share.changed reached the desktop while held")
	}
	for _, ev := range desk.Events() {
		if ev.Type == "location.event" {
			t.Fatal("location.event reached the desktop while held")
		}
	}
}
