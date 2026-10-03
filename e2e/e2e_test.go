//go:build devenclave && e2e

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/vault"
)

// V2 exit: pair an app (enrollment) and a desktop (§6.7), connect two
// vaults by remote invite (open token + claim, §6.4), and exchange messages
// both ways, with fan-out to the owner's other device and receipts.
func TestPairConnectMessage(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", func(o *vault.Options) { o.WebSocket = true }) // §12.2 WebSocket collect

	// Pair a desktop to vault A from A's app.
	ctx := ctxT(t, 60*time.Second)
	desk, err := client.New(ctx, client.Config{Role: vault.KindDesktop, Name: "a-desk", RelayURL: r.URL, PollWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	pc := mustOK(t, a.request(a.app, "device.pair.create", `{"role":"desktop"}`))
	link, _ := pc.String("link")
	pairingID, _ := pc.String("pairing_id")
	sas, err := desk.Pair(ctx, link)
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	pend := waitEvent(t, a.app, "device.pair.pending", has("pairing_id", pairingID))
	if field(t, pend.Body, "sas") != sas {
		t.Fatal("SAS differs between the new device and the approving app")
	}
	if field(t, pend.Body, "name") != "a-desk" {
		t.Fatal("pending name")
	}
	// The approval grants the desktop its first access session (§6.8).
	mustOK(t, a.request(a.app, "device.pair.approve", `{"pairing_id":"`+pairingID+`","session_seconds":3600}`))
	if err := desk.AwaitPaired(ctx); err != nil {
		t.Fatalf("await paired: %v", err)
	}
	dl := mustOK(t, a.request(desk, "device.list", `{}`))
	var devs []json.RawMessage
	_ = json.Unmarshal(dl["devices"], &devs)
	if len(devs) != 2 {
		t.Fatalf("devices: %d", len(devs))
	}

	// A desktop may not approve pairings (§6.7: apps approve).
	if rr := a.request(desk, "device.pair.create", `{"role":"agent"}`); rr.OK() || rr.ErrorCode() != "forbidden" {
		t.Fatalf("desktop created a pairing: %v", rr.ErrorCode())
	}

	// Connect A and B by a remote (1 h) invite.
	aConn, bConn := connect(t, a, b, 3600)

	// A → B.
	id1 := sendText(t, a, a.app, aConn, "hello from A")
	in := waitEvent(t, b.app, "message.new", has("message_id", id1))
	if field(t, in.Body, "text") != "hello from A" || field(t, in.Body, "direction") != "in" {
		t.Fatalf("B got %s", in.Body)
	}
	// Fan-out: A's desktop sees the side effect of the app's send (§9.1).
	waitEvent(t, desk, "message.new", has("message_id", id1))
	// Delivered receipt back at A.
	waitEvent(t, a.app, "sync.event", has("message_id", id1))

	// B → A.
	id2 := sendText(t, b, b.app, bConn, "hello from B")
	waitEvent(t, a.app, "message.new", has("message_id", id2))
	waitEvent(t, desk, "message.new", has("message_id", id2))
	// Read receipt.
	mustOK(t, a.request(a.app, "message.read", `{"connection_id":"`+aConn+`","message_id":"`+id2+`"}`))
	waitEvent(t, b.app, "sync.event", func(b json.RawMessage) bool { return has("receipt", "read")(b) })

	lst := mustOK(t, b.request(b.app, "message.list", `{"connection_id":"`+bConn+`"}`))
	var msgs []json.RawMessage
	_ = json.Unmarshal(lst["messages"], &msgs)
	if len(msgs) != 2 {
		t.Fatalf("B history: %d", len(msgs))
	}
}

// V2 exit: revoke a connection and see the peer's deposit rejected. A's
// best-effort connection.removed notice is dropped (fault injection), so B
// keeps sending; the relay refuses B's deposit (token_revoked, §8.6) and B
// marks the connection stale.
func TestRevokeConnection(t *testing.T) {
	r := relaytest.Start(t, nil)
	var dropNotices atomic.Bool
	a := newTestVault(t, r.URL, "a", func(o *vault.Options) {
		o.Hooks.DropDeposit = func(e *vault.OutboxEntry) bool { return e.BestEffort && dropNotices.Load() }
	})
	b := newTestVault(t, r.URL, "b", nil)
	aConn, bConn := connect(t, a, b, 600)
	id := sendText(t, b, b.app, bConn, "before")
	waitEvent(t, a.app, "message.new", has("message_id", id))

	dropNotices.Store(true)
	mustOK(t, a.request(a.app, "connection.remove", `{"connection_id":"`+aConn+`"}`))
	waitEvent(t, a.app, "connection.event", has("event", "removed"))

	// B still thinks it is connected; its deposit is refused by the relay.
	sendText(t, b, b.app, bConn, "after removal")
	waitEvent(t, b.app, "connection.event", has("event", "stale"))
	if l := mustOK(t, a.request(a.app, "connection.list", `{}`)); string(l["connections"]) != "[]" {
		t.Fatalf("A still lists connections: %s", l["connections"])
	}
	// Nothing from B arrived at A after removal.
	for _, ev := range a.app.Events() {
		if ev.Type == "message.new" && has("text", "after removal")(ev.Body) {
			t.Fatal("removed peer's message delivered")
		}
	}
}

// V2 exit: kill and restart a vault (reload from the store) and see
// redelivery deduped. The vault crashes after its flush and before its
// acks (§8.3 "between steps 3 and 4"); the relay redelivers the batch after
// the visibility timeout and the new instance dedupes it by msg_id. A
// retransmission with the same inner id gets the cached response (§8.2).
func TestRestartDedupe(t *testing.T) {
	r := relaytest.Start(t, nil)
	var crashOnce atomic.Bool
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	aConn, _ := connect(t, a, b, 600)

	// Restart A with a crash hook armed.
	a.stop()
	a.manager().Crash()
	m, f, err := a.unlock(ctxT(t, 30*time.Second), func(o *vault.Options) {
		o.Hooks.AfterFlush = func() error {
			if crashOnce.CompareAndSwap(true, false) {
				return errors.New("crash")
			}
			return nil
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.msg = f
	a.mu.Unlock()
	a.start(m)

	crashOnce.Store(true)
	body, _ := json.Marshal(map[string]string{"connection_id": aConn, "text": "once"})
	reqID, err := a.app.Send(ctxT(t, 10*time.Second), "message.send", body)
	if err != nil {
		t.Fatal(err)
	}
	// The crash zeroized the manager: Run returns; reload from the store.
	select {
	case err := <-a.done:
		if !errors.Is(err, vault.ErrCrash) {
			t.Fatalf("run ended with %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("no crash")
	}
	a.restart()

	resp, err := a.app.AwaitResponse(ctxT(t, 30*time.Second), reqID)
	if err != nil || !resp.OK() {
		t.Fatalf("response: %v", err)
	}
	msgID := field(t, resp.Body(), "message_id")
	waitEvent(t, b.app, "message.new", has("message_id", msgID))

	// Retransmission with the same inner id: same answer, no second send.
	if _, err := a.app.SendWithID(ctxT(t, 10*time.Second), reqID, "message.send", body); err != nil {
		t.Fatal(err)
	}
	resp2, err := a.app.AwaitResponse(ctxT(t, 30*time.Second), reqID)
	if err != nil || field(t, resp2.Body(), "message_id") != msgID {
		t.Fatalf("retransmission: %v", err)
	}
	time.Sleep(3 * time.Second) // past the relay visibility timeout
	_ = b.app.Events()
	extra := 0
	for _, ev := range a.app.Events() {
		if ev.Re == reqID {
			extra++ // a third response would mean re-execution
		}
	}
	if extra != 0 {
		t.Fatalf("%d extra responses", extra)
	}
	if n := len(a.msg.Conversation(aConn)); n != 1 {
		t.Fatalf("A history has %d messages, want 1", n)
	}
	l := mustOK(t, b.request(b.app, "message.list", `{"connection_id":"`+connOf(t, b)+`"}`))
	var msgs []json.RawMessage
	_ = json.Unmarshal(l["messages"], &msgs)
	if len(msgs) != 1 {
		t.Fatalf("B received %d messages, want 1", len(msgs))
	}
}

func connOf(t *testing.T, tv *testVault) string {
	l := mustOK(t, tv.request(tv.app, "connection.list", `{}`))
	var cs []json.RawMessage
	_ = json.Unmarshal(l["connections"], &cs)
	if len(cs) != 1 {
		t.Fatalf("%d connections", len(cs))
	}
	return field(t, cs[0], "id")
}

// V2 exit: the split-brain guard locks a second writer (§12.3). Two
// instances hold the same vault; after the first flushes, the second's
// conditional write finds a newer version and it zeroizes at once,
// without acking, so the message is redelivered to the first.
func TestSplitBrainLocksSecondWriter(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	a.stop()
	ctx := ctxT(t, 60*time.Second)

	second, _, err := a.unlock(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := a.manager()
	// The first instance processes a request and flushes.
	id, err := a.app.Send(ctx, "vault.status", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	for {
		n, err := first.Step(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			break
		}
	}
	if _, err := a.app.AwaitResponse(ctx, id); err != nil {
		t.Fatal(err)
	}
	// The stale second instance gets the next message and must lock.
	id2, err := a.app.Send(ctx, "vault.status", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	for !second.Locked() {
		_, err := second.Step(ctx)
		if errors.Is(err, vault.ErrSplitBrain) || errors.Is(err, vault.ErrLocked) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !second.Locked() {
		t.Fatal("second writer not locked")
	}
	// Not acked: redelivered to the first instance after the visibility
	// timeout.
	a.start(first)
	if _, err := a.app.AwaitResponse(ctx, id2); err != nil {
		t.Fatalf("redelivery to the first writer: %v", err)
	}
}

// Lock and unlock (§12.3, §13.2, §11.8): the owner locks, devices get
// vault.locking; a wrong PIN is refused and counted; a rollback minimum is
// enforced; the right PIN unlocks with state intact.
func TestLockUnlockRollback(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	mustOK(t, a.request(a.app, "vault.lock", `{}`))
	ev := waitEvent(t, a.app, "vault.locking", nil)
	if ev.Exp.IsZero() {
		t.Fatal("vault.locking without exp")
	}
	select {
	case <-a.done:
	case <-time.After(30 * time.Second):
		t.Fatal("still running")
	}
	ctx := ctxT(t, 60*time.Second)
	o := a.opts
	_, res, err := vault.Unlock(ctx, vault.UnlockParams{Options: o, VaultID: a.vaultID, PIN: "000000"})
	if !errors.Is(err, vault.ErrBadPIN) {
		t.Fatalf("bad PIN: %v", err)
	}
	_, res2, err := vault.Unlock(ctx, vault.UnlockParams{Options: o, VaultID: a.vaultID, PIN: pin, MinStateSeq: 1 << 40})
	if !errors.Is(err, vault.ErrRollback) || res2.HeaderSeq != res.HeaderSeq {
		t.Fatalf("rollback: %v", err)
	}
	m, f, err := a.unlock(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	a.msg = f
	a.start(m)
	st := mustOK(t, a.request(a.app, "vault.status", `{}`))
	if p, _ := st.Bool("provisional"); p {
		t.Fatal("provisional after confirm")
	}
}

// Reconnect (§6.6): B's standing token for A expires while B is locked; on
// unlock B reconnects with its reconnect token, and messages flow again.
// (relayclient backdates iat by 60 s, so the shortest useful TTL is ~65 s.)
func TestReconnectAfterExpiry(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", func(o *vault.Options) { o.ConnectionStandingTTL = 65 * time.Second })
	b := newTestVault(t, r.URL, "b", nil)
	_, bConn := connect(t, a, b, 600)
	b.stop()
	b.manager().Crash()
	time.Sleep(6 * time.Second) // 65 s TTL minus the 60 s backdate, plus margin
	m, f, err := b.unlock(ctxT(t, 30*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	b.msg = f
	b.start(m)
	waitEvent(t, b.app, "connection.event", has("event", "reconnected"))
	waitEvent(t, a.app, "connection.event", has("event", "reconnected"))
	id := sendText(t, b, b.app, bConn, "after reconnect")
	waitEvent(t, a.app, "message.new", has("message_id", id))
}

var _ = context.Background
