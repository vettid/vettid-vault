//go:build devenclave && e2e

package e2e

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/vault"
)

// requestBoth runs an invitation from a to b until both members see the
// SAS; it returns a's pending_id and b's connection_id.
func requestBoth(t *testing.T, a, b *testVault) (pid, cid string) {
	t.Helper()
	inv := mustOK(t, a.request(a.app, "connection.invite.create", `{"ttl_seconds":600}`))
	link, _ := inv.String("link")
	acc := mustOK(t, b.request(b.app, "connection.invite.accept", `{"link":"`+link+`"}`))
	cid, _ = acc.String("connection_id")
	waitEvent(t, b.app, "connection.request.outgoing", has("connection_id", cid))
	pend := waitEvent(t, a.app, "connection.request.pending", nil)
	return field(t, pend.Body, "pending_id"), cid
}

func peerDeclined(idKey, id string) func(json.RawMessage) bool {
	return func(m json.RawMessage) bool {
		return has("kind", "connection.request")(m) && has("state", "peer_declined")(m) && has(idKey, id)(m)
	}
}

// VAULT-MESSAGING 0.10.5 (§6.4) through the real relay: a declined
// connection request is sent to the other party in both directions. The
// accepter whose request the inviter declines sees peer_declined and
// connection.event{failed, reason: declined}; the inviter whose accepter
// declines sees peer_declined. Both can then connect.
func TestConnectionDeclineSent(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)

	pid, cid := requestBoth(t, a, b)
	mustOK(t, a.request(a.app, "connection.decline", `{"pending_id":"`+pid+`"}`))
	waitEvent(t, b.app, "sync.event", peerDeclined("connection_id", cid))
	waitEvent(t, b.app, "connection.event", func(m json.RawMessage) bool {
		return has("event", "failed")(m) && has("reason", "declined")(m) && has("connection_id", cid)(m)
	})

	pid, cid = requestBoth(t, a, b) // exists no longer refers to the declined request
	mustOK(t, b.request(b.app, "connection.decline", `{"connection_id":"`+cid+`"}`))
	waitEvent(t, a.app, "sync.event", peerDeclined("pending_id", pid))
	lst := mustOK(t, a.request(a.app, "connection.request.list", `{}`))
	if string(lst["incoming"]) != "[]" {
		t.Fatalf("incoming after peer_declined: %s", lst["incoming"])
	}

	connect(t, a, b, 600)
}

// VAULT-MESSAGING 0.10.5 (§6.7): the owner's rejection after the new
// device's hs.fin is sent to it as device.pair.rejected; the Go client
// stops waiting with ErrPairRejected instead of waiting out 10 minutes.
func TestPairingRejectSent(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	ctx := ctxT(t, 60*time.Second)
	desk, err := client.New(ctx, client.Config{Role: vault.KindDesktop, Name: "a-desk", RelayURL: r.URL, PollWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	pc := mustOK(t, a.request(a.app, "device.pair.create", `{"role":"desktop"}`))
	link, _ := pc.String("link")
	pairingID, _ := pc.String("pairing_id")
	if _, err := desk.Pair(ctx, link); err != nil {
		t.Fatalf("pair: %v", err)
	}
	waitEvent(t, a.app, "device.pair.pending", has("pairing_id", pairingID))
	mustOK(t, a.request(a.app, "device.pair.reject", `{"pairing_id":"`+pairingID+`"}`))
	start := time.Now()
	if err := desk.AwaitPaired(ctxT(t, 30*time.Second)); !errors.Is(err, client.ErrPairRejected) {
		t.Fatalf("await paired after a rejection: %v", err)
	}
	if time.Since(start) > 20*time.Second {
		t.Fatal("the rejection took too long")
	}
	dl := mustOK(t, a.request(a.app, "device.list", `{}`))
	var devs []json.RawMessage
	_ = json.Unmarshal(dl["devices"], &devs)
	if len(devs) != 1 {
		t.Fatalf("devices after the rejection: %d", len(devs))
	}
}
