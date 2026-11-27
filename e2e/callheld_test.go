//go:build devenclave && e2e

package e2e

import (
	"context"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/callswire"
	"github.com/vettid/vettid-vault/vms/callwire"
)

// turnIssuer is a calling service that hands out TURN credentials.
type turnIssuer struct {
	name  string
	asked atomic.Int32
	n     atomic.Int32
}

func (is *turnIssuer) Credentials(_ context.Context, count int) (*callswire.Answer, error) {
	is.asked.Add(1)
	a := &callswire.Answer{STUN: []string{"stun:stun.example:3478"}, TURN: []string{"turn:turn.example:3478"}}
	exp := time.Now().Add(6 * time.Hour).UTC().Truncate(time.Second)
	for range count {
		a.Credentials = append(a.Credentials, callswire.Credential{
			Username: is.name + "-u" + strconv.Itoa(int(is.n.Add(1))), Credential: "TURN-SECRET", Exp: exp})
	}
	return a, nil
}

// primed waits until the issuer answered at unlock and the pool has had time to keep the credentials.
func (is *turnIssuer) primed(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for is.asked.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the pool never asked the issuer")
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
}

func hasTURNEntry(c *callwire.ICEConfig) bool {
	for _, sv := range c.Servers {
		if sv.Username != "" && sv.Credential == "TURN-SECRET" {
			return true
		}
	}
	return false
}

// VAULT-MESSAGING 0.97.0 §10.10 through the Manager, the real calls feature and the real relay: the caller's
// call.start answer and the callee's offer, both held in memory (never in the stored outbox), arrive with their
// TURN entry.
func TestCallHeldMessagesArriveWithTURN(t *testing.T) {
	r := relaytest.Start(t, nil)
	ia, ib := &turnIssuer{name: "a"}, &turnIssuer{name: "b"}
	a := newTestVault(t, r.URL, "a", func(o *vault.Options) { o.Calls = ia })
	b := newTestVault(t, r.URL, "b", func(o *vault.Options) { o.Calls = ib })
	ctx := ctxT(t, 120*time.Second)
	aConn, _ := connect(t, a, b, 600)
	ia.primed(t)
	ib.primed(t)

	call, err := a.app.CallStart(ctx, aConn, "audio", "v=0 offer")
	if err != nil {
		t.Fatal(err)
	}
	defer call.Destroy()
	if !hasTURNEntry(call.ICE) {
		t.Fatalf("the caller's answer has no TURN entry: %+v", call.ICE.Servers)
	}
	ev := waitEvent(t, b.app, "call.offer", has("call_id", call.ID))
	in, err := b.app.IncomingCall(ev)
	if err != nil {
		t.Fatal(err)
	}
	if !hasTURNEntry(in.ICE) {
		t.Fatalf("the callee's offer has no TURN entry: %+v", in.ICE.Servers)
	}
}
