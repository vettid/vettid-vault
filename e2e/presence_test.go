//go:build devenclave && e2e

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/relaytest"
)

// V4 batch 4, presence (§9.2, §10.17) through the real relay: A's app
// pings B and gets B's state and a rounded last-active time; C's member
// does not share presence with A, so A's ping of C gets no answer
// (silence, as from a locked vault).
func TestPresencePing(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	c := newTestVault(t, r.URL, "c", nil)
	ctx := ctxT(t, 120*time.Second)
	aB, _ := connect(t, a, b, 600)
	aC, cA := connect(t, a, c, 600)

	if _, err := b.app.PresenceSet(ctx, 0, "busy", "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.app.PresenceSet(ctx, 0, "", "", []string{cA}); err != nil {
		t.Fatal(err)
	}
	pid, err := a.app.PresenceQuery(ctx, aB)
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.app.PresenceResult(ctx, pid)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := res.String("state"); st != "busy" {
		t.Fatalf("result: %v", res)
	}
	la, err := res.String("last_active")
	if err != nil || la[15:] != "0:00.000Z" && la[15:] != "5:00.000Z" {
		t.Fatalf("last_active not rounded to 5 minutes: %v", res)
	}
	// Within the minute, the same ping is returned (and its result again).
	if again, err := a.app.PresenceQuery(ctx, aB); err != nil || again != pid {
		t.Fatalf("ping not reused: %v %s", err, again)
	}

	pc, err := a.app.PresenceQuery(ctx, aC)
	if err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if res, err := a.app.PresenceResult(wctx, pc); err == nil {
		t.Fatalf("opted-out connection answered: %v", res)
	}
}
