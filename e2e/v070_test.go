//go:build devenclave && e2e

package e2e

import (
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/internal/strictjson"
)

// pendingAll reads every page of pending.list.
func pendingAll(t *testing.T, d *client.Device) []struct{ Kind, Body string } {
	t.Helper()
	var out []struct{ Kind, Body string }
	after := ""
	for i := 0; i < 20; i++ {
		o, err := d.PendingList(ctxT(t, 30*time.Second), after, 0)
		if err != nil {
			t.Fatalf("pending.list: %v", err)
		}
		arr, err := o.Array("asks")
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range arr {
			e, err := strictjson.ParseObject(raw)
			if err != nil {
				t.Fatal(err)
			}
			k, _ := e.String("kind")
			out = append(out, struct{ Kind, Body string }{k, string(e["body"])})
		}
		if !o.Has("next") {
			return out
		}
		after, _ = o.String("next")
	}
	t.Fatal("pending.list does not end")
	return nil
}

// §10.4.2 (0.70.0): the open asks that arrive only as events are listed
// to the app after a lock and an unlock, each as the body of its event; a
// decided ask is no longer listed.
func TestPendingListSurvivesLockE2E(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 120*time.Second)
	aConn, _ := connect(t, a, b, 600)

	rid, err := a.app.AuthRequestFor(ctx, aConn, "example.org, Firefox on Linux", "signin")
	if err != nil {
		t.Fatal(err)
	}
	authEv := waitEvent(t, b.app, "connection.authenticate.pending", has("request_id", rid))
	lid, err := a.app.LocationRequest(ctx, aConn, "where are you?")
	if err != nil {
		t.Fatal(err)
	}
	locEv := waitEvent(t, b.app, "location.request.pending", has("request_id", lid))

	checkListed := func() {
		t.Helper()
		got := pendingAll(t, b.app)
		if len(got) != 2 {
			t.Fatalf("listed: %+v", got)
		}
		want := map[string]string{"authenticate": string(authEv.Body), "location": string(locEv.Body)}
		for _, e := range got {
			if want[e.Kind] != e.Body {
				t.Fatalf("%s: listed %s, event %s", e.Kind, e.Body, want[e.Kind])
			}
			delete(want, e.Kind)
		}
		if len(want) != 0 {
			t.Fatalf("missing: %v", want)
		}
	}
	lockVault(t, b)
	unlockVault(t, b, nil)
	checkListed()
	// A restart (a crash, no lock) keeps them too.
	b.stop()
	b.manager().Crash()
	unlockVault(t, b, nil)
	checkListed()

	// Decided: no longer listed.
	if err := b.app.AuthDeny(ctx, rid); err != nil {
		t.Fatal(err)
	}
	got := pendingAll(t, b.app)
	if len(got) != 1 || got[0].Kind != "location" {
		t.Fatalf("after a decision: %+v", got)
	}
	// Listing changed nothing for the asker (§10.4.2): the location request is still open.
	if !strings.Contains(got[0].Body, lid) {
		t.Fatalf("%+v", got)
	}
}
