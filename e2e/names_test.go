//go:build devenclave && e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
)

// VAULT-MESSAGING 0.18.0 (§10.8, §11.5, §11.13) through the real relay:
// a connection's profile carries the peer's account names and its ik
// (no display name needed); the app's account.name.set reports
// account_name, and the snapshot that settles it brings the new names to
// the connection; after an ik rotation the update with the new ik
// arrives in the epoch under it and is kept (no ik mismatch).
func TestProfileCoreNamesAndRotation(t *testing.T) {
	r := relaytest.Start(t, nil)
	names := make(chan vault.NameChange, 4)
	a := newTestVault(t, r.URL, "a", func(o *vault.Options) {
		o.Lifecycle = func(ev vault.LifecycleEvent) {
			if ev.Event == vault.EventAccountName && ev.Name != nil {
				names <- *ev.Name
			}
		}
	})
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 180*time.Second)
	_, bConn := connect(t, a, b, 600)
	waitEvent(t, b.app, "connection.event", has("event", "profile"))
	view := func() (strictjson.Object, strictjson.Object) {
		t.Helper()
		g := mustOK(t, b.request(b.app, "connection.get", `{"connection_id":"`+bConn+`"}`))
		p, err := g.Object("profile")
		if err != nil {
			t.Fatalf("no profile: %s", g["profile"])
		}
		return g, p
	}
	g, p := view()
	if f, _ := p.String("first_name"); f != "Member" {
		t.Fatalf("B's view of A: %s", g["profile"])
	}
	if l, _ := p.String("last_name"); l != "A" || p.Has("name") || g.Has("name") && string(g["name"]) != `""` {
		t.Fatalf("B's view of A: %s (name %s)", g["profile"], g["name"])
	}
	if string(p["ik"]) != string(g["ik"]) {
		t.Fatalf("profile ik %s, pinned %s", p["ik"], g["ik"])
	}
	own := mustOK(t, a.request(a.app, "profile.get", `{}`))
	if string(own["ik"]) != string(g["ik"]) || string(own["first_name"]) != `"Member"` {
		t.Fatalf("A's profile.get %v", own)
	}
	ik, _ := base64.StdEncoding.DecodeString(strings.Trim(string(g["ik"]), `"`))
	if fp := client.IKFingerprint(ik); len(fp) != 39 || strings.Count(fp, " ") != 7 {
		t.Fatalf("fingerprint %q", fp)
	}

	// The name change: requested with the PIN and the password, reported
	// to the host, settled by the member API's snapshot.
	req, err := a.app.AccountNameSet(ctx, pin, credPW, "Ada", "King")
	if err != nil || !bytes.Contains(req, []byte(`"state":"pending"`)) {
		t.Fatalf("account.name.set: %v %s", err, req)
	}
	var n vault.NameChange
	select {
	case n = <-names:
	case <-time.After(30 * time.Second):
		t.Fatal("no account_name event")
	}
	if n.FirstName != "Ada" || n.LastName != "King" || n.Seq != 1 {
		t.Fatalf("event %+v", n)
	}
	b.app.Events() // drain
	snap := strings.Replace(string(enclavetest.Snapshot(time.Now(), "Ada", "King")), `"last":null`,
		`"last":{"seq":`+strconv.FormatUint(n.Seq, 10)+`,"status":"applied"}`, 1)
	if err := a.manager().SetAccount(context.Background(), []byte(snap)); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, b.app, "connection.event", has("event", "profile"))
	if _, p = view(); string(p["first_name"]) != `"Ada"` || string(p["last_name"]) != `"King"` {
		t.Fatalf("after the change: %v", p)
	}
	if acc := mustOK(t, a.request(a.app, "account.get", `{}`)); !strings.Contains(string(acc["name_request"]), `"state":"applied"`) {
		t.Fatalf("name_request %s", acc["name_request"])
	}

	// The ik rotates: B follows identity.rotate, then gets the update
	// with the new ik in the epoch under it.
	b.app.Events()
	if err := a.manager().RotateIdentity(ctx); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, b.app, "connection.event", has("event", "profile"))
	g, p = view()
	if string(p["ik"]) != string(g["ik"]) || string(g["ik"]) == `"`+base64.StdEncoding.EncodeToString(ik)+`"` {
		t.Fatalf("after the rotation: profile ik %s, pinned %s", p["ik"], g["ik"])
	}
	al, err := b.app.AuditList(ctx, map[string]any{}, false)
	if err != nil || strings.Contains(string(al["entries"]), "profile_ik_mismatch") || strings.Contains(string(al["entries"]), "profile_malformed") {
		t.Fatalf("B's audit: %v %s", err, al["entries"])
	}
}
