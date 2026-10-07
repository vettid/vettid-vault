//go:build devenclave && e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/vault"
)

// VAULT-MESSAGING 0.20.0 (§11.13, §13.7, §10.2): the snapshot's full email
// reaches the member's app through account.get and goes nowhere else: not
// into the profile a connection receives (activation, a name change), the
// hs.init profile, a remote invitation's bundle, the feed, the audit log,
// what a connection lists, or the host's lifecycle events and audit.
func TestEmailStaysWithTheMember(t *testing.T) {
	const email = "ada.private@hidden-domain.test"
	leaks := []string{"ada.private", "hidden-domain", "a***@"}
	r := relaytest.Start(t, nil)
	var mu sync.Mutex
	var events []string
	a := newTestVault(t, r.URL, "a", func(o *vault.Options) {
		o.Lifecycle = func(ev vault.LifecycleEvent) {
			mu.Lock()
			events = append(events, fmt.Sprintf("%+v %+v", ev, ev.Name))
			mu.Unlock()
		}
	})
	b := newTestVault(t, r.URL, "b", nil)
	c := newTestVault(t, r.URL, "c", nil)
	ctx := ctxT(t, 240*time.Second)
	if err := a.manager().SetAccount(ctx, enclavetest.SnapshotEmail(time.Now(), "Ada", "Private", email)); err != nil {
		t.Fatal(err)
	}
	// A remote invitation (a bundle with its hint) from A to B; A accepts
	// C's invitation, so A sends C its hs.init profile.
	inv := mustOK(t, a.request(a.app, "connection.invite.create", `{"ttl_seconds":3600}`))
	_, bConn := connect(t, a, b, 3600)
	cConn, _ := connect(t, c, a, 600)
	waitEvent(t, b.app, "connection.event", has("event", "profile"))
	// A name change reaches B and C as a profile.update, with the email in
	// A's snapshot unchanged.
	if err := a.manager().SetAccount(ctx, enclavetest.SnapshotEmail(time.Now().Add(time.Second), "Ada", "Hidden", email)); err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct {
		tv   *testVault
		conn string
	}{{b, bConn}, {c, cConn}} {
		for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(200 * time.Millisecond) {
			g := mustOK(t, v.tv.request(v.tv.app, "connection.get", `{"connection_id":"`+v.conn+`"}`))
			if strings.Contains(string(g["profile"]), `"last_name":"Hidden"`) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s did not get the new names: %s", v.tv.name, g["profile"])
			}
		}
	}

	acct := mustOK(t, a.request(a.app, "account.get", `{}`))
	if !strings.Contains(string(acct["account"]), `"email":"`+email+`"`) {
		t.Fatalf("account.get: %s", acct["account"])
	}
	check := func(who string, raw []byte) {
		t.Helper()
		for _, l := range leaks {
			if strings.Contains(strings.ToLower(string(raw)), l) {
				t.Errorf("%s holds %q: %s", who, l, raw)
			}
		}
	}
	check("A's invitation", jsonOf(t, inv))
	for _, req := range []string{"profile.get", "connection.list", "device.list", "vault.status", "feed.list", "audit.list"} {
		check("A's "+req, a.request(a.app, req, `{}`).Body())
	}
	for _, v := range []struct {
		name string
		tv   *testVault
		conn string
	}{{"B", b, bConn}, {"C", c, cConn}} {
		g := mustOK(t, v.tv.request(v.tv.app, "connection.get", `{"connection_id":"`+v.conn+`"}`))
		check(v.name+"'s connection.get", jsonOf(t, g))
		for _, req := range []string{"connection.list", "connection.request.list", "feed.list", "audit.list"} {
			check(v.name+"'s "+req, v.tv.request(v.tv.app, req, `{}`).Body())
		}
	}
	mu.Lock()
	check("A's lifecycle events", []byte(strings.Join(events, "\n")))
	mu.Unlock()
	for _, e := range a.manager().Audit() {
		check("A's host audit", []byte(fmt.Sprintf("%+v", e)))
	}
}

// §10.9 (0.20.0) through the real vault: q finds entries by kind, by the
// current names of their connection (profile names, "First Last", the
// alias) and item; with since/until; the client follows the cursors.
// (Device names: vault.TestSearchNamesFromManager; the harness's apps
// have none.)
func TestAuditSearch(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 180*time.Second)
	aConn, _ := connect(t, a, b, 600)
	start := time.Now().Add(-time.Second)
	if _, _, err := a.app.ItemPut(ctx, "", 0, "", []string{"bank"}, client.ItemContent{Name: "Brokerage Login", Category: "login",
		Fields: []client.ItemField{{Label: "Password", Kind: "password", Value: "zebra-horse"}}}); err != nil {
		t.Fatal(err)
	}
	search := func(q client.AuditQuery) []string {
		t.Helper()
		es, err := a.app.AuditSearchAll(ctx, q, q.ConnectionID != "", 0)
		if err != nil {
			t.Fatalf("%+v: %v", q, err)
		}
		var kinds []string
		for _, e := range es {
			var v struct {
				Kind string `json:"kind"`
			}
			_ = json.Unmarshal(e, &v)
			kinds = append(kinds, v.Kind)
		}
		return kinds
	}
	if k := search(client.AuditQuery{Q: "brokerage"}); len(k) != 1 || k[0] != "item.added" {
		t.Fatalf("item name: %v", k)
	}
	if k := search(client.AuditQuery{Q: "zebra"}); len(k) != 0 {
		t.Fatalf("a field value was searched: %v", k)
	}
	if k := search(client.AuditQuery{Q: "member b"}); len(k) == 0 || !contains(k, "connection.added") {
		t.Fatalf("connection First Last: %v", k)
	}
	if k := search(client.AuditQuery{Q: "item added", Since: start, Until: time.Now().Add(time.Minute)}); len(k) != 1 {
		t.Fatalf("kind with a range: %v", k)
	}
	if k := search(client.AuditQuery{Q: "item added", Until: start}); len(k) != 0 {
		t.Fatalf("until: %v", k)
	}
	if _, err := a.app.ConnectionUpdate(ctx, aConn, 0, map[string]any{"alias": "Gardener"}); err != nil {
		t.Fatal(err)
	}
	if k := search(client.AuditQuery{ConnectionID: aConn, Q: "gardener"}); len(k) == 0 {
		t.Fatalf("alias: %v", k)
	}
	if _, err := a.app.AuditList(ctx, map[string]any{"q": "   "}, false); client.Code(err) != "bad_request" {
		t.Fatalf("blank q: %v", err)
	}
}

func jsonOf(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
