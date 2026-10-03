//go:build devenclave && e2e

package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
)

// V4 batch 3, grants (§10.12) through the real relay: A has a profile
// field and a cataloged secret; B reads A's catalog, asks for both; A's
// app approves; B's app fetches the secret (sealed to its one-time key,
// opened on B's device) and the field; uses are counted; A revokes and B
// is told, and B's next fetch is refused as revoked.
func TestGrantShareAndRevoke(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 180*time.Second)
	_, bConn := connect(t, a, b, 600)

	if _, err := a.app.ProfileSet(ctx, map[string]any{"version": 0, "name": "Alice",
		"set": map[string]any{"contact.phone": map[string]any{"value": "+1 555 0100"}}}); err != nil {
		t.Fatal(err)
	}
	sid, _, err := a.app.SecretPut(ctx, "", 0, "wifi", "hunter22", map[string]any{"discoverability": "cataloged"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.app.SecretPut(ctx, "", 0, "diary", "private-thoughts", nil); err != nil {
		t.Fatal(err)
	}

	cat, err := b.app.GrantCatalog(ctx, bConn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cat), sid) || strings.Contains(string(cat), "diary") || strings.Contains(string(cat), "hunter22") {
		t.Fatalf("catalog: %s", cat)
	}

	rid, err := b.app.GrantRequest(ctx, bConn, []client.GrantItem{{Kind: "field", Ref: "contact.phone"}, {Kind: "secret", Ref: sid}}, 2, 0, "dinner")
	if err != nil {
		t.Fatal(err)
	}
	pend := waitEvent(t, a.app, "grant.pending", has("request_id", rid))
	if !strings.Contains(string(pend.Body), `"available":true`) || !strings.Contains(string(pend.Body), "dinner") {
		t.Fatalf("pending: %s", pend.Body)
	}
	if _, err := a.app.GrantDecide(ctx, rid, true, nil, 0, 0); err != nil {
		t.Fatal(err)
	}
	ev := waitEvent(t, b.app, "grant.event", has("event", "granted"))
	var granted struct {
		Grants []struct {
			ID   string `json:"grant_id"`
			Kind string `json:"kind"`
		} `json:"grants"`
	}
	if err := json.Unmarshal(ev.Body, &granted); err != nil || len(granted.Grants) != 2 {
		t.Fatalf("granted: %s", ev.Body)
	}
	ids := map[string]string{}
	for _, g := range granted.Grants {
		ids[g.Kind] = g.ID
	}

	res, err := b.app.GrantFetch(ctx, ids["secret"])
	if err != nil || res.Error != "" || string(res.Value) != "hunter22" || res.UsesLeft != 1 {
		t.Fatalf("fetch secret: %+v %v", res, err)
	}
	res, err = b.app.GrantFetch(ctx, ids["field"])
	if err != nil || string(res.Value) != "+1 555 0100" {
		t.Fatalf("fetch field: %+v %v", res, err)
	}
	gl, err := a.app.GrantList(ctx)
	if err != nil || !strings.Contains(string(gl["given"]), `"used":1`) {
		t.Fatalf("given: %s %v", gl["given"], err)
	}

	if err := a.app.GrantRevoke(ctx, ids["secret"]); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, b.app, "grant.event", func(raw json.RawMessage) bool {
		return has("event", "revoked")(raw) && has("grant_id", ids["secret"])(raw)
	})
	res, err = b.app.GrantFetch(ctx, ids["secret"])
	if err != nil || res.Error != "revoked" || res.Value != nil {
		t.Fatalf("after revoke: %+v %v", res, err)
	}
	au, err := a.app.AuditList(ctx, map[string]any{"kinds": []string{"grant"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"grant.requested", "grant.issued", "grant.fetched", "grant.revoked"} {
		if !strings.Contains(string(au["entries"]), `"`+k+`"`) {
			t.Errorf("audit lacks %s", k)
		}
	}
}
