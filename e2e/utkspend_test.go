//go:build devenclave && e2e

package e2e

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
)

// VAULT-MESSAGING 0.52.0 through the real relay and runtime: a refusal
// spends the UTK the request presents (§3.5.4 "Using a UTK"), so an app
// that drops a UTK when it sends it stays in step with the vault; and an
// app whose own pool is empty while the vault's is full (UTKs it no
// longer has) gets a fresh pool with credential.utk.get{resync: true},
// audited credential.utk_resync.
func TestUTKSpendFirstAndResync(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	ctx := ctxT(t, 120*time.Second)

	// A bad_request whose utk_id reads: the UTK is spent.
	u := takeUTK(t, a.app)
	blob := a.app.CredentialBlob()
	body := `{"credential":"` + base64.StdEncoding.EncodeToString(blob) + `","utk_id":"` + u.ID + `","sealed":7}`
	if res := a.request(a.app, "credential.unlock", body); res.ErrorCode() != "bad_request" {
		t.Fatalf("malformed sealed: %q", res.ErrorCode())
	}
	if _, err := a.app.CredentialRaw(ctx, "credential.unlock", u, blob, map[string]any{"password": credPW}); client.Code(err) != "utk_invalid" {
		t.Fatalf("the refused request's UTK: %v", err)
	}

	// The app drops every UTK it holds without using them: the vault's
	// pool is then full of UTKs the app no longer has, a top-up returns
	// none, and the client resyncs once.
	resyncs := func() []map[string]any {
		au, err := a.app.AuditList(ctx, map[string]any{"kinds": []string{"credential.utk_resync"}}, false)
		if err != nil {
			t.Fatal(err)
		}
		var entries []map[string]any
		if err := json.Unmarshal(au["entries"], &entries); err != nil {
			t.Fatal(err)
		}
		return entries
	}
	for round := 0; round < 3 && len(resyncs()) == 0; round++ {
		for a.app.UTKCount() > 0 {
			takeUTK(t, a.app)
		}
		takeUTK(t, a.app) // a top-up, and once the vault's pool is full a resync
	}
	if e := resyncs(); len(e) != 1 || e[0]["ref"] != "20" {
		t.Fatalf("credential.utk_resync entries %v", e)
	}
	if _, err := a.app.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatalf("unlock after the resync: %v", err)
	}
	// A second resync within 10 minutes: too_soon {allowed_after}.
	if res := a.request(a.app, "credential.utk.get", `{"resync":true}`); res.ErrorCode() != "too_soon" {
		t.Fatalf("second resync: %q", res.ErrorCode())
	}
}
