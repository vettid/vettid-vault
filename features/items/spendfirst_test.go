package items_test

import (
	"testing"
)

// §3.5.4 "Using a UTK", §10.7 (0.52.0): a critical item's operation spends
// its UTK before any check of the items feature: a recovering app's
// request refused by the app-only rule, and the holder's request refused
// for its shape, both leave the UTK spent.
func TestCriticalRefusalsSpendTheUTK(t *testing.T) {
	e := newEnv(t)
	e.createCredential()
	cred := e.set.Credential
	// The app-only rule: a recovering app's UTK.
	n := len(e.utks)
	e.ok(e.call("recovering-app", "credential.utk.get", `{}`))
	ru := e.utks[n]
	e.utks = e.utks[:n]
	pool := cred.PoolSizeOf("dev-recovering")
	item := map[string]any{"name": "Bank", "fields": []field{{Label: "PIN", Kind: "password", Value: "1234"}}}
	e.code(e.sealedUTK("recovering-app", "item.put", map[string]any{"sensitivity": "critical"},
		map[string]any{"password": pw, "item": item}, true, false, ru), "forbidden")
	if cred.PoolSizeOf("dev-recovering") != pool-1 {
		t.Fatal("the app-only refusal left the UTK unspent")
	}
	// The shape: the item travels sealed, never in the outer body.
	u := e.take()
	e.code(e.sealedUTK("app", "item.put", map[string]any{"sensitivity": "critical", "name": "Bank"},
		map[string]any{"password": pw, "item": item}, true, false, u), "bad_request")
	e.code(e.sealedUTK("app", "item.put", map[string]any{"sensitivity": "critical"},
		map[string]any{"password": pw, "item": item}, true, false, u), "utk_invalid")
}
