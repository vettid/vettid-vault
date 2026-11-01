package wallet_test

import (
	"encoding/json"
	"testing"

	"github.com/vettid/vettid-vault/features/wallet"
	"github.com/vettid/vettid-vault/vms/btc"
)

// Two wallets that share an account key can exist in a vault from before
// an import of equal keys was refused (exists). The vault refuses caps on
// them (duplicate_wallet), and the reveal of either takes the PIN, until
// one of them is deleted (VAULT-MESSAGING 0.82.3 §10.18).
//
// The twin is built as saved state: a wallet's record whose account keys
// are replaced by another wallet's, loaded by the current code.
func TestTwinWallets(t *testing.T) {
	e := newEnv(t, &fakeChain{})
	idA, _ := e.importAs(btc.P2WPKH)
	ob := e.ok(e.sealed("app", "wallet.create", map[string]any{"name": "Other", "network": "regtest"}, map[string]any{"password": pw}, true, false))
	idB, _ := ob.String("wallet_id")
	e.unlock()

	raw, err := e.wl.Save()
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Wallets map[string]map[string]json.RawMessage `json:"wallets"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	st.Wallets[idB]["xpubs"] = st.Wallets[idA]["xpubs"]
	st.Wallets[idB]["fingerprint"] = st.Wallets[idA]["fingerprint"]
	fixture, _ := json.Marshal(st)
	wl2 := wallet.New(e.cred, e.it, e.opt)
	if err := wl2.Load(fixture); err != nil {
		t.Fatal(err)
	}
	e.it.SetGuard(wl2)
	for _, ts := range wl2.Types() {
		e.owner[ts.Type] = wl2
	}
	e.wl = wl2
	a, b := &capW{e: e, id: idA}, &capW{e: e, id: idB}

	reveal := func(id string, extra map[string]any) string {
		p := map[string]any{"password": pw, "item_id": id}
		for k, v := range extra {
			p[k] = v
		}
		r := e.sealed("app", "item.reveal", map[string]any{"item_id": id}, p, true, true)
		if r.Code == "bad_request" {
			return r.Message
		}
		return r.Code
	}

	// Caps are refused on either twin; nothing changes, no secret is tried.
	tries := e.h.PINTries
	for _, c := range []*capW{a, b} {
		was := c.w()
		if r := c.set(map[string]any{"per_tx_sats": 1000}); r.Code != "duplicate_wallet" {
			t.Fatalf("caps.set: %q", r.Code)
		}
		// With a wrong PIN, a wrong password and a stale version: still
		// duplicate_wallet, before any of them is looked at.
		r := c.raiseWith(map[string]any{"per_tx_sats": 2000}, "000000", "not the password 91", bind(c.id, was.Version+5, "2000", "none"))
		if r.Code != "duplicate_wallet" {
			t.Fatalf("caps.raise: %q", r.Code)
		}
		if got := c.w(); got.Caps != was.Caps || got.Version != was.Version {
			t.Fatal("a refusal changed the wallet")
		}
	}
	// conflict comes first (0.82.3): a stale version on a twin is conflict.
	e.code(e.call("app", "wallet.caps.set", js(map[string]any{"wallet_id": idA, "version": a.w().Version + 1, "per_tx_sats": 1000})), "conflict")
	{
		v := a.w().Version + 1
		e.code(e.sealed("app", "wallet.caps.raise", map[string]any{"wallet_id": idA, "version": v, "per_tx_sats": 2000},
			map[string]any{"pin": "000000", "password": "not the password 91", "item_id": idA, "payload_sha256": bind(idA, v, "2000", "none")}, true, false), "conflict")
	}
	// An invalid request on a twin is duplicate_wallet before the value rules.
	if r := a.set(map[string]any{"per_tx_sats": nil}); r.Code != "duplicate_wallet" {
		t.Fatalf("value rules after the twin check: %q", r.Code)
	}
	if e.h.PINTries != tries || len(e.h.CheckFailed) != 0 {
		t.Fatalf("a refusal tried a secret: %v", e.h.CheckFailed)
	}

	// Either twin reveals only with the PIN, whether or not it has caps.
	for _, id := range []string{idA, idB} {
		if got := reveal(id, nil); got != "pin_required" {
			t.Fatalf("reveal without pin: %q", got)
		}
		if got := reveal(id, map[string]any{"pin": "000000"}); got != "bad_pin" {
			t.Fatalf("reveal with a wrong pin: %q", got)
		}
		if got := reveal(id, map[string]any{"pin": e.h.PIN}); got != "" {
			t.Fatalf("reveal with the pin: %q", got)
		}
	}

	// A twin saved and loaded again is still a twin.
	again, _ := e.wl.Save()
	wl3 := wallet.New(e.cred, e.it, e.opt)
	if err := wl3.Load(again); err != nil {
		t.Fatal(err)
	}
	if !wl3.RevealNeedsPIN(idA) || !wl3.RevealNeedsPIN(idB) {
		t.Fatal("the reveal guard was not restored")
	}

	// Deleting one twin frees the other: it reveals with the password
	// alone, and can be capped.
	e.ok(e.sealed("app", "item.delete", map[string]any{"item_id": idB}, map[string]any{"password": pw, "item_id": idB}, true, false))
	e.ok(e.call("app", "wallet.list", `{}`))
	if got := reveal(idA, nil); got != "" {
		t.Fatalf("reveal after the twin was deleted: %q", got)
	}
	a.mustSet(map[string]any{"per_tx_sats": 1000})
	if got := reveal(idA, nil); got != "pin_required" {
		t.Fatalf("capped: %q", got)
	}
	e.ok(a.raise(map[string]any{"per_tx_sats": 2000}))
}
