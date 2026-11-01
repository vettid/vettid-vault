package wallet_test

import (
	"testing"

	"github.com/vettid/vettid-vault/features/wallet"
	"github.com/vettid/vettid-vault/vms/btc"
)

// §10.18 (0.82.3) "Who needs the PIN to reveal": by master fingerprint, so
// a testnet4 wallet of the phrase of a capped mainnet wallet needs the PIN
// too; the requirement ends when the capped wallet is deleted. It is
// derived from the current wallets, never stored.
func TestRevealPINByFingerprint(t *testing.T) {
	e := newEnvWith(t, wallet.Options{Networks: []string{btc.Mainnet, btc.Testnet4}})
	mk := func(network string) string {
		o := e.ok(e.sealed("app", "wallet.create", map[string]any{"name": network, "network": network},
			map[string]any{"password": pw, "item": map[string]any{"mnemonic": abandon}}, true, false))
		id, _ := o.String("wallet_id")
		return id
	}
	main, test := mk(btc.Mainnet), mk(btc.Testnet4)
	other := e.ok(e.sealed("app", "wallet.create", map[string]any{"name": "other", "network": "mainnet"}, map[string]any{"password": pw}, true, false))
	otherID, _ := other.String("wallet_id")
	reveal := func(id string, pin bool) string {
		p := map[string]any{"password": pw, "item_id": id}
		if pin {
			p["pin"] = e.h.PIN
		}
		r := e.sealed("app", "item.reveal", map[string]any{"item_id": id}, p, true, true)
		if r.Code == "bad_request" {
			return r.Message
		}
		return r.Code
	}
	for _, id := range []string{main, test, otherID} {
		if got := reveal(id, false); got != "" {
			t.Fatalf("no caps anywhere: %q", got)
		}
	}
	(&capW{e: e, id: main}).mustSet(map[string]any{"per_tx_sats": 1000})
	if got := reveal(main, false); got != "pin_required" {
		t.Fatalf("capped: %q", got)
	}
	if got := reveal(test, false); got != "pin_required" {
		t.Fatalf("the testnet4 wallet of the capped wallet's phrase: %q", got)
	}
	if got := reveal(test, true); got != "" {
		t.Fatalf("with the pin: %q", got)
	}
	if got := reveal(otherID, false); got != "" {
		t.Fatalf("another phrase: %q", got)
	}
	// Deleting the capped wallet ends the requirement.
	e.ok(e.sealed("app", "item.delete", map[string]any{"item_id": main}, map[string]any{"password": pw, "item_id": main}, true, false))
	// No wallet request in between: the requirement ends at once.
	if got := reveal(test, false); got != "" {
		t.Fatalf("after the capped wallet was deleted: %q", got)
	}
}
