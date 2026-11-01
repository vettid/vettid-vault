package wallet_test

import (
	"encoding/base64"
	"testing"

	"github.com/vettid/vettid-vault/features/wallet"
	"github.com/vettid/vettid-vault/vms/btc"
)

// Sums of satoshis saturate one above the largest cap and never wrap: many
// maximum-size entries on an uncapped wallet, then a cap: the next sign is
// refused per_period, spent_sats is the clamp, and a merge of the two
// oldest entries never lowers or wraps the total.
func TestCapsLedgerSaturates(t *testing.T) {
	c := newCapEnv(t)
	e := c.e
	const ceil = wallet.MaxCapSats + 1
	big := func() []byte { // outflow 2e15 + 1,000 fee, no change
		f, _ := btc.FundingTx(c.a, 0, 0, 2_000_000_000_001_000, 1)
		raw, err := btc.BuildPSBT(c.a, []btc.Coin{{PrevTx: f, Vout: 0}}, []btc.Payee{{Address: payee, Amount: 2_000_000_000_000_000}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for i := 0; i < wallet.MaxLedger+2; i++ {
		e.ok(e.sign(c.id, big(), nil))
		if got := c.spent(); got < 0 || c.w().Ledger[0].Sats < 0 {
			t.Fatalf("after %d signs the total wrapped: %d", i+1, got)
		}
		if l := c.ledger(); len(l) > wallet.MaxLedger {
			t.Fatalf("%d entries", len(l))
		}
		if i >= 1 {
			view := e.ok(e.call("app", "wallet.get", js(map[string]any{"wallet_id": c.id})))
			caps, _ := view.Object("caps")
			if num(t, caps, "spent_sats") != ceil {
				t.Fatalf("after %d signs spent_sats %d, want the clamp %d", i+1, num(t, caps, "spent_sats"), int64(ceil))
			}
		}
	}
	for _, en := range c.ledger() {
		if en.Sats <= 0 || en.Sats > ceil {
			t.Fatalf("entry %d", en.Sats)
		}
	}
	if l := c.ledger(); l[0].Sats != ceil {
		t.Fatalf("the merged entry %d is not the clamp", l[0].Sats)
	}
	c.mustSet(map[string]any{"per_period_sats": wallet.MaxCapSats})
	o := refusal(t, e.sign(c.id, c.psbt(5000), nil), "per_period")
	if num(t, o, "remaining_sats") != 0 {
		t.Fatalf("body %s", js(o))
	}
}

// §10.18 (0.82.2): every network but mainnet uses coin type 1, so one
// phrase gives at most one non-mainnet wallet in a vault: the second
// import is exists, for every pair. Mainnet and a test network of the same
// phrase have different keys (coin type 0 and 1) and both are allowed.
func TestExistsAcrossNonMainnet(t *testing.T) {
	nets := []string{btc.Testnet, btc.Testnet4, btc.Signet, btc.Regtest}
	all := wallet.Options{Networks: append([]string{btc.Mainnet}, nets...)}
	imp := func(e *env, network string) string {
		return e.sealed("app", "wallet.create", map[string]any{"name": network, "network": network},
			map[string]any{"password": pw, "item": map[string]any{"mnemonic": abandon}}, true, false).Code
	}
	for _, first := range nets {
		e := newEnvWith(t, all)
		if c := imp(e, first); c != "" {
			t.Fatalf("%s first: %q", first, c)
		}
		for _, second := range nets {
			if c := imp(e, second); c != "exists" {
				t.Fatalf("%s then %s: %q, want exists", first, second, c)
			}
		}
		// Mainnet is another coin type: allowed, and then it is the only
		// mainnet wallet of the phrase.
		if c := imp(e, btc.Mainnet); c != "" {
			t.Fatalf("%s then mainnet: %q", first, c)
		}
		if c := imp(e, btc.Mainnet); c != "exists" {
			t.Fatalf("mainnet twice: %q", c)
		}
	}
}

// §10.18 (0.82.2): wallet.caps.raise checks conflict, the value rules and
// the payload_sha256 binding after sealed is opened and before the
// backoff and the PIN and password: a stale or invalid raise tries
// neither, counts no failed check, moves no backoff; the UTK is spent.
func TestCapsRaiseChecksBeforeSecrets(t *testing.T) {
	c := newCapEnv(t)
	e := c.e
	c.mustSet(map[string]any{"per_tx_sats": 1000000, "per_period_sats": 2000000})
	m := map[string]any{"per_period_sats": 3000000}
	tx, per := c.after(m)
	ver := c.w().Version
	tries := e.h.PINTries
	wrongPIN, wrongPW := "000000", "not the password 91"
	run := func(name, code string, members map[string]any, version uint64, hash string) {
		t.Helper()
		outer := map[string]any{"wallet_id": c.id, "version": version}
		for k, v := range members {
			outer[k] = v
		}
		e.ensureUTK()
		u := e.utks[0]
		r := e.sealed("app", "wallet.caps.raise", outer,
			map[string]any{"pin": wrongPIN, "password": wrongPW, "item_id": c.id, "payload_sha256": hash}, true, false)
		if r.Code != code {
			t.Fatalf("%s: %q, want %q", name, r.Code, code)
		}
		// The UTK it presented is spent.
		e.utks = append([]utk{u}, e.utks...)
		if r := e.sealed("app", "wallet.caps.raise", outer,
			map[string]any{"pin": wrongPIN, "password": wrongPW, "item_id": c.id, "payload_sha256": hash}, true, false); r.Code != "utk_invalid" {
			t.Fatalf("%s: the UTK was not spent: %q", name, r.Code)
		}
	}
	good := bind(c.id, ver, tx, per)
	// Many more than the backoff's five: none of them tries a secret.
	for i := 0; i < 3; i++ {
		run("stale", "conflict", m, ver-1, bind(c.id, ver-1, tx, per))
		run("nothing raised", "bad_request", map[string]any{"per_period_sats": 2000000}, ver, bind(c.id, ver, tx, "2000000"))
		run("tx above period", "bad_request", map[string]any{"per_tx_sats": 2500000}, ver, bind(c.id, ver, "2500000", per))
		run("bad binding", "bad_request", m, ver, bind(c.id, ver, tx, "3000001"))
		run("not a hash", "bad_request", m, ver, base64.StdEncoding.EncodeToString([]byte("short")))
	}
	if e.h.PINTries != tries || len(e.h.CheckFailed) != 0 {
		t.Fatalf("a PIN or password was tried: %d tries, failed checks %v", e.h.PINTries-tries, e.h.CheckFailed)
	}
	// No backoff moved: the real request works at once.
	e.ok(c.raiseWith(m, e.h.PIN, pw, good))
}
