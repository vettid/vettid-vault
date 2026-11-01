//go:build devenclave && e2e

package e2e

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/client/wallet"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/btc"
)

// Wallet spend caps (VAULT-MESSAGING 0.82.0 §10.18 "Spend caps") through
// the real relay and a real vault: lowering, the refusal and its body, a
// retry with the same inner id counted once, a new inner id counted again,
// raising with the PIN and the password, the PIN to reveal a capped
// wallet's phrase, and the caps and the ledger surviving a restart.
func TestWalletCaps(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	ctx := ctxT(t, 180*time.Second)

	o, err := wallet.CreateType(ctx, a.app, credPW, "Savings", "regtest", "p2wpkh", bip84Phrase, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	wid, _ := o.String("wallet_id")
	if c, err := o.Object("caps"); err != nil || c.Has("per_tx_sats") || c.Has("per_period_sats") {
		t.Fatalf("a new wallet has no caps: %s", o["caps"])
	}
	accts, _, err := wallet.Accounts(ctx, a.app, wid)
	if err != nil {
		t.Fatal(err)
	}
	acct := accts["p2wpkh"]
	view := func() (version uint64, caps strictjson.Object) {
		t.Helper()
		w, err := a.app.Op(ctx, "wallet.get", map[string]any{"wallet_id": wid})
		if err != nil {
			t.Fatal(err)
		}
		version, _ = w.Uint("version", 1, strictjson.MaxSafeInteger)
		caps, _ = w.Object("caps")
		return
	}
	spent := func() uint64 {
		t.Helper()
		_, c := view()
		n, err := c.Uint("spent_sats", 0, strictjson.MaxSafeInteger)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	// psbt spends a coin of 1,000,000 sats: out to the payee (outflow out + 1,000 fee).
	psbt := func(out int64) []byte {
		t.Helper()
		coin, _ := btc.FundingTx(acct, 0, 0, 1000000, 9)
		raw, err := btc.BuildPSBT(acct, []btc.Coin{{PrevTx: coin, Vout: 0}},
			[]btc.Payee{{Address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", Amount: out}, {Change: true, Chain: 1, Index: 0, Amount: 1000000 - 1000 - out}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	i64 := func(v int64) *int64 { return &v }

	ver, _ := view()
	if ver, err = wallet.CapsSet(ctx, a.app, wid, ver, nil, i64(100000)); err != nil {
		t.Fatal(err)
	}
	// Larger is for wallet.caps.raise; a stale version is a conflict.
	if _, err := wallet.CapsSet(ctx, a.app, wid, ver, nil, i64(100001)); client.Code(err) != "bad_request" {
		t.Fatalf("a larger cap: %v", err)
	}
	if _, err := wallet.CapsSet(ctx, a.app, wid, ver-1, i64(5), nil); client.Code(err) != "conflict" {
		t.Fatalf("stale: %v", err)
	}
	if _, c := view(); c.Has("per_tx_sats") || !c.Has("per_period_sats") {
		t.Fatalf("caps %s", js(c))
	}

	if _, err := a.app.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	// A sign of 60,000 + 1,000, sent twice with the same inner id: the
	// second is answered from the response cache and counts once.
	raw := psbt(59000)
	h := sha256.Sum256(raw)
	if err := a.app.CredentialFetch(ctx); err != nil {
		t.Fatal(err)
	}
	id, body := changeRequest(t, a.app, "wallet.sign", a.app.CredentialBlob(), map[string]any{"password": credPW,
		"item_id": wid, "payload_sha256": base64.StdEncoding.EncodeToString(h[:])})
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	m["wallet_id"], m["psbt"] = wid, base64.StdEncoding.EncodeToString(raw)
	body, _ = json.Marshal(m)
	exp := time.Now().Add(10 * time.Minute)
	first := send(t, a.app, id, "wallet.sign", body, exp)
	if !first.OK() {
		t.Fatalf("sign: %s", first.ErrorCode())
	}
	again := send(t, a.app, id, "wallet.sign", body, exp)
	if !again.OK() || string(again.Body()) != string(first.Body()) {
		t.Fatalf("resend: %s", again.ErrorCode())
	}
	if n := spent(); n != 60000 {
		t.Fatalf("a retry with the same inner id counted %d, want 60000 once", n)
	}
	if err := a.app.CredentialFetch(ctx); err != nil {
		t.Fatal(err)
	}

	// The same PSBT under a new inner id counts again: refused, with the
	// body for the app and nothing in the audit log or the feed.
	_, err = wallet.Sign(ctx, a.app, credPW, wid, raw)
	var oe *client.OpError
	if client.Code(err) != "cap_exceeded" || !errors.As(err, &oe) {
		t.Fatalf("a new inner id: %v", err)
	}
	ob, _ := strictjson.ParseObject(oe.Body)
	if reason, _ := ob.String("reason"); reason != "per_period" {
		t.Fatalf("body %s", oe.Body)
	}
	if lim, _ := ob.Uint("limit_sats", 0, 1<<53); lim != 100000 {
		t.Fatalf("body %s", oe.Body)
	}
	if rem, _ := ob.Uint("remaining_sats", 0, 1<<53); rem != 40000 || !ob.Has("allowed_after") {
		t.Fatalf("body %s", oe.Body)
	}
	if audits(a, "wallet.cap_refused") != 1 {
		t.Fatal("not audited")
	}
	au, err := a.app.AuditList(ctx, map[string]any{"kinds": []string{"wallet"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"40000", "60000", "100000"} {
		if numberInBody(au["entries"], v) {
			t.Fatalf("%s in the audit log: %s", v, au["entries"])
		}
	}
	if n := spent(); n != 60000 {
		t.Fatalf("a refusal counted: %d", n)
	}

	// Raising takes the PIN and the password, and leaves the ledger.
	ver, _ = view()
	if _, err := wallet.CapsRaise(ctx, a.app, "000000", credPW, wid, ver, nil, i64(200000)); client.Code(err) != "bad_pin" {
		t.Fatalf("wrong pin: %v", err)
	}
	if _, err := wallet.CapsRaise(ctx, a.app, pin, "not the password", wid, ver, nil, i64(200000)); client.Code(err) != "bad_password" {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := wallet.CapsRaise(ctx, a.app, pin, credPW, wid, ver, nil, i64(50000)); client.Code(err) != "bad_request" {
		t.Fatalf("a raise that raises nothing: %v", err)
	}
	ro, err := wallet.CapsRaise(ctx, a.app, pin, credPW, wid, ver, nil, i64(200000))
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := ro.Uint("version", 1, strictjson.MaxSafeInteger); v != ver+1 {
		t.Fatalf("version %d", v)
	}
	if n := spent(); n != 60000 {
		t.Fatalf("a raise changed the ledger: %d", n)
	}
	if _, err := wallet.Sign(ctx, a.app, credPW, wid, psbt(100000)); err != nil {
		t.Fatalf("after the raise: %v", err)
	}

	// The phrase of a capped wallet is revealed with the PIN as well.
	if _, err := a.app.ItemRevealCritical(ctx, credPW, wid); client.Code(err) != "bad_request" {
		t.Fatalf("reveal without the PIN: %v", err)
	}
	if _, err := a.app.ItemRevealCriticalPIN(ctx, credPW, "000000", wid); client.Code(err) != "bad_pin" {
		t.Fatalf("reveal with a wrong PIN: %v", err)
	}
	if _, err := a.app.ItemRevealCriticalPIN(ctx, credPW, pin, wid); err != nil {
		t.Fatal(err)
	}

	// Caps and ledger survive a restart (a lock and an unlock).
	before, bc := view()
	a.restart()
	after, ac := view()
	if before != after || js(bc) != js(ac) || spent() != 161000 {
		t.Fatalf("after a restart: version %d/%d caps %s/%s", before, after, js(bc), js(ac))
	}
}

func js(v any) string { b, _ := json.Marshal(v); return string(b) }

// numberInBody reports whether the decimal n appears as a JSON number.
func numberInBody(raw []byte, n string) bool {
	for i := 0; i+len(n) <= len(raw); i++ {
		if string(raw[i:i+len(n)]) != n {
			continue
		}
		before, after := byte(0), byte(0)
		if i > 0 {
			before = raw[i-1]
		}
		if i+len(n) < len(raw) {
			after = raw[i+len(n)]
		}
		if (before < '0' || before > '9') && (before < 'A' || before > 'Z') && (before < 'a' || before > 'z') &&
			(after < '0' || after > '9') && (after < 'A' || after > 'Z') && (after < 'a' || after > 'z') {
			return true
		}
	}
	return false
}
