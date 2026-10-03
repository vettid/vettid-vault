//go:build devenclave && e2e

package e2e

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/btc"
)

const bip84Phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// V4 batch 4, the wallet (§10.18) through the real relay, on regtest with
// synthetic coins (no real funds): A imports a wallet as a critical item
// and derives receive addresses; B's request-address invocation gets A's
// address for B; B asks A to pay B's own address (wallet.request-payment,
// critical): A's app approves with a PSBT and the credential within the
// unlock window, B gets the txid; A also signs a PSBT directly.
func TestWallet(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 180*time.Second)
	aConn, bConn := connect(t, a, b, 600)

	o, err := a.app.WalletCreate(ctx, credPW, "Savings", "regtest", bip84Phrase, "", []string{"money"})
	if err != nil {
		t.Fatal(err)
	}
	wid, _ := o.String("wallet_id")
	if fp, _ := o.String("fingerprint"); fp != "73c5da0a" {
		t.Fatalf("fingerprint %s", fp)
	}
	acct, err := a.app.WalletAccount(ctx, wid)
	if err != nil {
		t.Fatal(err)
	}
	// The recovery phrase is a critical item: its metadata is listed, its
	// value is not.
	it, err := a.app.ItemGet(ctx, wid)
	if err != nil || strings.Contains(string(mustJSON(it)), "abandon") {
		t.Fatalf("item: %v", err)
	}
	if s, _ := it.String("sensitivity"); s != "critical" {
		t.Fatal(s)
	}
	addr0, _, _ := acct.Address(0, 0)
	ad, err := a.app.WalletAddressNew(ctx, wid, false, "shop")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := ad.String("address"); got != addr0 {
		t.Fatalf("address %s", got)
	}

	// B's wallet: the address B wants to be paid at.
	bo, err := b.app.WalletCreate(ctx, credPW, "B", "regtest", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	bwid, _ := bo.String("wallet_id")
	bad, err := b.app.WalletAddressNew(ctx, bwid, false, "from A")
	if err != nil {
		t.Fatal(err)
	}
	bAddr, _ := bad.String("address")

	waitOffer := func(want string) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for {
			l, err := b.app.ActionList(ctx, bConn)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(l["actions"]), want) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("offer %s not seen: %s", want, l["actions"])
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	status := func(o strictjson.Object) string { s, _ := o.String("status"); return s }

	// wallet.request-address (normal), allowlisted for B.
	if _, err := a.app.ActionConfigure(ctx, client.ActionConfig{ActionID: "wallet.request-address", Mode: "allowlist",
		Connections: []string{aConn}, Items: []string{wid}}); err != nil {
		t.Fatal(err)
	}
	waitOffer(`"wallet.request-address","version":1,"prompt":false`)
	id, err := b.app.ActionInvoke(ctx, bConn, "wallet.request-address", json.RawMessage(`{"asset":"BTC"}`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := b.app.ActionResult(ctx, id)
	if err != nil || status(res) != "ok" {
		t.Fatalf("request-address: %v %v", err, res)
	}
	ro, _ := strictjson.ParseObject(res["result"])
	addr1, _, _ := acct.Address(0, 1) // index 0 went to the app's own request
	if got, _ := ro.String("address"); got != addr1 {
		t.Fatalf("address for B: %s, want %s", got, addr1)
	}

	// wallet.request-payment (critical), approved by A's app with a PSBT.
	if _, err := a.app.ActionConfigure(ctx, client.ActionConfig{ActionID: "wallet.request-payment", Mode: "prompt-each-time",
		Connections: []string{aConn}, Items: []string{wid}}); err != nil {
		t.Fatal(err)
	}
	waitOffer(`"wallet.request-payment","version":1,"prompt":true`)
	id, err = b.app.ActionInvoke(ctx, bConn, "wallet.request-payment", json.RawMessage(`{"asset":"BTC","amount_sats":250000,"address":"`+bAddr+`","memo":"rent"}`))
	if err != nil {
		t.Fatal(err)
	}
	p := waitEvent(t, a.app, "action.pending", has("invocation_id", id))
	if !strings.Contains(string(p.Body), bAddr) {
		t.Fatalf("pending: %s", p.Body)
	}
	coin, _ := btc.FundingTx(acct, 0, 0, 1000000, 9)
	psbt, err := btc.BuildPSBT(acct, []btc.Coin{{PrevTx: coin, Vout: 0}},
		[]btc.Payee{{Address: bAddr, Amount: 250000}, {Change: true, Chain: 1, Index: 0, Amount: 749000}})
	if err != nil {
		t.Fatal(err)
	}
	sum, err := a.app.WalletInspect(ctx, wid, psbt)
	if err != nil {
		t.Fatal(err)
	}
	if fee, _ := sum.Uint("fee_sats", 0, 1e9); fee != 1000 {
		t.Fatalf("fee %d", fee)
	}
	if _, err := a.app.WalletPay(ctx, credPW, id, wid, psbt); client.Code(err) != "credential_locked" {
		t.Fatalf("outside the unlock window: %v", err)
	}
	if _, err := a.app.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	wrong, _ := btc.BuildPSBT(acct, []btc.Coin{{PrevTx: coin, Vout: 0}},
		[]btc.Payee{{Address: bAddr, Amount: 200000}, {Change: true, Chain: 1, Index: 0, Amount: 799000}})
	if _, err := a.app.WalletPay(ctx, credPW, id, wid, wrong); client.Code(err) != "invalid_psbt" {
		t.Fatalf("wrong amount: %v", err)
	}
	po, err := a.app.WalletPay(ctx, credPW, id, wid, psbt)
	if err != nil {
		t.Fatal(err)
	}
	txid, _ := po.String("txid")
	txHex, _ := po.String("tx")
	raw, _ := hex.DecodeString(txHex)
	tx, err := btc.DecodeTx(raw)
	if err != nil || tx.TxHash().String() != txid || len(tx.TxIn[0].Witness) != 2 {
		t.Fatalf("signed tx: %v", err)
	}
	res, err = b.app.ActionResult(ctx, id)
	if err != nil || status(res) != "ok" || !strings.Contains(string(res["result"]), txid) {
		t.Fatalf("payment result: %v %v", err, res)
	}

	// A direct spend from A's app.
	coin2, _ := btc.FundingTx(acct, 0, 1, 500000, 10)
	psbt2, _ := btc.BuildPSBT(acct, []btc.Coin{{PrevTx: coin2, Vout: 0, Index: 1}}, []btc.Payee{{Address: bAddr, Amount: 499000}})
	so, err := a.app.WalletSign(ctx, credPW, wid, psbt2)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := so.Uint("sending_sats", 0, 1e15); s != 499000 {
		t.Fatalf("sign: %d", s)
	}
	h, err := a.app.WalletHistory(ctx, wid, 0)
	if err != nil {
		t.Fatal(err)
	}
	if arr, _ := h.Array("transactions"); len(arr) != 2 || !strings.Contains(string(h["transactions"]), aConn) {
		t.Fatalf("history: %s", h["transactions"])
	}
	au, err := a.app.AuditList(ctx, map[string]any{"kinds": []string{"wallet"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"wallet.created", "wallet.address_issued", "wallet.signed"} {
		if !strings.Contains(string(au["entries"]), `"`+k+`"`) {
			t.Errorf("audit lacks %s", k)
		}
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
