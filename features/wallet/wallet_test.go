package wallet_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/actions"
	"github.com/vettid/vettid-vault/features/credential"
	"github.com/vettid/vettid-vault/features/items"
	"github.com/vettid/vettid-vault/features/wallet"
	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/btc"
	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

const (
	pw      = "correct horse battery"
	abandon = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	payee   = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
	cA      = "01JB2Z6V9K3M4N5P6Q7R8S9TAA"
	cB      = "01JB2Z6V9K3M4N5P6Q7R8S9TBB"
)

type utk struct {
	id string
	ek *suite.PublicKey
}

type env struct {
	t     *testing.T
	h     *featuretest.Host
	clk   featuretest.Clock
	owner map[string]vault.Feature
	wl    *wallet.Feature
	act   *actions.Feature
	utks  []utk
	blob  string
	reply *suite.PrivateKey
	lastI string
}

type fakeChain struct {
	unspent []wallet.Unspent
	sent    [][]byte
}

func (c *fakeChain) Unspent(context.Context, string, [][]byte) ([]wallet.Unspent, error) {
	return c.unspent, nil
}
func (c *fakeChain) Broadcast(_ context.Context, _ string, tx []byte) error {
	c.sent = append(c.sent, tx)
	return nil
}

func newEnv(t *testing.T, chain wallet.ChainSource) *env {
	cred := credential.New(credential.Options{KDF: credential.MinKDF})
	it := items.New(cred)
	cred.SetItemRekeyer(it)
	cred.AddDeleteObserver(it)
	wl := wallet.New(cred, it, wallet.Options{Networks: []string{btc.Regtest, btc.Mainnet}, Chain: chain})
	it.SetGuard(wl)
	act := actions.New(actions.Deps{Keys: cred, Wallet: wl})
	e := &env{t: t, h: featuretest.NewHost(), clk: featuretest.Clock{T: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)},
		owner: map[string]vault.Feature{}, wl: wl, act: act}
	for _, f := range []vault.Feature{cred, it, wl, act} {
		for _, ts := range f.Types() {
			e.owner[ts.Type] = f
		}
	}
	e.h.AddDevice("dev-app", vault.KindApp)
	e.h.AddDevice("dev-desktop", vault.KindDesktop)
	e.h.AddConnection(cA)
	e.h.AddConnection(cB)
	e.sealed("app", "credential.create", nil, map[string]any{"password": pw}, false, false)
	return e
}

func js(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (e *env) call(kind, typ, body string) featuretest.Result {
	e.t.Helper()
	e.clk.Advance(time.Second)
	id, _ := envelope.NewULID(e.clk.T)
	e.lastI = id
	r := featuretest.CallID(e.owner[typ], e.h, e.clk.T, kind, typ, id, body)
	e.absorb(r)
	return r
}

func (e *env) ok(r featuretest.Result) strictjson.Object {
	e.t.Helper()
	if !r.OK() {
		e.t.Fatalf("error %s", r.Code)
	}
	return r.Obj(e.t)
}

func (e *env) code(r featuretest.Result, want string) {
	e.t.Helper()
	if r.Code != want {
		e.t.Fatalf("code %q, want %q", r.Code, want)
	}
}

func (e *env) absorb(r featuretest.Result) {
	if !r.OK() || r.Body == nil {
		return
	}
	var out struct {
		UTKs []struct {
			ID string `json:"utk_id"`
			EK []byte `json:"ek"`
		} `json:"utks"`
		Credential string `json:"credential"`
	}
	if json.Unmarshal(r.Body, &out) != nil {
		return
	}
	for _, u := range out.UTKs {
		ek, err := suite.ParsePublicKey(u.EK)
		if err != nil {
			e.t.Fatal(err)
		}
		e.utks = append(e.utks, utk{u.ID, ek})
	}
	if out.Credential != "" {
		e.blob = out.Credential
	}
}

func (e *env) sealed(kind, typ string, outer, payload map[string]any, blob, reply bool) featuretest.Result {
	e.t.Helper()
	if len(e.utks) == 0 {
		e.ok(e.call("app", "credential.utk.get", `{}`))
	}
	u := e.utks[0]
	e.utks = e.utks[1:]
	if payload == nil {
		payload = map[string]any{}
	}
	if reply {
		k, _ := suite.GeneratePrivateKey()
		e.reply = k
		payload["reply_key"] = base64.StdEncoding.EncodeToString(k.Public().Bytes())
	}
	pt, _ := json.Marshal(payload)
	e.clk.Advance(time.Second)
	id, _ := envelope.NewULID(e.clk.T)
	e.lastI = id
	s, err := credwire.SealPayload(u.ek, e.h.VaultID(), u.id, typ, id, pt)
	if err != nil {
		e.t.Fatal(err)
	}
	body := map[string]any{}
	for k, v := range outer {
		body[k] = v
	}
	body["utk_id"], body["sealed"] = u.id, base64.StdEncoding.EncodeToString(s)
	if blob {
		body["credential"] = e.blob
	}
	r := featuretest.CallID(e.owner[typ], e.h, e.clk.T, kind, typ, id, js(body))
	e.absorb(r)
	return r
}

func (e *env) unlock() {
	e.t.Helper()
	e.ok(e.sealed("app", "credential.unlock", nil, map[string]any{"password": pw}, true, false))
}

// importAbandon imports the BIP84 test phrase on regtest.
func (e *env) importAbandon() (string, *btc.Account) {
	e.t.Helper()
	o := e.ok(e.sealed("app", "wallet.create", map[string]any{"name": "Savings", "network": "regtest", "tags": []string{"Money"}},
		map[string]any{"password": pw, "item": map[string]any{"mnemonic": strings.ToUpper(abandon)}}, true, false))
	id, _ := o.String("wallet_id")
	fp, _ := o.String("fingerprint")
	xpub, _ := o.String("xpub")
	if fp != "73c5da0a" {
		e.t.Fatalf("fingerprint %s", fp)
	}
	a, err := btc.ParseAccount(btc.Regtest, fp, xpub)
	if err != nil {
		e.t.Fatal(err)
	}
	return id, a
}

func psbtFor(t *testing.T, a *btc.Account, pay string, amount, change int64) []byte {
	t.Helper()
	f1, _ := btc.FundingTx(a, 0, 0, 60000, 1)
	f2, _ := btc.FundingTx(a, 0, 1, 50000, 2)
	payees := []btc.Payee{{Address: pay, Amount: amount}}
	if change > 0 {
		payees = append(payees, btc.Payee{Change: true, Chain: 1, Index: 0, Amount: change})
	}
	raw, err := btc.BuildPSBT(a, []btc.Coin{{PrevTx: f1, Vout: 0, Chain: 0, Index: 0}, {PrevTx: f2, Vout: 0, Chain: 0, Index: 1}}, payees)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (e *env) sign(walletID string, raw []byte, extra map[string]any) featuretest.Result {
	e.t.Helper()
	h := sha256.Sum256(raw)
	outer := map[string]any{"wallet_id": walletID, "psbt": base64.StdEncoding.EncodeToString(raw)}
	for k, v := range extra {
		outer[k] = v
	}
	return e.sealed("app", "wallet.sign", outer, map[string]any{"password": pw, "item_id": walletID,
		"payload_sha256": base64.StdEncoding.EncodeToString(h[:])}, true, false)
}

func TestCreateGeneratedAndReveal(t *testing.T) {
	e := newEnv(t, nil)
	o := e.ok(e.sealed("app", "wallet.create", map[string]any{"name": "Main"}, map[string]any{"password": pw}, true, false))
	id, _ := o.String("wallet_id")
	if n, _ := o.String("network"); n != "mainnet" {
		t.Fatal(n)
	}
	if !o.Has("credential") || !o.Has("credential_version") {
		t.Fatal("credential members")
	}
	// The phrase is the critical item's value: revealed only sealed to a reply key.
	r := e.ok(e.sealed("app", "item.reveal", map[string]any{"item_id": id}, map[string]any{"password": pw, "item_id": id}, true, true))
	sv, _ := r.Base64("values_sealed", -1)
	pt, err := credwire.OpenValue(e.reply, e.h.VaultID(), e.lastI, sv)
	if err != nil {
		t.Fatal(err)
	}
	var vals struct {
		Fields []struct {
			Value string `json:"value"`
		} `json:"fields"`
	}
	if json.Unmarshal(pt, &vals) != nil || len(vals.Fields) != 2 || len(strings.Fields(vals.Fields[0].Value)) != 24 {
		t.Fatal("phrase")
	}
	seed, _ := btc.Seed(vals.Fields[0].Value, "")
	n, _ := btc.LookupNetwork(btc.Mainnet)
	a, _ := btc.NewAccount(seed, n)
	if x, _ := o.String("xpub"); x != a.XPub {
		t.Fatal("xpub does not come from the phrase")
	}
	// item.get shows the metadata, never the phrase.
	gr := e.call("desktop", "item.get", js(map[string]any{"item_id": id}))
	if c, _ := e.ok(gr).String("category"); c != "crypto_wallet" || strings.Contains(string(gr.Body), vals.Fields[0].Value[:12]) {
		t.Fatal("item metadata")
	}
	// Regtest is not allowed here? It is (test networks); mainnet default; unknown refused.
	e.code(e.sealed("app", "wallet.create", map[string]any{"name": "X", "network": "litecoin"}, map[string]any{"password": pw}, true, false), "bad_request")
}

func TestAddressesAndGuard(t *testing.T) {
	e := newEnv(t, nil)
	id, a := e.importAbandon()
	o := e.ok(e.call("desktop", "wallet.address.new", js(map[string]any{"wallet_id": id, "label": "Shop"})))
	want, _, _ := a.Address(0, 0)
	if got, _ := o.String("address"); got != want || !strings.HasPrefix(got, "bcrt1q") {
		t.Fatal(got)
	}
	if p, _ := o.String("path"); p != "m/84'/1'/0'/0/0" {
		t.Fatal(p)
	}
	e.ok(e.call("app", "wallet.address.new", js(map[string]any{"wallet_id": id, "change": true})))
	l := e.ok(e.call("app", "wallet.address.list", js(map[string]any{"wallet_id": id})))
	arr, _ := l.Array("addresses")
	if len(arr) != 1 {
		t.Fatal("list")
	}
	u := e.ok(e.call("app", "wallet.address.used", js(map[string]any{"wallet_id": id, "addresses": []string{strings.ToUpper(want)}})))
	if m, _ := u.Uint("marked", 0, 10); m != 1 {
		t.Fatal("used")
	}
	// The wallet's item changes only through the wallet; tags stay free.
	e.code(e.sealed("app", "item.put", map[string]any{"version": 1, "sensitivity": "critical"},
		map[string]any{"password": pw, "item_id": id, "item": map[string]any{"name": "x"}}, true, false), "in_use")
	e.code(e.sealed("app", "item.sensitivity", map[string]any{"item_id": id, "version": 1, "sensitivity": "data"},
		map[string]any{"password": pw, "item_id": id}, true, false), "in_use")
	e.ok(e.call("app", "item.tag", js(map[string]any{"item_id": id, "version": 1, "tags": []string{"btc"}})))
	// Roles: agents nothing, desktops no create or sign.
	e.code(e.call("agent", "wallet.list", `{}`), "forbidden")
	e.code(e.call("desktop", "wallet.sign", js(map[string]any{"wallet_id": id, "psbt": "AA=="})), "forbidden")
	e.code(e.call("app", "wallet.balance", js(map[string]any{"wallet_id": id})), "unavailable")
	// Deleting the item deletes the wallet.
	e.ok(e.sealed("app", "item.delete", map[string]any{"item_id": id}, map[string]any{"password": pw, "item_id": id}, true, false))
	l = e.ok(e.call("app", "wallet.list", `{}`))
	if arr, _ := l.Array("wallets"); len(arr) != 0 {
		t.Fatal("wallet survived its item")
	}
	if !e.h.HasActivity("wallet.deleted") {
		t.Fatal("audit")
	}
}

func TestSign(t *testing.T) {
	chain := &fakeChain{}
	e := newEnv(t, chain)
	id, a := e.importAbandon()
	raw := psbtFor(t, a, payee, 70000, 39000)
	// Inspect from a desktop: the vault's own view of amounts and fee.
	in := e.ok(e.call("desktop", "wallet.psbt.inspect", js(map[string]any{"wallet_id": id, "psbt": base64.StdEncoding.EncodeToString(raw)})))
	if fee, _ := in.Uint("fee_sats", 0, 1e9); fee != 1000 {
		t.Fatal(fee)
	}
	if s, _ := in.Uint("sending_sats", 0, 1e9); s != 70000 {
		t.Fatal(s)
	}
	// Spending needs the unlock window.
	e.code(e.sign(id, raw, nil), "credential_locked")
	e.unlock()
	// The password is bound to this PSBT.
	other := psbtFor(t, a, payee, 69000, 40000)
	h := sha256.Sum256(other)
	e.code(e.sealed("app", "wallet.sign", map[string]any{"wallet_id": id, "psbt": base64.StdEncoding.EncodeToString(raw)},
		map[string]any{"password": pw, "item_id": id, "payload_sha256": base64.StdEncoding.EncodeToString(h[:])}, true, false), "bad_request")
	e.code(e.sign(id, psbtFor(t, a, payee, 70000, 100), nil), "invalid_psbt")
	o := e.ok(e.sign(id, raw, map[string]any{"broadcast": true}))
	txHex, _ := o.String("tx")
	txb, _ := hex.DecodeString(txHex)
	tx, err := btc.DecodeTx(txb)
	if err != nil {
		t.Fatal(err)
	}
	if txid, _ := o.String("txid"); txid != tx.TxHash().String() || len(chain.sent) != 1 {
		t.Fatal("txid / broadcast")
	}
	if b, _ := o.Bool("broadcast"); !b {
		t.Fatal("broadcast")
	}
	hist := e.ok(e.call("desktop", "wallet.history", js(map[string]any{"wallet_id": id})))
	if arr, _ := hist.Array("transactions"); len(arr) != 1 {
		t.Fatal("history")
	}
	w := e.wl.Wallets()[0]
	if w.Next[1] != 1 {
		t.Fatal("change index not advanced")
	}
	if !e.h.HasActivity("wallet.signed") {
		t.Fatal("audit")
	}
	chain.unspent = []wallet.Unspent{{Amount: 39000, Confirmed: true}, {Amount: 5, Confirmed: false}}
	bal := e.ok(e.call("app", "wallet.balance", js(map[string]any{"wallet_id": id})))
	if c, _ := bal.Uint("confirmed_sats", 0, 1e9); c != 39000 {
		t.Fatal(c)
	}
}

func invoke(e *env, conn, action string, params map[string]any) string {
	e.t.Helper()
	inv, _ := envelope.NewULID(e.clk.T)
	e.h.Reset()
	r := e.call("connection:"+conn, "action.invocation", js(map[string]any{"invocation_id": inv, "action_id": action, "version": 1, "params": params}))
	if !r.OK() {
		e.t.Fatal(r.Code)
	}
	return inv
}

func lastResult(e *env, conn string) strictjson.Object {
	e.t.Helper()
	rs := e.h.SentOfType("action.result")
	if len(rs) == 0 || rs[len(rs)-1].To != conn {
		e.t.Fatal("no result")
	}
	o, err := strictjson.ParseObject(rs[len(rs)-1].Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return o
}

func TestActions(t *testing.T) {
	e := newEnv(t, nil)
	id, a := e.importAbandon()
	// request-address: allowlisted for cA, naming the wallet.
	e.code(e.call("app", "action.configure", js(map[string]any{"action_id": "wallet.request-address", "mode": "allowlist",
		"connections": []string{cA}, "items": []string{id, id}})), "bad_request")
	e.ok(e.call("app", "action.configure", js(map[string]any{"action_id": "wallet.request-address", "mode": "allowlist",
		"connections": []string{cA}, "items": []string{id}})))
	invoke(e, cA, "wallet.request-address", map[string]any{"asset": "BTC"})
	r := lastResult(e, cA)
	res, _ := r.Object("result")
	first, _ := res.String("address")
	if n, _ := res.String("network"); n != "regtest" {
		t.Fatal(n)
	}
	if want, _, _ := a.Address(0, 0); first != want {
		t.Fatal(first)
	}
	invoke(e, cA, "wallet.request-address", map[string]any{"asset": "BTC"})
	res, _ = lastResult(e, cA).Object("result")
	if again, _ := res.String("address"); again != first {
		t.Fatal("a connection keeps its address until it is used")
	}
	e.ok(e.call("app", "wallet.address.used", js(map[string]any{"wallet_id": id, "addresses": []string{first}})))
	invoke(e, cA, "wallet.request-address", map[string]any{"asset": "BTC"})
	res, _ = lastResult(e, cA).Object("result")
	if next, _ := res.String("address"); next == first {
		t.Fatal("used address reissued")
	}
	invoke(e, cB, "wallet.request-address", map[string]any{"asset": "BTC"})
	if st, _ := lastResult(e, cB).String("status"); st != "unavailable" {
		t.Fatal("not offered to cB")
	}

	// request-payment: critical, prompt-each-time only.
	e.code(e.call("app", "action.configure", js(map[string]any{"action_id": "wallet.request-payment", "mode": "allowlist",
		"connections": []string{cA}, "items": []string{id}})), "bad_request")
	e.ok(e.call("app", "action.configure", js(map[string]any{"action_id": "wallet.request-payment", "mode": "prompt-each-time",
		"connections": []string{cA}, "items": []string{id}})))
	inv := invoke(e, cA, "wallet.request-payment", map[string]any{"asset": "BTC", "amount_sats": 70000, "address": payee, "memo": "lunch"})
	if len(e.h.SentOfType("action.pending")) != 1 {
		t.Fatal("pending")
	}
	raw := psbtFor(t, a, payee, 70000, 39000)
	approve := func(psbt []byte) featuretest.Result {
		h := sha256.Sum256(psbt)
		return e.sealed("app", "action.respond", map[string]any{"invocation_id": inv, "approve": true, "psbt": base64.StdEncoding.EncodeToString(psbt)},
			map[string]any{"password": pw, "item_id": id, "request_id": inv, "payload_sha256": base64.StdEncoding.EncodeToString(h[:])}, true, false)
	}
	e.code(approve(raw), "credential_locked")
	e.unlock()
	e.code(e.call("desktop", "action.respond", js(map[string]any{"invocation_id": inv, "approve": true})), "forbidden")
	e.code(approve(psbtFor(t, a, payee, 60000, 49000)), "invalid_psbt") // another amount
	if len(e.act.PendingInvocations()) != 1 {
		t.Fatal("a refused approval must leave the invocation pending")
	}
	e.h.Reset()
	o := e.ok(approve(raw))
	txid, _ := o.String("txid")
	rr := lastResult(e, cA)
	if st, _ := rr.String("status"); st != "ok" {
		t.Fatal(st)
	}
	res, _ = rr.Object("result")
	if got, _ := res.String("txid"); got != txid {
		t.Fatal("txid to the connection")
	}
	if len(e.act.PendingInvocations()) != 0 {
		t.Fatal("still pending")
	}
	w := e.wl.Wallets()[0]
	if w.History[len(w.History)-1].Conn != cA {
		t.Fatal("history connection")
	}
}

func TestPayAddressNetwork(t *testing.T) {
	e := newEnv(t, nil)
	id, _ := e.importAbandon()
	e.unlock()
	e.ok(e.call("app", "action.configure", js(map[string]any{"action_id": "wallet.request-payment", "mode": "prompt-each-time",
		"connections": []string{cA}, "items": []string{id}})))
	inv := invoke(e, cA, "wallet.request-payment", map[string]any{"asset": "BTC", "amount_sats": 5000, "address": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"})
	r := e.call("app", "action.respond", js(map[string]any{"invocation_id": inv, "approve": true, "psbt": "AA=="}))
	if r.Code != "invalid_psbt" {
		t.Fatal(r.Code, "a mainnet payee for a regtest wallet")
	}
}

func FuzzParseCreate(f *testing.F) {
	f.Add([]byte(`{"name":"x","network":"regtest","tags":["a"]}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = wallet.ParseCreate(b) })
}

func FuzzParseImport(f *testing.F) {
	f.Add([]byte(`{"mnemonic":"` + abandon + `","passphrase":"TREZOR"}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = wallet.ParseImport(b) })
}
