//go:build devenclave && e2e

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/client/wallet"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/btc"
)

// Wallet spend caps and the ledger are part of the wallet's DEK state
// (VAULT-MESSAGING 0.82.0 §10.18 "Restore, transfer, recovery"): they move
// with the vault through a phone transfer (§6.7.1) and a recovery
// (§11.11) unchanged, so a new phone has the same remaining allowance;
// credential.reset deletes the wallets and so their caps.

// cappedWallet makes a regtest wallet on d with per_period_sats 100,000
// and 60,000 of it spent, and returns its id and a PSBT builder.
func cappedWallet(t *testing.T, ctx context.Context, d *client.Device) (string, func(out int64) []byte) {
	t.Helper()
	o, err := wallet.CreateType(ctx, d, credPW, "Savings", "regtest", "p2wpkh", bip84Phrase, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	wid, _ := o.String("wallet_id")
	accts, _, err := wallet.Accounts(ctx, d, wid)
	if err != nil {
		t.Fatal(err)
	}
	acct := accts["p2wpkh"]
	psbt := func(out int64) []byte {
		coin, _ := btc.FundingTx(acct, 0, 0, 1000000, 9)
		raw, err := btc.BuildPSBT(acct, []btc.Coin{{PrevTx: coin, Vout: 0}},
			[]btc.Payee{{Address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", Amount: out}, {Change: true, Chain: 1, Index: 0, Amount: 1000000 - 1000 - out}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	v := uint64(1)
	per := int64(100000)
	if _, err := wallet.CapsSet(ctx, d, wid, v, nil, &per); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	if _, err := wallet.Sign(ctx, d, credPW, wid, psbt(59000)); err != nil {
		t.Fatal(err)
	}
	return wid, psbt
}

// sameAllowance checks the wallet on d: the caps, 60,000 spent, and what
// the vault says of a spend of 41,000 (over by one) and 40,000 (fits).
func sameAllowance(t *testing.T, ctx context.Context, d *client.Device, wid string, psbt func(int64) []byte) {
	t.Helper()
	w, err := d.Op(ctx, "wallet.get", map[string]any{"wallet_id": wid})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := w.Object("caps")
	if p, _ := c.Uint("per_period_sats", 0, strictjson.MaxSafeInteger); p != 100000 {
		t.Fatalf("caps %s", w["caps"])
	}
	if s, _ := c.Uint("spent_sats", 0, strictjson.MaxSafeInteger); s != 60000 {
		t.Fatalf("caps %s", w["caps"])
	}
	for out, wantOK := range map[int64]bool{40000: true, 40001: false} {
		in, err := wallet.Inspect(ctx, d, wid, psbt(out-1000))
		if err != nil {
			t.Fatal(err)
		}
		cp, _ := in.Object("cap")
		if ok, _ := cp.Bool("ok"); ok != wantOK {
			t.Fatalf("outflow %d: cap %s", out, in["cap"])
		}
		if !wantOK {
			if rem, _ := cp.Uint("remaining_sats", 0, strictjson.MaxSafeInteger); rem != 40000 {
				t.Fatalf("cap %s", in["cap"])
			}
		}
	}
}

// A phone transfer (§6.7.1) keeps the caps and the ledger: the new phone
// has the same remaining allowance, and its spend over it is refused.
func TestWalletCapsTransfer(t *testing.T) {
	aw := newACWorld(t)
	a := aw.newApp("member-wc-tr", enclavetest.NewAndroidAttester(0x85, enclavetest.AndroidOptions{}))
	if r := aw.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	ctx := ctxT(t, 240*time.Second)
	wid, psbt := cappedWallet(t, ctx, a.dev)

	id, link, err := a.dev.TransferCreate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b := aw.newApp("new-phone-wc", enclavetest.NewIOSAttester(0x95, enclavetest.IOSOptions{}))
	if _, err := b.dev.PairAttested(ctx, link, b.att); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, a.dev, "device.transfer.pending", has("transfer_id", id))
	if err := a.dev.TransferApprove(ctx, id, acPIN, credPW); err != nil {
		t.Fatal(err)
	}
	if err := b.dev.AwaitPaired(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.dev.CredentialFetch(ctx); err != nil {
		t.Fatal(err)
	}
	sameAllowance(t, ctx, b.dev, wid, psbt)
	if _, err := b.dev.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}
	if _, err := wallet.Sign(ctx, b.dev, credPW, wid, psbt(40000)); client.Code(err) != "cap_exceeded" {
		t.Fatalf("over the remaining allowance on the new phone: %v", err)
	}
	if _, err := wallet.Sign(ctx, b.dev, credPW, wid, psbt(39000)); err != nil {
		t.Fatalf("within it: %v", err)
	}
}

// A recovery (§11.11) keeps the caps and the ledger: the recovered phone
// has the same remaining allowance.
func TestWalletCapsRecovery(t *testing.T) {
	aw, off := newRecWorld(t)
	a := aw.newApp("member-wc-rr", enclavetest.NewAndroidAttester(0x86, enclavetest.AndroidOptions{}))
	if r := aw.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	ctx := ctxT(t, 240*time.Second)
	wid, psbt := cappedWallet(t, ctx, a.dev)

	qr := requestRecovery(t, aw, a)
	off.Store(int64(24*time.Hour + time.Minute))
	b := aw.newApp(a.guid, enclavetest.NewIOSAttester(0x96, enclavetest.IOSOptions{}))
	b.vid = a.vid
	if res := register(t, aw, b, qr); !res.OK {
		t.Fatalf("register: %+v", res)
	}
	if r := openRecovery(t, aw, b, acPIN, credPW); !r.OK {
		t.Fatalf("open: %+v", r)
	}
	if err := b.dev.CompleteRecoveryHandshake(ctx); err != nil {
		t.Fatal(err)
	}
	sameAllowance(t, ctx, b.dev, wid, psbt)
}

// credential.reset deletes the wallets and so their caps and ledgers: the
// same phrase imported again starts with neither.
func TestWalletCapsReset(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	ctx := ctxT(t, 180*time.Second)
	wid, psbt := cappedWallet(t, ctx, a.app)
	sameAllowance(t, ctx, a.app, wid, psbt)

	if err := a.app.CredentialResetHolder(ctx, pin, credPW, credPW); err != nil {
		t.Fatal(err)
	}
	l, err := wallet.List(ctx, a.app)
	if err != nil {
		t.Fatal(err)
	}
	if arr, _ := l.Array("wallets"); len(arr) != 0 {
		t.Fatalf("wallets after the reset: %s", l["wallets"])
	}
	if _, err := a.app.Op(ctx, "wallet.get", map[string]any{"wallet_id": wid}); client.Code(err) != "not_found" {
		t.Fatalf("wallet.get after the reset: %v", err)
	}
	o, err := wallet.CreateType(ctx, a.app, credPW, "Again", "regtest", "p2wpkh", bip84Phrase, "", nil)
	if err != nil {
		t.Fatalf("the phrase imported again: %v", err)
	}
	c, _ := o.Object("caps")
	if c.Has("per_period_sats") || c.Has("per_tx_sats") {
		t.Fatalf("caps %s", o["caps"])
	}
	if s, _ := c.Uint("spent_sats", 0, strictjson.MaxSafeInteger); s != 0 {
		t.Fatalf("caps %s", o["caps"])
	}
}
