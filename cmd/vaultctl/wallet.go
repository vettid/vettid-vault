package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"os"
	"strconv"
	"strings"

	"github.com/vettid/vettid-vault/client"
	cwallet "github.com/vettid/vettid-vault/client/wallet"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/btc"
)

// The wallet (VAULT-MESSAGING §10.18). vaultctl is not a chain client: it
// signs PSBTs that another tool built (or, on regtest, the synthetic test
// PSBTs of `wallet test-psbt`) and prints the signed transaction for
// broadcasting elsewhere.

func init() {
	commands["wallet"] = command{"wallet create -name N [-network mainnet|testnet|signet|regtest] [-type p2tr|p2wpkh] [-tags a,b] [-import] " +
		"(password in VAULTCTL_PASSWORD; an imported phrase in VAULTCTL_MNEMONIC, passphrase in VAULTCTL_PASSPHRASE) | list | " +
		"address -wallet ID [-type p2tr|p2wpkh] [-change] [-label L] | addresses -wallet ID [-type T] [-change] | " +
		"receive -wallet ID -version N -type p2tr|p2wpkh | used -wallet ID -addresses a,b | " +
		"inspect -wallet ID -psbt FILE | sign -wallet ID -psbt FILE | pay -wallet ID -invocation ID -psbt FILE | history -wallet ID | " +
		"caps-set -wallet ID [-version N] [-per-tx SATS] [-per-period SATS] (lowers only) | " +
		"caps-raise -wallet ID [-version N] [-per-tx SATS|none] [-per-period SATS|none] (raises or removes; a member left out stays; PIN in VAULTCTL_PIN, password in VAULTCTL_PASSWORD) | " +
		"test-psbt -wallet ID -to ADDR -amount SATS -out FILE (regtest only: spends a synthetic coin)", cmdWallet}
}

func readPSBT(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(b))
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	return b, nil // binary PSBT
}

func cmdWallet(ctx context.Context, g *globals, args []string) error {
	op, rest, err := sub(args, commands["wallet"].usage)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("wallet "+op, flag.ExitOnError)
	name := fs.String("name", "", "wallet name")
	network := fs.String("network", "", "network (default mainnet)")
	tags := fs.String("tags", "", "comma-separated tags of the wallet's item")
	typ := fs.String("type", "", "address type: p2tr (default for new wallets) or p2wpkh")
	version := fs.Uint64("version", 0, "wallet version (receive)")
	imp := fs.Bool("import", false, "import the phrase in VAULTCTL_MNEMONIC")
	wallet := fs.String("wallet", "", "wallet id")
	change := fs.Bool("change", false, "change chain")
	label := fs.String("label", "", "address label")
	addrs := fs.String("addresses", "", "comma-separated addresses")
	psbtFile := fs.String("psbt", "", "PSBT file (binary or base64)")
	inv := fs.String("invocation", "", "wallet.request-payment invocation id")
	to := fs.String("to", "", "payee address (test-psbt)")
	amount := fs.Int64("amount", 0, "amount in satoshis (test-psbt)")
	out := fs.String("out", "", "output file (test-psbt)")
	perTx := fs.String("per-tx", "", "per-transaction cap in satoshis (caps-set, caps-raise; none: no limit)")
	perPeriod := fs.String("per-period", "", "per-period cap in satoshis (caps-set, caps-raise; none: no limit)")
	_ = fs.Parse(rest)
	return withDevice(ctx, g, func(d *client.Device) (any, error) {
		switch op {
		case "create":
			pw, err := password("VAULTCTL_PASSWORD")
			if err != nil {
				return nil, err
			}
			m, pp := "", ""
			if *imp {
				if m = os.Getenv("VAULTCTL_MNEMONIC"); m == "" {
					return nil, errors.New("VAULTCTL_MNEMONIC is not set")
				}
				pp = os.Getenv("VAULTCTL_PASSPHRASE")
			}
			return cwallet.CreateType(ctx, d, pw, *name, *network, *typ, m, pp, commaList(*tags))
		case "list":
			return cwallet.List(ctx, d)
		case "address":
			return cwallet.AddressNewType(ctx, d, *wallet, *typ, *change, *label)
		case "addresses":
			f := map[string]any{"change": *change}
			if *typ != "" {
				f["type"] = *typ
			}
			return cwallet.AddressList(ctx, d, *wallet, f)
		case "receive":
			v, err := cwallet.Update(ctx, d, *wallet, *version, *typ)
			return map[string]uint64{"version": v}, err
		case "used":
			return cwallet.AddressUsed(ctx, d, *wallet, commaList(*addrs))
		case "inspect", "sign", "pay":
			raw, err := readPSBT(*psbtFile)
			if err != nil {
				return nil, err
			}
			if op == "inspect" {
				return cwallet.Inspect(ctx, d, *wallet, raw)
			}
			pw, err := password("VAULTCTL_PASSWORD")
			if err != nil {
				return nil, err
			}
			if op == "sign" {
				return cwallet.Sign(ctx, d, pw, *wallet, raw)
			}
			return cwallet.Pay(ctx, d, pw, *inv, *wallet, raw)
		case "history":
			return cwallet.History(ctx, d, *wallet, 0)
		case "caps-set", "caps-raise":
			return walletCaps(ctx, d, op == "caps-raise", *wallet, *version, *perTx, *perPeriod)
		case "test-psbt":
			accts, recv, err := cwallet.Accounts(ctx, d, *wallet)
			if err != nil {
				return nil, err
			}
			a := accts[recv]
			if a.Network.Name != btc.Regtest {
				return nil, errors.New("test-psbt: regtest wallets only")
			}
			raw, err := TestPSBT(a, *to, *amount)
			if err != nil {
				return nil, err
			}
			return map[string]string{"psbt": *out}, os.WriteFile(*out, []byte(base64.StdEncoding.EncodeToString(raw)), 0o600)
		}
		return nil, errors.New(commands["wallet"].usage)
	})
}

// capValue parses a cap flag: "" is absent, "none" no limit, else sats.
func capValue(s string) (v *int64, none bool, err error) {
	switch s {
	case "":
		return nil, false, nil
	case "none":
		return nil, true, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 1 {
		return nil, false, errors.New("a cap is a whole number of satoshis, or none")
	}
	return &n, false, nil
}

// walletCaps is caps-set and caps-raise. The wallet's version defaults to
// the current one; for a raise a member left out keeps its current value
// (the request carries the values the wallet will have).
func walletCaps(ctx context.Context, d *client.Device, raise bool, id string, version uint64, perTx, perPeriod string) (any, error) {
	tx, txNone, err := capValue(perTx)
	if err != nil {
		return nil, err
	}
	per, perNone, err := capValue(perPeriod)
	if err != nil {
		return nil, err
	}
	cur, err := d.Op(ctx, "wallet.get", map[string]any{"wallet_id": id})
	if err != nil {
		return nil, err
	}
	if version == 0 {
		if version, err = cur.Uint("version", 1, strictjson.MaxSafeInteger); err != nil {
			return nil, client.ErrProtocol
		}
	}
	if !raise {
		if txNone || perNone {
			return nil, errors.New("caps-set only lowers: use caps-raise to remove a limit")
		}
		v, err := cwallet.CapsSet(ctx, d, id, version, tx, per)
		return map[string]uint64{"version": v}, err
	}
	caps, _ := cur.Object("caps")
	keep := func(given *int64, none bool, k string) *int64 {
		if given != nil || none {
			return given
		}
		if v, err := caps.Uint(k, 1, strictjson.MaxSafeInteger); err == nil {
			n := int64(v)
			return &n
		}
		return nil
	}
	pin, err := password("VAULTCTL_PIN")
	if err != nil {
		return nil, err
	}
	pw, err := password("VAULTCTL_PASSWORD")
	if err != nil {
		return nil, err
	}
	return cwallet.CapsRaise(ctx, d, pin, pw, id, version, keep(tx, txNone, "per_tx_sats"), keep(per, perNone, "per_period_sats"))
}

// TestPSBT spends one synthetic coin of 1,000,000 sats at the receiving
// account's first receive address: amount to `to`, a fee of 1,000 sats, the rest to
// change 1/0. Regtest only; the coin does not exist on any chain.
func TestPSBT(a *btc.Account, to string, amount int64) ([]byte, error) {
	const coin, fee = 1000000, 1000
	if amount <= 0 || amount > coin-fee-btc.MinOutput {
		return nil, errors.New("test-psbt: amount out of range")
	}
	f, err := btc.FundingTx(a, 0, 0, coin, 7)
	if err != nil {
		return nil, err
	}
	return btc.BuildPSBT(a, []btc.Coin{{PrevTx: f, Vout: 0, Chain: 0, Index: 0}},
		[]btc.Payee{{Address: to, Amount: amount}, {Change: true, Chain: 1, Index: 0, Amount: coin - fee - amount}})
}
