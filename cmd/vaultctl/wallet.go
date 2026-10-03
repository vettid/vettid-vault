package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"os"
	"strings"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/vms/btc"
)

// The wallet (VAULT-MESSAGING §10.18). vaultctl is not a chain client: it
// signs PSBTs that another tool built (or, on regtest, the synthetic test
// PSBTs of `wallet test-psbt`) and prints the signed transaction for
// broadcasting elsewhere.

func init() {
	commands["wallet"] = command{"wallet create -name N [-network mainnet|testnet|signet|regtest] [-tags a,b] [-import] " +
		"(password in VAULTCTL_PASSWORD; an imported phrase in VAULTCTL_MNEMONIC, passphrase in VAULTCTL_PASSPHRASE) | list | " +
		"address -wallet ID [-change] [-label L] | addresses -wallet ID [-change] | used -wallet ID -addresses a,b | " +
		"inspect -wallet ID -psbt FILE | sign -wallet ID -psbt FILE | pay -wallet ID -invocation ID -psbt FILE | history -wallet ID | " +
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
			return d.WalletCreate(ctx, pw, *name, *network, m, pp, commaList(*tags))
		case "list":
			return d.WalletList(ctx)
		case "address":
			return d.WalletAddressNew(ctx, *wallet, *change, *label)
		case "addresses":
			return d.WalletAddressList(ctx, *wallet, map[string]any{"change": *change})
		case "used":
			return d.WalletAddressUsed(ctx, *wallet, commaList(*addrs))
		case "inspect", "sign", "pay":
			raw, err := readPSBT(*psbtFile)
			if err != nil {
				return nil, err
			}
			if op == "inspect" {
				return d.WalletInspect(ctx, *wallet, raw)
			}
			pw, err := password("VAULTCTL_PASSWORD")
			if err != nil {
				return nil, err
			}
			if op == "sign" {
				return d.WalletSign(ctx, pw, *wallet, raw)
			}
			return d.WalletPay(ctx, pw, *inv, *wallet, raw)
		case "history":
			return d.WalletHistory(ctx, *wallet, 0)
		case "test-psbt":
			a, err := d.WalletAccount(ctx, *wallet)
			if err != nil {
				return nil, err
			}
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

// TestPSBT spends one synthetic coin of 1,000,000 sats at the account's
// first receive address: amount to `to`, a fee of 1,000 sats, the rest to
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
