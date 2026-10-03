package client

import (
	"context"
	"crypto/sha256"
	"encoding/base64"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/btc"
)

// The wallet (VAULT-MESSAGING §10.18). The app is the chain source: it
// finds the account's coins with its own chain access, builds a PSBT
// (btc.BuildPSBT in Go), shows the vault's wallet.psbt.inspect summary,
// and after signing broadcasts the transaction itself.

// WalletCreate creates a BIP84 wallet whose recovery phrase is a new
// critical item. mnemonic "" lets the vault generate a 24-word phrase;
// otherwise it is imported (with an optional BIP39 passphrase).
func (d *Device) WalletCreate(ctx context.Context, password, name, network, mnemonic, passphrase string, tags []string) (strictjson.Object, error) {
	return d.WalletCreateType(ctx, password, name, network, "", mnemonic, passphrase, tags)
}

// WalletCreateType is WalletCreate with the account to receive on ("":
// the default, p2tr).
func (d *Device) WalletCreateType(ctx context.Context, password, name, network, addressType, mnemonic, passphrase string, tags []string) (strictjson.Object, error) {
	extra := map[string]any{"name": name}
	if addressType != "" {
		extra["address_type"] = addressType
	}
	if network != "" {
		extra["network"] = network
	}
	if tags != nil {
		extra["tags"] = tags
	}
	o, _, _, err := d.credOpWith(ctx, "wallet.create", extra, func() map[string]any {
		p := map[string]any{"password": password}
		if mnemonic != "" {
			im := map[string]any{"mnemonic": mnemonic}
			if passphrase != "" {
				im["passphrase"] = passphrase
			}
			p["item"] = im
		}
		return p
	}, false)
	return o, err
}

// WalletList lists the wallets (public keys and bookkeeping only).
func (d *Device) WalletList(ctx context.Context) (strictjson.Object, error) {
	return d.Op(ctx, "wallet.list", nil)
}

// WalletAccounts returns a wallet's accounts (their public halves, by
// address type: "p2tr", "p2wpkh") and the type it receives on, for
// scanning the chain, deriving addresses and building PSBTs locally.
func (d *Device) WalletAccounts(ctx context.Context, walletID string) (map[string]*btc.Account, string, error) {
	o, err := d.Op(ctx, "wallet.get", map[string]any{"wallet_id": walletID})
	if err != nil {
		return nil, "", err
	}
	n, _ := o.String("network")
	fp, _ := o.String("fingerprint")
	recv, _ := o.String("address_type")
	arr, err := o.Array("accounts")
	if err != nil {
		return nil, "", ErrProtocol
	}
	out := map[string]*btc.Account{}
	for _, raw := range arr {
		ao, err := strictjson.ParseObject(raw)
		if err != nil {
			return nil, "", ErrProtocol
		}
		t, _ := ao.String("type")
		x, _ := ao.String("xpub")
		a, err := btc.ParseAccount(n, t, fp, x)
		if err != nil {
			return nil, "", ErrProtocol
		}
		out[t] = a
	}
	return out, recv, nil
}

// WalletUpdate sets the account the wallet receives on ("p2tr" or
// "p2wpkh"), for example after scanning an imported phrase's accounts.
func (d *Device) WalletUpdate(ctx context.Context, walletID string, version uint64, addressType string) (uint64, error) {
	o, err := d.Op(ctx, "wallet.update", map[string]any{"wallet_id": walletID, "version": version, "address_type": addressType})
	if err != nil {
		return 0, err
	}
	return o.Uint("version", 1, strictjson.MaxSafeInteger)
}

// WalletAddressNew issues the next receive (or change) address of the
// account the wallet receives on.
func (d *Device) WalletAddressNew(ctx context.Context, walletID string, change bool, label string) (strictjson.Object, error) {
	return d.WalletAddressNewType(ctx, walletID, "", change, label)
}

// WalletAddressNewType is WalletAddressNew for one account ("": the
// receiving one).
func (d *Device) WalletAddressNewType(ctx context.Context, walletID, addressType string, change bool, label string) (strictjson.Object, error) {
	body := map[string]any{"wallet_id": walletID}
	if addressType != "" {
		body["type"] = addressType
	}
	if change {
		body["change"] = true
	}
	if label != "" {
		body["label"] = label
	}
	return d.Op(ctx, "wallet.address.new", body)
}

// WalletAddressList lists issued addresses (filter: change, after, limit).
func (d *Device) WalletAddressList(ctx context.Context, walletID string, filter map[string]any) (strictjson.Object, error) {
	body := map[string]any{"wallet_id": walletID}
	for k, v := range filter {
		body[k] = v
	}
	return d.Op(ctx, "wallet.address.list", body)
}

// WalletAddressUsed reports addresses the app saw funded on chain.
func (d *Device) WalletAddressUsed(ctx context.Context, walletID string, addresses []string) (strictjson.Object, error) {
	return d.Op(ctx, "wallet.address.used", map[string]any{"wallet_id": walletID, "addresses": addresses})
}

// WalletInspect returns the vault's view of a PSBT: what it would sign.
func (d *Device) WalletInspect(ctx context.Context, walletID string, psbt []byte) (strictjson.Object, error) {
	return d.Op(ctx, "wallet.psbt.inspect", map[string]any{"wallet_id": walletID, "psbt": base64.StdEncoding.EncodeToString(psbt)})
}

// WalletSign signs a PSBT with the wallet's recovery phrase: one
// credential operation bound to the wallet and the PSBT's hash, within
// the unlock window. The response holds the summary and `tx` (hex).
func (d *Device) WalletSign(ctx context.Context, password, walletID string, psbt []byte) (strictjson.Object, error) {
	h := sha256.Sum256(psbt)
	o, _, _, err := d.credOpWith(ctx, "wallet.sign", map[string]any{"wallet_id": walletID, "psbt": base64.StdEncoding.EncodeToString(psbt)},
		func() map[string]any {
			return map[string]any{"password": password, "item_id": walletID, "payload_sha256": base64.StdEncoding.EncodeToString(h[:])}
		}, false)
	return o, err
}

// WalletHistory lists the transactions the vault signed, newest first.
func (d *Device) WalletHistory(ctx context.Context, walletID string, limit int) (strictjson.Object, error) {
	body := map[string]any{"wallet_id": walletID}
	if limit > 0 {
		body["limit"] = limit
	}
	return d.Op(ctx, "wallet.history", body)
}

// WalletPay approves a pending wallet.request-payment invocation with a
// PSBT that pays exactly the requested amount to the requested address:
// a credential operation bound to the invocation, the wallet and the
// PSBT's hash (§10.14, §10.18). The response holds txid, the summary and
// `tx` for the app to broadcast.
func (d *Device) WalletPay(ctx context.Context, password, invocationID, walletID string, psbt []byte) (strictjson.Object, error) {
	h := sha256.Sum256(psbt)
	o, _, _, err := d.credOpWith(ctx, "action.respond", map[string]any{"invocation_id": invocationID, "approve": true,
		"psbt": base64.StdEncoding.EncodeToString(psbt)},
		func() map[string]any {
			return map[string]any{"password": password, "item_id": walletID, "request_id": invocationID,
				"payload_sha256": base64.StdEncoding.EncodeToString(h[:])}
		}, false)
	return o, err
}
