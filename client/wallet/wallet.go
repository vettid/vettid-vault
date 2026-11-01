// Package wallet is the client side of the wallet (VAULT-MESSAGING
// §10.18). It is a package of its own so that importers of client do not
// compile the Bitcoin libraries (vms/btc) unless they use the wallet.
package wallet

import (
	"context"
	"crypto/sha256"
	"encoding/base64"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/btc"
	"github.com/vettid/vettid-vault/vms/credwire"
)

// The wallet (VAULT-MESSAGING §10.18). The app is the chain source: it
// finds the account's coins with its own chain access, builds a PSBT
// (btc.BuildPSBT in Go), shows the vault's wallet.psbt.inspect summary,
// and after signing broadcasts the transaction itself.

// Create creates a BIP84 wallet whose recovery phrase is a new
// critical item. mnemonic "" lets the vault generate a 24-word phrase;
// otherwise it is imported (with an optional BIP39 passphrase).
func Create(ctx context.Context, d *client.Device, password, name, network, mnemonic, passphrase string, tags []string) (strictjson.Object, error) {
	return CreateType(ctx, d, password, name, network, "", mnemonic, passphrase, tags)
}

// CreateType is Create with the account to receive on ("": the
// default, p2tr).
func CreateType(ctx context.Context, d *client.Device, password, name, network, addressType, mnemonic, passphrase string, tags []string) (strictjson.Object, error) {
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
	return d.CredentialOp(ctx, "wallet.create", extra, func() map[string]any {
		p := map[string]any{"password": password}
		if mnemonic != "" {
			im := map[string]any{"mnemonic": mnemonic}
			if passphrase != "" {
				im["passphrase"] = passphrase
			}
			p["item"] = im
		}
		return p
	})
}

// List lists the wallets (public keys and bookkeeping only).
func List(ctx context.Context, d *client.Device) (strictjson.Object, error) {
	return d.Op(ctx, "wallet.list", nil)
}

// Accounts returns a wallet's accounts (their public halves, by
// address type: "p2tr", "p2wpkh") and the type it receives on, for
// scanning the chain, deriving addresses and building PSBTs locally.
func Accounts(ctx context.Context, d *client.Device, walletID string) (map[string]*btc.Account, string, error) {
	o, err := d.Op(ctx, "wallet.get", map[string]any{"wallet_id": walletID})
	if err != nil {
		return nil, "", err
	}
	n, _ := o.String("network")
	fp, _ := o.String("fingerprint")
	recv, _ := o.String("address_type")
	arr, err := o.Array("accounts")
	if err != nil {
		return nil, "", client.ErrProtocol
	}
	out := map[string]*btc.Account{}
	for _, raw := range arr {
		ao, err := strictjson.ParseObject(raw)
		if err != nil {
			return nil, "", client.ErrProtocol
		}
		t, _ := ao.String("type")
		x, _ := ao.String("xpub")
		a, err := btc.ParseAccount(n, t, fp, x)
		if err != nil {
			return nil, "", client.ErrProtocol
		}
		out[t] = a
	}
	return out, recv, nil
}

// Update sets the account the wallet receives on ("p2tr" or
// "p2wpkh"), for example after scanning an imported phrase's accounts.
func Update(ctx context.Context, d *client.Device, walletID string, version uint64, addressType string) (uint64, error) {
	o, err := d.Op(ctx, "wallet.update", map[string]any{"wallet_id": walletID, "version": version, "address_type": addressType})
	if err != nil {
		return 0, err
	}
	return o.Uint("version", 1, strictjson.MaxSafeInteger)
}

// AddressNew issues the next receive (or change) address of the
// account the wallet receives on.
func AddressNew(ctx context.Context, d *client.Device, walletID string, change bool, label string) (strictjson.Object, error) {
	return AddressNewType(ctx, d, walletID, "", change, label)
}

// AddressNewType is AddressNew for one account ("": the
// receiving one).
func AddressNewType(ctx context.Context, d *client.Device, walletID, addressType string, change bool, label string) (strictjson.Object, error) {
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

// AddressList lists issued addresses (filter: change, after, limit).
func AddressList(ctx context.Context, d *client.Device, walletID string, filter map[string]any) (strictjson.Object, error) {
	body := map[string]any{"wallet_id": walletID}
	for k, v := range filter {
		body[k] = v
	}
	return d.Op(ctx, "wallet.address.list", body)
}

// AddressUsed reports addresses the app saw funded on chain.
func AddressUsed(ctx context.Context, d *client.Device, walletID string, addresses []string) (strictjson.Object, error) {
	return d.Op(ctx, "wallet.address.used", map[string]any{"wallet_id": walletID, "addresses": addresses})
}

// Inspect returns the vault's view of a PSBT: what it would sign.
func Inspect(ctx context.Context, d *client.Device, walletID string, psbt []byte) (strictjson.Object, error) {
	return d.Op(ctx, "wallet.psbt.inspect", map[string]any{"wallet_id": walletID, "psbt": base64.StdEncoding.EncodeToString(psbt)})
}

// Sign signs a PSBT with the wallet's recovery phrase: one
// credential operation bound to the wallet and the PSBT's hash, within
// the unlock window. The response holds the summary and `tx` (hex).
func Sign(ctx context.Context, d *client.Device, password, walletID string, psbt []byte) (strictjson.Object, error) {
	h := sha256.Sum256(psbt)
	return d.CredentialOp(ctx, "wallet.sign", map[string]any{"wallet_id": walletID, "psbt": base64.StdEncoding.EncodeToString(psbt)},
		func() map[string]any {
			return map[string]any{"password": password, "item_id": walletID, "payload_sha256": base64.StdEncoding.EncodeToString(h[:])}
		})
}

// History lists the transactions the vault signed, newest first.
func History(ctx context.Context, d *client.Device, walletID string, limit int) (strictjson.Object, error) {
	body := map[string]any{"wallet_id": walletID}
	if limit > 0 {
		body["limit"] = limit
	}
	return d.Op(ctx, "wallet.history", body)
}

// Pay approves a pending wallet.request-payment invocation with a
// PSBT that pays exactly the requested amount to the requested address:
// a credential operation bound to the invocation, the wallet and the
// PSBT's hash (§10.14, §10.18). The response holds txid, the summary and
// `tx` for the app to broadcast.
func Pay(ctx context.Context, d *client.Device, password, invocationID, walletID string, psbt []byte) (strictjson.Object, error) {
	h := sha256.Sum256(psbt)
	return d.CredentialOp(ctx, "action.respond", map[string]any{"invocation_id": invocationID, "approve": true,
		"psbt": base64.StdEncoding.EncodeToString(psbt)},
		func() map[string]any {
			return map[string]any{"password": password, "item_id": walletID, "request_id": invocationID,
				"payload_sha256": base64.StdEncoding.EncodeToString(h[:])}
		})
}

// CapsSet sets or lowers a wallet's spend caps (wallet.caps.set,
// §10.18, 0.56.0): a versioned change that may only lower; a nil member
// is not sent (unchanged). It returns the wallet's version.
func CapsSet(ctx context.Context, d *client.Device, walletID string, version uint64, perTxSats, perPeriodSats *int64) (uint64, error) {
	body := map[string]any{"wallet_id": walletID, "version": version}
	if perTxSats != nil {
		body["per_tx_sats"] = *perTxSats
	}
	if perPeriodSats != nil {
		body["per_period_sats"] = *perPeriodSats
	}
	o, err := d.Op(ctx, "wallet.caps.set", body)
	if err != nil {
		return 0, err
	}
	return o.Uint("version", 1, strictjson.MaxSafeInteger)
}

// CapsRaise raises or removes a wallet's spend caps (wallet.caps.raise,
// §10.18, 0.56.0): one credential operation with the PIN and the
// password, bound to the values the wallet will have after the request.
// perTxSats and perPeriodSats are those values, both always sent; nil is
// no limit. The response holds the wallet's new version.
func CapsRaise(ctx context.Context, d *client.Device, pin, password, walletID string, version uint64, perTxSats, perPeriodSats *int64) (strictjson.Object, error) {
	h := credwire.WalletCapsBinding(walletID, version, perTxSats, perPeriodSats)
	member := func(v *int64) any {
		if v == nil {
			return nil // JSON null: no limit
		}
		return *v
	}
	return d.CredentialOp(ctx, "wallet.caps.raise", map[string]any{"wallet_id": walletID, "version": version,
		"per_tx_sats": member(perTxSats), "per_period_sats": member(perPeriodSats)},
		func() map[string]any {
			return map[string]any{"pin": pin, "password": password, "item_id": walletID, "payload_sha256": base64.StdEncoding.EncodeToString(h[:])}
		})
}
