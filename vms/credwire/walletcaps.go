package credwire

import (
	"crypto/sha256"
	"strconv"
)

// WalletCapsLabel is the label of the binding of wallet.caps.raise
// (VAULT-MESSAGING §10.18 "Spend caps").
const WalletCapsLabel = "vettid/wallet.caps/1"

// WalletCapsBinding is the payload_sha256 of wallet.caps.raise: the
// SHA-256 of the ASCII label, 0x00, wallet_id, 0x00, version, 0x00,
// per_tx, 0x00, per_period (each field in UTF-8, 0x00 between them and
// none after the last). version is in decimal ASCII without leading
// zeros; perTx and perPeriod are the values the wallet will have after
// the request, in decimal ASCII without leading zeros, or nil for the
// literal "none" (no limit). The password and PIN so authorise these
// numbers on this wallet only.
func WalletCapsBinding(walletID string, version uint64, perTx, perPeriod *int64) [sha256.Size]byte {
	field := func(v *int64) string {
		if v == nil {
			return "none"
		}
		return strconv.FormatInt(*v, 10)
	}
	b := []byte(WalletCapsLabel)
	for _, f := range []string{walletID, strconv.FormatUint(version, 10), field(perTx), field(perPeriod)} {
		b = append(b, 0)
		b = append(b, f...)
	}
	return sha256.Sum256(b)
}
