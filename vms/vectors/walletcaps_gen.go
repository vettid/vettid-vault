//go:build vmsvectors

package vectors

import (
	"crypto/sha256"
	"errors"
	"strconv"

	"github.com/vettid/vettid-vault/vms/credwire"
)

// WalletCapsID is the wallet_id of wallet_caps.json (a ULID; TEST ONLY).
const WalletCapsID = "01HXZ3N5Q8R2T4V6W9Y0B1C2D3"

// walletCapsCases are the inputs of wallet_caps.json: the two values of
// §16 "§10.18 wallet.caps.raise binding" (per_tx and per_period are
// decimal ASCII, or none), then two that the spec text does not print.
var walletCapsCases = []struct {
	name             string
	version          uint64
	perTx, perPeriod string
}{
	{"both", 7, "500000", "2000000"},
	{"per_tx_none", 7, "none", "2000000"},
	{"both_none", 1, "none", "none"},
	{"largest", 12, "2100000000000000", "2100000000000000"},
}

// genWalletCaps builds wallet_caps.json (VAULT-MESSAGING 0.56.0 §10.18
// "Spend caps", §16 "wallet.caps.raise binding"): payload_sha256 =
// SHA-256("vettid/wallet.caps/1" || 0x00 || wallet_id || 0x00 || version
// || 0x00 || per_tx || 0x00 || per_period). The first two cases are the
// values §16 prints; this file is authoritative from now on.
func genWalletCaps() (obj, error) {
	out := obj{
		{"description", "VAULT-MESSAGING 0.56.0 §10.18 \"Spend caps\" and §16 \"wallet.caps.raise binding\" (features/wallet, vms/credwire): payload_sha256 of wallet.caps.raise = SHA-256(preimage), preimage = label || 0x00 || wallet_id || 0x00 || version || 0x00 || per_tx || 0x00 || per_period (the label in ASCII, each field in UTF-8, 0x00 between them and none after the last). version, per_tx and per_period are decimal ASCII without leading zeros; per_tx and per_period are the values the wallet will have after the request, or the literal none. The cases 'both' and 'per_tx_none' are the two values printed in §16. Standard base64 of payload_sha256 is what the sealed payload carries. TEST ONLY."},
		{"label", credwire.WalletCapsLabel},
		{"wallet_id", WalletCapsID},
	}
	cases := obj{}
	for _, c := range walletCapsCases {
		pre := []byte(credwire.WalletCapsLabel + "\x00" + WalletCapsID + "\x00" + strconv.FormatUint(c.version, 10) + "\x00" + c.perTx + "\x00" + c.perPeriod)
		var tx, per *int64
		for _, f := range []struct {
			s string
			p **int64
		}{{c.perTx, &tx}, {c.perPeriod, &per}} {
			if f.s == "none" {
				continue
			}
			n, err := strconv.ParseInt(f.s, 10, 64)
			if err != nil {
				return nil, err
			}
			*f.p = &n
		}
		h := credwire.WalletCapsBinding(WalletCapsID, c.version, tx, per)
		if sha256.Sum256(pre) != h {
			return nil, errors.New("vectors: wallet caps binding differs from its preimage")
		}
		cases = append(cases, member{c.name, obj{
			{"version", c.version},
			{"per_tx", c.perTx},
			{"per_period", c.perPeriod},
			{"preimage_hex", hx(pre)},
			{"payload_sha256_hex", hx(h[:])},
			{"payload_sha256_b64", b64(h[:])},
		}})
	}
	return append(out, member{"cases", cases}), nil
}
