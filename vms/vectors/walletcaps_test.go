package vectors

import (
	"crypto/sha256"
	"strconv"
	"testing"

	"github.com/vettid/vettid-vault/vms/credwire"
)

func TestWalletCapsVectors(t *testing.T) { checkWalletCapsVectors(t, Dir) }

// checkWalletCapsVectors re-derives wallet_caps.json (0.56.0, §10.18,
// §16) by hand: the preimage from its fields and its SHA-256, then
// through credwire.WalletCapsBinding, and the two values §16 prints.
func checkWalletCapsVectors(t *testing.T, dir string) {
	d := load(t, dir, "wallet_caps.json")
	if d.str("label") != "vettid/wallet.caps/1" || credwire.WalletCapsLabel != d.str("label") {
		t.Fatalf("label %q", d.str("label"))
	}
	id := d.str("wallet_id")
	cases := d.sub("cases")
	spec := map[string]string{
		"both":        "9479e8f7e06134aab2e7fcfec8dc1ba7fd2ed5cde4be3553ccaf4e6cf9aa1259",
		"per_tx_none": "7bcbbf3d027952bb1a7cbafba930b385732185b8f61d4b15218a8ee7a32d58ae",
	}
	if len(cases.m) < 2 {
		t.Fatal("cases missing")
	}
	for name := range cases.m {
		c := cases.sub(name)
		version, perTx, perPeriod := c.num("version"), c.str("per_tx"), c.str("per_period")
		pre := []byte("vettid/wallet.caps/1")
		for _, f := range []string{id, strconv.Itoa(version), perTx, perPeriod} {
			pre = append(pre, 0)
			pre = append(pre, f...)
		}
		eq(t, name+" preimage", pre, c.hex("preimage_hex"))
		h := sha256.Sum256(pre)
		eq(t, name+" payload_sha256", h[:], c.hex("payload_sha256_hex"))
		eq(t, name+" payload_sha256 (base64)", h[:], c.b64("payload_sha256_b64"))
		var tx, per *int64
		for _, f := range []struct {
			s string
			p **int64
		}{{perTx, &tx}, {perPeriod, &per}} {
			if f.s == "none" {
				continue
			}
			n, err := strconv.ParseInt(f.s, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			*f.p = &n
		}
		got := credwire.WalletCapsBinding(id, uint64(version), tx, per)
		eq(t, name+" (credwire.WalletCapsBinding)", got[:], h[:])
		if want, ok := spec[name]; ok {
			eq(t, name+" (§16)", h[:], mustHex(want))
			delete(spec, name)
		}
	}
	if len(spec) != 0 {
		t.Fatalf("§16 cases missing from the file: %v", spec)
	}
}
