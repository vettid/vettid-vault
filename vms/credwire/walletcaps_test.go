package credwire

import (
	"encoding/hex"
	"testing"
)

// The §16 vectors of wallet.caps.raise's binding (VAULT-MESSAGING
// 0.56.0), as printed there.
func TestWalletCapsBindingSpecVectors(t *testing.T) {
	i := func(v int64) *int64 { return &v }
	for _, c := range []struct {
		perTx, perPeriod *int64
		want             string
	}{
		{i(500000), i(2000000), "9479e8f7e06134aab2e7fcfec8dc1ba7fd2ed5cde4be3553ccaf4e6cf9aa1259"},
		{nil, i(2000000), "7bcbbf3d027952bb1a7cbafba930b385732185b8f61d4b15218a8ee7a32d58ae"},
	} {
		h := WalletCapsBinding("01HXZ3N5Q8R2T4V6W9Y0B1C2D3", 7, c.perTx, c.perPeriod)
		if got := hex.EncodeToString(h[:]); got != c.want {
			t.Errorf("binding %s, want %s", got, c.want)
		}
	}
}
