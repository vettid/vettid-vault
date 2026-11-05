package client

import (
	"bytes"
	"testing"
	"time"
)

// VAULT-MESSAGING §3.4: a device accepts the vault's earlier relay keys as
// senders after following its relay.address.update, until the relay's
// grace (or until the vault deposits with its new key, client.handle).
func TestVaultRecordEarlierRelayKeys(t *testing.T) {
	now := time.Now()
	k0, k1, k2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	v := &VaultRecord{RelayPK: k1, PrevRelay: []PrevRelayKey{{PK: k0, Until: now.Add(PrevRelayGrace)}}}
	if !v.hasKey(k1, now) || !v.hasKey(k0, now) || v.hasKey(k2, now) {
		t.Fatal("current and earlier keys")
	}
	if v.hasKey(k0, now.Add(PrevRelayGrace)) {
		t.Fatal("an earlier key accepted past the grace")
	}
}
