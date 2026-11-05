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
	var unknown time.Time
	if !v.hasKey(k1, now, unknown) || !v.hasKey(k0, now, unknown) || v.hasKey(k2, now, unknown) {
		t.Fatal("current and earlier keys")
	}
	if v.hasKey(k0, now.Add(PrevRelayGrace), unknown) {
		t.Fatal("an earlier key accepted past the grace")
	}
	// Ended at the vault's first deposit with its new key (relay time T):
	// a deposit by the earlier key taken before T is the vault's, one after
	// it (or of unknown time) is not.
	cut := now.Add(-time.Minute)
	v.endEarlierKeys(cut, now)
	if !v.hasKey(k0, now, cut.Add(-time.Second)) || v.hasKey(k0, now, cut.Add(time.Second)) || v.hasKey(k0, now, unknown) {
		t.Fatal("an ended key: the deposit time rule")
	}
}
