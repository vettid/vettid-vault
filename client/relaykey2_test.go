package client

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// addressUpdate is the vault's relay.address.update moving it to key k.
func addressUpdate(t *testing.T, v *fakeVault, k ed25519.PrivateKey) []byte {
	t.Helper()
	pk := k.Public().(ed25519.PublicKey)
	tok, err := relayclient.New(v.r.url(), k).MintToken(relayauth.EncodeKey(v.dev.PK), v.dev.URL, relayclient.TokenOptions{TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	addr := strictjson.NewBuilder().String("url", v.r.url()).String("mailbox", handshake.MailboxID(pk)).
		String("pk", base64.StdEncoding.EncodeToString(pk)).Bytes()
	return strictjson.NewBuilder().Raw("relay", addr).String("token", tok).Bytes()
}

// sendWith seals in the current epoch and deposits with the relay key k.
func sendWith(t *testing.T, v *fakeVault, k ed25519.PrivateKey, typ string, body []byte) {
	t.Helper()
	now := time.Now()
	id, _ := envelope.NewULID(now)
	raw, err := v.kr.Current().Seal(&envelope.Inner{ID: id, Type: typ, TS: now, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	v.r.put(v.dev.Mailbox, k.Public().(ed25519.PublicKey), raw)
}

// VAULT-MESSAGING §3.4 with the owner decision of 2026-11-05: after
// following the vault's new address, the device takes from the vault's
// earlier relay key no address change, no identity.rotate and no rekey;
// from the current key it does.
func TestDeviceRefusesKeyChangesFromAnEarlierKey(t *testing.T) {
	ctx := context.Background()
	_, v, d := pair(t)
	k0 := v.relayKey
	k1 := ed25519.NewKeyFromSeed(make([]byte, 32))
	k1[0] = 1
	k1 = ed25519.NewKeyFromSeed(k1[:32])
	sendWith(t, v, k0, "relay.address.update", addressUpdate(t, v, k1))
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if !suite.EqualPublic(d.st.Vault.RelayPK, k1.Public().(ed25519.PublicKey)) {
		t.Fatal("the device did not follow")
	}
	// From K0 now: an address change, a key change, a rekey.
	k2 := ed25519.NewKeyFromSeed(make([]byte, 32))
	sendWith(t, v, k0, "relay.address.update", addressUpdate(t, v, k2))
	newIK := ed25519.NewKeyFromSeed(make([]byte, 32))
	kem, _ := suite.NewPrivateKey(make([]byte, 32))
	rot, err := handshake.NewRotation(v.ik, newIK, kem.Public())
	if err != nil {
		t.Fatal(err)
	}
	rotBody := strictjson.NewBuilder().Raw("rotation", rot.Marshal()).Bytes()
	sendWith(t, v, k0, "identity.rotate", rotBody)
	v.startRekey() // deposited with K0
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if !suite.EqualPublic(d.st.Vault.RelayPK, k1.Public().(ed25519.PublicKey)) {
		t.Fatal("an address change from the earlier key was taken")
	}
	if suite.EqualPublic(d.st.Vault.IK, newIK.Public().(ed25519.PublicKey)) {
		t.Fatal("a key change from the earlier key was taken")
	}
	if len(d.awaiting) != 0 {
		t.Fatal("a rekey from the earlier key was answered")
	}
	// The same key change from the current key is taken.
	sendWith(t, v, k1, "identity.rotate", rotBody)
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if !suite.EqualPublic(d.st.Vault.IK, newIK.Public().(ed25519.PublicKey)) {
		t.Fatal("a key change from the current key was not taken")
	}
}
