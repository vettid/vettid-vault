package client

import (
	"context"
	"testing"
	"time"

	"crypto/ed25519"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// S8 toward a device (review H1): the vault rotates its ik, then rekeys
// the device carrying its link. Whether the device saw identity.rotate or
// not, it answers, the vault finishes the rekey under its new ik, and the
// device holds the vault's new ik.
func TestDeviceRekeyAfterVaultRotation(t *testing.T) {
	for _, sawRotate := range []bool{true, false} {
		r, v, d := pair(t)
		ctx := context.Background()
		seed, _ := suite.RandomBytes(32)
		newIK := ed25519.NewKeyFromSeed(seed)
		kseed, _ := suite.RandomBytes(32)
		newKEM, err := suite.NewPrivateKey(kseed)
		if err != nil {
			t.Fatal(err)
		}
		rot, err := handshake.NewRotation(v.ik, newIK, newKEM.Public())
		if err != nil {
			t.Fatal(err)
		}
		if sawRotate {
			body := strictjson.NewBuilder().Raw("rotation", rot.Marshal()).Raw("rotations", append(append([]byte{'['}, rot.Marshal()...), ']')).Bytes()
			v.send("identity.rotate", body)
			if err := d.Poll(ctx); err != nil {
				t.Fatal(err)
			}
		}
		v.ik, v.kem = newIK, newKEM
		ini, err := handshake.NewInitiator(handshake.InitiatorConfig{
			Purpose: handshake.PurposeRekey, Identity: v.ik, StaticKEM: v.kem.Public(), Relay: v.addr(),
			ResponderIK: v.devIK, ResponderRelayKey: v.dev.PK, Current: v.kr.Current(), PinnedSuite: v.kr.Current().Suite(),
			Policy: handshake.PolicyVaultToDevice, Now: time.Now(), Rotations: []*handshake.Rotation{rot},
		})
		if err != nil {
			t.Fatal(err)
		}
		v.rekey = ini
		v.r.put(v.dev.Mailbox, v.relayPK(), ini.Envelope())
		if err := d.Poll(ctx); err != nil {
			t.Fatal(err)
		}
		v.process()
		if v.rekeyResps != 1 {
			t.Fatalf("sawRotate=%v: the device did not answer the rekey carrying the link", sawRotate)
		}
		if err := d.Poll(ctx); err != nil { // hs.fin
			t.Fatal(err)
		}
		if string(d.st.Vault.IK) != string(newIK.Public().(ed25519.PublicKey)) || d.keyring.Current().ID() != v.kr.Current().ID() {
			t.Fatalf("sawRotate=%v: the device is not on the new epoch under the vault's new ik", sawRotate)
		}
		_ = r
	}
}

// Review RR2 L7: a device that followed the vault's first rotation before
// it kept the chain (state from before 4bdad44: an empty Chain) still
// answers a rekey carrying the whole chain since the epoch's signer.
func TestDeviceRekeyWholeChainWithoutRecordedChain(t *testing.T) {
	_, v, d := pair(t)
	ctx := context.Background()
	key := func() (ed25519.PrivateKey, *suite.PrivateKey) {
		s1, _ := suite.RandomBytes(32)
		s2, _ := suite.RandomBytes(32)
		k, err := suite.NewPrivateKey(s2)
		if err != nil {
			t.Fatal(err)
		}
		return ed25519.NewKeyFromSeed(s1), k
	}
	ik1, kem1 := key()
	ik2, kem2 := key()
	l1, _ := handshake.NewRotation(v.ik, ik1, kem1.Public())
	l2, _ := handshake.NewRotation(ik1, ik2, kem2.Public())
	v.send("identity.rotate", strictjson.NewBuilder().Raw("rotation", l1.Marshal()).Bytes())
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	d.st.Vault.Chain = nil // as recorded before 4bdad44
	v.ik, v.kem = ik2, kem2
	ini, err := handshake.NewInitiator(handshake.InitiatorConfig{
		Purpose: handshake.PurposeRekey, Identity: v.ik, StaticKEM: v.kem.Public(), Relay: v.addr(),
		ResponderIK: v.devIK, ResponderRelayKey: v.dev.PK, Current: v.kr.Current(), PinnedSuite: v.kr.Current().Suite(),
		Policy: handshake.PolicyVaultToDevice, Now: time.Now(), Rotations: []*handshake.Rotation{l1, l2},
	})
	if err != nil {
		t.Fatal(err)
	}
	v.rekey = ini
	v.r.put(v.dev.Mailbox, v.relayPK(), ini.Envelope())
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	v.process()
	if v.rekeyResps != 1 || string(d.st.Vault.IK) != string(ik2.Public().(ed25519.PublicKey)) {
		t.Fatal("the device did not answer a whole-chain rekey without its recorded chain")
	}
}
