package handshake

import (
	"github.com/vettid/vettid-vault/vms/envelope"
	"testing"
	"time"
)

// 0.86.0 (§6.3.1): the keyring's pending epoch opens messages but is not
// current until confirmed; an abandoned one keeps its receive key 16 days;
// a superseded epoch can keep its rk (a responder's confirmed epoch) or
// its send key and rk (a reverting initiator), be reinstated, released
// and destroyed by id; all of it survives Export/Import.
func TestKeyringPendingAndKept(t *testing.T) {
	ip, rp := newParty(t, 1), newParty(t, 2)
	i0, r0 := runHandshake(t, ip, rp, PurposeConnection)
	i1, r1 := runHandshake(t, ip, rp, PurposeConnection)
	now := t0
	var kI Keyring
	kI.Activate(i0, now)
	kI.SetPending(i1, now)
	if kI.Current() != i0 || kI.Pending() != i1 {
		t.Fatal("pending is current")
	}
	if err := sealOpen(t, r1, &kI, now); err != nil {
		t.Fatalf("a message under the pending epoch does not open: %v", err)
	}
	st := kI.Export()
	k2, err := ImportKeyring(st)
	if err != nil || k2.Pending() == nil {
		t.Fatal("pending lost at export")
	}
	if kI.ConfirmPending(now) != i1 || kI.Current() != i1 || kI.Pending() != nil || i0.CanSend() {
		t.Fatal("confirmation")
	}
	if err := sealOpen(t, r0, &kI, now); err != nil {
		t.Fatal("the previous epoch's receive key is gone at once")
	}
	// Abandon: receive key kept, nothing else.
	var kA Keyring
	kA.Activate(i0, now)
	i2, _ := runHandshake(t, ip, rp, PurposeConnection)
	kA.SetPending(i2, now)
	kA.AbandonPending(now)
	if kA.Pending() != nil || i2.CanSend() || i2.HasRK() {
		t.Fatal("an abandoned pending epoch kept its send key or rk")
	}
	if kA.Find(i2.ID()) == nil {
		t.Fatal("an abandoned epoch's receive key was not kept")
	}
	kA.Prune(now.Add(ReceiveKeyRetention + time.Hour))
	if kA.Find(i2.ID()) != nil {
		t.Fatal("an abandoned epoch outlived 16 days")
	}
}

func TestKeyringKeepReinstateRelease(t *testing.T) {
	ip, rp := newParty(t, 3), newParty(t, 4)
	a0, _ := runHandshake(t, ip, rp, PurposeConnection)
	a1, _ := runHandshake(t, ip, rp, PurposeConnection)
	now := t0
	var k Keyring
	k.Activate(a0, now)
	k.ActivateKeeping(a1, now, now.Add(48*24*time.Hour), KeepSend)
	if !a0.CanSend() || !a0.HasRK() {
		t.Fatal("KeepSend dropped the send key or rk")
	}
	k2, err := ImportKeyring(k.Export())
	if err != nil || k2.Find(a0.ID()) == nil || !k2.Find(a0.ID()).CanSend() {
		t.Fatal("a kept epoch did not survive export")
	}
	if !k.Reinstate(a0.ID(), now) || k.Current() != a0 || k.Find(a1.ID()) == nil || a1.CanSend() || a1.HasRK() {
		t.Fatal("reinstate: the superseded current keeps its receive key only")
	}
	// KeepRK: rk without the send key; Release ends both.
	b1, _ := runHandshake(t, ip, rp, PurposeConnection)
	k.ActivateKeeping(b1, now, now.Add(48*24*time.Hour), KeepRK)
	if a0.CanSend() || !a0.HasRK() {
		t.Fatal("KeepRK")
	}
	if k.Reinstate(a0.ID(), now) {
		t.Fatal("reinstated an epoch without its send key")
	}
	k.Release(a0.ID(), now.Add(ReceiveKeyRetention))
	if a0.HasRK() {
		t.Fatal("release kept the rk")
	}
	k.DestroyEpoch(a0.ID())
	if k.Find(a0.ID()) != nil {
		t.Fatal("destroy")
	}
}

// 0.85.0 S8: a rekey's hs.init and hs.resp carry rotations; both parse
// (release 28 refused them at parse; the stage-a change missed the parse
// step and only relaxed validation).
func TestRekeyRotationsParse(t *testing.T) {
	ip, rp := newParty(t, 5), newParty(t, 6)
	i0, r0 := runHandshake(t, ip, rp, PurposeConnection)
	nk := newParty(t, 7)
	rot, err := NewRotation(ip.ik, nk.ik, nk.kem.Public())
	if err != nil {
		t.Fatal(err)
	}
	cfg := InitiatorConfig{Purpose: PurposeRekey, Identity: nk.ik, StaticKEM: nk.kem.Public(), Relay: ip.addr,
		ResponderIK: rp.pub(), ResponderRelayKey: rp.relayPK(), Current: i0, Policy: PolicyVaultToVault, Now: t0,
		Rotations: []*Rotation{rot}}
	ini, err := NewInitiator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := envelope.Parse(ini.Envelope())
	in, err := r0.Open(env)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseInit(in.Body)
	if err != nil || len(b.Rotations) != 1 {
		t.Fatalf("a rekey hs.init with rotations does not parse: %v", err)
	}
	pi, err := AcceptRekey(ini.Envelope(), in, r0, t0)
	if err != nil {
		t.Fatal(err)
	}
	_, renv, err := pi.Respond(ResponderConfig{Identity: rp.ik, Policy: PolicyVaultToVault, CollectSender: ip.relayPK(),
		RecordRelayKey: ip.relayPK(), KnownInitiatorIK: ip.pub(), Now: t0, Rotations: nil})
	if err != nil {
		t.Fatalf("respond: %v", err)
	}
	if _, err := ini.HandleResp(renv, rp.relayPK(), t0); err != nil {
		t.Fatalf("hs.resp: %v", err)
	}
}
