package credential

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// fakeRekeyer re-keys every item of the plaintext and counts the commits.
type fakeRekeyer struct{ calls, commits int }

func (r *fakeRekeyer) RekeyCriticalItems(_ *vault.Session, in *Inner) (func(), error) {
	r.calls++
	for i := range in.Items {
		in.Items[i].Key = bytes.Repeat([]byte{byte(0x40 + r.calls)}, ItemKeySize)
	}
	return func() { r.commits++ }, nil
}

// xferEnv is a holder with a critical item, a signer and a scanned
// transfer, ready for the approval.
type xferEnv struct {
	*env
	o     *signerObs
	order []string
	rk    *fakeRekeyer
	blob  string
	id    string
	k0    []byte
}

func newXferEnv(t *testing.T) *xferEnv {
	x := &xferEnv{env: newEnv(t), rk: &fakeRekeyer{}}
	x.o = &signerObs{order: &x.order}
	x.f.AddKeyRotationObserver(x.o)
	x.f.SetItemRekeyer(x.rk)
	x.blob = x.create()
	itemID, _ := envelope.NewULID(time.Unix(1, 0))
	x.op = &opFeature{cred: x.f, op: func(in *Inner, _ *Payload) error {
		if len(in.Items) == 0 {
			in.Items = append(in.Items, Item{ID: itemID, Gen: 1, Key: bytes.Repeat([]byte{0xee}, ItemKeySize)})
		}
		return nil
	}}
	x.blob = blobOf(t, x.ok(x.call("app", "test.op", x.blob, map[string]any{"password": pw})))
	x.ok(x.raw("app", "credential.ack", `{"version":2}`))
	x.k0 = x.key()
	o := x.ok(x.raw("app", "device.transfer.create", `{}`)).Obj(t)
	x.id, _ = o.String("transfer_id")
	x.h.Xfer.Scanned = true
	return x
}

// key is the credential key the vault reports.
func (x *xferEnv) key() []byte {
	k, err := x.ok(x.raw("app", "credential.version", `{}`)).Obj(x.t).Base64("key", ed25519.PublicKeySize)
	if err != nil {
		x.t.Fatal(err)
	}
	return k
}

func (x *xferEnv) approve() featuretest.Result {
	return x.callBody("app", "device.transfer.approve", x.blob, map[string]any{"password": pw, "pin": testPIN}, `"transfer_id":"`+x.id+`"`)
}

// itemKey is the critical item's key in the plaintext of blob, opened by
// the holder kind.
func (x *xferEnv) itemKey(kind, blob string) ([]byte, string) {
	var got []byte
	x.op.op = func(in *Inner, _ *Payload) error {
		got = append([]byte(nil), in.Items[0].Key...)
		return nil
	}
	nb := blobOf(x.t, x.ok(x.call(kind, "test.op", blob, map[string]any{"password": pw})))
	return got, nb
}

// §11.14.10 "The credential key, at the approval": the approval's write
// rotates the credential key K0 to K1, re-keys the critical items, and
// seals the new blob (the backup copy the new phone takes over) with K1;
// the statement K0→K1 is held by the runtime, not sent; the signers sign
// with both keys but are told the statement is held.
func TestTransferApprovalRotatesCredentialKey(t *testing.T) {
	x := newXferEnv(t)
	r := x.ok(x.approve())
	if string(r.Body) != `{"unlink":"after_new_unlock"}` {
		t.Fatalf("answer %s", r.Body)
	}
	x.f.TransferCompleted(nil, "dev-app", "dev-app2")
	k1 := x.key()
	if bytes.Equal(k1, x.k0) {
		t.Fatal("the credential key did not rotate at the approval")
	}
	if len(x.order) != 1 || x.order[0] != "held keys" || x.o.statement != nil {
		t.Fatalf("observers %v: the statement was sent at the approval", x.order)
	}
	if !bytes.Equal(x.o.oldPub, x.k0) || !bytes.Equal(x.o.newPub, k1) {
		t.Fatal("the signers did not get K0 and K1")
	}
	if len(x.h.HeldRotations) != 1 {
		t.Fatalf("%d statements held", len(x.h.HeldRotations))
	}
	st, err := credwire.ParseKeyRotation(x.h.HeldRotations[0])
	if err != nil || st.Verify() != nil || !bytes.Equal(st.Old, x.k0) || !bytes.Equal(st.New, k1) {
		t.Fatalf("held statement %+v: %v", st, err)
	}
	if x.rk.commits != 1 {
		t.Fatalf("items re-keyed %d times", x.rk.commits)
	}
	// The vault's backup copy is the new blob, under K1, with the items
	// re-keyed; the new phone takes it over and unlocks K1.
	if !x.f.HasBackupCopy() {
		t.Fatal("no backup copy")
	}
	latest := blobOf(t, x.ok(x.raw("app2", "credential.get", `{}`)))
	ik, latest := x.itemKey("app2", latest)
	if bytes.Equal(ik, bytes.Repeat([]byte{0xee}, ItemKeySize)) {
		t.Fatal("the critical item was not re-keyed")
	}
	x.ok(x.raw("app2", "credential.ack", `{"version":4}`))
	x.ok(x.call("app2", "credential.unlock", latest, map[string]any{"password": pw}))
	priv, ok := x.f.UseKey(x.clk.T, time.Minute)
	if !ok || !bytes.Equal(priv.Public().(ed25519.PublicKey), k1) {
		t.Fatal("the new blob does not hold K1")
	}
	// The runtime sends the held statement (the new phone's first unlock
	// from storage): the observers get K0→K1.
	x.f.SendKeyRotations(vault.NewSession(context.Background(), x.h, vault.PeerInfo{}, x.clk.T, nil), x.h.TakeHeldKeyRotations(x.clk.T))
	if x.o.statement == nil || !bytes.Equal(x.o.statement.Old, x.k0) || !bytes.Equal(x.o.statement.New, k1) {
		t.Fatalf("statement sent %+v", x.o.statement)
	}
}

// A refused or failed approval leaves K0, the items and the blob, and holds
// nothing: busy from the vault's part, and a statement it cannot hold.
func TestTransferApprovalFailureKeepsK0(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(*featuretest.Host)
		code string
	}{
		{"busy", func(h *featuretest.Host) { h.ApproveErr = vault.NewError("busy", "") }, "busy"},
		{"hold", func(h *featuretest.Host) { h.HoldErr = vault.NewError("internal", "") }, "internal"},
	} {
		x := newXferEnv(t)
		c.set(x.h)
		if r := x.approve(); r.Code != c.code {
			t.Fatalf("%s: %q", c.name, r.Code)
		}
		if !bytes.Equal(x.key(), x.k0) || len(x.h.HeldRotations) != 0 || x.rk.commits != 0 || len(x.order) != 0 {
			t.Fatalf("%s: key changed %v, held %d, commits %d, observers %v", c.name, !bytes.Equal(x.key(), x.k0),
				len(x.h.HeldRotations), x.rk.commits, x.order)
		}
		// The old app's blob is still the credential.
		if ik, _ := x.itemKey("app", x.blob); !bytes.Equal(ik, bytes.Repeat([]byte{0xee}, ItemKeySize)) {
			t.Fatalf("%s: the item changed", c.name)
		}
	}
}

// §11.14.10 "The owed mark": a credential.rotate while the transfer's
// statement is held sends K0→K1 first, then its own K1→K2, so a connection
// that pinned K0 follows an unbroken chain.
func TestRotateSendsHeldStatementFirst(t *testing.T) {
	x := newXferEnv(t)
	x.ok(x.approve())
	x.f.TransferCompleted(nil, "dev-app", "dev-app2")
	k1 := x.key()
	latest := blobOf(t, x.ok(x.raw("app2", "credential.get", `{}`)))
	var stmts []*credwire.KeyRotation
	x.order = nil
	rec := &stmtRec{got: &stmts}
	x.f.AddKeyRotationObserver(rec)
	r := x.ok(x.call("app2", "credential.rotate", latest, map[string]any{"password": pw}))
	k2, _ := r.Obj(t).Base64("key", ed25519.PublicKeySize)
	if len(stmts) != 2 || !bytes.Equal(stmts[0].Old, x.k0) || !bytes.Equal(stmts[0].New, k1) || !bytes.Equal(stmts[1].Old, k1) ||
		!bytes.Equal(stmts[1].New, k2) {
		t.Fatalf("statements %+v", stmts)
	}
	if end, err := credwire.FollowChain(x.k0, stmts); err != nil || !bytes.Equal(end, k2) {
		t.Fatalf("chain from K0: %v", err)
	}
	if len(x.h.HeldRotations) != 0 {
		t.Fatal("still held after the rotation")
	}
	if x.order[len(x.order)-1] != "keys" {
		t.Fatalf("observers %v", x.order)
	}
}

// stmtRec records every statement it is told of.
type stmtRec struct{ got *[]*credwire.KeyRotation }

func (s *stmtRec) CredentialKeyRotated(_ *vault.Session, r *credwire.KeyRotation) {
	*s.got = append(*s.got, r)
}

// batchRec is a KeyRotationBatchObserver and a KeyRotationFollower that
// records what it is told, in order.
type batchRec struct {
	order  *[]string
	chains [][]*credwire.KeyRotation
}

func (b *batchRec) CredentialKeyRotated(_ *vault.Session, r *credwire.KeyRotation) {
	b.CredentialKeyRotations(nil, []*credwire.KeyRotation{r})
}
func (b *batchRec) CredentialKeyRotations(_ *vault.Session, rs []*credwire.KeyRotation) {
	*b.order = append(*b.order, "batch")
	b.chains = append(b.chains, rs)
}

// followRec is a KeyRotationFollower registered before the observers.
type followRec struct{ order *[]string }

func (f *followRec) CredentialKeyRotated(*vault.Session, *credwire.KeyRotation) {}
func (f *followRec) CredentialKeyRotationsSent(_ *vault.Session, rs []*credwire.KeyRotation) {
	*f.order = append(*f.order, "followed")
}

// Held statements go to a batch observer as one chain, and every follower
// is told after every observer, whatever the order of registration.
func TestHeldStatementsOneChainFollowersLast(t *testing.T) {
	var order []string
	e := newEnv(t)
	e.f.AddKeyRotationObserver(&followRec{order: &order})
	br := &batchRec{order: &order}
	e.f.AddKeyRotationObserver(br)
	k0 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	k1 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	k2 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	s1, _ := credwire.NewKeyRotation(k0, k1)
	s2, _ := credwire.NewKeyRotation(k1, k2)
	e.f.SendKeyRotations(vault.NewSession(context.Background(), e.h, vault.PeerInfo{}, e.clk.T, nil), [][]byte{s1.Marshal(), s2.Marshal()})
	if len(order) != 2 || order[0] != "batch" || order[1] != "followed" || len(br.chains) != 1 || len(br.chains[0]) != 2 {
		t.Fatalf("order %v, chains %d", order, len(br.chains))
	}
}

// credential.rotate while a statement is held tells a batch observer one
// chain K0→K1→K2 (member authentication sends it as one), and no
// follower: the signers re-sign under K2.
func TestRotateDuringHeldOneChain(t *testing.T) {
	x := newXferEnv(t)
	br := &batchRec{order: &x.order}
	x.f.AddKeyRotationObserver(br)
	fr := &followRec{order: &x.order}
	x.f.AddKeyRotationObserver(fr)
	x.ok(x.approve())
	x.f.TransferCompleted(nil, "dev-app", "dev-app2")
	latest := blobOf(t, x.ok(x.raw("app2", "credential.get", `{}`)))
	x.order = nil
	x.ok(x.call("app2", "credential.rotate", latest, map[string]any{"password": pw}))
	if len(br.chains) != 1 || len(br.chains[0]) != 2 || !bytes.Equal(br.chains[0][0].Old, x.k0) {
		t.Fatalf("chains %+v", br.chains)
	}
	for _, o := range x.order {
		if o == "followed" {
			t.Fatal("a follower was told at a rotation")
		}
	}
}

// credential.reset while a statement is held: the statement is never
// sent (the key it announces is destroyed) and the delete observers are
// told.
func TestResetDropsHeldStatement(t *testing.T) {
	x := newXferEnv(t)
	x.ok(x.approve())
	x.f.TransferCompleted(nil, "dev-app", "dev-app2")
	latest := blobOf(t, x.ok(x.raw("app2", "credential.get", `{}`)))
	x.order = nil
	x.o.statement = nil
	r := x.call("app2", "credential.reset", latest, map[string]any{"password": pw, "pin": testPIN, "new_password": pw + "-2"})
	x.ok(r)
	if len(x.h.HeldRotations) != 0 || x.o.statement != nil {
		t.Fatalf("held %d, statement %v", len(x.h.HeldRotations), x.o.statement)
	}
}
