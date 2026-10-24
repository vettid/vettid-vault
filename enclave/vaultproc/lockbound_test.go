package vaultproc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/internal/vaultipc"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/suite"
)

type testSealer struct{ key []byte }

func (s testSealer) Seal(_ context.Context, pt, aad []byte) ([]byte, error) {
	n, _ := suite.NewNonce()
	ct, err := suite.SealX(s.key, n, aad, pt)
	return append(n, ct...), err
}

func (s testSealer) Unseal(_ context.Context, b, aad []byte) ([]byte, error) {
	if len(b) < 40 {
		return nil, errors.New("short")
	}
	return suite.OpenX(s.key, b[:24], aad, b[24:])
}

// runningProc is a vault process with an open vault (a real Manager on the
// real relay), as after a successful open.
func runningProc(t *testing.T) (*proc, *vault.Manager) {
	t.Helper()
	r := relaytest.Start(t, relaytest.Options{})
	k, err := vault.MinKDF()
	if err != nil {
		t.Fatal(err)
	}
	opts := vault.Options{Store: store.NewMemory(), Sealer: testSealer{key: bytes.Repeat([]byte{7}, 32)},
		Release: vault.Release{PCR0: "dev", Number: 1}, MarkDeleting: vault.NoHostMark, ConfirmAppKey: vault.NoHostAppKey,
		Relay: func(base string, key ed25519.PrivateKey) vault.Relay {
			return vault.NewClientRelay(base, key, nil, time.Now)
		}}
	m, err := vault.Create(context.Background(), vault.CreateParams{Options: opts, UserGUID: "u1", PIN: "123456",
		UnlockSecret: bytes.Repeat([]byte{9}, 32), KDF: k, RelayURL: r.URL})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	close(done)
	return &proc{mgr: m, cancel: func() {}, runDone: done, exit: make(chan int, 2)}, m
}

// VAULT-MESSAGING 0.29.0 §11.5 (release L): the vault process locks for a
// bound lock only when the value names its current unlock; another value
// is stale and nothing is done; a malformed one is refused before it is
// compared; with no vault it answers ok, as a lock does.
func TestLockBound(t *testing.T) {
	ctx := context.Background()
	pr, m := runningProc(t)
	other := "0123456789abcdef0123456789abcdef"
	if other == m.UnlockID() {
		other = "fedcba9876543210fedcba9876543210"
	}
	if r := pr.lockBound(ctx, other); string(r[0]) != vaultipc.StatusStale || m.Locked() || pr.mgr == nil {
		t.Fatalf("another unlock: %q, locked %v", r[0], m.Locked())
	}
	for _, bad := range [][]byte{[]byte("0123"), []byte(m.UnlockID()[:31] + "G")} {
		if r := pr.handle(ctx, &hostproto.Frame{Kind: vaultipc.KindLockBound, Fields: [][]byte{bad}}); string(r[0]) != hostproto.StatusInvalid || m.Locked() {
			t.Fatalf("malformed %q: %q", bad, r[0])
		}
	}
	if r := pr.handle(ctx, &hostproto.Frame{Kind: vaultipc.KindLockBound}); string(r[0]) != hostproto.StatusInvalid || m.Locked() {
		t.Fatalf("no field: %q", r[0])
	}
	if r := pr.handle(ctx, &hostproto.Frame{Kind: vaultipc.KindLockBound, Fields: [][]byte{[]byte(m.UnlockID())}}); string(r[0]) != hostproto.StatusOK || !m.Locked() || pr.mgr != nil {
		t.Fatalf("the current unlock: %q, locked %v", r[0], m.Locked())
	}
	// No vault (locked already): ok, nothing to do.
	if r := pr.lockBound(ctx, other); string(r[0]) != hostproto.StatusOK {
		t.Fatalf("no vault: %q", r[0])
	}
}
