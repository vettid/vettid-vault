package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
)

// An hs.resp that does not end the handshake (it does not open) keeps it;
// once it has ended, the device drops it and says the handshake failed.
// Asked through Initiator.Done, never Export.
func TestHandleRespKeepsAHandshakeThatGoesOn(t *testing.T) {
	_, v, d := startPair(t)
	d.mu.Lock()
	defer d.mu.Unlock()
	ini := d.ini
	if ini == nil {
		t.Fatal("setup: no handshake")
	}
	d.handleResp(context.Background(), []byte("junk"), v.relayPK())
	if d.ini != ini || d.hsFailed {
		t.Fatalf("a junk answer ended the handshake: kept %v, failed %v", d.ini == ini, d.hsFailed)
	}
	ini.Abort()
	d.handleResp(context.Background(), []byte("junk"), v.relayPK())
	if d.ini != nil || !d.hsFailed {
		t.Fatalf("an ended handshake kept: %v, failed %v", d.ini != nil, d.hsFailed)
	}
}

// startTransferInit begins a transfer's new-phone hs.init (an app key and
// the unlock secret of epoch 1) on a device set up as startPair's.
func startTransferInit(t *testing.T, failDeposit bool) (d *Device, ini *handshake.Initiator, secret []byte, err error) {
	t.Helper()
	r := newFakeRelay(t)
	v := newFakeVault(t, r)
	d, err = Generate(Config{Role: "app", Name: "phone", RelayURL: r.url(), HTTP: r.srv.Client(), PollWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	v.dev, v.devIK = d.RelayAddr(), d.IdentityKey()
	k, kerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if kerr != nil {
		t.Fatal(kerr)
	}
	apiKey, kerr := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if kerr != nil {
		t.Fatal(kerr)
	}
	testInitiatorHook = func(i *handshake.Initiator, s []byte) { ini, secret = i, s }
	t.Cleanup(func() { testInitiatorHook = nil })
	if failDeposit {
		r.failDeposit, r.depositStatus = 1, http.StatusBadRequest
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.st.VaultID = testVaultID
	d.st.Vault = &VaultRecord{IK: v.ik.Public().(ed25519.PublicKey), KEM: v.kem.Public().Bytes(), RelayURL: r.url(), Mailbox: v.mailbox(), RelayPK: v.relayPK()}
	tok := v.token(30 * 24 * time.Hour)
	if d.st.Vault.TokenExp, err = d.heldFromVault(tok); err != nil {
		t.Fatal(err)
	}
	d.st.Vault.Token = tok
	err = d.startInitWith(handshake.PurposeApp, testVaultID, tok, nil, nil, "", time.Now(), apiKey)
	return d, ini, secret, err
}

// The unlock secret the device derives for a transfer's hs.init is wiped
// once the Initiator has its own copy, which the hs.init still carries.
func TestStartInitWipesTheUnlockSecret(t *testing.T) {
	d, ini, secret, err := startTransferInit(t, false)
	if err != nil {
		t.Fatal(err)
	}
	if ini == nil || d.ini != ini {
		t.Fatal("setup: no handshake kept")
	}
	if !wiped(secret) {
		t.Fatal("the derived unlock secret was not wiped")
	}
	if held := ini.Body().UnlockSecret; len(held) != len(secret) || wiped(held) {
		t.Fatal("the Initiator's own copy is missing or wiped")
	}
}

// A handshake whose hs.init could not be deposited is aborted (its keys
// and its copies of the app key and unlock secret wiped), never kept.
func TestStartInitAbortsAFailedDeposit(t *testing.T) {
	d, ini, _, err := startTransferInit(t, true)
	if err == nil {
		t.Fatal("the deposit did not fail")
	}
	if ini == nil {
		t.Fatal("setup: no handshake begun")
	}
	if d.ini != nil || !ini.Done() || ini.Body().UnlockSecret != nil || ini.Body().APIKey != nil {
		t.Fatalf("kept %v, done %v", d.ini != nil, ini.Done())
	}
}
