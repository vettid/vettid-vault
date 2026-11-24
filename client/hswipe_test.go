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

	"github.com/vettid/vettid-vault/vms/envelope"
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

// A handshake that ended (answered, or aborted) has its stored snapshot
// (eph seed, K_s, the hs.init body with a transfer's unlock secret) wiped
// and dropped at once, not left until the next export.
func TestEndedHandshakeDropsItsSnapshot(t *testing.T) {
	for _, answered := range []bool{true, false} {
		r, v, d := startPair(t)
		resp := r.take(v.dev.Mailbox)
		if len(resp) != 1 {
			t.Fatalf("setup: %d hs.resp", len(resp))
		}
		d.mu.Lock()
		d.export()
		og := d.st.Outgoing
		if og == nil {
			d.mu.Unlock()
			t.Fatal("setup: no stored snapshot")
		}
		got := [][]byte{og.EphSeed, og.Ks, og.Body}
		raw := resp[0].Payload
		if !answered {
			d.ini.Abort()
			raw = []byte("junk")
		}
		d.handleResp(context.Background(), raw, v.relayPK())
		kept := d.st.Outgoing
		d.mu.Unlock()
		if kept != nil {
			t.Fatalf("answered=%v: the snapshot was kept", answered)
		}
		for i, b := range got {
			if len(b) == 0 || !allZeroBytes(b) {
				t.Fatalf("answered=%v: secret %d of the snapshot not wiped", answered, i)
			}
		}
	}
}

func allZeroBytes(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// A pairing started again (a retry) replaces the earlier handshake: it is
// aborted and its stored snapshot wiped and dropped.
func TestRestartedHandshakeEndsTheEarlierOne(t *testing.T) {
	_, _, d := startPair(t)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.export()
	first, og := d.ini, d.st.Outgoing
	if first == nil || og == nil {
		t.Fatal("setup: no handshake")
	}
	got := [][]byte{og.EphSeed, og.Ks, og.Body}
	if err := d.startInit(handshake.PurposeApp, testVaultID, d.st.Vault.Token, nil); err != nil {
		t.Fatal(err)
	}
	if !first.Done() || d.ini == first {
		t.Fatal("the earlier handshake was not ended")
	}
	for i, b := range got {
		if len(b) == 0 || !allZeroBytes(b) {
			t.Fatalf("secret %d of the earlier snapshot not wiped", i)
		}
	}
}

// A vault rekey whose answer Respond refuses (another collect sender) is
// discarded: its K_s and its plaintext are wiped.
func TestRefusedRekeyDiscarded(t *testing.T) {
	ctx := context.Background()
	r, v, d := pair(t)
	v.startRekey()
	var refused []*handshake.PendingInit
	testRekeyRefusedHook = func(pi *handshake.PendingInit) { refused = append(refused, pi) }
	defer func() { testRekeyRefusedHook = nil }()
	msgs := r.take(v.dev.Mailbox)
	d.mu.Lock()
	for _, m := range msgs {
		env, err := envelope.Parse(m.Payload)
		if err != nil {
			continue
		}
		in, ep, err := d.keyring.Open(env, time.Now())
		if err != nil || in.Type != handshake.TypeInit {
			continue
		}
		other := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
		d.handleRekey(ctx, m.Payload, in, ep, other, time.Now())
	}
	d.mu.Unlock()
	if len(refused) != 1 {
		t.Fatalf("%d rekeys refused", len(refused))
	}
	if body := refused[0].Inner().Body; len(body) == 0 || !allZeroBytes(body) {
		t.Fatal("the refused rekey was not discarded")
	}
}

// A responder that ended (here, its hs.fin did not come in time) has its
// stored snapshot wiped and dropped at once, not left until the next
// export.
func TestEndedResponderDropsItsSnapshot(t *testing.T) {
	ctx := context.Background()
	_, v, d := pair(t)
	v.startRekey()
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.awaiting) != 1 {
		t.Fatalf("setup: %d responders", len(d.awaiting))
	}
	d.export()
	if len(d.st.Awaiting) != 1 {
		t.Fatalf("setup: %d stored responders", len(d.st.Awaiting))
	}
	s := d.st.Awaiting[0]
	got := [][]byte{s.Ks, s.Ke, s.PRK, s.RK}
	d.pruneAwaiting(time.Now().Add(365 * 24 * time.Hour))
	if len(d.awaiting) != 0 || len(d.st.Awaiting) != 0 {
		t.Fatalf("%d responders, %d stored, after the prune", len(d.awaiting), len(d.st.Awaiting))
	}
	for i, b := range got {
		if len(b) == 0 || !allZeroBytes(b) {
			t.Fatalf("secret %d of the stored responder not wiped", i)
		}
	}
}

// A responder ended by its hs.fin has its stored snapshot wiped and
// dropped at once too.
func TestFinishedResponderDropsItsSnapshot(t *testing.T) {
	ctx := context.Background()
	_, v, d := pair(t)
	v.startRekey()
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	if len(d.awaiting) != 1 {
		d.mu.Unlock()
		t.Fatalf("setup: %d responders", len(d.awaiting))
	}
	d.export()
	if len(d.st.Awaiting) != 1 {
		d.mu.Unlock()
		t.Fatalf("setup: %d stored responders", len(d.st.Awaiting))
	}
	s := d.st.Awaiting[0]
	got := [][]byte{s.Ks, s.Ke, s.PRK, s.RK}
	d.mu.Unlock()
	v.process() // the vault answers with hs.fin
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.awaiting) != 0 || len(d.st.Awaiting) != 0 {
		t.Fatalf("%d responders, %d stored, after hs.fin", len(d.awaiting), len(d.st.Awaiting))
	}
	for i, b := range got {
		if len(b) == 0 || !allZeroBytes(b) {
			t.Fatalf("secret %d of the stored responder not wiped", i)
		}
	}
}

// A prune that ends several responders re-exports the stored ones once,
// not once per responder.
func TestPruneExportsOnce(t *testing.T) {
	ctx := context.Background()
	_, v, d := pair(t)
	v.startRekey()
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	v.startRekey()
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.awaiting) != 2 {
		t.Fatalf("setup: %d responders, want 2", len(d.awaiting))
	}
	exports := 0
	testExportAwaitingHook = func() { exports++ }
	defer func() { testExportAwaitingHook = nil }()
	d.pruneAwaiting(time.Now().Add(365 * 24 * time.Hour))
	if len(d.awaiting) != 0 || len(d.st.Awaiting) != 0 {
		t.Fatalf("%d responders, %d stored, after the prune", len(d.awaiting), len(d.st.Awaiting))
	}
	if exports != 1 {
		t.Fatalf("exported %d times, want once", exports)
	}
}
