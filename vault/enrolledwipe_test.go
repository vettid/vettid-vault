package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/suite"
)

// enrollApp wipes vault.enrolled's body, which carries the app's token,
// once it is sealed and queued.
func TestEnrolledBodyWiped(t *testing.T) {
	var bodies [][]byte
	testEnrolledBodyHook = func(b []byte) { bodies = append(bodies, b) }
	defer func() { testEnrolledBodyHook = nil }()
	st := store.NewMemory()
	c := &confirmer{}
	opts := Options{Store: st, Sealer: testSealer{key: bytes.Repeat([]byte{7}, 32)}, Release: testRelease, MarkDeleting: NoHostMark,
		ConfirmAppKey: c.confirm, AppKeyRetry: quickKeyRetry,
		Relay: func(base string, key ed25519.PrivateKey) Relay { return &stubRelay{base: base, key: key} }}
	k, err := MinKDF()
	if err != nil {
		t.Fatal(err)
	}
	kem, _ := suite.NewPrivateKey(bytes.Repeat([]byte{0x33}, 32))
	relayPK := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x32}, 32)).Public().(ed25519.PublicKey)
	m, err := Create(context.Background(), CreateParams{Options: opts, VaultID: "0123456789abcdef0123456789abcdef", UserGUID: "u1", PIN: testPIN,
		UnlockSecret: testSecret, KDF: k, RelayURL: "https://relay.example.org", Provisional: true,
		App: &EnrollApp{IK: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, 32)).Public().(ed25519.PublicKey), KEM: kem.Public(),
			Relay: PeerRelay{URL: "https://relay.example.org", Mailbox: "m", PK: relayPK}, APIKey: testAppKeyDER(t, 0x44)}})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Crash()
	if len(bodies) != 1 || len(bodies[0]) == 0 || bytes.Count(bodies[0], []byte{0}) != len(bodies[0]) {
		t.Fatalf("%d vault.enrolled bodies wiped", len(bodies))
	}
}
