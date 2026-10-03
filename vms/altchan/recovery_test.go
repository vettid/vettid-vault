package altchan

import (
	"crypto/ecdh"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
)

const (
	recVault = "0123456789abcdef0123456789abcdef"
	recID    = "01JB2Z6V9K3M4N5P6Q7R8S9T0V"
)

func testCode() *RecoveryCode {
	t := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	return &RecoveryCode{VaultID: recVault, RecoveryID: recID, Code: strings.Repeat("A", 32), NotBefore: t, Expires: t.Add(24 * time.Hour)}
}

func TestSealRecoveryCode(t *testing.T) {
	bk, _ := ecdh.P256().GenerateKey(nil)
	sealed, err := SealRecoveryCode(bk.PublicKey().Bytes(), testCode())
	if err != nil || len(sealed) != SealedCodeSize {
		t.Fatalf("seal: %v %d", err, len(sealed))
	}
	c, err := OpenRecoveryCode(bk, sealed, recVault, recID)
	if err != nil || c.Code != testCode().Code || !c.Expires.Equal(testCode().Expires) {
		t.Fatalf("open: %v", err)
	}
	other, _ := ecdh.P256().GenerateKey(nil)
	if _, err := OpenRecoveryCode(other, sealed, recVault, recID); err == nil {
		t.Fatal("opened with another key")
	}
	if _, err := OpenRecoveryCode(bk, sealed, recVault, "01JB2Z6V9K3M4N5P6Q7R8S9T0W"); err == nil {
		t.Fatal("opened for another recovery")
	}
	for _, i := range []int{0, 5, 70, 100, len(sealed) - 1} {
		bad := append([]byte(nil), sealed...)
		bad[i] ^= 1
		if _, err := OpenRecoveryCode(bk, bad, recVault, recID); err == nil {
			t.Fatalf("tampered byte %d accepted", i)
		}
	}
	if _, err := SealRecoveryCode([]byte{4, 1, 2}, testCode()); err == nil {
		t.Fatal("bad browser key accepted")
	}
}

func TestRecoveryQR(t *testing.T) {
	c, err := ParseRecoveryQR(RecoveryQR(testCode()))
	if err != nil || c.Code != testCode().Code {
		t.Fatal(err)
	}
	for _, s := range []string{`{"v":1,"t":"c","vault_id":"` + recVault + `","recovery_id":"` + recID + `","code":"` + strings.Repeat("A", 32) + `"}`,
		`{"v":1,"t":"r","vault_id":"` + recVault + `","recovery_id":"x","code":"` + strings.Repeat("A", 32) + `"}`,
		`{"v":1,"t":"r","vault_id":"` + recVault + `","recovery_id":"` + recID + `","code":"short"}`} {
		if _, err := ParseRecoveryQR([]byte(s)); err == nil {
			t.Errorf("%s accepted", s)
		}
	}
}

func TestUnlockSigningStringCancel(t *testing.T) {
	f := UnlockFields{UserGUID: "user-1", VaultID: "vault-1", RequestID: recID, TS: "2026-10-01T12:00:00.000Z",
		PIN: "123456", Token: "v4.public.VEVTVA", Manifest: []byte("{}")}
	plain, _ := UnlockSigningString(f)
	f.CancelRecovery = true
	s, _ := UnlockSigningString(f)
	if s != plain+"\ncancel_recovery" {
		t.Fatalf("%q", s)
	}
}

func testRegister(t testing.TB) []byte {
	kem, _ := suite.GeneratePrivateKey()
	r := &RecoveryRegisterRequest{UserGUID: "u", VaultID: recVault, RequestID: recID, RecoveryID: recID, Code: strings.Repeat("A", 32),
		IK: make([]byte, 32), KEM: kem.Public(), Relay: RelayAddr{URL: "https://relay.example.org", Mailbox: "m", PK: make([]byte, 32)},
		Name: "phone", Attest: &DeviceAttest{Platform: PlatformAndroid, Chain: [][]byte{{1, 2, 3}}}}
	b, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func FuzzParseRecoveryRegister(f *testing.F) {
	f.Add(testRegister(f))
	f.Fuzz(func(t *testing.T, b []byte) {
		o, err := strictjson.ParseObject(b)
		if err != nil {
			return
		}
		r, err := ParseRecoveryRegister(o)
		if err != nil {
			return
		}
		if len(r.Code) != 32 || len(r.IK) != 32 {
			t.Fatal("invalid request accepted")
		}
	})
}

func FuzzParseRecoveryQR(f *testing.F) {
	f.Add(RecoveryQR(testCode()))
	f.Fuzz(func(t *testing.T, b []byte) {
		if c, err := ParseRecoveryQR(b); err == nil && len(c.Code) != 32 {
			t.Fatal("invalid QR accepted")
		}
	})
}

func FuzzOpenRecoveryCode(f *testing.F) {
	bk, _ := ecdh.P256().NewPrivateKey(append(make([]byte, 31), 7))
	sealed, _ := SealRecoveryCode(bk.PublicKey().Bytes(), testCode())
	f.Add(sealed)
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = OpenRecoveryCode(bk, b, recVault, recID)
	})
}
