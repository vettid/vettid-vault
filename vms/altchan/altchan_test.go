package altchan

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/vms/suite"
)

func TestDevattChallenge(t *testing.T) {
	const rid, ts = "01JB2Z6V9K3M4N5P6Q7R8S9T0V", "2026-10-01T12:00:00.000Z"
	c, err := DevattChallenge(rid, "", ts)
	if err != nil {
		t.Fatal(err)
	}
	if c != sha256.Sum256([]byte("vettid/vms/2/devatt"+rid+ts)) {
		t.Fatal("enroll challenge")
	}
	u, err := DevattChallenge(rid, "vault-1", ts)
	if err != nil || u == c {
		t.Fatal("unlock challenge")
	}
	for _, bad := range [][3]string{{"x", "", ts}, {rid, "a\nb", ts}, {rid, "", "2026-10-01T12:00:00Z"}} {
		if _, err := DevattChallenge(bad[0], bad[1], bad[2]); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestUnlockSigningString(t *testing.T) {
	f := UnlockFields{UserGUID: "user-1", VaultID: "vault-1", RequestID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V",
		TS: "2026-10-01T12:00:00.000Z", ETKKid: suite.Kid{1, 2, 3, 4, 5, 6, 7, 8}, MinStateSeq: 1234, MinHeaderSeq: 1301,
		PIN: "123456", Token: "v4.public.VEVTVA"}
	s, err := UnlockSigningString(f)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(s, "\n")
	if len(lines) != 10 || lines[0] != "vettid/vms/2/unlock" || lines[5] != "0102030405060708" || lines[6] != "1234" ||
		lines[8] != "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92" {
		t.Fatalf("%q", lines)
	}
	f.UserGUID = "a\nb"
	if _, err := UnlockSigningString(f); err == nil {
		t.Fatal("newline accepted")
	}
}

func TestUserData(t *testing.T) {
	if ETKUserData([]byte("d")) != sha256.Sum256([]byte("vettid/vms/2/etkd")) {
		t.Fatal("etk")
	}
	if VaultUserData([]byte("b")) != sha256.Sum256([]byte("vettid/vms/2/vaultb")) {
		t.Fatal("vault")
	}
}
