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
		PIN: "123456", Token: "v4.public.VEVTVA", Manifest: []byte("{}")}
	s, err := UnlockSigningString(f)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(s, "\n")
	if len(lines) != 12 || lines[0] != "vettid/vms/2/unlock" || lines[5] != "0102030405060708" || lines[6] != "1234" ||
		lines[8] != "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92" ||
		lines[10] != "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" || lines[11] != "" {
		t.Fatalf("%q", lines)
	}
	f.ToPCR0 = strings.Repeat("cd", 48)
	if s, _ := UnlockSigningString(f); !strings.HasSuffix(s, "\n"+f.ToPCR0) {
		t.Fatal("to_pcr0")
	}
	for name, g := range map[string]func(*UnlockFields){
		"newline":     func(f *UnlockFields) { f.UserGUID = "a\nb" },
		"no manifest": func(f *UnlockFields) { f.Manifest = nil },
		"upper pcr0":  func(f *UnlockFields) { f.ToPCR0 = strings.Repeat("CD", 48) },
		"short pcr0":  func(f *UnlockFields) { f.ToPCR0 = "cd" },
	} {
		h := f
		g(&h)
		if _, err := UnlockSigningString(h); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The §16 approval vector.
func TestApprovalSigningString(t *testing.T) {
	s, err := ApprovalSigningString("test-vault-0001", "01JB2Z6V9K3M4N5P6Q7R8S9T22", strings.Repeat("ab", 48), strings.Repeat("cd", 48), 4, 7)
	if err != nil {
		t.Fatal(err)
	}
	if h := sha256.Sum256([]byte(s)); hexs(h[:]) != "1217fb681eb6a11899ff5ab2ab1a620f179bb942088dc2b79e9b0466380d10b5" {
		t.Fatalf("%x", h)
	}
	if _, err := ApprovalSigningString("v", "01JB2Z6V9K3M4N5P6Q7R8S9T22", strings.Repeat("ab", 48), strings.Repeat("cd", 48), 0, 7); err == nil {
		t.Fatal("release 0")
	}
}

func hexs(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, d[c>>4], d[c&15])
	}
	return string(out)
}

func TestUserData(t *testing.T) {
	if ETKUserData([]byte("d")) != sha256.Sum256([]byte("vettid/vms/2/etkd")) {
		t.Fatal("etk")
	}
	if VaultUserData([]byte("b")) != sha256.Sum256([]byte("vettid/vms/2/vaultb")) {
		t.Fatal("vault")
	}
}
