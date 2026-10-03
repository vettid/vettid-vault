package sharewire

import (
	"bytes"
	"testing"

	"github.com/vettid/vettid-vault/vms/suite"
)

// §10.12: a value sealed to the fetching device's one-time key, bound to
// the grant and the fetch.
func TestSealValue(t *testing.T) {
	k, err := suite.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer k.Destroy()
	sealed, err := SealValue(k.Public(), "g1", "f1", []byte("hunter22"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := OpenValue(k, "g1", "f1", sealed)
	if err != nil || string(v) != "hunter22" {
		t.Fatalf("open: %q %v", v, err)
	}
	for _, c := range [][2]string{{"g2", "f1"}, {"g1", "f2"}} {
		if _, err := OpenValue(k, c[0], c[1], sealed); err == nil {
			t.Fatalf("opened under %v", c)
		}
	}
	other, _ := suite.GeneratePrivateKey()
	defer other.Destroy()
	if _, err := OpenValue(other, "g1", "f1", sealed); err == nil {
		t.Fatal("opened with another key")
	}
	if _, err := SealValue(k.Public(), "g", "f", make([]byte, MaxValue+1)); err == nil {
		t.Fatal("oversized value sealed")
	}
}

func TestAuthMessage(t *testing.T) {
	m := AuthMessage(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), "01JB2Z6V9K3M4N5P6Q7R8S9T0V", []byte("x"))
	if len(m) != 32+32+26+1 || m[0] != 1 || m[32] != 2 || m[len(m)-1] != 'x' {
		t.Fatalf("layout: %x", m)
	}
}

func FuzzOpenValue(f *testing.F) {
	k, _ := suite.NewPrivateKey(bytes.Repeat([]byte{7}, 32))
	s, _ := SealValue(k.Public(), "g", "f", []byte("v"))
	f.Add(s)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = OpenValue(k, "g", "f", b) })
}
