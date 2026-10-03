package credwire

import (
	"bytes"
	"testing"

	"github.com/vettid/vettid-vault/vms/suite"
)

func TestPayloadBinding(t *testing.T) {
	k, _ := suite.GeneratePrivateKey()
	pt := []byte(`{"password":"p"}`)
	s, err := SealPayload(k.Public(), "v", "u1", "credential.unlock", "I1", pt)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := OpenPayload(k, "v", "u1", "credential.unlock", "I1", s); err != nil || !bytes.Equal(got, pt) {
		t.Fatal(err)
	}
	for name, f := range map[string]func() error{
		"other vault":   func() error { _, err := OpenPayload(k, "w", "u1", "credential.unlock", "I1", s); return err },
		"other utk":     func() error { _, err := OpenPayload(k, "v", "u2", "credential.unlock", "I1", s); return err },
		"other type":    func() error { _, err := OpenPayload(k, "v", "u1", "credential.delete", "I1", s); return err },
		"other request": func() error { _, err := OpenPayload(k, "v", "u1", "credential.unlock", "I2", s); return err },
	} {
		if f() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestValue(t *testing.T) {
	k, _ := suite.GeneratePrivateKey()
	s, _ := SealValue(k.Public(), "v", "I1", []byte("seed"))
	if got, err := OpenValue(k, "v", "I1", s); err != nil || string(got) != "seed" {
		t.Fatal(err)
	}
	if _, err := OpenValue(k, "v", "I2", s); err == nil {
		t.Fatal("value moved to another request")
	}
}

func FuzzOpenPayload(f *testing.F) {
	k, _ := suite.NewPrivateKey(bytes.Repeat([]byte{3}, 32))
	s, _ := SealPayload(k.Public(), "v", "u", "t", "i", []byte(`{}`))
	f.Add(s)
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = OpenPayload(k, "v", "u", "t", "i", b) })
}
