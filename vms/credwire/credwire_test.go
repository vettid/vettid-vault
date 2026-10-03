package credwire

import (
	"bytes"
	"crypto/ed25519"
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

func rotKey(b byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)) }

// §3.5.5: a rotation statement is signed by both keys; a chain is followed
// link by link from the pinned key; forged, unsigned, broken or overlong
// chains fail.
func TestKeyRotationChain(t *testing.T) {
	k0, k1, k2 := rotKey(1), rotKey(2), rotKey(3)
	r1, err := NewKeyRotation(k0, k1)
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := NewKeyRotation(k1, k2)
	p1, err := ParseKeyRotation(r1.Marshal())
	if err != nil || p1.Verify() != nil {
		t.Fatalf("round trip: %v", err)
	}
	pin := k0.Public().(ed25519.PublicKey)
	end, err := FollowChain(pin, []*KeyRotation{r1, r2})
	if err != nil || !bytes.Equal(end, k2.Public().(ed25519.PublicKey)) {
		t.Fatal("chain not followed")
	}
	if got := ChainFrom([]*KeyRotation{r1, r2}, k1.Public().(ed25519.PublicKey)); len(got) != 1 {
		t.Fatal("ChainFrom")
	}
	if _, err := FollowChain(pin, []*KeyRotation{r2}); err != ErrChain {
		t.Fatal("chain not starting at the pin accepted")
	}
	// Forged: an attacker key signs as the "new" key but cannot sign as the old.
	evil := rotKey(9)
	forged, _ := NewKeyRotation(evil, k1)
	forged.Old = pin
	if _, err := FollowChain(pin, []*KeyRotation{forged}); err != ErrChain {
		t.Fatal("forged statement accepted")
	}
	unsigned := *r1
	unsigned.SigNew = make([]byte, ed25519.SignatureSize)
	if _, err := FollowChain(pin, []*KeyRotation{&unsigned}); err != ErrChain {
		t.Fatal("statement without the new key's signature accepted")
	}
	if _, err := NewKeyRotation(k0, k0); err != ErrRotation {
		t.Fatal("rotation to the same key")
	}
	long := make([]*KeyRotation, MaxKeyChain+1)
	for i := range long {
		long[i] = r1
	}
	if _, err := FollowChain(pin, long); err != ErrChain {
		t.Fatal("overlong chain")
	}
}

func FuzzParseKeyRotation(f *testing.F) {
	r, _ := NewKeyRotation(rotKey(1), rotKey(2))
	f.Add(r.Marshal())
	f.Fuzz(func(t *testing.T, b []byte) {
		if r, err := ParseKeyRotation(b); err == nil && (len(r.Old) != 32 || len(r.SigNew) != 64) {
			t.Fatal("invalid statement parsed")
		}
	})
}
