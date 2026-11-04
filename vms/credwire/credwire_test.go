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
		t.Fatal("chain not reaching the pin accepted")
	}
	// A chain that starts before the pin (links the receiver already
	// followed) is followed from the pin on (VAULT-MESSAGING §10.4).
	k3 := rotKey(4)
	r3, _ := NewKeyRotation(k2, k3)
	end, err = FollowChain(k1.Public().(ed25519.PublicKey), []*KeyRotation{r1, r2, r3})
	if err != nil || !bytes.Equal(end, k3.Public().(ed25519.PublicKey)) {
		t.Fatalf("chain from before the pin: %v", err)
	}
	// The skipped links are not trusted for anything: a broken link after
	// the pin still fails, whatever comes before it.
	brokenAfter := *r3
	brokenAfter.SigOld = make([]byte, ed25519.SignatureSize)
	if _, err := FollowChain(k1.Public().(ed25519.PublicKey), []*KeyRotation{r1, r2, &brokenAfter}); err != ErrChain {
		t.Fatal("a broken link after the pin accepted")
	}
	// An unverifiable link before the pin is skipped, not followed: the
	// result is the same as the chain from the pin alone.
	junk := *r1
	junk.SigNew = make([]byte, ed25519.SignatureSize)
	if end, err = FollowChain(k1.Public().(ed25519.PublicKey), []*KeyRotation{&junk, r2}); err != nil || !bytes.Equal(end, k2.Public().(ed25519.PublicKey)) {
		t.Fatalf("leading link before the pin: %v", err)
	}
	// The first statement from the pin is the one followed: a junk one
	// from the pin before a valid one fails closed (only the member's own
	// vault composes a chain, and honest keys never repeat).
	junkFromPin := *r2
	junkFromPin.SigOld = make([]byte, ed25519.SignatureSize)
	if _, err := FollowChain(k1.Public().(ed25519.PublicKey), []*KeyRotation{&junkFromPin, r2}); err != ErrChain {
		t.Fatal("a junk statement from the pin followed past")
	}
	// MaxKeyChain counts the whole chain, skipped statements included.
	prefixed := make([]*KeyRotation, 0, MaxKeyChain+1)
	for len(prefixed) < MaxKeyChain-1 {
		prefixed = append(prefixed, &junk)
	}
	if _, err := FollowChain(k1.Public().(ed25519.PublicKey), append(prefixed, r2, r3)); err != ErrChain {
		t.Fatal("a chain over MaxKeyChain with its prefix accepted")
	}
	if _, err := FollowChain(k1.Public().(ed25519.PublicKey), append(prefixed[:MaxKeyChain-2], r2, r3)); err != nil {
		t.Fatalf("a chain of MaxKeyChain with its prefix: %v", err)
	}
	// A pinned key that is only a link's new key, never an old one: nothing
	// to follow.
	if _, err := FollowChain(k3.Public().(ed25519.PublicKey), []*KeyRotation{r1, r2, r3}); err != ErrChain {
		t.Fatal("a chain ending at the pin accepted as a change")
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
