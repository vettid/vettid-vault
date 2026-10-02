package hpkederand

import (
	"bytes"
	"crypto/hpke"
	"testing"
)

// The derandomized sender is an independent implementation of the X-Wing
// combiner and the RFC 9180 key schedule; crypto/hpke must open what it
// seals and export the same secrets.
func TestAgreesWithCryptoHPKE(t *testing.T) {
	kem := hpke.MLKEM768X25519()
	for _, b := range []byte{0x05, 0x42, 0xa7} {
		sk, err := kem.NewPrivateKey(bytes.Repeat([]byte{b}, 32))
		if err != nil {
			t.Fatal(err)
		}
		info := []byte("vettid/vms/2/sealed")
		rnd := bytes.Repeat([]byte{b ^ 0x07}, 64)
		s, err := NewSender(sk.PublicKey().Bytes(), info, rnd)
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Enc()) != 1120 {
			t.Fatalf("enc %d", len(s.Enc()))
		}
		ct1, _ := s.Seal([]byte("aad1"), []byte("first"))
		ct2, _ := s.Seal([]byte("aad2"), []byte("second"))
		r, err := hpke.NewRecipient(s.Enc(), sk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
		if err != nil {
			t.Fatal(err)
		}
		for i, c := range []struct{ aad, ct, pt string }{{"aad1", string(ct1), "first"}, {"aad2", string(ct2), "second"}} {
			pt, err := r.Open([]byte(c.aad), []byte(c.ct))
			if err != nil || string(pt) != c.pt {
				t.Fatalf("message %d: %v", i, err)
			}
		}
		a, _ := s.Export("vettid/vms/2/hs-ks", 32)
		e, _ := r.Export("vettid/vms/2/hs-ks", 32)
		if !bytes.Equal(a, e) {
			t.Fatal("exports differ")
		}
		// Deterministic: the same inputs give the same enc.
		s2, _ := NewSender(sk.PublicKey().Bytes(), info, rnd)
		if !bytes.Equal(s.Enc(), s2.Enc()) {
			t.Fatal("not deterministic")
		}
	}
}

func TestRejectsBadInputs(t *testing.T) {
	if _, err := NewSender(make([]byte, 1215), nil, make([]byte, 64)); err == nil {
		t.Fatal("short ek")
	}
	sk, _ := hpke.MLKEM768X25519().NewPrivateKey(bytes.Repeat([]byte{5}, 32))
	if _, err := NewSender(sk.PublicKey().Bytes(), nil, make([]byte, 63)); err == nil {
		t.Fatal("short randomness")
	}
}
